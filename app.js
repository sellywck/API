let express = require("express");
let path = require("path");
const cors = require("cors");
const { Pool } = require("pg");
// const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { DATABASE_URL, SECRET_KEY } = process.env;

let app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    require: true,
  },
});

async function getPostgresVersion() {
  const client = await pool.connect();
  try {
    const response = await client.query("SELECT version()");
    console.log(response.rows[0]);
  } finally {
    client.release();
  }
}

getPostgresVersion();

/** Authentication APIs **/
app.post("/v1/signup", async (req, res) => {
  const client = await pool.connect();

  try {
    const { uid, email, username } = req.body;

    let userResult = await client.query(
      "SELECT * FROM users WHERE email = $1 LIMIT 1",
      [email],
    );

    if (userResult.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered!" });
    }

    await client.query(
      "INSERT INTO users (uid, email, username) VALUES($1, $2, $3)",
      [uid, email, username],
    );
    userResult = await client.query(
      "SELECT * FROM users WHERE email = $1 LIMIT 1",
      [email],
    );
    const user = userResult.rows[0];
    res
      .status(201)
      .json({ user: user, message: "User registered successfully" });
  } catch (error) {
    console.error("Error: ", error.message);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

app.post("/v1/login", async (req, res) => {
  const client = await pool.connect();

  try {
    const { email } = req.body;
    const result = await client.query(
      "SELECT * FROM users WHERE email = $1 LIMIT 1",
      [email],
    );
    const user = result.rows[0];
    // console.log({user})

    //if user not exists, return an error
    if (!user) {
      return res.status(400).json({ message: "User not registered" });
    }

    //if user exists , return token
    const token = jwt.sign(
      {
        id: user.id,
        uid: user.uid,
        email: user.email,
        is_admin: user.is_admin,
      },
      SECRET_KEY,
      { expiresIn: 86400 },
    );

    res
      .status(200)
      .json({ token: token, message: "User logged in successfully" });
  } catch (error) {
    console.error("Error :", error.message);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

app.post("/v1/login/sso", async (req, res) => {
  const client = await pool.connect();

  try {
    const { uid, email, username, profilepicture } = req.body;

    //check if the user exits,if not exists, insert into database
    let userResult = await client.query(
      "SELECT * FROM users WHERE email = $1 LIMIT 1",
      [email],
    );
    // console.log({ userResult });

    if (userResult.rows.length === 0) {
      await client.query(
        "INSERT INTO users (uid, email, username, profilepicture) VALUES($1, $2, $3, $4)",
        [uid, email, username, profilepicture],
      );
    }

    //queries the database again to retrieve the user data after insertion. This is necessary because the user data might have been modified by other processes since the previous query.
    userResult = await client.query(
      "SELECT * FROM users WHERE email = $1 LIMIT 1",
      [email],
    );
    const user = userResult.rows[0];
    // console.log({ user });

    const token = jwt.sign(
      {
        id: user.id,
        uid: user.uid,
        email: user.email,
        is_admin: user.is_admin,
      },
      SECRET_KEY,
      { expiresIn: 86400 },
    );

    res
      .status(200)
      .json({ token: token, message: "User logged in successfully" });
  } catch (error) {
    console.error("Error: ", error.message);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// Update user information

//get user info
app.get("/v1/profile/:id", async (req, res) => {
  const client = await pool.connect();
  const userId = req.params.id;

  try {
    const authToken = req.headers.authorization;

    if (!authToken) return res.status(401).json({ message: "Access Denied" });
    // console.log({ authToken });

    const userIdentity = jwt.verify(authToken, SECRET_KEY);
    const id = req.params.id;
    const parseId = parseInt(id);

    if (userIdentity.id !== parseId) {
      res
        .status(401)
        .json({ message: "You can only update your own account!" });
      return;
    }

    const user = await client.query("SELECT * FROM users WHERE id = $1", [
      userId,
    ]);

    if (user.rowCount > 0) {
      res.json(user.rows[0]);
    } else {
      res.status(400).json({ error: `User with id ${userId} not found` });
    }
  } catch (error) {
    console.error("Error: ", error.message);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

//update user info
app.patch("/v1/profile/:id", async (req, res) => {
  const client = await pool.connect();

  try {
    const authToken = req.headers.authorization;

    if (!authToken) return res.status(401).json({ message: "Access Denied" });
    // console.log({ authToken });

    const userIdentity = jwt.verify(authToken, SECRET_KEY);
    const id = req.params.id;
    const parseId = parseInt(id);

    if (userIdentity.id !== parseId) {
      res
        .status(401)
        .json({ message: "You can only update your own account!" });
      return;
    }

    const { username, profilepicture } = req.body;

    const updateFields = [];
    const queryParams = [];

    if (username !== undefined) {
      updateFields.push("username = $1");
      queryParams.push(username);
    }

    if (profilepicture !== undefined) {
      updateFields.push("profilepicture = $" + (queryParams.length + 1));
      queryParams.push(profilepicture);
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ error: "No fields provided for update" });
    }

    const updatedQuery = `UPDATE users SET ${updateFields.join(", ")} WHERE id = $${queryParams.length + 1} RETURNING *`;

    queryParams.push(id);

    const userExists = await client.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    if (userExists.rowCount === 0) {
      return res.status(400).json({ error: `User with id ${id} not found` });
    }

    const updatedUser = await client.query(updatedQuery, queryParams);
    res.status(200).json({
      data: updatedUser.rows[0],
      message: "User updated successfully!",
    });
  } catch (error) {
    console.error("Error: ", error.message);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

//Posts listing API//
//create listing
app.post("/v1/listings", async (req, res) => {
  const client = await pool.connect();

  try {
    const authToken = req.headers.authorization;

    if (!authToken) return res.status(401).json({ message: "Access Denied" });
    // console.log({ authToken });

    const userIdentity = jwt.verify(authToken, SECRET_KEY);

    const {
      name,
      description,
      address,
      regularprice,
      discountedprice,
      bathrooms,
      bedrooms,
      furnished,
      parking,
      type,
      offer,
      imageurls,
      latitude, 
      longitude, 
      phoneNumber
    } = req.body;
    const listing = await client.query(
      "INSERT INTO listings (user_id, name, description, address, regularprice, discountedprice, bathrooms,bedrooms, furnished, parking, type, offer, imageurls,latitude,longitude, phoneNumber) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16 ) RETURNING *",
      [
        userIdentity.id,
        name,
        description,
        address,
        regularprice,
        discountedprice,
        bathrooms,
        bedrooms,
        furnished,
        parking,
        type,
        offer,
        imageurls,
        latitude, 
        longitude, 
        phoneNumber
      ],
    );

    res.status(201).json(listing.rows[0]);
  } catch (error) {
    console.error("Error: ", error.message);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

//get all listing by userid
app.get("/v1/listings", async (req, res) => {
  const client = await pool.connect();
  try {
    const authToken = req.headers.authorization;

    if (!authToken) return res.status(401).json({ message: "Access Denied" });
    // console.log({ authToken });

    const userIdentity = jwt.verify(authToken, SECRET_KEY);

    const listings = await client.query(
      "SELECT * FROM listings WHERE user_id = $1 ORDER BY created_at DESC",
      [userIdentity.id],
    );
    res.json(listings.rows);
  } catch (error) {
    console.error("Error: ", error.message);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

//get specific listing
app.get("/v1/listings/:listing_id", async (req , res) => {
  
 const client = await pool.connect();
  const listing_id = req.params.listing_id
  try {

    const listing = await client.query(
      "SELECT * FROM listings WHERE id = $1 ",
      [listing_id]
    );
    res.json(listing.rows[0]);
  } catch (error) {
    console.error("Error: ", error.message);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});
//Delete Listing
app.delete("/v1/listings/:listing_id", async (req, res) => {
  const client = await pool.connect();
  const listing_id = req.params.listing_id;

  try {
    const authToken = req.headers.authorization;
    if (!authToken) return res.status(401).json({ message: "Access Denied" });
    // console.log({ authToken });
    const userIdentity = jwt.verify(authToken, SECRET_KEY);
    const userId = userIdentity.id;

    const result = await client.query(
      "DELETE FROM listings WHERE id = $1 AND user_id = $2",
      [listing_id, userId],
    );
    if (result.rowCount === 1) {
      res
        .status(200)
        .json({
          message: `Listing with id ${listing_id} deleted successfully`,
        });
    } else {
      res
        .status(400)
        .json({ message: `Listing with id ${listing_id} not found` });
    }
  } catch (error) {
    console.error("Error: ", error.message);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

//Update Listing
app.put("/v1/listings/:listing_id", async (req, res) => {
  const client = await pool.connect();
  const listing_id = req.params.listing_id;

  try {
    const authToken = req.headers.authorization;
    if (!authToken) return res.status(401).json({ message: "Access Denied" });
    // console.log({ authToken });
    const userIdentity = jwt.verify(authToken, SECRET_KEY);
    const userId = userIdentity.id;

    const {
      name,
      description,
      address,
      regularprice,
      discountedprice,
      bathrooms,
      bedrooms,
      furnished,
      parking,
      type,
      offer,
      imageurls,
      latitude, 
      longitude, 
      phoneNumber
    } = req.body;

    const listingExists = await client.query(
      "SELECT * FROM listings WHERE id = $1 AND user_id = $2 ",
      [listing_id, userId],
    );
    if (listingExists.rowCount === 0) {
      return res
        .status(400)
        .json({
          error: `Listing with id ${listing_id} not found or does not belong to the authenticated user.`,
        });
    }
    const updatedListing = await client.query(
      `UPDATE listings SET name = $1, description = $2, address = $3, regularprice = $4, discountedprice = $5, bathrooms = $6, bedrooms = $7, furnished = $8, parking = $9, type = $10, offer = $11, imageurls = $12,latitude=$13,longitude=$14, phoneNumber=$15, updated_at = NOW()
        WHERE id = $16
        RETURNING *
      `,
      [
        name,
        description,
        address,
        regularprice,
        discountedprice,
        bathrooms,
        bedrooms,
        furnished,
        parking,
        type,
        offer,
        imageurls,
        latitude, 
        longitude, 
        phoneNumber,
        listing_id,
      ],
    );
    res.status(200).json(updatedListing.rows[0]);
  } catch (error) {
    console.error("Error: ", error.message);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

//getListingLandlordEmail
app.get("/v1/listings/landlord/:listing_id", async (req, res) => {
  const client = await pool.connect();
    const listing_id = req.params.listing_id;

    try {
      const authToken = req.headers.authorization;
      if (!authToken) return res.status(401).json({ message: "Access Denied" });
      // console.log({ authToken });


      const listingExists = await client.query(
        "SELECT * FROM listings WHERE id = $1",
        [listing_id],
      );
      if (listingExists.rowCount === 0) {
        return res
          .status(400)
          .json({
            error: `Listing with id ${listing_id} not found!`,
          });
      }
      const listingInfo = await client.query(
        `SELECT users.email, users.username FROM listings INNER JOIN users on listings.user_id = users.id WHERE listings.id = $1
        `, [listing_id]);
      res.status(200).json(listingInfo.rows[0]);
    } catch (error) {
      console.error("Error: ", error.message);
      res.status(500).json({ error: error.message });
    } finally {
      client.release();
    }
  });


//search
app.get("/v1/alllistings", async (req, res) => {
  const client = await pool.connect();

  try {
    const limit = parseInt(req.query.limit) || 9;
    const startIndex = parseInt(req.query.startIndex) || 0;

    let offer = req.query.offer;
    offer = (offer === undefined || offer === 'false') ? [false, true] : [true];

    let furnished = req.query.furnished;
    furnished = (furnished === undefined || furnished === 'false') ? [false, true] : [true];

    let parking = req.query.parking;
    parking = (parking === undefined || parking === 'false') ? [false, true] : [true];

    let type = req.query.type;
    type = (type === undefined || type === 'all') ? ['sale', 'rent'] : [type];

    const searchTerm = `%${req.query.searchTerm || ''}%`;

    const sort = req.query.sort || 'created_at';
    const order = req.query.order || 'desc';

    const listings = await client.query(
      `SELECT * FROM listings 
       WHERE (name ILIKE $1 OR description ILIKE $1 OR address ILIKE $1) 
       AND offer = ANY($2) 
       AND furnished = ANY($3) 
       AND parking = ANY($4) 
       AND type = ANY($5) 
       ORDER BY ${sort} ${order} 
       LIMIT $6 OFFSET $7`,
      [searchTerm, offer, furnished, parking, type, limit, startIndex]
    );

    return res.status(200).json(listings.rows);
  } catch (error) {
    console.error("Error: ", error.message);
    res.status(500).json({ error: "An error occurred while fetching listings." });
  } finally {
    client.release();
  }
});

/** Endpoint ended  */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname + "/index.html"));
});

app.listen(3000, () => {
  console.log("App is listening on port 3000");
});
