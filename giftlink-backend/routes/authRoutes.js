/*jshint esversion: 8 */
const express = require("express");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const connectToDatabase = require("../models/db");
const router = express.Router();
const dotenv = require("dotenv");
const pino = require("pino"); // Import Pino logger
const { validationResult } = require("express-validator");
const { ObjectId } = require('mongodb');
dotenv.config();

const logger = pino(); // Create a Pino logger instance

//Create JWT secret
dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;

router.post("/register", async (req, res) => {
  try {
    //Connect to `giftsdb` in MongoDB through `connectToDatabase` in `db.js`.
    const db = await connectToDatabase();

    //Access the `users` collection
    const collection = db.collection("users");

    //Check for existing email in DB
    const existingEmail = await collection.findOne({ email: req.body.email });

    if (existingEmail) {
      logger.error("Email id already exists");
      return res.status(400).json({ error: "Email id already exists" });
    }

    const salt = await bcryptjs.genSalt(10);
    const hash = await bcryptjs.hash(req.body.password, salt);
    const email = req.body.email;

    //Save user details
    const newUser = await collection.insertOne({
      email: req.body.email,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      password: hash,
      createdAt: new Date(),
    });

    const payload = {
      user: {
        id: newUser.insertedId,
      },
    };

    //Create JWT
    const authtoken = jwt.sign(payload, JWT_SECRET);
    logger.info("User registered successfully");
    res.json({ authtoken, email });
  } catch (e) {
    logger.error(e);
    return res.status(500).send("Internal server error");
  }
});

//Login Endpoint
router.post("/login", async (req, res) => {
  console.log("\n\n Inside login");

  try {
    // const collection = await connectToDatabase();
    const db = await connectToDatabase();
    const collection = db.collection("users");
    const theUser = await collection.findOne({ email: req.body.email });

    if (theUser) {
      let result = await bcryptjs.compare(req.body.password, theUser.password);
      if (!result) {
        logger.error("Passwords do not match");
        return res.status(404).json({ error: "Wrong pasword" });
      }
      let payload = {
        user: {
          id: theUser._id.toString(),
        },
      };

      const userName = theUser.firstName;
      const userEmail = theUser.email;

      const authtoken = jwt.sign(payload, JWT_SECRET);
      logger.info("User logged in successfully");
      return res.status(200).json({ authtoken, userName, userEmail });
    } else {
      logger.error("User not found");
      return res.status(404).json({ error: "User not found" });
    }
  } catch (e) {
    logger.error(e);
    return res
      .status(500)
      .json({ error: "Internal server error", details: e.message });
  }
});
router.put("/update", async (req, res) => {
  // Task 2: Validate the input using `validationResult` and return approiate message if there is an error.
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.error("Validation errors in update request", errors.array());
    return res.status(400).json({ errors: errors.array() });
  }
  // Task 3: Check if the user is logged in
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    logger.error("No token provided");
    return res.status(401).json({ error: "No token provided" });
  }
  // Task 4: Verify the token
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded.user;
  } catch (e) {
    logger.error("Invalid token");
    return res.status(401).json({ error: "Invalid token" });
  }

  try {
    const userId = req.user.id;
    const db = await connectToDatabase();
    const collection = db.collection("users");

    // Convert userId string to ObjectId
    const id = new ObjectId(userId);

    const existingUser = await collection.findOne({ _id: id });
    if (!existingUser) {
      logger.error('User not found');
      return res.status(404).json({ error: "User not found" });
    }

    const { firstName, lastName, email, password, name } = req.body;
    const updateData = {};
    if (firstName || name) updateData.firstName = firstName || name;
    if (lastName) updateData.lastName = lastName;
    if (email) updateData.email = email;

    if (password) {
      const salt = await bcryptjs.genSalt(10);
      updateData.password = await bcryptjs.hash(password, salt);
    }

    const updatedUser = await collection.findOneAndUpdate(
      { _id: id },
      { $set: updateData },
      { returnDocument: 'after' }
    );
    // Task 7: create JWT authentication using secret key from .env file
    const payload = {
      user: {
        id: updatedUser._id.toString(),
      },
    };
    const authtoken = jwt.sign(payload, JWT_SECRET);

    res.json({ authtoken });
  } catch (e) {
    logger.error(e);
    return res.status(500).send("Internal server error");
  }
});

module.exports = router;
