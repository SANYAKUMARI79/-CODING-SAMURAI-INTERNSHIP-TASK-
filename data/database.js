const mongoose = require("mongoose");

// Import all schemas
const User = require("../model/users"); // Adjust the path as needed
const Post = require("../model/posts");
const Comment = require("../model/comments");
const Like = require("../model/likes");

// MongoDB connection URI
const uri =
  "mongodb+srv://sanyasrivastava08092004:xoV9CH104YB2s2pF@cluster0.utron.mongodb.net/?retryWrites=true&w=majority&appName=Cosmic";

// Connect to MongoDB using Mongoose
async function connectToDatabase() {
  try {
    await mongoose.connect(uri);
    console.log("Connected successfully to MongoDB");
  } catch (error) {
    console.error("Error connecting to MongoDB:", error.message);
  }
}

// Exporting the connection function and models
module.exports = {
  connectToDatabase,
  User,
  Post,
  Comment,
  Like,
};

// Connect to the database immediately when this file is required
connectToDatabase();
