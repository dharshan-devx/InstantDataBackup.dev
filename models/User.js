import mongoose from 'mongoose'; // Or const mongoose = require('mongoose');
import bcrypt from 'bcrypt'; // Or const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
  },
  // You can add other fields later, e.g., name, subscription_tier, etc.
  // --- NEW FIELDS FOR PASSWORD RESET ---
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  // --- END NEW FIELDS ---
  createdAt: {
    type: Date,
    default: Date.now,
  }
}, {
  timestamps: true // Adds createdAt and updatedAt timestamps automatically (createdAt and updatedAt)
});

// Middleware to hash password before saving the user
// This will be triggered for new users and when a user's password is changed.
userSchema.pre('save', async function(next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('password')) {
    return next();
  }
  try {
    const salt = await bcrypt.genSalt(10); // Generate a salt with 10 rounds
    this.password = await bcrypt.hash(this.password, salt); // Hash the password
    next();
  } catch (error) {
    next(error); // Pass any errors to the next middleware
  }
});

const User = mongoose.model('User', userSchema);

export default User; // Or module.exports = User; if using CommonJS