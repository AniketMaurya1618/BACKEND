const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
  fullname: {
    firstname: {
      type: String,
      required: true,
      minLength: [3, 'First name must be at least 3 characters.'],
    },
    lastname: {
      type: String,
      minLength: [3, 'Last name must be at least 3 characters.'],
    },
  },
  email: {
    type: String,
    required: true,
    unique: true,
    minLength: [3, 'Email ID must be at least 3 characters.'],
    match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please enter a valid email address.'],
  },
  password: {
    type: String,
    required: true,
    select: false,
  },
  socketId: {
    type: String,
  },
});

// Generate auth token
userSchema.methods.generateAuthToken = function () {
  const token = jwt.sign({ _id: this._id }, process.env.JWT_SECRET);
  return token;
};

// Compare password
userSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// Hash password
userSchema.methods.hashPassword = async function (password) {
  return await bcrypt.hash(password, 10);
};

// Create the model
const userModel = mongoose.model('User', userSchema);

module.exports = userModel;
