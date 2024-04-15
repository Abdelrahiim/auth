const mongoose = require("mongoose");

const UserSchmea = mongoose.Schema({
  email: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  firstname: String,
  lastname: String,
  age: Number,
  gender: String,
  address: String,
  phone: String,
  image: String,
  role: {
    type: String,
    default: "user"
  },
}, { timestamps: true });

const User = mongoose.model("user", UserSchmea);

module.exports = User
