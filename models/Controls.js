const mongoose = require("mongoose");

const ControlSchema = new mongoose.Schema({
  id: { type: Number, required: true, unique: true }, // matches your JSON ID system
  category: { type: String, required: true },
  description: { type: String, required: true },
});

module.exports = mongoose.model("Control", ControlSchema);
