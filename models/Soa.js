const mongoose = require("mongoose");

const SoaSchema = new mongoose.Schema({
  id: { type: Number, required: true, unique: true }, // keep Date.now() style ID
  controlId: { type: Number, required: true },
  category: String,
  description: String,
  status: String,
  documentRef: [String],
  justification: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date },
});

module.exports = mongoose.model("Soa", SoaSchema);
