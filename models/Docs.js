const mongoose = require("mongoose");

const DocumentSchema = new mongoose.Schema({
  id: { type: Number, required: true, unique: true }, // same as your JSON id
  name: { type: String, required: true },
  url: { type: String, required: true },
  soaId: { type: String, default: null },
  controlId: { type: String, default: null },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Document", DocumentSchema);
