const mongoose = require("mongoose");

const DocumentSchema = new mongoose.Schema({
  id: { type: Number, required: true, unique: true },
  name: { type: String, required: true },
  url: { type: String, required: true },
  soaId: { type: String, default: null },
  controlId: { type: String, default: null },
  uploaderName: { type: String, default: null }, // 🆕 Add this
  departmentName: { type: String, default: null }, // 🆕 Add this
  approvalDate: { type: Date, default: null }, // 🆕 Add this (optional)
  nextApprovalDate: { type: Date, default: null }, // 🆕 Add this (optional)
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Document", DocumentSchema);
