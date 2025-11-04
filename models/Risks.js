const mongoose = require('mongoose');

const RiskSchema = new mongoose.Schema({
  riskId: { type: String, required: true, unique: true },
  department: String,
  date: String,
  riskType: String,
  assetType: String,
  asset: String,
  location: String,
  riskDescription: String,
  confidentiality: Number,
  integrity: Number,
  availability: Number,
  impact: Number,
  probability: String,
  threat: String,
  vulnerability: [String],
  existingControls: String,
  additionalNotes: String,
  controlReference: [String],
  additionalControls: String,
  numberOfDays: String,
  deadlineDate: String,
  riskScore: Number,
  riskLevel: String,
  likelihoodAfterTreatment: String,
  impactAfterTreatment: String,
  status: { type: String, default: 'Active' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Risk', RiskSchema);
