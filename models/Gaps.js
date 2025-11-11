const mongoose = require('mongoose');

const gapSchema = new mongoose.Schema({
  clause: { type: String, required: true },
  standardRequirement: { type: String }, // optional
  question: { type: String, required: true },
  documentURL: { type: String },
  practiceEvidence: { type: String },

  docScore: { type: String },
  practiceScore: { type: String },
  docRemarks: { type: String },
  practiceRemarks: { type: String },

  createdBy: { type: String },    // no longer required
  verifiedBy: { type: String },   
  status: { type: String, default: 'Pending' },
}, { timestamps: true });

module.exports = mongoose.model('Gap', gapSchema);
