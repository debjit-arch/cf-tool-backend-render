const mongoose = require("mongoose");

const gapSchema = new mongoose.Schema(
  {
    docId: { type: String, required: true },
    status: { type: String, default: "Pending" },
    docName: { type: String, required: true },
    missing_sections: { type: [String], default: [] },
    forbidden_phrases_found: { type: [String], default: [] },
    missing_keywords: { type: [String], default: [] },
    score: { type: Number, default: 0 },
    label: { type: String, default: "non-compliant" },
    checkedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Gap", gapSchema);
