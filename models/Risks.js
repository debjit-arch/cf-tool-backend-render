const mongoose = require("mongoose");

const RiskSchema = new mongoose.Schema(
  {
    // 🔐 Multi-tenant isolation
    organization: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true,
    },

    // Risk identity (unique per organization)
    riskId: {
      type: String,
      required: true,
    },

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
    additionalControls: String,
    additionalNotes: String,

    controlReference: [String],

    numberOfDays: String,
    deadlineDate: String,

    riskScore: Number,
    riskLevel: String,

    likelihoodAfterTreatment: String,
    impactAfterTreatment: String,

    status: {
      type: String,
      default: "Active",
    },
  },
  {
    timestamps: true, // ✅ auto manages createdAt & updatedAt
    strict: true, // ✅ keep strict ON (important)
  }
);

// ✅ Risk ID must be unique PER organization (not globally)
RiskSchema.index({ riskId: 1, organization: 1 }, { unique: true });

module.exports = mongoose.model("Risk", RiskSchema);
