const mongoose = require("mongoose");

const RiskSchema = new mongoose.Schema(
  {
    // 🔐 Multi-tenant isolation (KEEP STRING for consistency)
    organization: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      index: true,
    },

    // Risk identity (unique per organization)
    riskId: {
      type: String,
      required: true,
      trim: true,
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
      enum: ["Active", "Closed", "Mitigated"],
    },
  },
  {
    timestamps: true, // auto manages createdAt & updatedAt
    strict: true,
  }
);

// ✅ Unique riskId PER organization
RiskSchema.index({ riskId: 1, organization: 1 }, { unique: true });

/**
 * 🚨 IMPORTANT
 * Export ONLY the schema
 * Model MUST be created per-region via getModel(db, ...)
 */
module.exports = RiskSchema;
