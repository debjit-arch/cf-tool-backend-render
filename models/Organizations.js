const mongoose = require("mongoose");

const OrganizationSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      unique: true,       // each organization must have a unique name
      trim: true,
    },

    // optional metadata
    address: { type: String },
    phone: { type: String },
    website: { type: String },

    // The root user that originally created this org (optional)
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Organization", OrganizationSchema);
