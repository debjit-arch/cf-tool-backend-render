const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },

    role: {
      type: String,
      enum: [
        "super_admin",
        "root",
        "risk_owner",
        "risk_manager",
        "risk_identifier",
      ],
      required: true,
    },

    organization: {
      type: String,
      required: function () {
        return this.role !== "super_admin";
      },
      lowercase: true,
      trim: true,
    },

    department: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Department",
      required: function () {
        return this.role !== "super_admin" && this.role !== "root";
      },
    },

    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },

    password: { type: String, required: true },

    isAuditor: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

// Unique email per organization
UserSchema.index({ email: 1, organization: 1 }, { unique: true });

module.exports = UserSchema; // ✅ SCHEMA ONLY
