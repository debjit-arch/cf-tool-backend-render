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

    // 🔹 Organization each user belongs to
    organization: {
      type: String,
      required: function () {
        return this.role !== "super_admin"; // super_admin does NOT need organization
      },
      lowercase: true,
      trim: true,
    },

    // 🔹 Department inside that organization
    department: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Department",
      required: function () {
        return this.role !== "super_admin" && this.role !== "root";
        // only required for risk_owner, risk_manager, risk_identifier
      },
    },

    // 🔹 Email should be unique per organization, not globally
    email: {
      type: String,
      required: true,
    },
    password: { type: String, required: true },
    isAuditor: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

// 🔹 MongoDB compound index: unique email within the same organization
UserSchema.index({ email: 1, organization: 1 }, { unique: true });

module.exports = mongoose.model("User", UserSchema);
