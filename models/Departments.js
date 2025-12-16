const mongoose = require("mongoose");

const DepartmentSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    organization: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },
  },
  { timestamps: true }
);

DepartmentSchema.index({ name: 1, organization: 1 }, { unique: true });

module.exports = DepartmentSchema; // ✅ SCHEMA ONLY
