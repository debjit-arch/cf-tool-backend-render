const mongoose = require("mongoose");

const DepartmentSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    // 🔹 department belongs to a specific organization
    organization: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    }
  },
  { timestamps: true }
);

// 🔹 Ensure department names are unique inside each organization
DepartmentSchema.index({ name: 1, organization: 1 }, { unique: true });

module.exports = mongoose.model("Department", DepartmentSchema);
