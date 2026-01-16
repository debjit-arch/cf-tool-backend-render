const mongoose = require("mongoose");

const taskSchema = new mongoose.Schema(
  {
    riskId: { type: String, required: true },
    department: { type: String, required: true },
    employee: { type: String, default: "" },
    description: { type: String, required: true },
    startDate: { type: String, required: true },
    endDate: { type: String, required: true },
    taskId: { type: String, unique: true },
    status: { type: String, default: "Pending" },
  },
  { timestamps: true } // adds createdAt, updatedAt
);

module.exports = mongoose.model("Task", taskSchema);
