const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  role: { 
    type: String, 
    required: true, 
    enum: ["risk_owner", "risk_manager", "risk_identifier"] 
  },
  department: { type: mongoose.Schema.Types.ObjectId, ref: "Department", required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}, { timestamps: true });

module.exports = mongoose.model("User", UserSchema);
