require("dotenv").config();
const mongoose = require("mongoose");
const Department = require("./models/Departments");

const departments = [
  { name: "IT" },
  { name: "HR" },
  { name: "Finance" }
];

async function seedDepartments() {
  try {
    await mongoose.connect("mongodb+srv://debjit:katana007@cluster0.kd9pbws.mongodb.net/test?retryWrites=true&w=majority&appName=Cluster0");
    console.log("Connected to MongoDB");

    // Remove existing
    await Department.deleteMany({});
    console.log("Cleared existing departments");

    // Insert new
    const result = await Department.insertMany(departments);
    console.log("Departments created:", result);

    process.exit();
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

seedDepartments();
