require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const User = require("./models/Users");
const Department = require("./models/Departments");

const users = [
  {
    name: "Alice(Risk_owner)",
    role: "risk_owner",
    department: "IT",
    email: "alice@example.com",
    password: "password123"
  },
  {
    name: "Bob(Risk_manager)",
    role: "risk_manager",
    department: "HR",
    email: "bob2021@example.com",
    password: "password123"
  },
  {
    name: "Boby(Risk_identifier)",
    role: "risk_identifier",
    department: "HR",
    email: "bob20@example.com",
    password: "password123"
  },
  {
    name: "Debjit(Risk_manager)",
    role: "risk_manager",
    department: "IT",
    email: "debjit@example.com",
    password: "password123"
  }
];

async function seedUsers() {
  try {
    await mongoose.connect("mongodb+srv://debjit:katana007@cluster0.kd9pbws.mongodb.net/test?retryWrites=true&w=majority&appName=Cluster0");
    console.log("Connected to MongoDB");

    // Clear existing users
    await User.deleteMany({});
    console.log("Cleared existing users");

    for (let u of users) {
      const dept = await Department.findOne({ name: u.department });
      if (!dept) throw new Error(`Department not found: ${u.department}`);

      const hashedPassword = bcrypt.hashSync(u.password, 10);

      const user = new User({
        name: u.name,
        role: u.role,
        department: dept._id,
        email: u.email,
        password: hashedPassword
      });

      await user.save();
      console.log(`Created user: ${u.name}`);
    }

    console.log("All users created successfully");
    process.exit();
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

seedUsers();
