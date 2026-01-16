require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const User = require("./models/Users");
const Department = require("./models/Departments");

const users = [
  {
    name: "Saikat Basu",
    role: "super_admin",
    email: "sbasu@consultantsfactory.com",
    password: "admin",
  },
];

async function seedUsers() {
  try {
    await mongoose.connect(
      "mongodb://cftoolind:katana007@docdb-ind.cyarnzzhddsw.ap-south-1.docdb.amazonaws.com:27017/?tls=true&tlsCAFile=global-bundle.pem&retryWrites=false"
    );
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
        password: hashedPassword,
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
