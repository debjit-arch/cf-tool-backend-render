const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/Users");
const Department = require("../models/Departments");
const { authenticate, authorizeRoles } = require("../middleware/auth");

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// Allowed roles
const ALLOWED_ROLES = ["risk_owner", "risk_manager", "risk_identifier"];

// ================= USERS =================

// Get all users (protected)
// GET all users
// In new backend: routes/users.js

// Get all users (public)
router.get("/", async (req, res) => {
  try {
    const users = await User.find().populate("department", "name");
    const sanitized = users.map((u) => {
      const { password, ...rest } = u.toObject();
      return {
        ...rest,
        departmentId: u.department?._id,
        departmentName: u.department?.name,
      };
    });
    res.json(sanitized);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add a new user (protected: risk_owner, risk_manager)
router.post(
  "/",
  authenticate,
  authorizeRoles("risk_owner", "risk_manager"),
  async (req, res) => {
    try {
      const { name, role, departmentId, email, password } = req.body;

      if (!name || !role || !departmentId || !email || !password) {
        return res.status(400).json({ error: "All fields are required" });
      }

      if (!ALLOWED_ROLES.includes(role)) {
        return res.status(400).json({
          error: `Invalid role. Allowed roles: ${ALLOWED_ROLES.join(", ")}`,
        });
      }

      const department = await Department.findById(departmentId);
      if (!department)
        return res.status(400).json({ error: "Invalid departmentId" });

      const exists = await User.findOne({ email: email.toLowerCase() });
      if (exists)
        return res.status(400).json({ error: "Email already exists" });

      const hashedPassword = bcrypt.hashSync(password, 10);

      const newUser = new User({
        name,
        role,
        department: department._id,
        email: email.toLowerCase(),
        password: hashedPassword,
      });

      await newUser.save();

      const { password: pwd, ...userWithoutPassword } = newUser.toObject();
      res.status(201).json(userWithoutPassword);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() }).populate(
      "department"
    );
    if (!user)
      return res.status(401).json({ error: "Invalid email or password" });

    const isMatch = bcrypt.compareSync(password, user.password);
    if (!isMatch)
      return res.status(401).json({ error: "Invalid email or password" });

    const token = jwt.sign(
      { id: user._id, role: user.role, departmentId: user.department?._id },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        role: user.role,
        department: user.department,
        email: user.email,
      },
    });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Change password
router.post("/change-password", authenticate, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword)
      return res
        .status(400)
        .json({ error: "Both old and new passwords required" });

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });

    if (!bcrypt.compareSync(oldPassword, user.password))
      return res.status(401).json({ error: "Old password incorrect" });

    user.password = bcrypt.hashSync(newPassword, 10);
    await user.save();

    res.json({ message: "Password changed successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update user
router.put(
  "/:id",
  authenticate,
  authorizeRoles("risk_owner", "risk_manager"),
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ error: "User not found" });

      const { name, role, departmentId, email, password } = req.body;

      if (role && !ALLOWED_ROLES.includes(role))
        return res.status(400).json({
          error: `Invalid role. Allowed roles: ${ALLOWED_ROLES.join(", ")}`,
        });

      if (departmentId) {
        const department = await Department.findById(departmentId);
        if (!department)
          return res.status(400).json({ error: "Invalid departmentId" });
        user.department = department._id;
      }

      if (email) {
        const exists = await User.findOne({
          email: email.toLowerCase(),
          _id: { $ne: user._id },
        });
        if (exists)
          return res.status(400).json({ error: "Email already exists" });
        user.email = email.toLowerCase();
      }

      if (name) user.name = name;
      if (role) user.role = role;
      if (password) user.password = bcrypt.hashSync(password, 10);

      await user.save();
      const { password: pwd, ...userWithoutPassword } = user.toObject();
      res.json(userWithoutPassword);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Delete user
router.delete(
  "/:id",
  authenticate,
  authorizeRoles("risk_owner", "risk_manager"),
  async (req, res) => {
    try {
      if (req.user.id === req.params.id)
        return res.status(400).json({ error: "You cannot delete yourself" });

      const user = await User.findByIdAndDelete(req.params.id);
      if (!user) return res.status(404).json({ error: "User not found" });

      const { password, ...userWithoutPassword } = user.toObject();
      res.json({
        message: "User deleted successfully",
        user: userWithoutPassword,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// ================= DEPARTMENTS =================

// Get all departments
router.get("/departments", async (req, res) => {
  try {
    const depts = await Department.find();
    res.json(depts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add a new department (protected: only risk_owner)
router.post(
  "/departments",
  authenticate,
  authorizeRoles("risk_owner"),
  async (req, res) => {
    try {
      const { name } = req.body;
      if (!name)
        return res.status(400).json({ error: "Department name required" });

      const exists = await Department.findOne({ name });
      if (exists)
        return res.status(400).json({ error: "Department already exists" });

      const newDept = new Department({ name });
      await newDept.save();
      res.status(201).json(newDept);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

module.exports = router;
