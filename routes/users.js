const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/Users");
const Department = require("../models/Departments");
const { authenticate, authorizeRoles } = require("../middleware/auth");

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// Allowed roles
const ALLOWED_ROLES = ["super_admin","risk_owner", "risk_manager", "risk_identifier"];

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
  authorizeRoles("super_admin", "risk_owner", "risk_manager"),
  async (req, res) => {
    try {
      const { name, role, departmentId, email, password } = req.body;

      if (!name || !role || !email || !password) {
        return res.status(400).json({ error: "All fields are required" });
      }

      // ✅ Validate role
      if (!ALLOWED_ROLES.includes(role)) {
        return res.status(400).json({
          error: `Invalid role. Allowed roles: ${ALLOWED_ROLES.join(", ")}`,
        });
      }

      // ✅ Prevent non-super-admins from creating super_admins
      if (role === "super_admin" && req.user.role !== "super_admin") {
        return res.status(403).json({ error: "Only super_admin can create another super_admin" });
      }

      // ✅ For users (non-super_admin), department is required
      if (role !== "super_admin" && !departmentId) {
        return res.status(400).json({ error: "departmentId is required for this role" });
      }

      const department =
        role !== "super_admin" ? await Department.findById(departmentId) : null;
      if (role !== "super_admin" && !department)
        return res.status(400).json({ error: "Invalid departmentId" });

      const exists = await User.findOne({ email: email.toLowerCase() });
      if (exists)
        return res.status(400).json({ error: "Email already exists" });

      const hashedPassword = bcrypt.hashSync(password, 10);

      const newUser = new User({
        name,
        role,
        department: role === "super_admin" ? undefined : department?._id,
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
  authorizeRoles("super_admin", "risk_owner", "risk_manager"), // ✅ also allow super_admin
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ error: "User not found" });

      const { name, role, departmentId, email, password } = req.body;

      // ✅ Check for valid role first
      if (role && !ALLOWED_ROLES.includes(role)) {
        return res.status(400).json({
          error: `Invalid role. Allowed roles: ${ALLOWED_ROLES.join(", ")}`,
        });
      }

      // ✅ Prevent non-super-admins from assigning super_admin role
      if (role === "super_admin" && req.user.role !== "super_admin") {
        return res
          .status(403)
          .json({ error: "Only super_admin can assign super_admin role" });
      }

      // ✅ Prevent non-super-admins from editing a super_admin user
      if (user.role === "super_admin" && req.user.role !== "super_admin") {
        return res
          .status(403)
          .json({ error: "Only super_admin can modify another super_admin" });
      }

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
  authorizeRoles("super_admin", "risk_owner", "risk_manager"), // ✅ allow super_admin too
  async (req, res) => {
    try {
      // ✅ Prevent self-deletion
      if (req.user.id === req.params.id)
        return res.status(400).json({ error: "You cannot delete yourself" });

      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ error: "User not found" });

      // ✅ Only super_admin can delete another super_admin
      if (user.role === "super_admin" && req.user.role !== "super_admin") {
        return res
          .status(403)
          .json({ error: "Only super_admin can delete another super_admin" });
      }

      await user.deleteOne();

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
  authorizeRoles("super_admin"),
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

// Update department name
router.put(
  "/departments/:id",
  authenticate,
  authorizeRoles("super_admin"), // ✅ Only super_admin can update departments
  async (req, res) => {
    try {
      const { name } = req.body;
      if (!name)
        return res.status(400).json({ error: "Department name required" });

      const department = await Department.findById(req.params.id);
      if (!department)
        return res.status(404).json({ error: "Department not found" });

      // Check if name already exists
      const exists = await Department.findOne({ name, _id: { $ne: req.params.id } });
      if (exists)
        return res.status(400).json({ error: "Department name already exists" });

      department.name = name;
      await department.save();

      res.json({ message: "Department updated successfully", department });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Delete department
router.delete(
  "/departments/:id",
  authenticate,
  authorizeRoles("super_admin"), // ✅ Only super_admin can delete departments
  async (req, res) => {
    try {
      const department = await Department.findById(req.params.id);
      if (!department)
        return res.status(404).json({ error: "Department not found" });

      // Optional: Check if any users belong to this department
      const userExists = await User.findOne({ department: department._id });
      if (userExists)
        return res.status(400).json({
          error: "Cannot delete department with assigned users",
        });

      await department.deleteOne();
      res.json({ message: "Department deleted successfully" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);


module.exports = router;
