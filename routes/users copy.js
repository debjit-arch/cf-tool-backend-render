const express = require("express");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const router = express.Router();

const dataFile = path.join(__dirname, "../data/users.json");

// Allowed roles
const ALLOWED_ROLES = ["risk_owner", "risk_manager", "risk_identifier"];
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// ================= Helper Functions =================
function readData() {
  if (!fs.existsSync(dataFile)) return { users: [], departments: [] };
  return JSON.parse(fs.readFileSync(dataFile));
}

function writeData(data) {
  fs.writeFileSync(dataFile, JSON.stringify(data, null, 2));
}

function getNextId(items) {
  if (items.length === 0) return 1;
  return Math.max(...items.map((i) => i.id)) + 1;
}

// ================= Middleware =================
function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader)
    return res.status(401).json({ error: "Authorization header missing" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token missing" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res
        .status(403)
        .json({ error: "Access denied: insufficient role" });
    }
    next();
  };
}

// ================= USERS =================

// Get all users (public)
router.get("/", (req, res) => {
  const data = readData();
  const usersWithoutPasswords = data.users.map((u) => {
    const { password, ...rest } = u;
    return rest;
  });
  res.json(usersWithoutPasswords);
});

// Add a new user (protected: risk_owner, risk_manager)
router.post(
  "/",
  authenticate,
  authorizeRoles("risk_owner", "risk_manager"),
  (req, res) => {
    const data = readData();
    const { name, role, departmentId, email, password } = req.body;

    if (!name || !role || !departmentId || !email || !password) {
      return res.status(400).json({
        error: "name, role, departmentId, email, password are required",
      });
    }

    if (!ALLOWED_ROLES.includes(role)) {
      return res.status(400).json({
        error: `Invalid role. Allowed roles: ${ALLOWED_ROLES.join(", ")}`,
      });
    }

    const departmentExists = data.departments.some(
      (d) => d.id === departmentId
    );
    if (!departmentExists)
      return res.status(400).json({ error: "Invalid departmentId" });

    const emailExists = data.users.some(
      (u) => u.email.toLowerCase() === email.toLowerCase()
    );
    if (emailExists)
      return res.status(400).json({ error: "Email already exists" });

    const hashedPassword = bcrypt.hashSync(password, 10);

    const newUser = {
      id: getNextId(data.users),
      name,
      role,
      departmentId,
      email,
      password: hashedPassword,
    };

    data.users.push(newUser);
    writeData(data);

    const { password: pwd, ...userWithoutPassword } = newUser;
    res.status(201).json(userWithoutPassword);
  }
);
// ================= CHANGE PASSWORD =================
// Logged-in user can change their own password
router.post("/change-password", authenticate, (req, res) => {
  const { oldPassword, newPassword } = req.body;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: "oldPassword and newPassword are required" });
  }

  const data = readData();
  const userIndex = data.users.findIndex((u) => u.id === req.user.id);

  if (userIndex === -1) {
    return res.status(404).json({ error: "User not found" });
  }

  const user = data.users[userIndex];

  // Check old password
  const isMatch = bcrypt.compareSync(oldPassword, user.password);
  if (!isMatch) {
    return res.status(401).json({ error: "Old password is incorrect" });
  }

  // Update with new hashed password
  data.users[userIndex].password = bcrypt.hashSync(newPassword, 10);
  writeData(data);

  res.json({ message: "Password changed successfully" });
});

// Update user by ID (protected: risk_owner, risk_manager)
router.put(
  "/:id",
  authenticate,
  authorizeRoles("risk_owner", "risk_manager"),
  (req, res) => {
    const userId = parseInt(req.params.id);
    const data = readData();
    const { name, role, departmentId, email, password } = req.body;

    const userIndex = data.users.findIndex((u) => u.id === userId);
    if (userIndex === -1)
      return res.status(404).json({ error: "User not found" });

    if (role && !ALLOWED_ROLES.includes(role)) {
      return res.status(400).json({
        error: `Invalid role. Allowed roles: ${ALLOWED_ROLES.join(", ")}`,
      });
    }

    if (departmentId && !data.departments.some((d) => d.id === departmentId)) {
      return res.status(400).json({ error: "Invalid departmentId" });
    }

    if (email) {
      const emailExists = data.users.some(
        (u) => u.email.toLowerCase() === email.toLowerCase() && u.id !== userId
      );
      if (emailExists)
        return res.status(400).json({ error: "Email already exists" });
    }

    // Update fields
    if (name) data.users[userIndex].name = name;
    if (role) data.users[userIndex].role = role;
    if (departmentId) data.users[userIndex].departmentId = departmentId;
    if (email) data.users[userIndex].email = email;
    if (password)
      data.users[userIndex].password = bcrypt.hashSync(password, 10);

    writeData(data);

    const { password: pwd, ...updatedUser } = data.users[userIndex];
    res.json(updatedUser);
  }
);

// ================= DELETE USER =================
// Delete user by ID (protected: risk_owner, risk_manager)
router.delete(
  "/:id",
  authenticate,
  authorizeRoles("risk_owner", "risk_manager"),
  (req, res) => {
    const userId = parseInt(req.params.id);
    const data = readData();

    // Prevent deleting yourself
    if (req.user.id === userId) {
      return res.status(400).json({ error: "You cannot delete yourself" });
    }

    const userIndex = data.users.findIndex((u) => u.id === userId);
    if (userIndex === -1)
      return res.status(404).json({ error: "User not found" });

    const deletedUser = data.users.splice(userIndex, 1)[0];
    writeData(data);

    const { password, ...userWithoutPassword } = deletedUser;
    res.json({
      message: "User deleted successfully",
      user: userWithoutPassword,
    });
  }
);

// ================= LOGIN =================
router.post("/login", (req, res) => {
  const { email, password } = req.body;
  const data = readData();

  const user = data.users.find(
    (u) => u.email.toLowerCase() === email.toLowerCase()
  );
  if (!user)
    return res.status(401).json({ error: "Invalid email or password" });

  const isMatch = bcrypt.compareSync(password, user.password);
  if (!isMatch)
    return res.status(401).json({ error: "Invalid email or password" });

  const token = jwt.sign(
    { id: user.id, role: user.role, departmentId: user.departmentId },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      role: user.role,
      departmentId: user.departmentId,
      email: user.email,
    },
  });
});

// ================= DEPARTMENTS =================

// Get all departments (public)
router.get("/departments", (req, res) => {
  const data = readData();
  res.json(data.departments);
});

// Add a new department (protected: only risk_owner)
router.post(
  "/departments",
  authenticate,
  authorizeRoles("risk_owner"),
  (req, res) => {
    const data = readData();
    const { name } = req.body;

    if (!name)
      return res.status(400).json({ error: "Department name is required" });

    const exists = data.departments.some(
      (dept) => dept.name.toLowerCase() === name.toLowerCase()
    );
    if (exists)
      return res.status(400).json({ error: "Department already exists" });

    const newDept = { id: getNextId(data.departments), name };
    data.departments.push(newDept);
    writeData(data);
    res.status(201).json(newDept);
  }
);

module.exports = router;
