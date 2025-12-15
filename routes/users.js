const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { authenticate, authorizeRoles } = require("../middleware/auth");
const { sendOtpEmail } = require("../utils/mail");

const User = require("../models/Users");
const Department = require("../models/Departments");
const Organization = require("../models/Organizations");

const router = express.Router();

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "hbDGxyixY2wvTjNVUcxjIX/hyRasXYo/b0HrXm8GdinvtWQrq0/0NGO+acdzfNyrw5DccbNQHy0S0TKGWNjHWQ==";

const ALLOWED_ROLES = [
  "super_admin",
  "root",
  "risk_owner",
  "risk_manager",
  "risk_identifier",
];

// -------------------------
// Helper: get region-specific models
// -------------------------
function getModels(db) {
  return {
    User: db.model("User", User.schema),
    Department: db.model("Department", Department.schema),
    Organization: db.model("Organization", Organization.schema),
  };
}

// =============================
// USERS ROUTES
// =============================

// GET ALL USERS
router.get("/", authenticate, async (req, res) => {
  try {
    const { User, Department } = getModels(req.db);

    let query = {};
    if (req.user.role === "super_admin" || req.user.role === "root") {
      query.organization = req.user.organization;
    }

    const users = await User.find(query).populate("department", "name");
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

// CREATE USER
router.post(
  "/",
  authenticate,
  authorizeRoles("super_admin", "root"),
  async (req, res) => {
    try {
      const { User, Department } = getModels(req.db);
      const { name, role, departmentId, email, password, organization } =
        req.body;

      if (!name || !role || !email || !password)
        return res.status(400).json({ error: "All fields are required" });

      if (!ALLOWED_ROLES.includes(role))
        return res
          .status(400)
          .json({
            error: `Invalid role. Allowed roles: ${ALLOWED_ROLES.join(", ")}`,
          });

      // Role-based creation rules
      if (role === "root" && req.user.role !== "super_admin")
        return res
          .status(403)
          .json({ error: "Only super_admin can create root accounts" });

      if (
        (role === "risk_owner" || role === "risk_identifier") &&
        req.user.role !== "root"
      )
        return res
          .status(403)
          .json({ error: "Only root can create risk owners or identifiers" });

      let userOrg;
      if (role === "super_admin") userOrg = undefined;
      else if (role === "root") {
        if (!organization)
          return res
            .status(400)
            .json({ error: "Organization is required for root" });
        userOrg = organization;
      } else userOrg = req.user.organization;

      let userDept;
      if (role === "risk_owner" || role === "risk_identifier") {
        if (!departmentId)
          return res
            .status(400)
            .json({ error: "Department is required for this role" });
        const dep = await Department.findById(departmentId);
        if (!dep)
          return res.status(400).json({ error: "Invalid departmentId" });
        userDept = dep._id;
      }

      const exists = await User.findOne({
        email: email.toLowerCase(),
        organization: userOrg,
      });
      if (exists)
        return res
          .status(400)
          .json({ error: "Email already exists in this organization" });

      const hashedPassword = bcrypt.hashSync(password, 10);

      const newUser = new User({
        name,
        role,
        organization: userOrg,
        department: userDept,
        email: email.toLowerCase(),
        password: hashedPassword,
      });
      await newUser.save();

      const { password: pwd, ...withoutPassword } = newUser.toObject();
      res.status(201).json(withoutPassword);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// LOGIN
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const { User } = getModels(req.db);

    const user = await User.findOne({ email: email.toLowerCase() }).populate(
      "department"
    );
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const isMatch = bcrypt.compareSync(password, user.password);
    if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      {
        id: user._id,
        role: user.role,
        organization: user.organization,
        departmentId: user.department?._id,
      },
      JWT_SECRET,
      { expiresIn: "10h" }
    );

    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// CHANGE PASSWORD
router.post("/change-password", authenticate, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const { User } = getModels(req.db);

    if (!oldPassword || !newPassword)
      return res
        .status(400)
        .json({ error: "Old & new passwords are required" });

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });
    if (!bcrypt.compareSync(oldPassword, user.password))
      return res.status(401).json({ error: "Incorrect old password" });

    user.password = bcrypt.hashSync(newPassword, 10);
    await user.save();
    res.json({ message: "Password changed successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// FORGOT / VERIFY / RESET PASSWORD
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const { User } = getModels(req.db);

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ error: "User not found" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + 10 * 60 * 1000;
    if (!req.session.otpStore) req.session.otpStore = {};
    req.session.otpStore[email.toLowerCase()] = { otp, expiresAt: expiry };
    await sendOtpEmail(email, otp);

    res.json({ message: "OTP sent" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/verify-otp", (req, res) => {
  try {
    const { email, otp } = req.body;
    const store = req.session.otpStore?.[email.toLowerCase()];
    if (!store) return res.status(400).json({ error: "OTP not found" });
    if (store.otp !== otp)
      return res.status(400).json({ error: "Incorrect OTP" });
    if (Date.now() > store.expiresAt)
      return res.status(400).json({ error: "OTP expired" });

    delete req.session.otpStore[email.toLowerCase()];
    res.json({ message: "OTP verified" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/reset-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    const { User } = getModels(req.db);

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ error: "User not found" });

    user.password = bcrypt.hashSync(newPassword, 10);
    await user.save();
    res.json({ message: "Password reset successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE USER
router.put(
  "/:id",
  authenticate,
  authorizeRoles("super_admin", "root"),
  async (req, res) => {
    try {
      const { User, Department } = getModels(req.db);
      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ error: "User not found" });

      const {
        name,
        role,
        departmentId,
        email,
        password,
        organization,
        isAuditor,
      } = req.body;

      if (
        req.user.role !== "root" &&
        user.organization !== req.user.organization
      )
        return res
          .status(403)
          .json({ error: "Cannot modify users from another organization" });

      if (role && !ALLOWED_ROLES.includes(role))
        return res.status(400).json({ error: "Invalid role" });
      if (role === "super_admin" && req.user.role !== "root")
        return res
          .status(403)
          .json({ error: "Only root can assign super_admin role" });

      if (email) {
        const exists = await User.findOne({
          email: email.toLowerCase(),
          _id: { $ne: user._id },
        });
        if (exists)
          return res.status(400).json({ error: "Email already in use" });
        user.email = email.toLowerCase();
      }

      if (name) user.name = name;
      if (role) user.role = role;
      if (password) user.password = bcrypt.hashSync(password, 10);

      if (departmentId) {
        const dep = await Department.findById(departmentId);
        if (!dep)
          return res.status(400).json({ error: "Invalid departmentId" });
        user.department = dep._id;
      }

      if (organization && req.user.role === "root")
        user.organization = organization;
      if (typeof isAuditor !== "undefined") user.isAuditor = isAuditor;

      await user.save();
      const { password: pwd, ...finalUser } = user.toObject();
      res.json(finalUser);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// DELETE USER
router.delete(
  "/:id",
  authenticate,
  authorizeRoles("super_admin", "root"),
  async (req, res) => {
    try {
      const { User } = getModels(req.db);
      if (req.user.id === req.params.id)
        return res.status(400).json({ error: "You cannot delete yourself" });

      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ error: "User not found" });

      if (
        req.user.role !== "root" &&
        user.organization !== req.user.organization
      )
        return res
          .status(403)
          .json({ error: "Cannot delete users from another organization" });

      if (user.role === "super_admin" && req.user.role !== "root")
        return res
          .status(403)
          .json({ error: "Only root can delete a super_admin" });

      await user.deleteOne();
      const { password, ...rest } = user.toObject();
      res.json({ message: "User deleted", user: rest });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// =============================
// DEPARTMENTS ROUTES
// =============================
router.get("/departments", async (req, res) => {
  try {
    const { Department } = getModels(req.db);
    res.json(await Department.find());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post(
  "/departments",
  authenticate,
  authorizeRoles("super_admin", "root"),
  async (req, res) => {
    try {
      const { Department } = getModels(req.db);
      const { name } = req.body;
      if (!name)
        return res.status(400).json({ error: "Department name is required" });

      const exists = await Department.findOne({
        name,
        organization: req.user.organization,
      });
      if (exists)
        return res
          .status(400)
          .json({ error: "Department already exists in your organization" });

      const dept = await Department.create({
        name,
        organization: req.user.organization,
      });
      res.status(201).json(dept);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

router.put(
  "/departments/:id",
  authenticate,
  authorizeRoles("super_admin", "root"),
  async (req, res) => {
    try {
      const { Department } = getModels(req.db);
      const { name } = req.body;
      const department = await Department.findById(req.params.id);
      if (!department)
        return res.status(404).json({ error: "Department not found" });

      const exists = await Department.findOne({
        name,
        _id: { $ne: department._id },
      });
      if (exists)
        return res
          .status(400)
          .json({ error: "Department name already exists" });

      department.name = name;
      await department.save();
      res.json({ message: "Department updated", department });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

router.delete(
  "/departments/:id",
  authenticate,
  authorizeRoles("super_admin"),
  async (req, res) => {
    try {
      const { Department, User } = getModels(req.db);
      const department = await Department.findById(req.params.id);
      if (!department)
        return res.status(404).json({ error: "Department not found" });

      const userExists = await User.findOne({ department: department._id });
      if (userExists)
        return res
          .status(400)
          .json({ error: "Cannot delete department with assigned users" });

      await department.deleteOne();
      res.json({ message: "Department deleted" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// =============================
// ORGANIZATIONS ROUTES
// =============================
router.get("/organizations", authenticate, async (req, res) => {
  try {
    const { Organization } = getModels(req.db);
    res.json(await Organization.find());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post(
  "/organizations",
  authenticate,
  authorizeRoles("super_admin"),
  async (req, res) => {
    try {
      const { Organization } = getModels(req.db);
      const { name } = req.body;
      if (!name)
        return res.status(400).json({ error: "Organization name is required" });

      const exists = await Organization.findOne({ name });
      if (exists)
        return res.status(400).json({ error: "Organization already exists" });

      const org = await Organization.create({ name });
      res.status(201).json(org);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

router.delete(
  "/organizations/:id",
  authenticate,
  authorizeRoles("super_admin"),
  async (req, res) => {
    try {
      const { Organization, User } = getModels(req.db);
      const org = await Organization.findById(req.params.id);
      if (!org)
        return res.status(404).json({ error: "Organization not found" });

      const usersExist = await User.findOne({ organization: org._id });
      if (usersExist)
        return res
          .status(400)
          .json({ error: "Cannot delete organization with assigned users" });

      await org.deleteOne();
      res.json({ message: "Organization deleted" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

module.exports = router;
