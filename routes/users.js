const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { authenticate, authorizeRoles } = require("../middleware/auth");
const { sendOtpEmail } = require("../utils/mail");
const getModel = require("../utils/getModel");

const UserSchema = require("../models/Users");
const DepartmentSchema = require("../models/Departments");
const OrganizationSchema = require("../models/Organizations");

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET_IN_ENV";

const ALLOWED_ROLES = [
  "super_admin",
  "root",
  "risk_owner",
  "risk_manager",
  "risk_identifier",
];

// -------------------------
// Region / tenant aware models
// -------------------------
function getModels(db) {
  return {
    User: getModel(db, "User", UserSchema),
    Department: getModel(db, "Department", DepartmentSchema),
    Organization: getModel(db, "Organization", OrganizationSchema),
  };
}

/* ======================================================
   USERS
====================================================== */

// GET USERS
router.get("/", authenticate, async (req, res) => {
  try {
    const { User } = getModels(req.db);

    const query =
      req.user.role === "super_admin"
        ? {}
        : { organization: req.user.organization };

    const users = await User.find(query)
      .populate("department", "name")
      .select("-password");

    res.json(users);
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
      const { name, role, email, password, departmentId, organization } =
        req.body;

      if (!name || !role || !email || !password)
        return res.status(400).json({ error: "Missing required fields" });

      if (!ALLOWED_ROLES.includes(role))
        return res.status(400).json({ error: "Invalid role" });

      if (role === "root" && req.user.role !== "super_admin")
        return res
          .status(403)
          .json({ error: "Only super_admin can create root" });

      let orgId;
      if (role === "super_admin") orgId = null;
      else if (role === "root") {
        if (!organization)
          return res.status(400).json({ error: "Organization required" });
        orgId = organization;
      } else {
        orgId = req.user.organization;
      }

      let deptId;
      if (["risk_owner", "risk_identifier"].includes(role)) {
        const dept = await Department.findOne({
          _id: departmentId,
          organization: orgId,
        });
        if (!dept) return res.status(400).json({ error: "Invalid department" });
        deptId = dept._id;
      }

      const exists = await User.findOne({
        email: email.toLowerCase(),
        organization: orgId,
      });
      if (exists)
        return res.status(400).json({ error: "Email already exists" });

      const user = await User.create({
        name,
        role,
        email: email.toLowerCase(),
        password: bcrypt.hashSync(password, 10),
        organization: orgId,
        department: deptId,
      });

      const { password: _, ...safeUser } = user.toObject();
      res.status(201).json(safeUser);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// LOGIN
router.post("/login", async (req, res) => {
  try {
    const { User } = getModels(req.db);
    const { email, password, organization } = req.body;

    const user = await User.findOne({
      email: email.toLowerCase(),
      ...(organization && { organization }),
    }).populate("department");

    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      {
        id: user._id,
        role: user.role,
        organization: user.organization,
      },
      JWT_SECRET,
      { expiresIn: "10h" }
    );

    const { password: _, ...safeUser } = user.toObject();
    res.json({ token, user: safeUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// CHANGE PASSWORD
router.post("/change-password", authenticate, async (req, res) => {
  try {
    const { User } = getModels(req.db);
    const { oldPassword, newPassword } = req.body;

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });

    if (!bcrypt.compareSync(oldPassword, user.password))
      return res.status(401).json({ error: "Incorrect old password" });

    user.password = bcrypt.hashSync(newPassword, 10);
    await user.save();

    res.json({ message: "Password updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// FORGOT PASSWORD
router.post("/forgot-password", async (req, res) => {
  try {
    const { User } = getModels(req.db);
    const { email } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ error: "User not found" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    req.session.otpStore ??= {};
    req.session.otpStore[email.toLowerCase()] = {
      otp,
      expiresAt: Date.now() + 10 * 60 * 1000,
    };

    await sendOtpEmail(email, otp);
    res.json({ message: "OTP sent" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VERIFY OTP
router.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const store = req.session.otpStore?.[email.toLowerCase()];

  if (!store) return res.status(400).json({ error: "OTP not found" });
  if (store.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });
  if (Date.now() > store.expiresAt)
    return res.status(400).json({ error: "OTP expired" });

  delete req.session.otpStore[email.toLowerCase()];
  res.json({ message: "OTP verified" });
});

// RESET PASSWORD
router.post("/reset-password", async (req, res) => {
  try {
    const { User } = getModels(req.db);
    const { email, newPassword } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ error: "User not found" });

    user.password = bcrypt.hashSync(newPassword, 10);
    await user.save();

    res.json({ message: "Password reset successful" });
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

      if (
        req.user.role !== "super_admin" &&
        !user.organization?.equals(req.user.organization)
      )
        return res.status(403).json({ error: "Forbidden" });

      const { name, role, email, password, departmentId } = req.body;

      if (email) user.email = email.toLowerCase();
      if (name) user.name = name;
      if (role) user.role = role;
      if (password) user.password = bcrypt.hashSync(password, 10);

      if (departmentId) {
        const dept = await Department.findOne({
          _id: departmentId,
          organization: user.organization,
        });
        if (!dept) return res.status(400).json({ error: "Invalid department" });
        user.department = dept._id;
      }

      await user.save();
      const { password: _, ...safeUser } = user.toObject();
      res.json(safeUser);
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
      await User.findByIdAndDelete(req.params.id);
      res.json({ message: "User deleted" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

/* ======================================================
   DEPARTMENTS
====================================================== */

router.get("/departments", authenticate, async (req, res) => {
  const { Department } = getModels(req.db);
  res.json(await Department.find({ organization: req.user.organization }));
});

router.post(
  "/departments",
  authenticate,
  authorizeRoles("super_admin", "root"),
  async (req, res) => {
    const { Department } = getModels(req.db);
    const dept = await Department.create({
      name: req.body.name,
      organization: req.user.organization,
    });
    res.status(201).json(dept);
  }
);

router.put(
  "/departments/:id",
  authenticate,
  authorizeRoles("super_admin", "root"),
  async (req, res) => {
    const { Department } = getModels(req.db);
    res.json(
      await Department.findByIdAndUpdate(
        req.params.id,
        { name: req.body.name },
        { new: true }
      )
    );
  }
);

router.delete(
  "/departments/:id",
  authenticate,
  authorizeRoles("super_admin"),
  async (req, res) => {
    const { Department } = getModels(req.db);
    await Department.findByIdAndDelete(req.params.id);
    res.json({ message: "Department deleted" });
  }
);

/* ======================================================
   ORGANIZATIONS
====================================================== */

router.get(
  "/organizations",
  authenticate,
  authorizeRoles("super_admin"),
  async (req, res) => {
    const { Organization } = getModels(req.db);
    res.json(await Organization.find());
  }
);

router.post(
  "/organizations",
  authenticate,
  authorizeRoles("super_admin"),
  async (req, res) => {
    const { Organization } = getModels(req.db);
    res.status(201).json(await Organization.create({ name: req.body.name }));
  }
);

router.delete(
  "/organizations/:id",
  authenticate,
  authorizeRoles("super_admin"),
  async (req, res) => {
    const { Organization } = getModels(req.db);
    await Organization.findByIdAndDelete(req.params.id);
    res.json({ message: "Organization deleted" });
  }
);

module.exports = router;
