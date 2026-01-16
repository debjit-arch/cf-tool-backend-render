const jwt = require("jsonwebtoken");
const JWT_SECRET =
  process.env.JWT_SECRET ||
  "hbDGxyixY2wvTjNVUcxjIX/hyRasXYo/b0HrXm8GdinvtWQrq0/0NGO+acdzfNyrw5DccbNQHy0S0TKGWNjHWQ==";

// ---------------------- AUTHENTICATION ----------------------
function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader)
    return res.status(401).json({ error: "Authorization header missing" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token missing" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // ❗ Allow super_admins without organization
    if (!decoded.organization && decoded.role !== "super_admin") {
      return res
        .status(400)
        .json({ error: "Token missing organization information" });
    }

    // ✅ NORMALIZE USER HERE
    const userId = decoded.id || decoded.sub;

    if (!userId) {
      return res
        .status(401)
        .json({ error: "Invalid token: missing user identifier" });
    }

    req.user = {
      id: userId, // 🔒 single source of truth
      role: decoded.role,
      name: decoded.name,
      department: decoded.department,
      organization: decoded.organization,
    };

    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ---------------------- ROLE + ORGANIZATION AUTH ----------------------
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user)
      return res.status(401).json({ error: "Unauthorized: no user found" });

    const { role, organization } = req.user;

    // SUPER ADMIN has global access
    if (role === "super_admin") return next();

    // Role restriction
    if (!allowedRoles.includes(role)) {
      return res
        .status(403)
        .json({ error: "Access denied: insufficient role" });
    }

    // Organization restriction
    const requestOrg =
      req.headers["x-org"] || req.body.organization || req.params.organization;

    if (!requestOrg) {
      return res.status(400).json({
        error:
          "Organization context missing. Pass 'x-org' header or include organization in request.",
      });
    }

    if (organization !== requestOrg) {
      return res.status(403).json({
        error: "Access denied: you cannot access another organization’s data",
      });
    }

    next();
  };
}

module.exports = { authenticate, authorizeRoles };
