const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET || "hbDGxyixY2wvTjNVUcxjIX/hyRasXYo/b0HrXm8GdinvtWQrq0/0NGO+acdzfNyrw5DccbNQHy0S0TKGWNjHWQ==";

function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "Authorization header missing" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token missing" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    console.log(decoded);
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });

    // 👇 Allow super_admin full access
    if (req.user.role === "super_admin") return next();

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: "Access denied: insufficient role" });
    }

    next();
  };
}

module.exports = { authenticate, authorizeRoles };
