const jwt = require("jsonwebtoken");

function requireAuth(req, res, next) {
  try {
    req.user = jwt.verify(req.headers.authorization, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "unauthorized" });
  }
}

module.exports = { requireAuth };
