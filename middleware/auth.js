const jwt = require("jsonwebtoken");

function getUserIdFromToken(token) {
  if (!token) return null;

  const secret = process.env.NEXTAUTH_SECRET;
  if (!secret) {
    throw new Error("NEXTAUTH_SECRET not configured in backend .env");
  }

  const decoded = jwt.verify(token, secret);
  return decoded.sub || decoded.userId || decoded.id || null;
}

/**
 * Extract user from either query param or NextAuth JWT token.
 * Prefer JWT when provided, but support old userId query behavior.
 */
function extractUserFromJWT(req, res, next) {
  try {
    const queryUserId = req.query.userId?.toString().trim();
    if (queryUserId) {
      req.userId = queryUserId;
      return next();
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Missing or invalid authorization header" });
    }

    const token = authHeader.slice(7); // Remove "Bearer " prefix
    let userId;

    try {
      userId = getUserIdFromToken(token);
    } catch (err) {
      console.error("Token verification failed:", err.message || err);
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    if (!userId) {
      return res.status(401).json({ 
        error: "Token does not contain user ID. Check NextAuth token structure." 
      });
    }

    req.userId = userId;
    next();
  } catch (err) {
    console.error("Auth middleware error:", err);
    res.status(500).json({ error: "Authentication error" });
  }
}

module.exports = { extractUserFromJWT, getUserIdFromToken };
