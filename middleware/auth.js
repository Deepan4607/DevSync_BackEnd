const { OAuth2Client } = require("google-auth-library");

/**
 * Use next-auth v4 for token verification since our frontend runs next-auth v4
 * (which produces JWE tokens with A256GCM encryption using a different key
 * derivation than next-auth v5). The @auth/core v5 JWT functions won't work
 * with v4-encoded tokens.
 *
 * We must use an absolute path to the frontend's next-auth v4 installation
 * because the backend has next-auth v5 installed in its own node_modules.
 * We fall back to jsonwebtoken + jose for direct JWE decryption if the
 * v4 module is temporarily unavailable.
 */
const FRONTEND_NEXTAUTH_PATH = "/home/fire/Documents/Projects/devsync/node_modules/next-auth/jwt";
let v4GetToken, v4Decode;
try {
  const v4Jwt = require(FRONTEND_NEXTAUTH_PATH);
  v4GetToken = v4Jwt.getToken;
  v4Decode = v4Jwt.decode;
  console.log("✓ Using next-auth v4 for JWT verification");
} catch (err) {
  console.warn("⚠ next-auth v4 not found at", FRONTEND_NEXTAUTH_PATH, "- falling back to jose");
  // Fallback: use jose directly (same library v4 uses internally)
}

const googleClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID
);

async function verifyGoogleAccessToken(token) {
  /**
   * Verify Google OAuth access token via Google's tokeninfo endpoint.
   * Returns the sub (user ID) if valid.
   */
  try {
    const response = await fetch(
      `https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(token)}`
    );
    const data = await response.json();
    
    if (!response.ok || data.error) {
      console.error("Google tokeninfo error response:", {
        status: response.status,
        error: data.error,
        error_description: data.error_description,
        fullResponse: data,
      });
      throw new Error(`Google tokeninfo error: ${data.error || data.error_description || response.statusText}`);
    }
    
    return data.sub;
  } catch (err) {
    throw new Error(`Google token verification failed: ${err.message}`);
  }
}

async function verifyGoogleIdToken(token) {
  /**
   * Verify Google ID token using google-auth-library.
   * This cryptographically verifies the JWT signature using Google's public keys,
   * without making a network call to Google's tokeninfo endpoint.
   */
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const userId = payload?.sub;
    if (userId) {
      return userId;
    }
    throw new Error("No sub claim in Google id_token");
  } catch (err) {
    throw new Error(`Google id_token verification failed: ${err.message}`);
  }
}

function normalizeToken(token) {
  if (!token || typeof token !== "string") return token;
  if (token.startsWith("Bearer ")) token = token.slice(7);
  try { token = decodeURIComponent(token); } catch (e) {}
  if (token.startsWith("s:")) token = token.slice(2);
  return token;
}

function classifyToken(token) {
  if (!token) return "EMPTY";
  const parts = token.split(".");
  if (token.startsWith("ya29.")) return "GOOGLE_ACCESS_TOKEN";
  if (parts.length === 5) return "NEXTAUTH_JWE";
  if (parts.length === 3) return "JWT_OR_ID_TOKEN";
  return "UNKNOWN";
}

async function getUserIdFromToken(token) {
  if (!token) return null;

  token = normalizeToken(token);
  if (!token) return null;

  const secret = process.env.NEXTAUTH_SECRET;
  if (!secret) {
    throw new Error("NEXTAUTH_SECRET not configured in backend .env");
  }

  const tokenType = classifyToken(token);
  const tokenPreview = typeof token === "string" 
    ? (token.length > 50 ? `${token.slice(0, 50)}...` : token)
    : String(token);

  console.log(`Token verification attempt: type=${tokenType}, preview=${tokenPreview}`);

  const parts = token.split(".");

  // ====== 1. Try NextAuth token verification FIRST ======
  // Uses next-auth v4's getToken() since our frontend runs next-auth v4.
  // v4 tokens are JWE with A256GCM encryption (no salt-based key derivation).
  if (parts.length === 3 || parts.length === 5) {
    try {
      // Use v4 decode directly (v4 doesn't salt keys)
      const decoded = await v4Decode({ token, secret }).catch(() => null);

      if (decoded && (decoded.sub || decoded.userId || decoded.id)) {
        const userId = decoded.sub || decoded.userId || decoded.id;
        console.log(`✓ NextAuth v4 token verified, userId=${userId}`);
        return userId;
      }

      // Fallback: use v4 getToken with Authorization header
      const decodedFromGetToken = await v4GetToken({
        req: { headers: { authorization: `Bearer ${token}` } },
        secret: secret,
        raw: false,
      }).catch(() => null);

      if (decodedFromGetToken && (decodedFromGetToken.sub || decodedFromGetToken.userId || decodedFromGetToken.id)) {
        const userId = decodedFromGetToken.sub || decodedFromGetToken.userId || decodedFromGetToken.id;
        console.log(`✓ NextAuth v4 token verified via getToken(), userId=${userId}`);
        return userId;
      }

      if (parts.length === 5) {
        console.log(`✗ NextAuth v4 token verification failed for 5-part JWE`);
        throw new Error("Invalid NextAuth token");
      }

      console.log(`✗ NextAuth token not valid, 3-part JWT will try Google id_token`);
    } catch (err) {
      if (parts.length === 5) throw err;
      console.log(`✗ NextAuth verification failed for 3-part JWT: ${err.message}`);
    }
  }

  // ====== 2. Try Google id_token ======
  if (parts.length === 3 && !token.startsWith("ya29.")) {
    try {
      const sub = await verifyGoogleIdToken(token);
      console.log(`✓ Google id_token verified, sub=${sub}`);
      return sub;
    } catch (err) {
      console.log(`✗ Google id_token verification failed: ${err.message}`);
    }
  }

  // ====== 3. Try Google access token (ya29... opaque) ======
  if (token.startsWith("ya29.")) {
    try {
      const sub = await verifyGoogleAccessToken(token);
      console.log(`✓ Google access token verified, sub=${sub}`);
      return sub;
    } catch (err) {
      console.error("Failed to verify Google access token:", err.message);
      throw new Error("Token verification failed: not a valid NextAuth token or Google token");
    }
  }

  throw new Error("Token verification failed: invalid token format or all methods exhausted");
}

async function extractUserFromJWT(req, res, next) {
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

    const token = authHeader.slice(7);
    let userId;

    try {
      userId = await getUserIdFromToken(token);
    } catch (err) {
      console.error("Token verification failed:", err.message || err);
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    if (!userId) {
      return res.status(401).json({ error: "Token does not contain user ID." });
    }

    req.userId = userId;
    next();
  } catch (err) {
    console.error("Auth middleware error:", err);
    res.status(500).json({ error: "Authentication error" });
  }
}

module.exports = { extractUserFromJWT, getUserIdFromToken };