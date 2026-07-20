const { Server } = require("socket.io");
const registerRoomHandlers = require("./room.handlers");
const registerFsHandlers = require("./fs.handlers");
const registerYjsHandlers = require("./yjs.handlers");
const registerPresenceHandlers = require("./presence.handlers");
const registerTerminalHandlers = require("./terminal.handlers");
const registerChatHandlers = require("./chat.handlers");
const registerVoiceHandlers = require("./voice.handlers");
const registerRepoHandlers = require("./repo.handlers");
const { getUserIdFromToken } = require("../middleware/auth");
const { startRoomGC } = require("./state");

function getAllowedOrigins() {
  const raw = [
    process.env.CLIENT_ORIGIN,
    process.env.CLIENT_ORIGIN_DEV,
  ]
    .filter(Boolean)
    .flatMap((value) => value.split(","))
    .map((value) => value.trim())
    .filter(Boolean);

  if (raw.length === 0) {
    return ["http://localhost:3000"];
  }

  return [...new Set(raw)];
}

function initSocket(server) {
  const allowedOrigins = getAllowedOrigins();
  const io = new Server(server, {
    cors: {
      origin: allowedOrigins,
      methods: ["GET", "POST"],
      credentials: true,
    },
  });

  function parseCookies(cookieHeader = "") {
    return cookieHeader.split(";").reduce((cookies, raw) => {
      const [name, ...valueParts] = raw.split("=");
      const nameTrimmed = name?.trim();
      if (!nameTrimmed) return cookies;
      cookies[nameTrimmed] = valueParts.join("=").trim();
      return cookies;
    }, {});
  }

  io.use(async (socket, next) => {
    try {
      const cookieHeader = socket.handshake.headers.cookie;
      const cookies = parseCookies(cookieHeader);

      // Try to get the NextAuth session token from cookies (JWE encrypted)
      const cookieToken =
        cookies["__Secure-next-auth.session-token"] ||
        cookies["next-auth.session-token"];

      // Prefer explicit auth token from client (auth payload, query, or Authorization header)
      const authTokenFromAuth = socket.handshake.auth?.token || socket.handshake.query?.token;
      const authHeader = socket.handshake.headers?.authorization;
      const authTokenFromHeader = authHeader && typeof authHeader === "string" && authHeader.startsWith("Bearer ")
        ? authHeader.slice(7)
        : null;

      const token = authTokenFromAuth || authTokenFromHeader || cookieToken || null;

      if (token) {
        try {
          const userId = await getUserIdFromToken(token);
          if (!userId) {
            return next(new Error("Authentication error"));
          }
          socket.userId = userId;
          return next();
        } catch (err) {
          console.error("Socket auth token verification failed:", err.message);
          return next(new Error("Invalid token"));
        }
      }

      // ONLY fall back to query userId when no token was provided at all
      const queryUserId = socket.handshake.auth?.userId || socket.handshake.query?.userId;
      if (queryUserId) {
        socket.userId = queryUserId;
        return next();
      }

      // Allow unauthenticated connections - handlers can decide
      return next();
    } catch (err) {
      console.error("Socket auth error:", err.message || err);
      return next(new Error("Authentication error"));
    }
  });

  io.on("connection", (socket) => {
    console.log("Connected:", socket.id, "userId=", socket.userId);

    registerRoomHandlers(io, socket);
    registerFsHandlers(io, socket);
    registerYjsHandlers(io, socket);
    registerPresenceHandlers(io, socket);
    registerTerminalHandlers(io, socket);
    registerChatHandlers(io, socket);
    registerVoiceHandlers(io, socket);
    registerRepoHandlers(io, socket);
  });

  startRoomGC();
}

module.exports = { initSocket };
