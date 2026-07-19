const express = require("express");
const cors = require("cors");

const roomRoutes = require("./routes/room.routes");

function getAllowedOrigins() {
  return [
    process.env.CLIENT_ORIGIN,
    process.env.CLIENT_ORIGIN_DEV,
  ]
    .filter(Boolean)
    .flatMap((value) => value.split(","))
    .map((value) => value.trim())
    .filter(Boolean);
}

function createApp() {
  const app = express();

  const allowedOrigins = getAllowedOrigins();

  app.use(
    cors({
      origin: allowedOrigins.length > 0 ? allowedOrigins : true,
      credentials: true,
    })
  );
  app.use(express.json());

  app.use("/api/rooms", roomRoutes);

  return app;
}

module.exports = { createApp };
