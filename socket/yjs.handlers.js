const Y = require("yjs");
const { getYDoc } = require("./state");
const roomService = require("../storage/room.service");

function registerYjsHandlers(io, socket) {
  socket.on("yjs:join", async ({ roomId, fileId }) => {
    const member = await roomService.isMember(roomId, socket.userId);
    if (!member) {
      socket.emit("room:error", {
        roomId,
        code: "forbidden",
        message: "You are not allowed to join this room",
      });
      return;
    }

    const doc = await getYDoc(roomId, fileId);
    socket.emit("yjs:sync", {
      roomId,
      fileId,
      update: Array.from(Y.encodeStateAsUpdate(doc)),
    });
  });

  socket.on("yjs:update", async ({ roomId, fileId, update }) => {
    const member = await roomService.isMember(roomId, socket.userId);
    if (!member || member.role === "viewer") {
      socket.emit("room:error", {
        roomId,
        code: "forbidden",
        message: "You do not have permission to edit this room",
      });
      return;
    }

    const doc = await getYDoc(roomId, fileId);
    const bytes =
      update instanceof Uint8Array ? update : new Uint8Array(update);

    Y.applyUpdate(doc, bytes);

    socket.to(roomId).emit("yjs:update", {
      roomId,
      fileId,
      update: Array.from(bytes),
    });
  });
}

module.exports = registerYjsHandlers;
