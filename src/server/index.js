import { WebSocketServer } from "ws";

const PORT = process.env.PORT ? Number(process.env.PORT) : 8085;
const wss = new WebSocketServer({ port: PORT });

/** rooms: roomId -> Map(peerId -> ws) */
const rooms = new Map();

function safeSend(ws, obj) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
}

wss.on("connection", (ws) => {
  ws.on("message", (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString("utf8")); }
    catch { return; }

    const { type, room, from, to, payload } = msg || {};
    if (!type || !room || !from) return;

    // join room
    if (type === "join") {
      if (!rooms.has(room)) rooms.set(room, new Map());
      rooms.get(room).set(from, ws);
      safeSend(ws, { type: "joined", room, from });
      return;
    }

    const roomMap = rooms.get(room);
    if (!roomMap) return;

    // direct messages only (avoid broadcast)
    if (!to) return;

    const target = roomMap.get(to);
    if (!target) {
      safeSend(ws, { type: "error", error: `peer '${to}' not in room` });
      return;
    }

    console.log("====================================");
    console.log("Message relayed:");
    console.log("Room:", room);
    console.log("of:", from);
    console.log("for:", to);
    console.log("type:", type);
    console.log("Payload (CIFRADO):");
    console.log(payload); 
    console.log("====================================");

    safeSend(target, { type, room, from, to, payload });
  });

  ws.on("close", () => {
    // cleanup: remove ws from any rooms
    for (const [roomId, m] of rooms.entries()) {
      for (const [peerId, sock] of m.entries()) {
        if (sock === ws) m.delete(peerId);
      }
      if (m.size === 0) rooms.delete(roomId);
    }
  });
});

console.log(`Relay server listening on ws://0.0.0.0:${PORT}`);
