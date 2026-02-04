import WebSocket from "ws";
import readline from "readline";
import {
  pickEcdhCurve,
  genKeyPairECDH,
  computeSharedSecret,
  deriveSessionKeys,
  encryptAesGcm,
  decryptAesGcm,
  hmacSha256,
  timingSafeEq,
  fingerprint,
  b64,
  unb64,
} from "../../lib/crypto";

// ===== Estado global =====
let joined = false;
let handshakeSent = false;

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function ask(q) {
  return new Promise((res) => rl.question(q, res));
}

function now() {
  return new Date().toISOString();
}

function buildAad(room, from, to, counter) {
  return Buffer.from(
    JSON.stringify({ room, from, to, counter }),
    "utf8"
  );
}

async function main() {
  const serverUrl =
    process.env.SERVER ||
    (await ask("WS Server (e.g. ws://192.168.1.10:8080): "));
  const room =
    process.env.ROOM ||
    (await ask("Room id (e.g. project): "));
  const me =
    process.env.ME ||
    (await ask("Your id (e.g. darwin): "));
  const peer =
    process.env.PEER ||
    (await ask("Peer id (e.g. john): "));

  const curve = pickEcdhCurve();
  const { ecdh, publicKey } = genKeyPairECDH(curve);

  console.log(`\n[${now()}] Using curve: ${curve}`);
  console.log(
    `[${now()}] Your public key fingerprint: ${fingerprint(publicKey)}\n`
  );

  const ws = new WebSocket(serverUrl);

  let session = null;
  let sendCounter = 0;
  let recvCounter = 0;
  let peerHandshakeReceived = false;
  let pendingMessages = []; //  Cola de mensajes recibidos antes de establecer sesión

  // Función para enviar handshake
  function sendHandshake(to) {
    ws.send(
      JSON.stringify({
        type: "handshake",
        room,
        from: me,
        to: to,
        payload: {
          curve,
          pub: b64(publicKey),
        },
      })
    );
    console.log(`[${now()}] Handshake sent to '${to}'.`);
  }

  // Procesar mensajes pendientes después de establecer sesión
  function processPendingMessages() {
    if (pendingMessages.length > 0) {
      console.log(`[${now()}] Processing ${pendingMessages.length} pending messages...`);
      pendingMessages.forEach(msg => {
        handleEncryptedMessage(msg);
      });
      pendingMessages = [];
    }
  }

  //  Función para manejar mensajes cifrados
  function handleEncryptedMessage(msg) {
    if (!session) {
      console.log(`[${now()}] Message queued, session not ready yet.`);
      return;
    }

    const { from, payload } = msg;
    const { iv, ct, tag, hmac, counter } = payload || {};
    const ivB = unb64(iv);
    const ctB = unb64(ct);
    const tagB = unb64(tag);
    const hmacB = unb64(hmac);

    const aad = buildAad(room, from, me, counter);
    const macData = Buffer.concat([aad, ivB, ctB, tagB]);
    const macExpected = hmacSha256(session.kMac, macData);

    if (!timingSafeEq(macExpected, hmacB)) {
      console.log(`\n[${now()}] ⚠️ HMAC verification FAILED.`);
      return;
    }

    try {
      const text = decryptAesGcm(session.kEnc, ivB, ctB, tagB, aad);
      recvCounter++;
      console.log(`\n[${from}] ${text}`);
    } catch (e) {
      console.log(`\n[${now()}] ⚠️ Decrypt/auth failed: ${e.message}`);
    }
  }

  // ===== Conexión =====
  ws.on("open", () => {
    ws.send(
      JSON.stringify({
        type: "join",
        room,
        from: me,
      })
    );
  });

  // ===== Mensajes =====
  ws.on("message", async (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString("utf8"));
    } catch {
      return;
    }

    const { type, from, to, payload } = msg || {};
    if (to && to !== me) return;

    // ---- Joined ----
    if (type === "joined") {
      joined = true;

      if (!handshakeSent) {
        sendHandshake(peer);
        handshakeSent = true;
      }
      
      // Solicitar handshake del peer si no lo hemos recibido
      // Esto ayuda cuando nos conectamos después que el otro cliente
      setTimeout(() => {
        if (!peerHandshakeReceived) {
          console.log(`[${now()}] Requesting handshake from peer...`);
          ws.send(JSON.stringify({
            type: "request_handshake",
            room,
            from: me,
            to: peer
          }));
        }
      }, 500);
    }

    // ---- Request handshake ----
    if (type === "request_handshake") {
      console.log(`[${now()}] Peer '${from}' requests handshake. Resending...`);
      sendHandshake(from);
    }

    // ---- Handshake ----
    if (type === "handshake") {
      if (peerHandshakeReceived) {
        console.log(`[${now()}] Duplicate handshake from '${from}' ignored.`);
        return;
      }

      const otherCurve = payload?.curve;
      const otherPub = unb64(payload?.pub || "");

      console.log(`\n[${now()}] Handshake received from '${from}'.`);
      console.log(
        `[${now()}] Peer public key fingerprint: ${fingerprint(otherPub)}`
      );
      console.log(
        `[${now()}] IMPORTANT: verify this fingerprint with your peer via another channel.\n`
      );

      if (otherCurve !== curve) {
        console.log(
          `[${now()}] Curve mismatch! mine=${curve}, peer=${otherCurve}. Abort.`
        );
        return;
      }

      // Responder con handshake si aún no lo hemos enviado
      if (!handshakeSent) {
        sendHandshake(from);
        handshakeSent = true;
      }

      // Derivar las claves de sesión
      const shared = computeSharedSecret(ecdh, otherPub);
      // Ordenar IDs alfabéticamente para contexto simétrico
      const [id1, id2] = [me, from].sort();
      const context = `room:${room}|peer1:${id1}|peer2:${id2}|curve:${curve}`;
      const { kEnc, kMac } = deriveSessionKeys(shared, context);
      session = { kEnc, kMac };
      peerHandshakeReceived = true;

      console.log(`[${now()}] Session keys derived ✅`);
      console.log(
        `[${now()}] You can start chatting. Type and press Enter.\n`
      );

      //  Procesar mensajes que llegaron antes de la sesión
      processPendingMessages();

      promptLoop();
    }

    // ---- Mensajes cifrados ----
    if (type === "msg") {
      if (!session) {
        console.log(`[${now()}] Received message but session not established yet.`);
        //  Encolar el mensaje para procesarlo después
        pendingMessages.push(msg);
        return;
      }

      handleEncryptedMessage(msg);
    }
  });

  ws.on("close", () => {
    console.log(`\n[${now()}] Disconnected.`);
    process.exit(0);
  });

  ws.on("error", (e) => {
    console.error(`[${now()}] WS error:`, e.message);
  });

  // ===== Entrada de usuario =====
  async function promptLoop() {
    if (promptLoop.running) return;
    promptLoop.running = true;

    while (ws.readyState === ws.OPEN) {
      const line = await ask("> ");
      if (!line) continue;

      if (line === "/quit") {
        ws.close();
        break;
      }

      if (!session) {
        console.log("⏳ Secure session not ready yet...");
        continue;
      }

      sendCounter++;
      const aad = buildAad(room, me, peer, sendCounter);
      const { iv, ct, tag } = encryptAesGcm(
        session.kEnc,
        line,
        aad
      );

      const macData = Buffer.concat([aad, iv, ct, tag]);
      const mac = hmacSha256(session.kMac, macData);

      ws.send(
        JSON.stringify({
          type: "msg",
          room,
          from: me,
          to: peer,
          payload: {
            counter: sendCounter,
            iv: b64(iv),
            ct: b64(ct),
            tag: b64(tag),
            hmac: b64(mac),
          },
        })
      );
    }
  }
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});