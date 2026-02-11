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
} from "../../lib/crypto.js";

/* ============================
   🎨 TERMINAL STYLING
============================ */

const reset = "\x1b[0m";
const bold = t => `\x1b[1m${t}${reset}`;
const dim = t => `\x1b[2m${t}${reset}`;

const green = t => `\x1b[32m${t}${reset}`;
const red = t => `\x1b[31m${t}${reset}`;
const yellow = t => `\x1b[33m${t}${reset}`;
const cyan = t => `\x1b[36m${t}${reset}`;
const magenta = t => `\x1b[35m${t}${reset}`;

/* ============================
   🧠 ESTADO GLOBAL
============================ */

let joined = false;
let handshakeSent = false;

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function ask(q) {
  return new Promise(res => rl.question(q, res));
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

/* ============================
   🚀 MAIN
============================ */

async function main() {

  console.clear();

  console.log(green(bold(`
███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  
███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝

        E N D - T O - E N D   E N C R Y P T I O N
        AES-256-GCM · HMAC-SHA256 · ECDH
  `)));

  const serverUrl =
    process.env.SERVER ||
    (await ask(cyan("WS Server  ➜ ")));

  const room =
    process.env.ROOM ||
    (await ask(cyan("Room ID    ➜ ")));

  const me =
    process.env.ME ||
    (await ask(cyan("Your ID    ➜ ")));

  const peer =
    process.env.PEER ||
    (await ask(cyan("Peer ID    ➜ ")));

  console.log(dim("\n[ Initializing cryptographic context ]\n"));

  const curve = pickEcdhCurve();
  const { ecdh, publicKey } = genKeyPairECDH(curve);

  console.log(green(`[✔] Curve: ${bold(curve)}`));
  console.log(green(`[✔] Public key fingerprint:`));
  console.log(magenta(`    ${fingerprint(publicKey)}\n`));

  const ws = new WebSocket(serverUrl);

  let session = null;
  let sendCounter = 0;
  let recvCounter = 0;
  let peerHandshakeReceived = false;
  let pendingMessages = [];

  function sendHandshake(to) {
    ws.send(
      JSON.stringify({
        type: "handshake",
        room,
        from: me,
        to,
        payload: {
          curve,
          pub: b64(publicKey),
        },
      })
    );
    console.log(yellow(`[→] Handshake sent to ${bold(to)}`));
  }

  function processPendingMessages() {
    if (pendingMessages.length > 0) {
      console.log(dim(`[ Processing ${pendingMessages.length} queued messages ]`));
      pendingMessages.forEach(msg => handleEncryptedMessage(msg));
      pendingMessages = [];
    }
  }

  function handleEncryptedMessage(msg) {
    if (!session) return;

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
      console.log(red(`
[ SECURITY ALERT ]
Message authentication failed.
Possible tampering detected.
`));
      return;
    }

    try {
      const text = decryptAesGcm(session.kEnc, ivB, ctB, tagB, aad);
      recvCounter++;

      console.log(`
${bold(cyan(from))} ${dim(`[msg #${recvCounter}]`)}
  ${text}
`);
    } catch (e) {
      console.log(red(`[ Decryption failed ] ${e.message}`));
    }
  }

  ws.on("open", () => {
    console.log(green("\n[ Connected to server ]"));
    ws.send(JSON.stringify({ type: "join", room, from: me }));
  });

  ws.on("message", async raw => {
    let msg;
    try {
      msg = JSON.parse(raw.toString("utf8"));
    } catch {
      return;
    }

    const { type, from, to, payload } = msg || {};
    if (to && to !== me) return;

    if (type === "joined") {
      joined = true;
      if (!handshakeSent) {
        sendHandshake(peer);
        handshakeSent = true;
      }
    }

    if (type === "handshake") {

      if (peerHandshakeReceived) return;

      const otherCurve = payload?.curve;
      const otherPub = unb64(payload?.pub || "");

      console.log(green(`\n[✔] Handshake received from ${bold(from)}`));
      console.log(cyan(`[🔎] Peer fingerprint:`));
      console.log(magenta(`    ${fingerprint(otherPub)}\n`));
      console.log(yellow("[!] Verify fingerprint externally\n"));

      if (otherCurve !== curve) {
        console.log(red("[ Curve mismatch detected. Abort. ]"));
        return;
      }

      const shared = computeSharedSecret(ecdh, otherPub);
      const [id1, id2] = [me, from].sort();
      const context = `room:${room}|peer1:${id1}|peer2:${id2}|curve:${curve}`;
      const { kEnc, kMac } = deriveSessionKeys(shared, context);

      session = { kEnc, kMac };
      peerHandshakeReceived = true;

      console.log(green(`
╔════════ SESSION ESTABLISHED ════════╗
║  Encryption : AES-256-GCM          ║
║  Integrity  : HMAC-SHA256          ║
║  Forward Secrecy : Enabled         ║
╚═════════════════════════════════════╝
`));

      processPendingMessages();
      promptLoop();
    }

    if (type === "msg") {
      if (!session) {
        pendingMessages.push(msg);
        return;
      }
      handleEncryptedMessage(msg);
    }
  });

  ws.on("close", () => {
    console.log(dim("\n[ Connection closed ]"));
    process.exit(0);
  });

  ws.on("error", e => {
    console.log(red(`[ WS ERROR ] ${e.message}`));
  });

  async function promptLoop() {
    if (promptLoop.running) return;
    promptLoop.running = true;

    while (ws.readyState === ws.OPEN) {

      const line = await ask(green("secure@node ➜ "));

      if (!line) continue;
      if (line === "/quit") {
        ws.close();
        break;
      }

      if (!session) {
        console.log(yellow("[ Secure session not ready ]"));
        continue;
      }

      sendCounter++;

      const aad = buildAad(room, me, peer, sendCounter);
      const { iv, ct, tag } = encryptAesGcm(session.kEnc, line, aad);

      const macData = Buffer.concat([aad, iv, ct, tag]);
      const mac = hmacSha256(session.kMac, macData);

      ws.send(JSON.stringify({
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
      }));
    }
  }
}

main().catch(e => {
  console.error(red("Fatal error:"), e);
  process.exit(1);
});
