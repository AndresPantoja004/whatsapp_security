import crypto from "crypto";

export function pickEcdhCurve() {
  const curves = crypto.getCurves();
  if (curves.includes("x25519")) return "x25519";
  if (curves.includes("prime256v1")) return "prime256v1"; // P-256
  // última opción: secp256k1 (no ideal pero usable)
  if (curves.includes("secp256k1")) return "secp256k1";
  throw new Error("No supported ECDH curves found in this Node build.");
}

export function genKeyPairECDH(curve) {
  const ecdh = crypto.createECDH(curve);
  ecdh.generateKeys();
  return {
    curve,
    ecdh,
    publicKey: ecdh.getPublicKey(), // Buffer
  };
}

export function computeSharedSecret(ecdh, otherPubKey) {
  return ecdh.computeSecret(otherPubKey);
}

export function hkdfSha256(ikm, salt, info, len) {
  const keyMaterial = crypto.hkdfSync("sha256", ikm, salt, info, len);
  return Buffer.from(keyMaterial);
}

// Deriva 2 claves separadas: enc y mac
export function deriveSessionKeys(sharedSecret, context) {
  const salt = crypto.createHash("sha256").update("chat-e2ee-salt").digest();
  const okm = hkdfSha256(sharedSecret, salt, Buffer.from(context, "utf8"), 64);
  const kEnc = okm.subarray(0, 32);   // AES-256
  const kMac = okm.subarray(32, 64);  // HMAC key
  return { kEnc, kMac };
}

export function fingerprint(buf) {
  // Huella corta para comparar por canal externo
  const h = crypto.createHash("sha256").update(buf).digest("hex");
  return `${h.slice(0, 6)}-${h.slice(6, 12)}-${h.slice(12, 18)}-${h.slice(18, 24)}`;
}

// AES-256-GCM
export function encryptAesGcm(kEnc, plaintext, aad) {
  const iv = crypto.randomBytes(12); // recomendado en GCM
  const cipher = crypto.createCipheriv("aes-256-gcm", kEnc, iv);
  if (aad) cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ct, tag };
}

export function decryptAesGcm(kEnc, iv, ct, tag, aad) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", kEnc, iv);
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString("utf8");
}

// HMAC sobre (header + iv + ct + tag)
export function hmacSha256(kMac, data) {
  return crypto.createHmac("sha256", kMac).update(data).digest();
}

export function timingSafeEq(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export function b64(buf) { return Buffer.from(buf).toString("base64"); }
export function unb64(s) { return Buffer.from(s, "base64"); }
