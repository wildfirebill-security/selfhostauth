/**
 * AES-256-GCM helpers built on WebCrypto. Works in Node, browsers,
 * and Electron. React Native requires a crypto.subtle polyfill
 * (e.g. react-native-quick-crypto) — see apps/mobile/README.
 */

export interface EncryptedPayload {
  /** Base64 iv (12 bytes) */
  iv: string;
  /** Base64 ciphertext */
  data: string;
  /** Base64 auth tag (16 bytes) */
  tag: string;
  /** Version marker for future migrations */
  v: 1;
}

function subtle(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error(
      "WebCrypto (crypto.subtle) is unavailable on this platform. " +
        "Node 20+, modern browsers, and Electron are supported.",
    );
  }
  return globalThis.crypto.subtle;
}

export async function randomBytes(n: number): Promise<Uint8Array> {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function toBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    out += B64_CHARS[b0 >> 2]!;
    out += B64_CHARS[((b0 & 3) << 4) | (b1 >> 4)]!;
    out += i + 1 < bytes.length ? B64_CHARS[((b1 & 15) << 2) | (b2 >> 6)]! : "=";
    out += i + 2 < bytes.length ? B64_CHARS[b2 & 63]! : "=";
  }
  return out;
}

function fromBase64(b64: string): Uint8Array {
  const clean = b64.replace(/=+$/, "");
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of clean) {
    const idx = B64_CHARS.indexOf(ch);
    if (idx === -1) throw new Error("Invalid base64 character");
    buffer = (buffer << 6) | idx;
    bits += 6;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

/** Raw 32-byte key -> AES-256-GCM import. */
async function importKey(raw: Uint8Array): Promise<CryptoKey> {
  return subtle().importKey("raw", raw as unknown as BufferSource, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** Encrypt plaintext with AES-256-GCM using a 32-byte key. */
export async function encryptAesGcm(
  key: Uint8Array,
  plaintext: Uint8Array | string,
): Promise<EncryptedPayload> {
  const data = typeof plaintext === "string" ? new TextEncoder().encode(plaintext) : plaintext;
  const iv = await randomBytes(12);
  const cryptoKey = await importKey(key);
  const cipher = await subtle().encrypt(
    { name: "AES-GCM", iv: iv as unknown as BufferSource },
    cryptoKey,
    data as unknown as BufferSource,
  );
  const full = new Uint8Array(cipher);
  // WebCrypto appends the 16-byte tag to the ciphertext.
  return {
    iv: toBase64(iv),
    data: toBase64(full.subarray(0, full.length - 16)),
    tag: toBase64(full.subarray(full.length - 16)),
    v: 1,
  };
}

/** Decrypt an EncryptedPayload with AES-256-GCM. Throws on tampering. */
export async function decryptAesGcm(
  key: Uint8Array,
  payload: EncryptedPayload,
): Promise<Uint8Array> {
  const iv = fromBase64(payload.iv);
  const data = fromBase64(payload.data);
  const tag = fromBase64(payload.tag);
  const full = new Uint8Array(data.length + tag.length);
  full.set(data);
  full.set(tag, data.length);
  const cryptoKey = await importKey(key);
  const plain = await subtle().decrypt(
    { name: "AES-GCM", iv: iv as unknown as BufferSource },
    cryptoKey,
    full as unknown as BufferSource,
  );
  return new Uint8Array(plain);
}

/** Decrypt and return a UTF-8 string. */
export async function decryptAesGcmText(key: Uint8Array, payload: EncryptedPayload): Promise<string> {
  const bytes = await decryptAesGcm(key, payload);
  return new TextDecoder().decode(bytes);
}

/**
 * Derive a 32-byte AES key from a passphrase using PBKDF2-HMAC-SHA256.
 * iterations default to 600k (OWASP 2023 guidance).
 */
export async function deriveKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  iterations = 600_000,
): Promise<Uint8Array> {
  const baseKey = await subtle().importKey(
    "raw",
    new TextEncoder().encode(passphrase) as unknown as BufferSource,
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await subtle().deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: salt as unknown as BufferSource,
      iterations,
    },
    baseKey,
    256,
  );
  return new Uint8Array(bits);
}

/** Generate a random 32-byte vault key. */
export async function generateVaultKey(): Promise<Uint8Array> {
  return randomBytes(32);
}

export { fromBase64, toBase64 };