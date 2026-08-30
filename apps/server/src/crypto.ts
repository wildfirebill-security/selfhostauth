/**
 * Server-side crypto: scrypt password hashing + AES-256-GCM vault
 * encryption (all via node:crypto — no extra deps).
 */
import {
  randomBytes,
  scryptSync,
  timingSafeEqual,
  createCipheriv,
  createDecipheriv,
  createHash,
} from "node:crypto";
import { EncryptedPayload } from "@selfhostauth/core";

/* ------------------------------------------------------------- scrypt */

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 32;

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, SCRYPT_KEYLEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString("base64")}$${hash.toString("base64")}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [, nStr, rStr, pStr, saltB64, hashB64] = parts;
  const salt = Buffer.from(saltB64!, "base64");
  const expected = Buffer.from(hashB64!, "base64");
  const actual = scryptSync(password, salt, expected.length, {
    N: Number(nStr),
    r: Number(rStr),
    p: Number(pStr),
  });
  return timingSafeEqual(actual, expected);
}

/* ---------------------------------------------------------- session tokens */

export function newSessionToken(): { token: string; tokenHash: string } {
  const token = randomBytes(32).toString("base64url");
  return { token, tokenHash: hashToken(token) };
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/* ------------------------------------------------------- vault encryption */

export function encryptJson(key: Uint8Array, value: unknown): EncryptedPayload {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(key), iv);
  const plain = Buffer.from(JSON.stringify(value), "utf8");
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 1,
    iv: iv.toString("base64"),
    data: enc.toString("base64"),
    tag: tag.toString("base64"),
  };
}

export function decryptJson<T>(key: Uint8Array, payload: EncryptedPayload): T {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    Buffer.from(key),
    Buffer.from(payload.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
  const plain = Buffer.concat([
    decipher.update(Buffer.from(payload.data, "base64")),
    decipher.final(),
  ]);
  return JSON.parse(plain.toString("utf8")) as T;
}