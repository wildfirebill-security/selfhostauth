/**
 * TOTP / HOTP implementation (RFC 4226, RFC 6238).
 *
 * WebCrypto (`crypto.subtle`) is used when available; a pure-JS HMAC
 * fallback keeps this working on React Native and other exotic runtimes.
 */
import { HashName, hmacBytes, bytesToHexString } from "./hash.js";
import { base32Decode } from "./base32.js";

export type TOTPAlgorithm = "SHA1" | "SHA256" | "SHA512";

export const TOTP_DEFAULTS = {
  period: 30,
  digits: 6,
  algorithm: "SHA1" as TOTPAlgorithm,
};

export interface TOTPParams {
  /** Base32-encoded secret (RFC 4648, no padding). */
  secret: string;
  algorithm?: TOTPAlgorithm;
  digits?: number;
  period?: number;
}

export interface TOTPResult {
  code: string;
  /** Seconds until the current code expires. */
  remaining: number;
  period: number;
  /** Unix seconds when the current period started. */
  periodStart: number;
}

export interface TOTPVerifyOptions {
  /** Allow codes from adjacent windows (default 1). */
  window?: number;
}

export interface TOTPValidation {
  valid: boolean;
  /** Unix seconds when the code was valid (for drift compensation). */
  timestamp?: number;
}

const HASH_NAME: Record<TOTPAlgorithm, HashName> = {
  SHA1: "SHA-1",
  SHA256: "SHA-256",
  SHA512: "SHA-512",
};

function normalizeParams(p: TOTPParams): Required<TOTPParams> {
  return {
    secret: p.secret,
    algorithm: p.algorithm ?? TOTP_DEFAULTS.algorithm,
    digits: p.digits ?? TOTP_DEFAULTS.digits,
    period: p.period ?? TOTP_DEFAULTS.period,
  };
}

/** RFC 6238 dynamic truncation -> numeric code. */
export function hotpFromBytes(mac: Uint8Array, digits: number): number {
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary =
    ((mac[offset]! & 0x7f) << 24) |
    ((mac[offset + 1]! << 16) & 0xffffff) |
    ((mac[offset + 2]! << 8) & 0xffff) |
    (mac[offset + 3]! & 0xff);
  const mod = Math.pow(10, digits);
  return binary % mod;
}

function isSubtleAvailable(): boolean {
  try {
    return typeof globalThis !== "undefined" && !!globalThis.crypto?.subtle;
  } catch {
    return false;
  }
}

async function hmacSha(name: HashName, key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  if (isSubtleAvailable()) {
    try {
      const cryptoKey = await globalThis.crypto.subtle.importKey(
        "raw",
        key as unknown as BufferSource,
        { name: "HMAC", hash: name },
        false,
        ["sign"],
      );
      const sig = await globalThis.crypto.subtle.sign("HMAC", cryptoKey, data as unknown as BufferSource);
      return new Uint8Array(sig);
    } catch {
      // fall through to pure JS
    }
  }
  return hmacBytes(name, key, data);
}

/** Compute the HOTP value for a given counter (RFC 4226). */
export async function hotp(params: TOTPParams, counter: number | bigint): Promise<string> {
  const { secret, algorithm, digits } = normalizeParams(params);
  const key = base32Decode(secret);
  const name = HASH_NAME[algorithm];
  const counterBuf = new Uint8Array(8);
  const dv = new DataView(counterBuf.buffer);
  dv.setBigUint64(0, typeof counter === "bigint" ? counter : BigInt(Math.floor(counter)), false);
  const mac = await hmacSha(name, key, counterBuf);
  const value = hotpFromBytes(mac, digits);
  return value.toString().padStart(digits, "0");
}

/** Generate the current TOTP code for the given params (RFC 6238). */
export async function totp(params: TOTPParams, nowSeconds?: number): Promise<TOTPResult> {
  const { period } = normalizeParams(params);
  const now = nowSeconds ?? Math.floor(Date.now() / 1000);
  const periodStart = Math.floor(now / period) * period;
  const counter = Math.floor(now / period);
  const code = await hotp(params, counter);
  return {
    code,
    remaining: period - (now - periodStart),
    period,
    periodStart,
  };
}

/**
 * Verify a code against the current (and optionally adjacent) time windows.
 * Returns the timestamp of the matching window when valid.
 */
export async function totpVerify(
  params: TOTPParams,
  code: string,
  nowSeconds?: number,
  options: TOTPVerifyOptions = {},
): Promise<TOTPValidation> {
  const { period } = normalizeParams(params);
  const now = nowSeconds ?? Math.floor(Date.now() / 1000);
  const window = options.window ?? 1;
  const expected = code.trim();

  for (let w = -window; w <= window; w++) {
    const counter = Math.floor(now / period) + w;
    const candidate = await hotp(params, counter);
    if (candidate === expected) {
      return { valid: true, timestamp: counter * period };
    }
  }
  return { valid: false };
}

/** True if the string is a plausible base32 TOTP secret. */
export function isValidSecret(secret: string): boolean {
  const cleaned = secret.toUpperCase().replace(/[=\s]/g, "");
  if (cleaned.length < 16) return false; // 80-bit minimum for TOTP
  return /^[A-Z2-7]+$/.test(cleaned);
}

/** Compute a stable SHA-256 fingerprint of a normalized otpauth URI (dedupe help). */
export async function otpauthFingerprint(uri: string): Promise<string> {
  const bytes = new TextEncoder().encode(uri.trim());
  if (isSubtleAvailable()) {
    try {
      const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
      return bytesToHexString(new Uint8Array(digest));
    } catch {
      /* fallthrough */
    }
  }
  return bytesToHexString(hmacBytes("SHA-256", new Uint8Array(0), bytes));
}