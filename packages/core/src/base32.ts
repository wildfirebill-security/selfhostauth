/**
 * RFC 4648 base32 (no padding) encode/decode.
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i]!;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31]!;
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31]!;
  return out;
}

/** Decode base32 (padding optional, case-insensitive). Throws on invalid input. */
export function base32Decode(input: string): Uint8Array {
  const cleaned = input.toUpperCase().replace(/[=\s]/g, "");
  if (cleaned.length === 0) return new Uint8Array(0);
  if (!/^[A-Z2-7]+$/.test(cleaned)) {
    throw new Error("Invalid base32 string: contains characters outside A-Z2-7");
  }
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (let i = 0; i < cleaned.length; i++) {
    const idx = ALPHABET.indexOf(cleaned[i]!);
    if (idx === -1) throw new Error("Invalid base32 character");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}