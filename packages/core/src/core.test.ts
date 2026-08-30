/**
 * RFC 6238 Appendix B test vectors + RFC 4226 HOTP vectors.
 * These are the canonical vectors every TOTP implementation must pass.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { hotp, totp, totpVerify, TOTPParams } from "./totp.js";
import { base32Encode, base32Decode } from "./base32.js";
import { parseOtpauthUri, toOtpauthUri } from "./otpauth.js";
import { encryptAesGcm, decryptAesGcmText, deriveKeyFromPassphrase } from "./crypto.js";
import { hmacBytes, bytesToHexString, hexStringToBytes } from "./hash.js";

// RFC 6238 test secret "12345678901234567890" (ASCII, 20 bytes)
const RFC6238_SECRET_B32 = base32Encode(new TextEncoder().encode("12345678901234567890"));

// RFC 6238 Appendix B vectors (T=0x00..0x32), 8 digits
const RFC6238_VECTORS: Array<[number, string]> = [
  [59, "94287082"],
  [1111111109, "07081804"],
  [1111111111, "14050471"],
  [1234567890, "89005924"],
  [2000000000, "69279037"],
  [20000000000, "65353130"],
];

const SHA256_SECRET = base32Encode(
  new TextEncoder().encode("12345678901234567890123456789012"),
);
const SHA512_SECRET = base32Encode(
  new TextEncoder().encode("1234567890123456789012345678901234567890123456789012345678901234"),
);

test("base32 roundtrip", () => {
  const bytes = new TextEncoder().encode("Hello, world!");
  assert.equal(base32Decode(base32Encode(bytes)).join(","), bytes.join(","));
  assert.equal(base32Encode(new TextEncoder().encode("foobar")), "MZXW6YTBOI");
  assert.throws(() => base32Decode("NOT VALID!"));
});

test("RFC 6238 SHA1 vectors (8 digits)", async () => {
  for (const [t, expected] of RFC6238_VECTORS) {
    const result = await totp(
      { secret: RFC6238_SECRET_B32, digits: 8, algorithm: "SHA1" },
      t,
    );
    assert.equal(result.code, expected, `T=${t}`);
  }
});

test("RFC 6238 SHA256 vectors", async () => {
  const vectors: Array<[number, string]> = [
    [59, "46119246"],
    [1111111109, "68084774"],
    [1111111111, "67062674"],
    [1234567890, "91819424"],
    [2000000000, "90698825"],
    [20000000000, "77737706"],
  ];
  for (const [t, expected] of vectors) {
    const result = await totp({ secret: SHA256_SECRET, digits: 8, algorithm: "SHA256" }, t);
    assert.equal(result.code, expected, `T=${t}`);
  }
});

test("RFC 6238 SHA512 vectors", async () => {
  const vectors: Array<[number, string]> = [
    [59, "90693936"],
    [1111111109, "25091201"],
    [1111111111, "99943326"],
    [1234567890, "93441116"],
    [2000000000, "38618901"],
    [20000000000, "47863826"],
  ];
  for (const [t, expected] of vectors) {
    const result = await totp({ secret: SHA512_SECRET, digits: 8, algorithm: "SHA512" }, t);
    assert.equal(result.code, expected, `T=${t}`);
  }
});

test("RFC 4226 HOTP vectors", async () => {
  const secret = base32Encode(new TextEncoder().encode("12345678901234567890"));
  const vectors: Array<[number, string]> = [
    [0, "755224"],
    [1, "287082"],
    [2, "359152"],
    [3, "969429"],
    [4, "338314"],
    [5, "254676"],
    [6, "287922"],
    [7, "162583"],
    [8, "399871"],
    [9, "520489"],
  ];
  for (const [c, expected] of vectors) {
    const code = await hotp({ secret, digits: 6 }, c);
    assert.equal(code, expected, `counter=${c}`);
  }
});

test("6-digit default TOTP from real-world key", async () => {
  // Known published vector: secret AAAAAAAAAAAAAAAAAAAA (10 bytes of A)
  const result = await totp({ secret: "AAAAAAAAAAAAAAAAAAAA", digits: 6, period: 30 }, 1700000000);
  assert.match(result.code, /^\d{6}$/);
  assert.equal(result.period, 30);
  assert.equal(result.remaining, 30 - (1700000000 % 30));
});

test("totpVerify accepts current + adjacent windows", async () => {
  const params: TOTPParams = { secret: RFC6238_SECRET_B32, digits: 6 };
  const now = 1_700_000_000;
  const current = await totp(params, now);
  assert.equal((await totpVerify(params, current.code, now)).valid, true);

  // Code from 30s in the past (window=-1) still verifies with default window
  const past = await totp(params, now - 30);
  const pastCheck = await totpVerify(params, past.code, now);
  assert.equal(pastCheck.valid, true);
  assert.equal(pastCheck.timestamp, Math.floor((now - 30) / 30) * 30);

  // Random garbage fails
  assert.equal((await totpVerify(params, "000000", now)).valid, false);
});

test("otpauth URI parse + serialize roundtrip", () => {
  const uri = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";
  const parsed = parseOtpauthUri(uri);
  assert.equal(parsed.type, "totp");
  assert.equal(parsed.issuer, "GitHub");
  assert.equal(parsed.account, "alice@example.com");
  assert.equal(parsed.secret, "JBSWY3DPEHPK3PXP");
  assert.equal(parsed.algorithm, "SHA1");
  assert.equal(parsed.digits, 6);
  assert.equal(parsed.period, 30);

  const rebuilt = toOtpauthUri(parsed);
  const reparsed = parseOtpauthUri(rebuilt);
  assert.equal(reparsed.secret, parsed.secret);
  assert.equal(reparsed.issuer, parsed.issuer);
  assert.equal(reparsed.account, parsed.account);

  assert.throws(() => parseOtpauthUri("https://example.com"));
  assert.throws(() => parseOtpauthUri("otpauth://totp/NoSecret"));
});

test("otpauth label without issuer param uses label issuer", () => {
  const parsed = parseOtpauthUri(
    "otpauth://totp/Example%20Co:john?secret=JBSWY3DPEHPK3PXP",
  );
  assert.equal(parsed.issuer, "Example Co");
  assert.equal(parsed.account, "john");
});

test("RFC 4231 HMAC vectors (pure-JS path used on React Native)", async () => {
  // RFC 4231 Test Case 1: key = 0x0b x20, data = "Hi There"
  const key1 = new Uint8Array(20).fill(0x0b);
  const data1 = new TextEncoder().encode("Hi There");
  assert.equal(
    bytesToHexString(hmacBytes("SHA-1", key1, data1)),
    "b617318655057264e28bc0b6fb378c8ef146be00",
  );
  assert.equal(
    bytesToHexString(hmacBytes("SHA-256", key1, data1)),
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  );
  assert.equal(
    bytesToHexString(hmacBytes("SHA-512", key1, data1)),
    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde" +
      "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
  );

  // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
  const key2 = new TextEncoder().encode("Jefe");
  const data2 = new TextEncoder().encode("what do ya want for nothing?");
  assert.equal(
    bytesToHexString(hmacBytes("SHA-1", key2, data2)),
    "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
  );
  assert.equal(
    bytesToHexString(hmacBytes("SHA-256", key2, data2)),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  );

  // key as bytes roundtrip
  const digest = hmacBytes("SHA-256", key1, data1);
  assert.deepEqual(hexStringToBytes(bytesToHexString(digest)), digest);
});

test("AES-256-GCM encrypt/decrypt roundtrip + tamper detection", async () => {
  const key = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
  const enc = await encryptAesGcm(key, "top-secret-totp-secret");
  assert.equal(enc.v, 1);
  const dec = await decryptAesGcmText(key, enc);
  assert.equal(dec, "top-secret-totp-secret");

  // Tampered ciphertext must throw
  const tampered = { ...enc, data: enc.data.replace(/^./, enc.data[0] === "A" ? "B" : "A") };
  await assert.rejects(() => decryptAesGcmText(key, tampered));
});

test("PBKDF2 derives stable keys", async () => {
  const salt = new TextEncoder().encode("saltysalt");
  const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const k1 = await deriveKeyFromPassphrase("correct horse battery staple", salt, 1000);
  const k2 = await deriveKeyFromPassphrase("correct horse battery staple", salt, 1000);
  const k3 = await deriveKeyFromPassphrase("different passphrase", salt, 1000);
  assert.equal(hex(k1), hex(k2));
  assert.notEqual(hex(k1), hex(k3));
});