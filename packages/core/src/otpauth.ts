/**
 * otpauth:// URI parsing and serialization (used by QR-code imports).
 * Supports totp and hotp schemes per the Google Authenticator URI format.
 */
import { TOTPParams, TOTPAlgorithm } from "./totp.js";

export interface OtpauthData {
  type: "totp" | "hotp";
  label: string;
  issuer: string;
  account: string;
  secret: string;
  algorithm?: TOTPAlgorithm;
  digits?: number;
  period?: number;
  /** HOTP only */
  counter?: number;
}

const LABEL_RE = /^(?:(.+):)?(.+)$/;

function parseLabel(label: string): { issuer: string; account: string } {
  const m = LABEL_RE.exec(label);
  if (!m) return { issuer: "", account: label };
  if (m[1]) {
    // Some providers repeat the issuer in the label AND the issuer param.
    return { issuer: m[1], account: m[2] ?? "" };
  }
  return { issuer: "", account: m[2] ?? "" };
}

/**
 * Parse an otpauth:// URI. Throws on malformed input.
 */
export function parseOtpauthUri(uri: string): OtpauthData {
  const trimmed = uri.trim();
  if (!trimmed.startsWith("otpauth://")) {
    throw new Error("Not an otpauth:// URI");
  }
  const url = new URL(trimmed);
  const type = url.hostname;
  if (type !== "totp" && type !== "hotp") {
    throw new Error(`Unsupported otpauth type: ${type}`);
  }
  const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
  if (!label) throw new Error("Missing label (issuer:account) in otpauth URI");

  const secret = url.searchParams.get("secret");
  if (!secret) throw new Error("Missing secret in otpauth URI");

  const parsedLabel = parseLabel(label);
  const issuerParam = url.searchParams.get("issuer") ?? "";
  const issuer = issuerParam || parsedLabel.issuer;
  const account = parsedLabel.issuer ? parsedLabel.account : label;

  const algorithm = (url.searchParams.get("algorithm") ?? "SHA1").toUpperCase();
  if (algorithm !== "SHA1" && algorithm !== "SHA256" && algorithm !== "SHA512") {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
  const digits = Number(url.searchParams.get("digits") ?? 6);
  const period = Number(url.searchParams.get("period") ?? 30);
  const counter = url.searchParams.get("counter") ? Number(url.searchParams.get("counter")) : undefined;

  return {
    type,
    label,
    issuer,
    account,
    secret,
    algorithm: algorithm as TOTPAlgorithm,
    digits,
    period,
    counter,
  };
}

/**
 * Serialize TOTP params into an otpauth:// URI.
 */
export function toOtpauthUri(data: OtpauthData): string {
  const label = encodeURIComponent(data.issuer ? `${data.issuer}:${data.account}` : data.account);
  const params = new URLSearchParams({
    secret: data.secret,
    issuer: data.issuer,
    algorithm: data.algorithm ?? "SHA1",
    digits: String(data.digits ?? 6),
  });
  if (data.type === "totp") {
    params.set("period", String(data.period ?? 30));
  } else {
    params.set("counter", String(data.counter ?? 0));
  }
  return `otpauth://${data.type}/${label}?${params.toString()}`;
}

/** Parse an otpauth URI into a TOTPParams (for storage). */
export function otpauthToTotpParams(uri: string): { params: TOTPParams; meta: Pick<OtpauthData, "issuer" | "account" | "type" | "counter"> } {
  const data = parseOtpauthUri(uri);
  return {
    params: {
      secret: data.secret,
      algorithm: data.algorithm,
      digits: data.digits,
      period: data.period,
    },
    meta: { issuer: data.issuer, account: data.account, type: data.type, counter: data.counter },
  };
}