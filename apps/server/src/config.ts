import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

export interface ServerConfig {
  host: string;
  port: number;
  dataDir: string;
  encryptionKey: Uint8Array;
  allowRegistration: boolean;
  sessionTtlDays: number;
  rateLimitPerMinute: number;
  version: string;
}

const VERSION = "0.1.0";

function loadOrCreateKey(dataDir: string): Uint8Array {
  const keyFile = join(dataDir, "encryption.key");
  if (existsSync(keyFile)) {
    const raw = readFileSync(keyFile, "utf8").trim();
    if (raw.length !== 44) {
      throw new Error(
        `Invalid encryption key file ${keyFile}: expected 44-char base64 (32 bytes). ` +
          "Delete it and restart to generate a fresh key (this will make existing data unrecoverable).",
      );
    }
    return Buffer.from(raw, "base64");
  }
  const key = globalThis.crypto.getRandomValues(new Uint8Array(32));
  writeFileSync(keyFile, Buffer.from(key).toString("base64") + "\n", { mode: 0o600 });
  return key;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ServerConfig {
  const dataDir = env.DATA_DIR ?? join(process.cwd(), "data");
  mkdirSync(dataDir, { recursive: true });

  let encryptionKey: Uint8Array;
  if (env.ENCRYPTION_KEY) {
    const raw = Buffer.from(env.ENCRYPTION_KEY, "base64");
    if (raw.length !== 32) {
      throw new Error("ENCRYPTION_KEY must be 32 bytes base64-encoded (run: node -e \"console.log(crypto.randomBytes(32).toString('base64'))\")");
    }
    encryptionKey = new Uint8Array(raw);
  } else {
    encryptionKey = loadOrCreateKey(dataDir);
  }

  return {
    host: env.HOST ?? "0.0.0.0",
    port: Number(env.PORT ?? 8787),
    dataDir,
    encryptionKey,
    allowRegistration: (env.ALLOW_REGISTRATION ?? "true") !== "false",
    sessionTtlDays: Number(env.SESSION_TTL_DAYS ?? 30),
    rateLimitPerMinute: Number(env.RATE_LIMIT_PER_MINUTE ?? 20),
    version: VERSION,
  };
}