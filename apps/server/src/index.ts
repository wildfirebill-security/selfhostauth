import Fastify, { FastifyInstance, FastifyRequest } from "fastify";
import cors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  AuthResponse,
  EncryptedVaultItem,
  ServerInfo,
  SyncPullResponse,
  SyncPushRequest,
  SyncPushResponse,
  TOTPParams,
  VaultItem,
} from "@selfhostauth/core";
import { totpVerify, encryptAesGcm, decryptAesGcmText, base32Decode, base32Encode } from "@selfhostauth/core";
import { Db, UserRow, itemRowToEncrypted, itemRowToPlain, openDb } from "./db.js";
import { ServerConfig, loadConfig } from "./config.js";
import {
  hashPassword,
  verifyPassword,
  newSessionToken,
  hashToken,
  encryptJson,
  decryptJson,
} from "./crypto.js";

declare module "fastify" {
  interface FastifyRequest {
    user?: UserRow;
  }
}

export interface AppDeps {
  db: Db;
  config: ServerConfig;
}

export function buildApp(deps: AppDeps): FastifyInstance {
  const { db, config } = deps;
  const app = Fastify({ logger: true });

  app.register(cors, { origin: true });

  // Serve the web UI (apps/web/dist) at / — if built. Falls back to a
  // tiny landing page that links to the API when web is not present.
  const webRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "web", "dist");
  if (existsSync(join(webRoot, "index.html"))) {
    void app.register(fastifyStatic, { root: webRoot, prefix: "/" });
    // SPA fallback: any non-API GET that missed a static file serves index.html
    app.setNotFoundHandler((req, reply) => {
      if (req.url.startsWith("/api/")) {
        return reply.code(404).send({ error: "not_found", message: "Not found", status: 404 });
      }
      return reply.sendFile("index.html");
    });
  } else {
    app.get("/", async (_req, reply) => {
      return reply.type("text/html").send(
        `<!doctype html><html><head><meta charset="utf-8"><title>selfhostauth</title></head>` +
          `<body style="font-family:system-ui;padding:2rem;background:#0f1117;color:#e6e9f0">` +
          `<h1>◈ selfhostauth</h1><p>API running. Build the web UI with <code>pnpm --filter @selfhostauth/web build</code> to serve it here.</p>` +
          `<p><a style="color:#4f8cff" href="/api/v1/info">/api/v1/info</a> · <a style="color:#4f8cff" href="/health">/health</a></p>` +
          `</body></html>`,
      );
    });
  }

  /* ------------------------------------------------------ helpers */

  const rateBuckets = new Map<string, number[]>();
  function rateLimited(key: string): boolean {
    const now = Date.now();
    const windowMs = 60_000;
    const hits = (rateBuckets.get(key) ?? []).filter((t) => now - t < windowMs);
    if (hits.length >= config.rateLimitPerMinute) {
      rateBuckets.set(key, hits);
      return true;
    }
    hits.push(now);
    rateBuckets.set(key, hits);
    return false;
  }

  function clientIp(req: FastifyRequest): string {
    const fwd = req.headers["x-forwarded-for"];
    if (typeof fwd === "string" && fwd.length > 0) return fwd.split(",")[0]!.trim();
    return req.ip ?? "unknown";
  }

  function requireAuth(req: FastifyRequest, reply: { code(code: number): unknown }): boolean {
    const header = req.headers.authorization;
    if (!header?.startsWith("Bearer ")) {
      reply.code(401);
      return false;
    }
    const token = header.slice("Bearer ".length);
    const user = db.getUserBySession(hashToken(token));
    if (!user) {
      reply.code(401);
      return false;
    }
    req.user = user;
    return true;
  }

  function fail(reply: { code(code: number): { send(body: unknown): unknown } }, status: number, code: string, message: string) {
    return reply.code(status).send({ error: code, message, status });
  }

  /* ------------------------------------------------------- routes */

  app.get("/api/v1/info", async (): Promise<ServerInfo> => {
    return {
      name: "selfhostauth",
      version: config.version,
      features: {
        sync: true,
        totpVerify: true,
        registration: config.allowRegistration,
      },
    };
  });

  app.get("/health", async () => ({ ok: true }));

  app.post("/api/v1/auth/register", async (req, reply) => {
    if (!config.allowRegistration) {
      return fail(reply, 403, "registration_disabled", "Registration is disabled on this server");
    }
    if (rateLimited(`register:${clientIp(req)}`)) {
      return fail(reply, 429, "rate_limited", "Too many attempts, try again later");
    }
    const { username, password } = req.body as { username?: string; password?: string };
    if (typeof username !== "string" || username.length < 3 || username.length > 64) {
      return fail(reply, 400, "invalid_username", "Username must be 3-64 characters");
    }
    if (typeof password !== "string" || password.length < 8) {
      return fail(reply, 400, "invalid_password", "Password must be at least 8 characters");
    }
    if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
      return fail(reply, 400, "invalid_username", "Username may only contain letters, digits, . _ -");
    }
    if (db.getUserByUsername(username)) {
      return fail(reply, 409, "username_taken", "Username is already taken");
    }
    const user = db.createUser(username, hashPassword(password));
    return issueSession(req, reply, user);
  });

  app.post("/api/v1/auth/login", async (req, reply) => {
    if (rateLimited(`login:${clientIp(req)}`)) {
      return fail(reply, 429, "rate_limited", "Too many attempts, try again later");
    }
    const { username, password, totpCode } = req.body as { username?: string; password?: string; totpCode?: string };
    if (typeof username !== "string" || typeof password !== "string") {
      return fail(reply, 400, "invalid_credentials", "Username and password are required");
    }
    const user = db.getUserByUsername(username);
    if (!user || !verifyPassword(password, user.password_hash)) {
      return fail(reply, 401, "invalid_credentials", "Invalid username or password");
    }
    if (user.totp_enabled) {
      if (typeof totpCode !== "string" || !user.totp_secret_enc) {
        return fail(reply, 400, "totp_required", "Two-factor code required");
      }
      const secret = decryptJson<string>(config.encryptionKey, JSON.parse(user.totp_secret_enc));
      const valid = await totpVerify({ secret }, totpCode);
      if (!valid.valid) {
        return fail(reply, 401, "invalid_totp", "Invalid two-factor code");
      }
    }
    return issueSession(req, reply, user);
  });

  function issueSession(req: FastifyRequest, reply: { code(code: number): { send(body: unknown): unknown } }, user: UserRow): AuthResponse | unknown {
    const { token, tokenHash } = newSessionToken();
    db.createSession(tokenHash, user.id, config.sessionTtlDays);
    return reply.code(200).send({
      token,
      user: { id: user.id, username: user.username, createdAt: user.created_at },
    }) as unknown as AuthResponse;
  }

  app.post("/api/v1/auth/2fa/setup", async (req, reply) => {
    if (!requireAuth(req, reply)) return;
    const user = req.user!;
    if (user.totp_enabled) {
      return fail(reply, 409, "totp_already_enabled", "Two-factor is already enabled");
    }
    const raw = globalThis.crypto.getRandomValues(new Uint8Array(20));
    const b32Secret = base32Encode(raw);
    const uri = `otpauth://totp/${encodeURIComponent(`selfhostauth:${user.username}`)}?secret=${b32Secret}&issuer=selfhostauth&algorithm=SHA1&digits=6&period=30`;
    const enc = JSON.stringify(encryptJson(config.encryptionKey, b32Secret));
    db.setUserTotp(user.id, enc, true); // enabled immediately; /confirm validates the first code
    return { uri, secret: b32Secret };
  });

  app.post("/api/v1/auth/2fa/confirm", async (req, reply) => {
    if (!requireAuth(req, reply)) return;
    const { code } = req.body as { code?: string };
    const user = req.user!;
    if (!user.totp_enabled || !user.totp_secret_enc) {
      return fail(reply, 400, "totp_not_setup", "Two-factor not set up");
    }
    const secret = decryptJson<string>(config.encryptionKey, JSON.parse(user.totp_secret_enc));
    const valid = await totpVerify({ secret }, code ?? "");
    if (!valid.valid) {
      return fail(reply, 401, "invalid_totp", "Invalid code");
    }
    return { enabled: true };
  });

  app.post("/api/v1/auth/logout", async (req, reply) => {
    const header = req.headers.authorization;
    if (header?.startsWith("Bearer ")) {
      db.deleteSession(hashToken(header.slice("Bearer ".length)));
    }
    return { ok: true };
  });

  /* ------------------------------------------------------- vault */

  async function encryptItemParams(user: UserRow, item: VaultItem): Promise<string> {
    const payload = encryptJson(config.encryptionKey, item.params);
    return JSON.stringify(payload);
  }

  async function decryptItemParams(user: UserRow, enc: string): Promise<TOTPParams> {
    return decryptJson<TOTPParams>(config.encryptionKey, JSON.parse(enc));
  }

  function validateItem(item: VaultItem): string | null {
    if (!item.id || !item.name) return "id and name are required";
    if (item.type !== "totp" && item.type !== "hotp") return "type must be totp or hotp";
    if (typeof item.params?.secret !== "string" || item.params.secret.length < 10) {
      return "params.secret (base32) is required";
    }
    return null;
  }

  app.post("/api/v1/vault/items", async (req, reply) => {
    if (!requireAuth(req, reply)) return;
    const user = req.user!;
    const item = req.body as VaultItem;
    const err = validateItem(item);
    if (err) return fail(reply, 400, "invalid_item", err);
    if (db.getItem(user.id, item.id)) {
      return fail(reply, 409, "item_exists", "Item with this id already exists");
    }
    const now = Date.now();
    const stored: VaultItem = {
      ...item,
      createdAt: item.createdAt ?? now,
      updatedAt: item.updatedAt ?? now,
      lastModifiedBy: user.username,
    };
    const secretEnc = await encryptItemParams(user, stored);
    const rev = db.bumpUserRevision(user.id);
    db.upsertItem(user.id, stored, secretEnc, rev);
    return { revision: rev, item: stored };
  });

  app.put("/api/v1/vault/items/:id", async (req, reply) => {
    if (!requireAuth(req, reply)) return;
    const user = req.user!;
    const id = (req.params as { id: string }).id;
    const existing = db.getItem(user.id, id);
    if (!existing) return fail(reply, 404, "not_found", "Item not found");
    const item = { ...(req.body as VaultItem), id, createdAt: existing.created_at };
    const err = validateItem(item);
    if (err) return fail(reply, 400, "invalid_item", err);
    const now = Date.now();
    const stored: VaultItem = { ...item, updatedAt: item.updatedAt ?? now, lastModifiedBy: user.username };
    const secretEnc = await encryptItemParams(user, stored);
    const rev = db.bumpUserRevision(user.id);
    db.upsertItem(user.id, stored, secretEnc, rev);
    return { revision: rev, item: stored };
  });

  app.delete("/api/v1/vault/items/:id", async (req, reply) => {
    if (!requireAuth(req, reply)) return;
    const user = req.user!;
    const id = (req.params as { id: string }).id;
    const existing = db.getItem(user.id, id);
    if (!existing) return fail(reply, 404, "not_found", "Item not found");
    const now = Date.now();
    const tombstone: VaultItem = {
      id,
      type: existing.type as VaultItem["type"],
      name: existing.name,
      params: await decryptItemParams(user, existing.secret_enc),
      createdAt: existing.created_at,
      updatedAt: now,
      deletedAt: now,
      lastModifiedBy: user.username,
    };
    const rev = db.bumpUserRevision(user.id);
    db.upsertItem(user.id, tombstone, existing.secret_enc, rev);
    return { revision: rev };
  });

  app.post("/api/v1/vault/items/:id/verify", async (req, reply) => {
    if (!requireAuth(req, reply)) return;
    const user = req.user!;
    const id = (req.params as { id: string }).id;
    const { code } = req.body as { code?: string };
    const row = db.getItem(user.id, id);
    if (!row || row.deleted_at) return fail(reply, 404, "not_found", "Item not found");
    const params = await decryptItemParams(user, row.secret_enc);
    const result = await totpVerify(params, code ?? "");
    return { valid: result.valid };
  });

  /* -------------------------------------------------------- sync */

  app.get("/api/v1/sync/pull", async (req, reply) => {
    if (!requireAuth(req, reply)) return;
    const user = req.user!;
    const since = Number((req.query as { since?: string }).since ?? 0);
    if (!Number.isFinite(since) || since < 0) return fail(reply, 400, "bad_since", "since must be a non-negative integer");

    const rows = db.getItemsSince(user.id, since);
    const items: EncryptedVaultItem[] = [];
    const deleted: SyncPullResponse["deleted"] = [];
    for (const row of rows) {
      const encrypted = itemRowToEncrypted(row);
      if (row.deleted_at) {
        deleted.push({ id: row.id, deletedAt: row.deleted_at });
      } else {
        items.push(encrypted);
      }
    }
    return {
      revision: db.maxItemRev(user.id),
      items,
      deleted,
    } satisfies SyncPullResponse;
  });

  app.post("/api/v1/sync/push", async (req, reply) => {
    if (!requireAuth(req, reply)) return;
    const user = req.user!;
    const body = req.body as SyncPushRequest;
    if (!Array.isArray(body?.items)) return fail(reply, 400, "bad_push", "items array is required");

    const conflicts: VaultItem[] = [];
    for (const clientItem of body.items) {
      const existing = db.getItem(user.id, clientItem.id);
      if (existing && existing.updated_at > clientItem.updatedAt) {
        // Server is newer — return it to the client as a conflict
        const params = await decryptItemParams(user, existing.secret_enc);
        conflicts.push(itemRowToPlain(existing, params));
        continue;
      }
      const now = Date.now();
      const stored: VaultItem = {
        ...clientItem,
        createdAt: existing?.created_at ?? clientItem.createdAt ?? now,
        updatedAt: Math.max(clientItem.updatedAt ?? 0, now),
        lastModifiedBy: user.username,
      };
      const secretEnc = existing && !clientItem.deletedAt ? existing.secret_enc : await encryptItemParams(user, stored);
      const rev = db.bumpUserRevision(user.id);
      db.upsertItem(user.id, stored, secretEnc, rev);
    }

    return {
      revision: db.maxItemRev(user.id),
      conflicts,
    } satisfies SyncPushResponse;
  });

  return app;
}

/** Standalone entrypoint. */
export async function startServer(configOverride?: Partial<ServerConfig>): Promise<{ app: FastifyInstance; db: Db; config: ServerConfig; close: () => Promise<void> }> {
  const config = { ...loadConfig(), ...configOverride };
  const db = openDb(config.dataDir);
  const app = buildApp({ db, config });
  await app.listen({ host: config.host, port: config.port });
  const close = async () => {
    await app.close();
    db.close();
  };
  return { app, db, config, close };
}

/** True when this file was launched directly (node dist/index.js). */
function isMainModule(): boolean {
  const arg = process.argv[1];
  if (!arg) return false;
  try {
    return fileURLToPath(import.meta.url) === arg;
  } catch {
    return false;
  }
}

if (isMainModule()) {
  const main = async () => {
    const config = loadConfig();
    const db = openDb(config.dataDir);
    const app = buildApp({ db, config });
    try {
      await app.listen({ host: config.host, port: config.port });
      app.log.info(`selfhostauth server v${config.version} listening on http://${config.host}:${config.port}`);
      app.log.info(`data dir: ${config.dataDir}`);
    } catch (err) {
      app.log.error(err);
      process.exit(1);
    }
  };
  void main();
}