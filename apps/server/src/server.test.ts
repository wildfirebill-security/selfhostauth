import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildApp } from "./index.js";
import { openDb } from "./db.js";
import { loadConfig } from "./config.js";
import { VaultItem, totp, base32Encode } from "@selfhostauth/core";

let deps: { db: ReturnType<typeof openDb>; config: ReturnType<typeof loadConfig> };
let dataDir: string;
let app: ReturnType<typeof buildApp>;
let baseUrl: string;

interface ApiClient {
  req<T>(method: string, path: string, body?: unknown, token?: string): Promise<T>;
}

function api(): ApiClient {
  return {
    async req<T>(method: string, path: string, body?: unknown, token?: string): Promise<T> {
      const headers: Record<string, string> = {};
      if (body !== undefined) headers["Content-Type"] = "application/json";
      if (token) headers["Authorization"] = `Bearer ${token}`;
      const res = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await res.text();
      const json = text ? JSON.parse(text) : null;
      if (!res.ok) {
        const err = new Error(json?.message ?? `HTTP ${res.status}`) as Error & {
          status: number;
          body: unknown;
        };
        err.status = res.status;
        err.body = json;
        throw err;
      }
      return json as T;
    },
  };
}

const SECRET_B32 = base32Encode(new TextEncoder().encode("12345678901234567890"));

async function register(username: string): Promise<string> {
  const client = api();
  const res = await client.req<{ token: string }>("POST", "/api/v1/auth/register", {
    username,
    password: "password-123456",
  });
  return res.token;
}

function makeItem(id: string, name: string, updatedAt?: number): VaultItem {
  const now = updatedAt ?? Date.now();
  return {
    id,
    type: "totp",
    name,
    params: { secret: SECRET_B32 },
    createdAt: now,
    updatedAt: now,
  };
}

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), "sha-test-"));
  const config = { ...loadConfig(), dataDir, port: 0, rateLimitPerMinute: 10_000 };
  deps = { db: openDb(dataDir), config };
  app = buildApp(deps);
  await app.listen({ host: "127.0.0.1", port: 0 });
  baseUrl = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
});

after(async () => {
  await app.close();
  deps.db.close();
  rmSync(dataDir, { recursive: true, force: true });
});

test("info endpoint", async () => {
  const info = await api().req<{ name: string; features: { sync: boolean } }>("GET", "/api/v1/info");
  assert.equal(info.name, "selfhostauth");
  assert.equal(info.features.sync, true);
});

test("register + login roundtrip, wrong password rejected", async () => {
  const client = api();
  const reg = await client.req<{ token: string; user: { username: string } }>(
    "POST",
    "/api/v1/auth/register",
    { username: "alice", password: "correct-horse-battery" },
  );
  assert.ok(reg.token);
  assert.equal(reg.user.username, "alice");

  await assert.rejects(
    () =>
      client.req("POST", "/api/v1/auth/login", {
        username: "alice",
        password: "wrong-password",
      }),
    (e: Error & { status: number }) => e.status === 401,
  );

  const login = await client.req<{ token: string }>("POST", "/api/v1/auth/login", {
    username: "alice",
    password: "correct-horse-battery",
  });
  assert.ok(login.token);
});

test("registration rate limiting kicks in", async () => {
  // Separate app instance with a tiny limit so other tests aren't affected
  const rlDir = mkdtempSync(join(tmpdir(), "sha-rl-"));
  const rlConfig = { ...loadConfig(), dataDir: rlDir, port: 0, rateLimitPerMinute: 3 };
  const rlDeps = { db: openDb(rlDir), config: rlConfig };
  const rlApp = buildApp(rlDeps);
  await rlApp.listen({ host: "127.0.0.1", port: 0 });
  const rlBase = `http://127.0.0.1:${(rlApp.server.address() as { port: number }).port}`;

  try {
    const client = api() as ApiClient & { base: string };
    // api() closes over the global baseUrl; rebuild a local requester
    const raw = fetch;
    let limited = false;
    for (let i = 0; i < 10; i++) {
      const res = await raw(`${rlBase}/api/v1/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: `spammer${i}`, password: "password-123456" }),
      });
      if (res.status === 429) {
        limited = true;
        break;
      }
    }
    void client;
    assert.equal(limited, true);
  } finally {
    await rlApp.close();
    rlDeps.db.close();
    rmSync(rlDir, { recursive: true, force: true });
  }
});

test("add item + server-side TOTP verify", async () => {
  const token = await register("bob");
  const item = makeItem("11111111-1111-4111-8111-111111111111", "GitHub");
  const added = await api().req<{ revision: number; item: VaultItem }>(
    "POST",
    "/api/v1/vault/items",
    item,
    token,
  );
  assert.equal(added.item.name, "GitHub");
  assert.ok(added.revision > 0);

  const now = Math.floor(Date.now() / 1000);
  const expected = (await totp({ secret: SECRET_B32 }, now)).code;
  const ok = await api().req<{ valid: boolean }>(
    "POST",
    `/api/v1/vault/items/${item.id}/verify`,
    { code: expected },
    token,
  );
  assert.equal(ok.valid, true);

  const bad = await api().req<{ valid: boolean }>(
    "POST",
    `/api/v1/vault/items/${item.id}/verify`,
    { code: "000000" },
    token,
  );
  assert.equal(bad.valid, false);
});

test("sync push / pull roundtrip with revisioning + tombstones", async () => {
  const token = await register("carol");
  const now = Date.now();
  const items = [makeItem("22222222-2222-4222-8222-222222222222", "AWS", now), makeItem("33333333-3333-4333-8333-333333333333", "Dropbox", now)];

  const pushed = await api().req<{ revision: number; conflicts: VaultItem[] }>(
    "POST",
    "/api/v1/sync/push",
    { items, baseRevision: 0 },
    token,
  );
  assert.equal(pushed.conflicts.length, 0);
  assert.ok(pushed.revision >= 2);

  const pull = await api().req<{ revision: number; items: unknown[]; deleted: unknown[] }>(
    "GET",
    "/api/v1/sync/pull?since=0",
    undefined,
    token,
  );
  assert.equal(pull.items.length, 2);
  assert.equal(pull.deleted.length, 0);

  await api().req("DELETE", `/api/v1/vault/items/${items[0]!.id}`, undefined, token);
  const pull2 = await api().req<{ deleted: Array<{ id: string }> }>(
    "GET",
    `/api/v1/sync/pull?since=${pull.revision}`,
    undefined,
    token,
  );
  assert.equal(pull2.deleted.length, 1);
  assert.equal(pull2.deleted[0]!.id, items[0]!.id);
});

test("sync conflict: server version wins when client is stale", async () => {
  const token = await register("dave");
  const item = makeItem("44444444-4444-4444-8444-444444444444", "Original", Date.now() - 60_000);
  await api().req("POST", "/api/v1/vault/items", { ...item, updatedAt: Date.now() }, token);

  // Client pushes a STALE version (older updatedAt) -> server returns conflict with its version
  const pushed = await api().req<{ revision: number; conflicts: VaultItem[] }>(
    "POST",
    "/api/v1/sync/push",
    { items: [item], baseRevision: 1 },
    token,
  );
  assert.equal(pushed.conflicts.length, 1);
  assert.equal(pushed.conflicts[0]!.name, "Original");
  assert.ok(pushed.conflicts[0]!.updatedAt > item.updatedAt);
});

test("2fa setup returns a working otpauth secret", async () => {
  const token = await register("erin");
  const setup = await api().req<{ uri: string; secret: string }>(
    "POST",
    "/api/v1/auth/2fa/setup",
    undefined,
    token,
  );
  assert.ok(setup.uri.startsWith("otpauth://totp/"));
  assert.match(setup.secret, /^[A-Z2-7]+$/);

  const code = (await totp({ secret: setup.secret }, Math.floor(Date.now() / 1000))).code;
  const confirm = await api().req<{ enabled: boolean }>(
    "POST",
    "/api/v1/auth/2fa/confirm",
    { code },
    token,
  );
  assert.equal(confirm.enabled, true);

  // Subsequent login now requires the 2FA code
  await assert.rejects(
    () => api().req("POST", "/api/v1/auth/login", { username: "erin", password: "password-123456" }),
    (e: Error & { status: number }) => e.status === 400,
  );
  const with2fa = await api().req<{ token: string }>("POST", "/api/v1/auth/login", {
    username: "erin",
    password: "password-123456",
    totpCode: code,
  });
  assert.ok(with2fa.token);
});

test("unauthenticated access rejected", async () => {
  await assert.rejects(
    () => api().req("GET", "/api/v1/sync/pull?since=0"),
    (e: Error & { status: number }) => e.status === 401,
  );
});