import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildApp } from "./index.js";
import { openDb } from "./db.js";
import { loadConfig } from "./config.js";
import { SelfhostAuthClient } from "@selfhostauth/client";
import { totp, base32Encode, VaultItem } from "@selfhostauth/core";

let deps: { db: ReturnType<typeof openDb>; config: ReturnType<typeof loadConfig> };
let dataDir: string;
let app: ReturnType<typeof buildApp>;
let baseUrl: string;

before(async () => {
  dataDir = mkdtempSync(join(tmpdir(), "sha-client-"));
  const config = { ...loadConfig(), dataDir, port: 0, rateLimitPerMinute: 1000 };
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

test("full client lifecycle: register → add → pull → verify → delete", async () => {
  const client = new SelfhostAuthClient({ baseUrl });

  const info = await client.serverInfo();
  assert.equal(info.name, "selfhostauth");

  const auth = await client.register("clienttest", "password-123456");
  assert.equal(auth.user.username, "clienttest");
  client.token = auth.token;

  const secret = base32Encode(new TextEncoder().encode("12345678901234567890"));
  const now = Date.now();
  const item: VaultItem = {
    id: "99999999-9999-4999-8999-999999999999",
    type: "totp",
    name: "Integration Test",
    issuer: "Selfhostauth",
    account: "integration@example.com",
    params: { secret, algorithm: "SHA1", digits: 6, period: 30 },
    createdAt: now,
    updatedAt: now,
  };

  const added = await client.addItem(item);
  assert.ok(added.revision > 0);

  const pull = await client.pull(0);
  assert.equal(pull.items.length, 1);
  assert.equal(pull.items[0]!.name, "Integration Test");
  // Secret is encrypted at rest — must NOT equal the plaintext base32 secret
  assert.notEqual(pull.items[0]!.params.secret, secret);
  console.log("server stores encrypted secret (preview):", pull.items[0]!.params.secret.slice(0, 30) + "…");

  const code = (await totp({ secret }, Math.floor(Date.now() / 1000))).code;
  const verified = await client.verifyCode(item.id, code);
  assert.equal(verified.valid, true);
  console.log(`server-verified code ${code}:`, verified.valid);

  await client.deleteItem(item.id);
  const pull2 = await client.pull(pull.revision);
  assert.equal(pull2.deleted.length, 1);
  assert.equal(pull2.deleted[0]!.id, item.id);

  console.log("integration OK");
});