import {
  getSettings,
  setSettings,
  clearSettings,
  makeClient,
  ensureHostAccess,
  syncVault,
  parseSecretInput,
} from "./shared.js";
import { SelfhostAuthClient } from "@selfhostauth/client";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

function status(el: HTMLElement, text: string, kind: "error" | "ok" | "" = "") {
  el.textContent = text;
  el.className = "status";
  if (kind) el.classList.add(kind);
}

async function boot(): Promise<void> {
  const settings = await getSettings();
  if (settings.serverUrl) ($("#server-url") as HTMLInputElement).value = settings.serverUrl;

  const authSection = $("#auth-section");
  const vaultSection = $("#vault-section");

  if (settings.token) {
    authSection.classList.add("hidden");
    vaultSection.classList.remove("hidden");
    $("#whoami").textContent = `Signed in as ${settings.username ?? "?"}`;
    const sync = await syncVault();
    status(
      $("#sync-status"),
      sync.ok ? `Synced ${sync.count} codes.` : `Sync failed: ${sync.error}`,
      sync.ok ? "ok" : "error",
    );
  }
}

$("#connect").addEventListener("click", async () => {
  const serverUrl = ($("#server-url") as HTMLInputElement).value.trim();
  const username = ($("#username") as HTMLInputElement).value.trim();
  const password = ($("#password") as HTMLInputElement).value;
  const register = ($("#register") as HTMLInputElement).checked;
  const el = $("#auth-status");

  try {
    new URL(serverUrl);
  } catch {
    status(el, "Enter a valid server URL.", "error");
    return;
  }
  if (!username || !password) {
    status(el, "Enter username and password.", "error");
    return;
  }
  if (!(await ensureHostAccess(serverUrl))) {
    status(el, "You denied access to the server host.", "error");
    return;
  }

  status(el, "Connecting…");
  const client = new SelfhostAuthClient({ baseUrl: serverUrl });
  try {
    const auth = register
      ? await client.register(username, password)
      : await client.login(username, password);
    await setSettings({
      serverUrl,
      token: auth.token,
      username: auth.user.username,
      lastRevision: 0,
      lastSyncAt: Date.now(),
    });
    status(el, register ? "Account created." : "Connected.", "ok");
    await boot();
  } catch (e) {
    status(el, e instanceof Error ? e.message : String(e), "error");
  }
});

$("#sync").addEventListener("click", async () => {
  const res = await syncVault();
  status(
    $("#sync-status"),
    res.ok ? `Synced ${res.count} codes.` : `Sync failed: ${res.error}`,
    res.ok ? "ok" : "error",
  );
});

$("#signout").addEventListener("click", async () => {
  const settings = await getSettings();
  if (settings.serverUrl && settings.token) {
    try {
      await makeClient(settings).login(settings.username ?? "", "");
    } catch {
      /* ignore */
    }
  }
  await clearSettings();
  location.reload();
});

$("#add").addEventListener("click", async () => {
  const secretInput = ($("#new-secret") as HTMLInputElement).value;
  const name = ($("#new-name") as HTMLInputElement).value.trim();
  const el = $("#add-status");

  if (!name) {
    status(el, "Enter a name for this authenticator.", "error");
    return;
  }
  try {
    const { params, issuer, account } = parseSecretInput(secretInput);
    const settings = await getSettings();
    const client = makeClient(settings);
    const now = Date.now();
    await client.addItem({
      id: crypto.randomUUID(),
      type: "totp",
      name,
      issuer,
      account,
      params,
      createdAt: now,
      updatedAt: now,
      lastModifiedBy: settings.username ?? undefined,
    });
    ($("#new-secret") as HTMLInputElement).value = "";
    ($("#new-name") as HTMLInputElement).value = "";
    status(el, "Added. Syncing…", "ok");
    const res = await syncVault();
    status(el, res.ok ? "Added and synced." : `Added but sync failed: ${res.error}`, res.ok ? "ok" : "error");
  } catch (e) {
    status(el, e instanceof Error ? e.message : String(e), "error");
  }
});

void boot();