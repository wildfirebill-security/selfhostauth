import "./styles.css";
import { SelfhostAuthClient } from "@selfhostauth/client";
import {
  VaultItem,
  parseOtpauthUri,
  totp,
  isValidSecret,
} from "@selfhostauth/core";

// ------------------------------------------------------------------ types / storage

interface WebSettings {
  serverUrl: string;
  token: string | null;
  username: string | null;
  lastRevision: number;
  lastSyncAt: number | null;
}

const LS_SETTINGS = "sha:web:settings";
const LS_ITEMS = "sha:web:items";
const LS_DIRTY = "sha:web:dirty";

function loadSettings(): WebSettings {
  try {
    const raw = localStorage.getItem(LS_SETTINGS);
    if (raw) return JSON.parse(raw) as WebSettings;
  } catch {}
  const defaultUrl = location.origin.includes("5174") ? "http://127.0.0.1:8787" : location.origin;
  return { serverUrl: defaultUrl, token: null, username: null, lastRevision: 0, lastSyncAt: null };
}

function saveSettings(s: WebSettings): void {
  localStorage.setItem(LS_SETTINGS, JSON.stringify(s));
}

function loadItems(): { items: VaultItem[]; dirty: string[] } {
  try {
    const items: VaultItem[] = JSON.parse(localStorage.getItem(LS_ITEMS) ?? "[]");
    const dirty: string[] = JSON.parse(localStorage.getItem(LS_DIRTY) ?? "[]");
    return { items, dirty };
  } catch {
    return { items: [], dirty: [] };
  }
}

function persistItems(items: VaultItem[], dirty: string[]): void {
  localStorage.setItem(LS_ITEMS, JSON.stringify(items));
  localStorage.setItem(LS_DIRTY, JSON.stringify(dirty));
}

// ------------------------------------------------------------------ state

let settings: WebSettings = loadSettings();
let items: VaultItem[] = loadItems().items;
let dirty: string[] = loadItems().dirty;
let filter = "";
let editingId: string | null = null;

function client(): SelfhostAuthClient {
  return new SelfhostAuthClient({ baseUrl: settings.serverUrl, token: settings.token ?? undefined });
}

// ------------------------------------------------------------------ DOM helpers

const $ = <T extends HTMLElement>(sel: string) => document.querySelector(sel) as T;
const $$ = (sel: string) => document.querySelectorAll<HTMLElement>(sel);

function showView(name: "login" | "vault" | "settings"): void {
  for (const id of ["view-login", "view-vault", "view-settings"] as const) {
    $(`#${id}`).classList.toggle("hidden", id !== `view-${name}`);
  }
}

function setStatus(text: string, isError = false): void {
  const el = $("#sync-status");
  el.textContent = text;
  el.style.color = isError ? "var(--danger)" : "";
}

// ------------------------------------------------------------------ sync

async function syncNow(showMsg = true): Promise<void> {
  if (!settings.token) return;
  if (showMsg) setStatus("Syncing…");
  try {
    const c = client();
    const pull = await c.pull(settings.lastRevision);
    const map = new Map(items.map((i) => [i.id, i]));

    for (const enc of pull.items) {
      const item: VaultItem = {
        id: enc.id,
        type: enc.type,
        name: enc.name,
        issuer: enc.issuer,
        account: enc.account,
        icon: enc.icon,
        note: enc.note,
        createdAt: enc.createdAt,
        updatedAt: enc.updatedAt,
        lastModifiedBy: enc.lastModifiedBy,
        params: {
          secret: enc.params.secret,
          algorithm: enc.params.algorithm as VaultItem["params"]["algorithm"],
          digits: enc.params.digits,
          period: enc.params.period,
        },
      };
      map.set(item.id, item);
    }
    for (const d of pull.deleted) map.delete(d.id);

    let merged = [...map.values()];
    const dirtySet = new Set(dirty);
    const toPush = merged.filter((i) => dirtySet.has(i.id));
    if (toPush.length > 0) {
      const push = await c.push({ items: toPush, baseRevision: settings.lastRevision });
      for (const conflict of push.conflicts) {
        const idx = merged.findIndex((i) => i.id === conflict.id);
        if (idx >= 0) merged[idx] = conflict;
      }
      dirty = dirty.filter((id) => !push.conflicts.some((x) => x.id === id));
    }

    settings.lastRevision = Math.max(pull.revision, settings.lastRevision);
    settings.lastSyncAt = Date.now();
    saveSettings(settings);
    items = merged;
    persistItems(items, dirty);
    render();
    if (showMsg) setStatus(`Synced ${merged.filter((i) => !i.deletedAt).length} codes · ${new Date().toLocaleTimeString()}`);
  } catch (e) {
    setStatus(`Sync failed: ${e instanceof Error ? e.message : String(e)}`, true);
  }
}

// ------------------------------------------------------------------ rendering + TOTP tick

function formatCode(code: string): string {
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

function render(): void {
  const list = $("#vault-list");
  list.innerHTML = "";
  const q = filter.toLowerCase();
  const visible = items
    .filter((i) => !i.deletedAt)
    .filter((i) => (q ? `${i.name} ${i.issuer ?? ""} ${i.account ?? ""}`.toLowerCase().includes(q) : true))
    .sort((a, b) => a.name.localeCompare(b.name));

  if (visible.length === 0) {
    list.innerHTML = `<p class="empty">No codes yet.<br/>Click <b>＋ Add</b> to import an authenticator.</p>`;
    return;
  }

  for (const item of visible) {
    const row = document.createElement("div");
    row.className = "item";
    row.dataset.itemId = item.id;

    const meta = document.createElement("div");
    meta.className = "item-meta";
    const nameEl = document.createElement("div");
    nameEl.className = "item-name";
    nameEl.textContent = item.name;
    const acctEl = document.createElement("div");
    acctEl.className = "item-account";
    acctEl.textContent = [item.issuer, item.account].filter(Boolean).join(" · ");
    meta.append(nameEl, acctEl);

    const col = document.createElement("div");
    col.className = "item-col";
    const codeEl = document.createElement("div");
    codeEl.className = "item-code";
    codeEl.textContent = "··· ···";
    codeEl.dataset.codeFor = item.id;
    const prog = document.createElement("div");
    prog.className = "progress";
    const fill = document.createElement("div");
    fill.className = "progress-fill";
    fill.dataset.fillFor = item.id;
    prog.append(fill);
    col.append(codeEl, prog);

    const actions = document.createElement("div");
    actions.className = "item-actions";
    const editBtn = document.createElement("button");
    editBtn.textContent = "✎";
    editBtn.title = "Edit";
    editBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      openModal(item);
    });
    const delBtn = document.createElement("button");
    delBtn.textContent = "🗑";
    delBtn.title = "Delete";
    delBtn.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      if (!confirm(`Delete "${item.name}"?`)) return;
      const now = Date.now();
      items = items.map((x) => (x.id === item.id ? { ...x, deletedAt: now, updatedAt: now } : x));
      dirty = [...new Set([...dirty, item.id])];
      persistItems(items, dirty);
      render();
      await syncNow(false);
    });
    actions.append(editBtn, delBtn);

    row.append(meta, col, actions);
    row.addEventListener("click", () => {
      const code = codeEl.textContent?.replace(/\s/g, "");
      if (code && /^\d+$/.test(code)) {
        void navigator.clipboard.writeText(code).then(() => setStatus(`Copied ${item.name}`));
      }
    });
    list.append(row);
  }
}

async function tick(): Promise<void> {
  for (const el of $$("[data-code-for]")) {
    const id = (el as HTMLElement).dataset.codeFor!;
    const item = items.find((x) => x.id === id);
    if (!item) continue;
    try {
      const r = await totp(item.params);
      (el as HTMLElement).textContent = formatCode(r.code);
      const fill = document.querySelector<HTMLElement>(`[data-fill-for="${id}"]`);
      if (fill) {
        fill.style.width = `${(r.remaining / r.period) * 100}%`;
        fill.classList.toggle("expiring", r.remaining <= 5);
      }
    } catch {}
  }
}

// ------------------------------------------------------------------ modal

function openModal(existing?: VaultItem): void {
  editingId = existing?.id ?? null;
  ($("#modal-title") as HTMLElement).textContent = existing ? "Edit authenticator" : "Add authenticator";
  ($("#item-secret") as HTMLInputElement).value = existing ? existing.params.secret : "";
  ($("#item-name") as HTMLInputElement).value = existing?.name ?? "";
  ($("#item-issuer") as HTMLInputElement).value = existing?.issuer ?? "";
  ($("#item-account") as HTMLInputElement).value = existing?.account ?? "";
  $("#item-error").classList.add("hidden");
  $("#modal").classList.remove("hidden");
  if (!existing) ($("#item-secret") as HTMLElement).focus();
}

function closeModal(): void {
  $("#modal").classList.add("hidden");
  editingId = null;
}

function parseSecretInput(input: string): { params: VaultItem["params"]; issuer?: string; account?: string } {
  const t = input.trim();
  if (t.startsWith("otpauth://")) {
    const p = parseOtpauthUri(t);
    return { params: { secret: p.secret, algorithm: p.algorithm, digits: p.digits, period: p.period }, issuer: p.issuer || undefined, account: p.account || undefined };
  }
  if (!isValidSecret(t)) throw new Error("Enter an otpauth:// URI or a valid base32 secret.");
  return { params: { secret: t.toUpperCase().replace(/[=\s]/g, "") } };
}

async function saveItem(ev: Event): Promise<void> {
  ev.preventDefault();
  const errEl = $("#item-error");
  errEl.classList.add("hidden");
  try {
    const secretInput = ($("#item-secret") as HTMLInputElement).value;
    const { params, issuer, account } = parseSecretInput(secretInput);
    const name = ($("#item-name") as HTMLInputElement).value.trim();
    if (!name) throw new Error("Name is required.");
    const now = Date.now();
    const existing = editingId ? items.find((x) => x.id === editingId) : undefined;
    const issuerVal = issuer ?? ((($("#item-issuer") as HTMLInputElement).value.trim() || undefined) as string | undefined);
    const accountVal = account ?? ((($("#item-account") as HTMLInputElement).value.trim() || undefined) as string | undefined);
    const item: VaultItem = {
      id: existing?.id ?? crypto.randomUUID(),
      type: "totp",
      name,
      issuer: issuerVal,
      account: accountVal,
      params,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      lastModifiedBy: settings.username ?? undefined,
    };
    const idx = items.findIndex((x) => x.id === item.id);
    if (idx >= 0) items[idx] = item;
    else items.push(item);
    dirty = [...new Set([...dirty, item.id])];
    persistItems(items, dirty);
    closeModal();
    render();
    await syncNow(false);
  } catch (e) {
    errEl.textContent = e instanceof Error ? e.message : String(e);
    errEl.classList.remove("hidden");
  }
}

// ------------------------------------------------------------------ app shell + boot

function renderShell(): void {
  document.querySelector("#app")!.innerHTML = `
    <header class="topbar">
      <div class="brand"><span class="logo">◈</span> selfhostauth</div>
      <div class="topbar-actions">
        <button id="btn-sync" class="ghost" title="Sync">⟳</button>
        <button id="btn-settings" class="ghost" title="Settings">⚙</button>
      </div>
    </header>
    <main>
      <section id="view-login" class="view hidden">
        <h1>Connect to your server</h1>
        <form id="login-form">
          <label>Server URL <input id="input-server" type="url" placeholder="https://auth.example.com" required /></label>
          <label>Username <input id="input-username" type="text" autocomplete="username" required /></label>
          <label>Password <input id="input-password" type="password" autocomplete="current-password" required /></label>
          <label class="row"><input id="input-register" type="checkbox" /> <span>Create a new account</span></label>
          <p id="login-error" class="error hidden"></p>
          <button type="submit" class="primary">Connect</button>
        </form>
      </section>
      <section id="view-vault" class="view hidden">
        <div class="vault-head">
          <input id="input-search" type="search" placeholder="Search codes…" />
          <button id="btn-add" class="primary">＋ Add</button>
        </div>
        <div id="vault-list" class="vault-list"></div>
        <p id="sync-status" class="sync-status"></p>
      </section>
      <section id="view-settings" class="view hidden">
        <h1>Settings</h1>
        <label>Server URL <input id="set-server" type="url" /></label>
        <p class="muted">Signed in as <span id="set-username"></span></p>
        <div class="row" style="margin-top:12px">
          <button id="btn-save-server" class="primary">Save</button>
          <button id="btn-signout" class="danger">Sign out</button>
        </div>
        <p id="settings-error" class="error hidden"></p>
        <p class="muted" style="margin-top:16px">Data is stored in this browser's localStorage. Use the desktop/mobile apps or extension for additional devices.</p>
      </section>
      <div id="modal" class="modal hidden">
        <div class="modal-card">
          <h2 id="modal-title">Add authenticator</h2>
          <form id="item-form">
            <label>Import URI or secret <input id="item-secret" type="text" placeholder="otpauth://totp/… or base32 secret" /></label>
            <label>Name <input id="item-name" type="text" placeholder="GitHub" /></label>
            <label>Issuer <span class="muted">(optional)</span> <input id="item-issuer" type="text" placeholder="GitHub" /></label>
            <label>Account <span class="muted">(optional)</span> <input id="item-account" type="text" placeholder="you@example.com" /></label>
            <p id="item-error" class="error hidden"></p>
            <div class="row" style="justify-content:flex-end">
              <button type="button" id="btn-item-cancel" class="ghost">Cancel</button>
              <button type="submit" class="primary">Save</button>
            </div>
          </form>
        </div>
      </div>
    </main>
  `;
}

function wireEvents(): void {
  $("#login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const serverUrl = ($("#input-server") as HTMLInputElement).value.trim();
    const username = ($("#input-username") as HTMLInputElement).value.trim();
    const password = ($("#input-password") as HTMLInputElement).value;
    const register = ($("#input-register") as HTMLInputElement).checked;
    const errEl = $("#login-error");
    errEl.classList.add("hidden");
    try {
      new URL(serverUrl);
    } catch {
      errEl.textContent = "Enter a valid server URL.";
      errEl.classList.remove("hidden");
      return;
    }
    try {
      const c = new SelfhostAuthClient({ baseUrl: serverUrl });
      const auth = register ? await c.register(username, password) : await c.login(username, password);
      settings = { serverUrl, token: auth.token, username: auth.user.username, lastRevision: 0, lastSyncAt: Date.now() };
      saveSettings(settings);
      showView("vault");
      await syncNow();
    } catch (e) {
      errEl.textContent = e instanceof Error ? e.message : String(e);
      errEl.classList.remove("hidden");
    }
  });

  $("#btn-sync").addEventListener("click", () => void syncNow());
  $("#btn-settings").addEventListener("click", () => {
    ($("#set-server") as HTMLInputElement).value = settings.serverUrl;
    ($("#set-username") as HTMLElement).textContent = settings.username ?? "—";
    $("#settings-error").classList.add("hidden");
    showView("settings");
  });
  $("#btn-save-server").addEventListener("click", () => {
    try {
      const url = ($("#set-server") as HTMLInputElement).value.trim();
      new URL(url);
      settings.serverUrl = url;
      saveSettings(settings);
      $("#settings-error").classList.add("hidden");
      showView("vault");
      void syncNow();
    } catch {
      const el = $("#settings-error");
      el.textContent = "Enter a valid URL.";
      el.classList.remove("hidden");
    }
  });
  $("#btn-signout").addEventListener("click", () => {
    localStorage.removeItem(LS_SETTINGS);
    localStorage.removeItem(LS_ITEMS);
    localStorage.removeItem(LS_DIRTY);
    settings = loadSettings();
    items = [];
    dirty = [];
    ($("#input-server") as HTMLInputElement).value = settings.serverUrl;
    showView("login");
  });

  $("#btn-add").addEventListener("click", () => openModal());
  $("#btn-item-cancel").addEventListener("click", closeModal);
  $("#item-form").addEventListener("submit", (ev) => void saveItem(ev));
  $("#modal").addEventListener("click", (ev) => {
    if (ev.target === $("#modal")) closeModal();
  });
  $("#input-search").addEventListener("input", (ev) => {
    filter = (ev.target as HTMLInputElement).value;
    render();
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") closeModal();
  });
}

function boot(): void {
  renderShell();
  wireEvents();
  if (settings.token) {
    showView("vault");
    render();
    void tick();
    setInterval(() => void tick(), 1000);
    void syncNow();
  } else {
    ($("#input-server") as HTMLInputElement).value = settings.serverUrl;
    showView("login");
    setInterval(() => void tick(), 1000);
  }
}

boot();
