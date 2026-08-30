import { SelfhostAuthClient } from "@selfhostauth/client";
import {
  VaultItem,
  parseOtpauthUri,
  totp,
  isValidSecret,
} from "@selfhostauth/core";
import type { DesktopSettings } from "../main/preload.js";

/* ------------------------------------------------------------- state */

interface AppState {
  settings: DesktopSettings;
  client: SelfhostAuthClient | null;
  items: Map<string, VaultItem>;
  dirty: Set<string>;
  filter: string;
  editingId: string | null;
}

const state: AppState = {
  settings: await window.desktop.getSettings(),
  client: null,
  items: new Map(),
  dirty: new Set(),
  filter: "",
  editingId: null,
};
/* ---------------------------------------------------------- elements */

const $ = <T extends HTMLElement>(sel: string): T => document.querySelector(sel) as T;

const views = {
  login: $("#view-login"),
  vault: $("#view-vault"),
  settings: $("#view-settings"),
};

/* ----------------------------------------------------------- helpers */

function showView(name: keyof typeof views): void {
  for (const [key, el] of Object.entries(views)) {
    el.classList.toggle("hidden", key !== name);
  }
}

function setSyncStatus(text: string): void {
  const el = $("#sync-status");
  if (el) el.textContent = text;
}

function persistLocal(): void {
  localStorage.setItem("items", JSON.stringify([...state.items.values()]));
  localStorage.setItem("dirty", JSON.stringify([...state.dirty]));
}

function loadLocal(): void {
  try {
    const raw = localStorage.getItem("items");
    if (raw) {
      const arr = JSON.parse(raw) as VaultItem[];
      for (const item of arr) state.items.set(item.id, item);
    }
    const dirtyRaw = localStorage.getItem("dirty");
    if (dirtyRaw) for (const id of JSON.parse(dirtyRaw) as string[]) state.dirty.add(id);
  } catch {
    /* ignore corrupted cache */
  }
}

function makeClient(): SelfhostAuthClient {
  return new SelfhostAuthClient({
    baseUrl: state.settings.serverUrl,
    token: state.settings.token ?? undefined,
  });
}

/* ------------------------------------------------------------ sync */

async function syncNow(show = true): Promise<void> {
  if (!state.client || !state.settings.token) return;
  if (show) setSyncStatus("Syncing…");
  try {
    // 1. pull remote changes
    const pull = await state.client.pull(state.settings.lastRevision);
    let changed = false;
    for (const enc of pull.items) {
      if (enc.deletedAt) {
        state.items.delete(enc.id);
        state.dirty.delete(enc.id);
        changed = true;
        continue;
      }
      const plain: VaultItem = {
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
      state.items.set(enc.id, plain);
      state.dirty.delete(enc.id); // remote wins over any local dirty copy
      changed = true;
    }
    for (const d of pull.deleted) {
      state.items.delete(d.id);
      state.dirty.delete(d.id);
      changed = true;
    }

    // 2. push local dirty changes
    const dirtyItems = [...state.dirty]
      .map((id) => state.items.get(id))
      .filter((i): i is VaultItem => !!i);
    let conflicts: VaultItem[] = [];
    if (dirtyItems.length > 0) {
      const push = await state.client.push({
        items: dirtyItems,
        baseRevision: state.settings.lastRevision,
      });
      conflicts = push.conflicts;
      if (push.revision > state.settings.lastRevision) {
        state.settings.lastRevision = push.revision;
      }
      for (const c of conflicts) {
        state.items.set(c.id, c);
        state.dirty.delete(c.id);
        changed = true;
      }
    }

    if (pull.revision > state.settings.lastRevision) {
      state.settings.lastRevision = pull.revision;
    }
    state.settings.lastSyncAt = Date.now();
    await window.desktop.setSettings(state.settings);
    persistLocal();
    render();
    setSyncStatus(
      changed
        ? `Synced ${new Date().toLocaleTimeString()}`
        : `Up to date · ${new Date().toLocaleTimeString()}`,
    );
  } catch (e) {
    setSyncStatus(`Sync failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/* ------------------------------------------------------- login/logout */

async function connectAndShow(serverUrl: string, username: string, password: string, register: boolean): Promise<void> {
  const client = new SelfhostAuthClient({ baseUrl: serverUrl });
  try {
    const auth = register
      ? await client.register(username, password)
      : await client.login(username, password);
    state.settings = await window.desktop.setSettings({
      serverUrl,
      token: auth.token,
      username: auth.user.username,
      lastSyncAt: Date.now(),
      lastRevision: 0,
    });
    state.client = makeClient();
    showView("vault");
    loadLocal();
    await syncNow();
  } catch (e) {
    const errEl = $("#login-error");
    errEl.textContent = e instanceof Error ? e.message : String(e);
    errEl.classList.remove("hidden");
  }
}

async function signOut(): Promise<void> {
  state.settings = await window.desktop.clearSettings();
  state.client = null;
  state.items.clear();
  state.dirty.clear();
  localStorage.removeItem("items");
  localStorage.removeItem("dirty");
  showView("login");
}

/* ----------------------------------------------------------- render */

function tickTimer(): ReturnType<typeof setInterval> {
  return setInterval(() => {
    for (const el of document.querySelectorAll<HTMLElement>("[data-code-id]")) {
      const item = state.items.get(el.dataset.codeId!);
      if (!item) continue;
      void renderCodeInto(el, item);
    }
  }, 1000);
}

async function renderCodeInto(el: HTMLElement, item: VaultItem): Promise<void> {
  try {
    const result = await totp(item.params);
    const codeEl = el.querySelector<HTMLElement>(".item-code");
    const fill = el.querySelector<HTMLElement>(".progress-fill");
    if (codeEl) codeEl.textContent = formatCode(result.code);
    if (fill) {
      const pct = (result.remaining / result.period) * 100;
      fill.style.width = `${pct}%`;
      fill.classList.toggle("expiring", result.remaining <= 5);
    }
  } catch {
    /* invalid secret — skip */
  }
}

function formatCode(code: string): string {
  // group digits visually e.g. 123 456
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

function render(): void {
  const list = $("#vault-list");
  list.innerHTML = "";

  const q = state.filter.toLowerCase();
  const items = [...state.items.values()]
    .filter((i) => !i.deletedAt)
    .filter((i) =>
      q
        ? `${i.name} ${i.issuer ?? ""} ${i.account ?? ""}`.toLowerCase().includes(q)
        : true,
    )
    .sort((a, b) => a.name.localeCompare(b.name));

  if (items.length === 0) {
    list.innerHTML = `<p class="empty">No authenticators yet.<br/>Click "＋ Add" to import one.</p>`;
    return;
  }

  for (const item of items) {
    const row = document.createElement("div");
    row.className = "item";
    row.dataset.codeId = item.id;

    const meta = document.createElement("div");
    meta.className = "item-meta";
    const name = document.createElement("div");
    name.className = "item-name";
    name.textContent = item.name;
    const account = document.createElement("div");
    account.className = "item-account";
    account.textContent = [item.issuer, item.account].filter(Boolean).join(" · ");
    meta.append(name, account);

    const codeWrap = document.createElement("div");
    codeWrap.className = "item-code";
    codeWrap.textContent = "··· ···";
    const progress = document.createElement("div");
    progress.className = "progress";
    const fill = document.createElement("div");
    fill.className = "progress-fill";
    progress.append(fill);

    const actions = document.createElement("div");
    actions.className = "item-actions";
    const editBtn = document.createElement("button");
    editBtn.textContent = "✎";
    editBtn.title = "Edit";
    editBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      openItemModal(item);
    });
    const delBtn = document.createElement("button");
    delBtn.textContent = "🗑";
    delBtn.title = "Delete";
    delBtn.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      if (!confirm(`Delete "${item.name}"?`)) return;
      const tombstone = { ...item, deletedAt: Date.now(), updatedAt: Date.now() };
      state.items.set(item.id, tombstone);
      state.dirty.add(item.id);
      persistLocal();
      render();
      await syncNow();
    });
    actions.append(editBtn, delBtn);

    row.append(meta, codeWrap, progress, actions);

    row.addEventListener("click", () => {
      const code = row.querySelector<HTMLElement>(".item-code")?.textContent?.replace(/\s/g, "");
      if (code && /^\d+$/.test(code)) {
        void navigator.clipboard.writeText(code).then(() => {
          setSyncStatus(`Copied ${item.name} code`);
        });
      }
    });

    list.append(row);
    void renderCodeInto(row, item);
  }
}

/* ------------------------------------------------------- item modal */

function openItemModal(existing?: VaultItem): void {
  state.editingId = existing?.id ?? null;
  $("#modal-title").textContent = existing ? "Edit authenticator" : "Add authenticator";
  ($("#item-secret") as HTMLInputElement).value = existing ? existing.params.secret : "";
  ($("#item-name") as HTMLInputElement).value = existing?.name ?? "";
  ($("#item-issuer") as HTMLInputElement).value = existing?.issuer ?? "";
  ($("#item-account") as HTMLInputElement).value = existing?.account ?? "";
  $("#item-error").classList.add("hidden");
  $("#modal").classList.remove("hidden");
  const secretField = $("#item-secret");
  if (!existing) secretField.focus();
}

function closeItemModal(): void {
  $("#modal").classList.add("hidden");
  state.editingId = null;
}

function secretToParams(input: string): { params: VaultItem["params"]; issuer?: string; account?: string } {
  const trimmed = input.trim();
  if (trimmed.startsWith("otpauth://")) {
    const parsed = parseOtpauthUri(trimmed);
    return {
      params: {
        secret: parsed.secret,
        algorithm: parsed.algorithm,
        digits: parsed.digits,
        period: parsed.period,
      },
      issuer: parsed.issuer || undefined,
      account: parsed.account || undefined,
    };
  }
  if (!isValidSecret(trimmed)) {
    throw new Error("Invalid secret — expected an otpauth:// URI or a base32 secret");
  }
  return { params: { secret: trimmed.toUpperCase().replace(/[=\s]/g, "") } };
}

async function saveItem(ev: SubmitEvent): Promise<void> {
  ev.preventDefault();
  const errEl = $("#item-error");
  errEl.classList.add("hidden");
  try {
    const secretInput = ($("#item-secret") as HTMLInputElement).value;
    const { params, issuer, account } = secretToParams(secretInput);
    const name = ($("#item-name") as HTMLInputElement).value.trim();
    if (!name) throw new Error("Name is required");

    const now = Date.now();
    const existing = state.editingId ? state.items.get(state.editingId) : undefined;
    const issuerVal = ($("#item-issuer") as HTMLInputElement).value.trim() || undefined;
    const accountVal = ($("#item-account") as HTMLInputElement).value.trim() || undefined;
    const item: VaultItem = {
      id: existing?.id ?? crypto.randomUUID(),
      type: "totp",
      name,
      issuer: issuer ?? issuerVal,
      account: account ?? accountVal,
      params,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      lastModifiedBy: state.settings.username ?? undefined,
    };
    state.items.set(item.id, item);
    state.dirty.add(item.id);
    persistLocal();
    closeItemModal();
    render();
    await syncNow(false);
  } catch (e) {
    errEl.textContent = e instanceof Error ? e.message : String(e);
    errEl.classList.remove("hidden");
  }
}

/* ------------------------------------------------------------- boot */

function wireEvents(): void {
  $("#login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const server = ($("#input-server") as HTMLInputElement).value.trim();
    const username = ($("#input-username") as HTMLInputElement).value.trim();
    const password = ($("#input-password") as HTMLInputElement).value;
    const register = ($("#input-register") as HTMLInputElement).checked;
    await connectAndShow(server, username, password, register);
  });

  $("#btn-sync").addEventListener("click", () => void syncNow());
  $("#btn-settings").addEventListener("click", () => {
    ($("#set-server") as HTMLInputElement).value = state.settings.serverUrl;
    $("#set-username").textContent = state.settings.username ?? "—";
    $("#settings-error").classList.add("hidden");
    showView("settings");
  });
  $("#btn-save-server").addEventListener("click", async () => {
    try {
      const url = ($("#set-server") as HTMLInputElement).value.trim();
      new URL(url);
      state.settings = await window.desktop.setSettings({ serverUrl: url });
      state.client = makeClient();
      $("#settings-error").classList.add("hidden");
      showView("vault");
      await syncNow();
    } catch {
      const el = $("#settings-error");
      el.textContent = "Enter a valid URL (e.g. https://auth.example.com)";
      el.classList.remove("hidden");
    }
  });
  $("#btn-signout").addEventListener("click", () => void signOut());

  $("#btn-add").addEventListener("click", () => openItemModal());
  $("#btn-item-cancel").addEventListener("click", closeItemModal);
  $("#item-form").addEventListener("submit", (ev) => void saveItem(ev));
  $("#modal").addEventListener("click", (ev) => {
    if (ev.target === $("#modal")) closeItemModal();
  });

  $("#input-search").addEventListener("input", (ev) => {
    state.filter = (ev.target as HTMLInputElement).value;
    render();
  });

  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") closeItemModal();
    if (ev.key === "s" && (ev.metaKey || ev.ctrlKey)) {
      ev.preventDefault();
      void syncNow();
    }
  });
}

function boot(): void {
  loadLocal();
  wireEvents();

  if (state.settings.token && state.settings.serverUrl) {
    state.client = makeClient();
    showView("vault");
    void syncNow();
    tickTimer();
  } else {
    ($("#input-server") as HTMLInputElement).value = state.settings.serverUrl;
    showView("login");
  }
}

void boot();
void tickTimer();