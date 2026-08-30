import { getCachedCodes, syncVault, getSettings, CachedCode } from "./shared.js";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

let codes: CachedCode[] = [];

function formatCode(code: string): string {
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

function render(): void {
  const list = $("#list");
  list.innerHTML = "";

  if (codes.length === 0) {
    list.innerHTML = `<p class="empty">No codes yet.<br/>Open options to add one.</p>`;
    return;
  }

  const now = Date.now();
  for (const c of codes) {
    const row = document.createElement("div");
    row.className = "item";
    row.title = "Click to copy";

    const meta = document.createElement("div");
    meta.className = "item-meta";
    const name = document.createElement("div");
    name.className = "item-name";
    name.textContent = c.name;
    const account = document.createElement("div");
    account.className = "item-account";
    account.textContent = [c.issuer, c.account].filter(Boolean).join(" · ");
    meta.append(name, account);

    const code = document.createElement("div");
    code.className = "item-code";
    const expired = c.expiresAt - now <= 5000;
    if (expired) code.classList.add("expiring");
    code.textContent = formatCode(c.code);

    row.append(meta, code);
    row.addEventListener("click", () => {
      void navigator.clipboard.writeText(c.code).then(() => {
        const s = $("#status");
        s.textContent = `Copied ${c.name}`;
        s.className = "status";
      });
    });
    list.append(row);
  }
}

$("#sync").addEventListener("click", async () => {
  const res = await syncVault();
  const s = $("#status");
  if (res.ok) {
    codes = await getCachedCodes();
    render();
    s.textContent = `Synced ${res.count} codes.`;
  } else {
    s.textContent = res.error ?? "Sync failed.";
    s.className = "status error";
  }
});

$("#options").addEventListener("click", () => {
  void chrome.runtime.openOptionsPage();
});

async function boot(): Promise<void> {
  const settings = await getSettings();
  if (!settings.token) {
    $("#status").textContent = "Not configured — open options.";
    $("#status").classList.add("error");
    return;
  }
  codes = await getCachedCodes();
  if (codes.length === 0) {
    const res = await syncVault();
    if (res.ok) {
      codes = await getCachedCodes();
      render();
    } else {
      $("#status").textContent = res.error ?? "Sync failed.";
      $("#status").classList.add("error");
    }
  } else {
    render();
    // refresh in the background; UI stays instant
    void syncVault().then((res) => {
      if (res.ok) {
        void getCachedCodes().then((c) => {
          codes = c;
          render();
        });
      }
    });
  }
}

// Live countdown redraw
setInterval(() => render(), 1000);

void boot();