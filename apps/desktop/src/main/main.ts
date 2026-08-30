import { app, BrowserWindow, ipcMain } from "electron";
import { join } from "node:path";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

interface Settings {
  serverUrl: string;
  token: string | null;
  username: string | null;
  lastSyncAt: number | null;
  lastRevision: number;
}

const DEFAULT_SETTINGS: Settings = {
  serverUrl: "http://127.0.0.1:8787",
  token: null,
  username: null,
  lastSyncAt: null,
  lastRevision: 0,
};

/* ------------------------------------------------- tiny JSON settings store */

function settingsPath(): string {
  return join(app.getPath("userData"), "settings.json");
}

function loadSettings(): Settings {
  try {
    const raw = readFileSync(settingsPath(), "utf8");
    return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

function saveSettings(s: Settings): void {
  const file = settingsPath();
  mkdirSync(join(file, ".."), { recursive: true });
  writeFileSync(file, JSON.stringify(s, null, 2), { mode: 0o600 });
}

/* ------------------------------------------------------------- window */

const __dirname = fileURLToPath(new URL(".", import.meta.url));

function createWindow(): void {
  const win = new BrowserWindow({
    width: 420,
    height: 720,
    minWidth: 360,
    minHeight: 560,
    title: "selfhostauth",
    backgroundColor: "#0f1117",
    webPreferences: {
      preload: join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  const devUrl = process.env.VITE_DEV_SERVER_URL;
  if (devUrl) {
    void win.loadURL(devUrl);
  } else {
    void win.loadFile(join(__dirname, "..", "renderer", "index.html"));
  }
}

app.whenReady().then(() => {
  ipcMain.handle("settings:get", () => loadSettings());
  ipcMain.handle("settings:set", (_e, patch: Partial<Settings>) => {
    const next = { ...loadSettings(), ...patch };
    saveSettings(next);
    return next;
  });
  ipcMain.handle("settings:clear", () => {
    saveSettings({ ...DEFAULT_SETTINGS });
    return loadSettings();
  });

  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});