/**
 * Shared storage helpers + sync logic for the extension.
 * Runs in popup, options, and background contexts.
 */
import { SelfhostAuthClient } from "@selfhostauth/client";
import { VaultItem, totp, parseOtpauthUri, isValidSecret } from "@selfhostauth/core";

export interface ExtSettings {
  serverUrl: string;
  token: string | null;
  username: string | null;
  lastRevision: number;
  lastSyncAt: number | null;
}

export interface CachedCode {
  id: string;
  name: string;
  issuer?: string;
  account?: string;
  code: string;
  expiresAt: number;
  period: number;
  remaining: number;
}

const SETTINGS_KEY = "settings";
const CACHE_KEY = "codes";

export async function getSettings(): Promise<ExtSettings> {
  const raw = await chrome.storage.local.get(SETTINGS_KEY);
  return (
    raw[SETTINGS_KEY] ?? {
      serverUrl: "",
      token: null,
      username: null,
      lastRevision: 0,
      lastSyncAt: null,
    }
  );
}

export async function setSettings(patch: Partial<ExtSettings>): Promise<ExtSettings> {
  const next = { ...(await getSettings()), ...patch };
  await chrome.storage.local.set({ [SETTINGS_KEY]: next });
  return next;
}

export async function clearSettings(): Promise<void> {
  await chrome.storage.local.remove(SETTINGS_KEY);
  await chrome.storage.session.remove(CACHE_KEY);
}

export function makeClient(settings: ExtSettings): SelfhostAuthClient {
  return new SelfhostAuthClient({
    baseUrl: settings.serverUrl,
    token: settings.token ?? undefined,
  });
}

/**
 * Request host permission for the configured server origin (MV3 requires
 * this for cross-origin fetches from extension pages).
 */
export async function ensureHostAccess(serverUrl: string): Promise<boolean> {
  try {
    const u = new URL(serverUrl);
    const origin = `${u.protocol}//${u.host}/*`;
    let granted = await chrome.permissions.contains({ origins: [origin] });
    if (!granted) {
      granted = await chrome.permissions.request({ origins: [origin] });
    }
    return granted;
  } catch {
    return false;
  }
}

/** Pull + push changes against the server, refresh the code cache. */
export async function syncVault(): Promise<{ ok: boolean; error?: string; count: number }> {
  const settings = await getSettings();
  if (!settings.serverUrl || !settings.token) {
    return { ok: false, error: "Not configured — open extension options to connect.", count: 0 };
  }
  if (!(await ensureHostAccess(settings.serverUrl))) {
    return { ok: false, error: "Permission denied for server host.", count: 0 };
  }
  const client = makeClient(settings);
  try {
    const pull = await client.pull(settings.lastRevision);
    const items = new Map<string, VaultItem>();
    const cached = await chrome.storage.local.get("vaultItems");
    if (cached.vaultItems) {
      for (const i of cached.vaultItems as VaultItem[]) items.set(i.id, i);
    }
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
      items.set(item.id, item);
    }
    for (const d of pull.deleted) items.delete(d.id);

    const arr = [...items.values()].filter((i) => !i.deletedAt);
    await chrome.storage.local.set({ vaultItems: arr });
    await setSettings({ lastRevision: Math.max(pull.revision, settings.lastRevision), lastSyncAt: Date.now() });
    await refreshCodes(arr);
    return { ok: true, count: arr.length };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e), count: 0 };
  }
}

/** Precompute codes for cached items and stash them for instant popup. */
export async function refreshCodes(items: VaultItem[]): Promise<void> {
  const codes: CachedCode[] = [];
  for (const item of items) {
    try {
      const result = await totp(item.params);
      codes.push({
        id: item.id,
        name: item.name,
        issuer: item.issuer,
        account: item.account,
        code: result.code,
        expiresAt: result.periodStart + result.period,
        period: result.period,
        remaining: result.remaining,
      });
    } catch {
      /* skip invalid item */
    }
  }
  await chrome.storage.session.set({ [CACHE_KEY]: codes });
}

export async function getCachedCodes(): Promise<CachedCode[]> {
  const raw = await chrome.storage.session.get(CACHE_KEY);
  return raw[CACHE_KEY] ?? [];
}

/** Parse user input (otpauth URI or raw base32 secret) into item params. */
export function parseSecretInput(input: string): {
  params: VaultItem["params"];
  issuer?: string;
  account?: string;
} {
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
    throw new Error("Enter an otpauth:// URI or a valid base32 secret.");
  }
  return { params: { secret: trimmed.toUpperCase().replace(/[=\s]/g, "") } };
}