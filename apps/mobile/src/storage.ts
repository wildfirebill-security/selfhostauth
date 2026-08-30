import AsyncStorage from "@react-native-async-storage/async-storage";
import { SelfhostAuthClient } from "@selfhostauth/client";
import { VaultItem } from "@selfhostauth/core";

export interface MobileSettings {
  serverUrl: string;
  token: string | null;
  username: string | null;
  lastRevision: number;
}

const SETTINGS_KEY = "sha.settings";
const ITEMS_KEY = "sha.items";
const DIRTY_KEY = "sha.dirty";

export async function loadSettings(): Promise<MobileSettings> {
  const raw = await AsyncStorage.getItem(SETTINGS_KEY);
  if (!raw) return { serverUrl: "", token: null, username: null, lastRevision: 0 };
  return JSON.parse(raw) as MobileSettings;
}

export async function saveSettings(s: MobileSettings): Promise<void> {
  await AsyncStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
}

export async function clearSettings(): Promise<void> {
  await AsyncStorage.multiRemove([SETTINGS_KEY, ITEMS_KEY, DIRTY_KEY]);
}

export async function loadItems(): Promise<{ items: VaultItem[]; dirty: string[] }> {
  const [itemsRaw, dirtyRaw] = await AsyncStorage.multiGet([ITEMS_KEY, DIRTY_KEY]);
  let items: VaultItem[] = [];
  let dirty: string[] = [];
  try {
    if (itemsRaw?.[1]) items = JSON.parse(itemsRaw[1]);
    if (dirtyRaw?.[1]) dirty = JSON.parse(dirtyRaw[1]);
  } catch {
    /* ignore */
  }
  return { items, dirty };
}

export async function saveItems(items: VaultItem[], dirty: string[]): Promise<void> {
  await AsyncStorage.multiSet([
    [ITEMS_KEY, JSON.stringify(items)],
    [DIRTY_KEY, JSON.stringify(dirty)],
  ]);
}

export function makeClient(s: MobileSettings): SelfhostAuthClient {
  return new SelfhostAuthClient({ baseUrl: s.serverUrl, token: s.token ?? undefined });
}

/** RFC 4122 v4 UUID (falls back to Math.random where getRandomValues is absent). */
export function uuid(): string {
  const bytes = new Uint8Array(16);
  const g = globalThis as unknown as { crypto?: { getRandomValues?: (b: Uint8Array) => void } };
  if (g.crypto?.getRandomValues) {
    g.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10, 16).join("")}`;
}