import { StatusBar } from "expo-status-bar";
import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  KeyboardAvoidingView,
  Modal,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import * as Clipboard from "expo-clipboard";
import {
  VaultItem,
  totp,
  parseOtpauthUri,
  isValidSecret,
  TOTPResult,
} from "@selfhostauth/core";
import {
  loadSettings,
  saveSettings,
  clearSettings,
  loadItems,
  saveItems,
  makeClient,
  uuid,
  MobileSettings,
} from "./src/storage";
import { colors, mono } from "./src/theme";

type Screen = "login" | "vault";

interface CachedCode extends TOTPResult {
  id: string;
  name: string;
  subtitle: string;
  expiresAt: number;
}

export default function App() {
  const [settings, setSettings] = useState<MobileSettings | null>(null);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [dirty, setDirty] = useState<string[]>([]);
  const [screen, setScreen] = useState<Screen>("login");
  const [syncMsg, setSyncMsg] = useState("");
  const [, forceTick] = useState(0);

  // login form
  const [serverUrl, setServerUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [register, setRegister] = useState(false);
  const [loginError, setLoginError] = useState("");

  // add form
  const [modalOpen, setModalOpen] = useState(false);
  const [secretInput, setSecretInput] = useState("");
  const [nameInput, setNameInput] = useState("");
  const [addError, setAddError] = useState("");

  const cached = useRef<CachedCode[]>([]);

  const persist = useCallback((next: VaultItem[], nextDirty: string[]) => {
    setItems(next);
    setDirty(nextDirty);
    void saveItems(next, nextDirty);
  }, []);

  const computeCodes = useCallback((list: VaultItem[]) => {
    const out: CachedCode[] = [];
    for (const item of list) {
      if (item.deletedAt) continue;
      void totp(item.params)
        .then((r) => {
          out.push({
            ...r,
            id: item.id,
            name: item.name,
            subtitle: [item.issuer, item.account].filter(Boolean).join(" · "),
            expiresAt: r.periodStart + r.period,
          });
          cached.current = [...out];
          forceTick((t) => t + 1);
        })
        .catch(() => {});
    }
  }, []);

  const syncNow = useCallback(
    async (showMsg = true) => {
      if (!settings?.token || !settings.serverUrl) return;
      const client = makeClient(settings);
      if (showMsg) setSyncMsg("Syncing…");
      try {
        const pull = await client.pull(settings.lastRevision);
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
        const merged = [...map.values()];

        const dirtyIds = new Set(dirty);
        const toPush = merged.filter((i) => dirtyIds.has(i.id));
        if (toPush.length > 0) {
          const push = await client.push({ items: toPush, baseRevision: settings.lastRevision });
          for (const c of push.conflicts) {
            const idx = merged.findIndex((i) => i.id === c.id);
            if (idx >= 0) merged[idx] = c;
          }
          const nextDirty = dirty.filter((id) => !push.conflicts.some((c) => c.id === id));
          setDirty(nextDirty);
          await saveItems(merged, nextDirty);
        }

        const nextSettings = {
          ...settings,
          lastRevision: Math.max(pull.revision, settings.lastRevision),
        };
        setSettings(nextSettings);
        await saveSettings(nextSettings);
        setItems(merged);
        computeCodes(merged);
        if (showMsg) setSyncMsg(`Synced ${merged.length} codes.`);
      } catch (e) {
        setSyncMsg(`Sync failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    },
    [settings, items, dirty, computeCodes],
  );

  const connect = useCallback(async () => {
    setLoginError("");
    const client = new (await import("@selfhostauth/client")).SelfhostAuthClient({
      baseUrl: serverUrl.trim(),
    });
    try {
      const auth = register
        ? await client.register(username.trim(), password)
        : await client.login(username.trim(), password);
      const next: MobileSettings = {
        serverUrl: serverUrl.trim(),
        token: auth.token,
        username: auth.user.username,
        lastRevision: 0,
      };
      setSettings(next);
      await saveSettings(next);
      setScreen("vault");
      await syncNow();
    } catch (e) {
      setLoginError(e instanceof Error ? e.message : String(e));
    }
  }, [serverUrl, username, password, register, syncNow]);

  const addItem = useCallback(async () => {
    setAddError("");
    if (!nameInput.trim()) return setAddError("Name is required.");
    let params: VaultItem["params"];
    let issuer: string | undefined;
    let account: string | undefined;
    try {
      if (secretInput.trim().startsWith("otpauth://")) {
        const p = parseOtpauthUri(secretInput.trim());
        params = { secret: p.secret, algorithm: p.algorithm, digits: p.digits, period: p.period };
        issuer = p.issuer || undefined;
        account = p.account || undefined;
      } else {
        if (!isValidSecret(secretInput.trim())) {
          return setAddError("Enter an otpauth:// URI or a valid base32 secret.");
        }
        params = { secret: secretInput.trim().toUpperCase().replace(/[=\s]/g, "") };
      }
    } catch (e) {
      return setAddError(e instanceof Error ? e.message : String(e));
    }

    const now = Date.now();
    const item: VaultItem = {
      id: uuid(),
      type: "totp",
      name: nameInput.trim(),
      issuer,
      account,
      params,
      createdAt: now,
      updatedAt: now,
      lastModifiedBy: settings?.username ?? undefined,
    };
    const next = [...items, item];
    const nextDirty = [...dirty, item.id];
    persist(next, nextDirty);
    setModalOpen(false);
    setSecretInput("");
    setNameInput("");
    void syncNow(false);
  }, [nameInput, secretInput, items, dirty, settings, persist, syncNow]);

  const removeItem = useCallback(
    async (id: string) => {
      const now = Date.now();
      const next = items.map((i) =>
        i.id === id ? { ...i, deletedAt: now, updatedAt: now } : i,
      );
      persist(next, [...dirty, id]);
      void syncNow(false);
    },
    [items, dirty, persist, syncNow],
  );

  const signOut = useCallback(async () => {
    await clearSettings();
    setSettings(null);
    setItems([]);
    setDirty([]);
    cached.current = [];
    setScreen("login");
  }, []);

  // tick every second to refresh countdowns + copy codes
  useEffect(() => {
    const t = setInterval(() => forceTick((x) => x + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const boot = useCallback(async () => {
    const s = await loadSettings();
    const { items: loaded, dirty: loadedDirty } = await loadItems();
    setSettings(s);
    setItems(loaded);
    setDirty(loadedDirty);
    setServerUrl(s.serverUrl);
    if (s.token && s.serverUrl) {
      setScreen("vault");
      computeCodes(loaded);
      void syncNow();
    }
  }, [computeCodes, syncNow]);

  useEffect(() => {
    void boot();
  }, [boot]);

  const now = Date.now();

  return (
    <View style={styles.container}>
      <StatusBar style="light" />
      <View style={styles.header}>
        <Text style={styles.brand}>◈ selfhostauth</Text>
        {screen === "vault" && (
          <View style={styles.headerActions}>
            <Pressable style={styles.ghostBtn} onPress={() => syncNow()}>
              <Text style={styles.ghostBtnText}>⟳ Sync</Text>
            </Pressable>
            <Pressable style={styles.ghostBtn} onPress={signOut}>
              <Text style={[styles.ghostBtnText, { color: colors.danger }]}>Sign out</Text>
            </Pressable>
          </View>
        )}
      </View>

      {screen === "login" ? (
        <KeyboardAvoidingView
          style={styles.flex}
          behavior={Platform.OS === "ios" ? "padding" : undefined}
        >
          <ScrollView contentContainerStyle={styles.formWrap} keyboardShouldPersistTaps="handled">
            <Text style={styles.title}>Connect to your server</Text>
            <Text style={styles.label}>Server URL</Text>
            <TextInput
              style={styles.input}
              value={serverUrl}
              onChangeText={setServerUrl}
              placeholder="https://auth.example.com"
              placeholderTextColor={colors.muted}
              autoCapitalize="none"
              keyboardType="url"
            />
            <Text style={styles.label}>Username</Text>
            <TextInput
              style={styles.input}
              value={username}
              onChangeText={setUsername}
              placeholder="you"
              placeholderTextColor={colors.muted}
              autoCapitalize="none"
              autoCorrect={false}
            />
            <Text style={styles.label}>Password</Text>
            <TextInput
              style={styles.input}
              value={password}
              onChangeText={setPassword}
              placeholder="••••••••"
              placeholderTextColor={colors.muted}
              secureTextEntry
            />
            <Pressable style={styles.checkRow} onPress={() => setRegister((r) => !r)}>
              <Text style={styles.checkBox}>{register ? "☑" : "☐"}</Text>
              <Text style={styles.checkLabel}>Create a new account</Text>
            </Pressable>
            {!!loginError && <Text style={styles.error}>{loginError}</Text>}
            <Pressable style={styles.primaryBtn} onPress={connect}>
              <Text style={styles.primaryBtnText}>Connect</Text>
            </Pressable>
          </ScrollView>
        </KeyboardAvoidingView>
      ) : (
        <View style={styles.flex}>
          <ScrollView contentContainerStyle={styles.listWrap}>
            {cached.current.length === 0 && (
              <Text style={styles.empty}>
                No codes yet.{'\n'}Tap "＋ Add" to import an authenticator.
              </Text>
            )}
            {cached.current.map((c) => {
              const remaining = c.expiresAt - now;
              const expiring = remaining <= 5000;
              return (
                <Pressable
                  key={c.id}
                  style={styles.item}
                  onPress={() => {
                    void Clipboard.setStringAsync(c.code);
                    setSyncMsg(`Copied ${c.name}`);
                  }}
                >
                  <View style={styles.itemMeta}>
                    <Text style={styles.itemName}>{c.name}</Text>
                    <Text style={styles.itemAccount}>{c.subtitle}</Text>
                  </View>
                  <Text style={[styles.itemCode, expiring && { color: colors.danger }]}>
                    {c.code.slice(0, Math.ceil(c.code.length / 2))} {c.code.slice(Math.ceil(c.code.length / 2))}
                  </Text>
                  <Pressable onPress={() => removeItem(c.id)} hitSlop={8}>
                    <Text style={styles.remove}>✕</Text>
                  </Pressable>
                </Pressable>
              );
            })}
            {!!syncMsg && <Text style={styles.syncMsg}>{syncMsg}</Text>}
          </ScrollView>
          <Pressable style={styles.fab} onPress={() => setModalOpen(true)}>
            <Text style={styles.fabText}>＋ Add</Text>
          </Pressable>
        </View>
      )}

      <Modal visible={modalOpen} transparent animationType="fade" onRequestClose={() => setModalOpen(false)}>
        <KeyboardAvoidingView
          style={styles.modalBackdrop}
          behavior={Platform.OS === "ios" ? "padding" : undefined}
        >
          <View style={styles.modalCard}>
            <Text style={styles.title}>Add authenticator</Text>
            <Text style={styles.label}>otpauth:// URI or base32 secret</Text>
            <TextInput
              style={styles.input}
              value={secretInput}
              onChangeText={setSecretInput}
              placeholder="otpauth://totp/GitHub:you?secret=…"
              placeholderTextColor={colors.muted}
              autoCapitalize="none"
              autoCorrect={false}
            />
            <Text style={styles.label}>Name</Text>
            <TextInput
              style={styles.input}
              value={nameInput}
              onChangeText={setNameInput}
              placeholder="GitHub"
              placeholderTextColor={colors.muted}
            />
            {!!addError && <Text style={styles.error}>{addError}</Text>}
            <View style={styles.modalActions}>
              <Pressable style={styles.ghostBtn} onPress={() => setModalOpen(false)}>
                <Text style={styles.ghostBtnText}>Cancel</Text>
              </Pressable>
              <Pressable style={styles.primaryBtn} onPress={addItem}>
                <Text style={styles.primaryBtnText}>Save</Text>
              </Pressable>
            </View>
          </View>
        </KeyboardAvoidingView>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  flex: { flex: 1 },
  header: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingHorizontal: 16,
    paddingVertical: 14,
    backgroundColor: colors.panel,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  brand: { color: colors.text, fontWeight: "600", fontSize: 16 },
  headerActions: { flexDirection: "row", gap: 8 },
  ghostBtn: {
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 7,
  },
  ghostBtnText: { color: colors.text, fontSize: 13 },
  formWrap: { padding: 20, gap: 8 },
  listWrap: { padding: 14, gap: 10, paddingBottom: 90 },
  title: { color: colors.text, fontSize: 18, fontWeight: "600", marginBottom: 8 },
  label: { color: colors.muted, fontSize: 13, marginTop: 6 },
  input: {
    backgroundColor: colors.panel2,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: colors.text,
    fontSize: 14,
  },
  checkRow: { flexDirection: "row", alignItems: "center", gap: 8, marginVertical: 6 },
  checkBox: { color: colors.accent, fontSize: 16 },
  checkLabel: { color: colors.text, fontSize: 13 },
  error: { color: colors.danger, fontSize: 13 },
  primaryBtn: {
    backgroundColor: colors.accent2,
    borderRadius: 8,
    paddingVertical: 12,
    alignItems: "center",
    marginTop: 8,
  },
  primaryBtnText: { color: "#fff", fontSize: 15, fontWeight: "600" },
  item: {
    backgroundColor: colors.panel,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 10,
    paddingHorizontal: 14,
    paddingVertical: 12,
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 10,
  },
  itemMeta: { flex: 1 },
  itemName: { color: colors.text, fontWeight: "600" },
  itemAccount: { color: colors.muted, fontSize: 12, marginTop: 1 },
  itemCode: { color: colors.text, fontFamily: mono.fontFamily, fontSize: 18, letterSpacing: 1.5 },
  remove: { color: colors.muted, fontSize: 14 },
  empty: { color: colors.muted, textAlign: "center", marginTop: 60, lineHeight: 22 },
  syncMsg: { color: colors.muted, textAlign: "center", fontSize: 12, marginTop: 10 },
  fab: {
    position: "absolute",
    right: 18,
    bottom: 24,
    backgroundColor: colors.accent2,
    borderRadius: 24,
    paddingHorizontal: 18,
    paddingVertical: 13,
  },
  fabText: { color: "#fff", fontWeight: "600" },
  modalBackdrop: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.6)",
    justifyContent: "center",
    padding: 20,
  },
  modalCard: {
    backgroundColor: colors.panel,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 14,
    padding: 20,
    gap: 6,
  },
  modalActions: { flexDirection: "row", justifyContent: "flex-end", gap: 10, marginTop: 10 },
});