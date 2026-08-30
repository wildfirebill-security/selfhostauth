/**
 * Background service worker: refreshes the code cache on an alarm so the
 * popup opens instantly and codes are (briefly) available offline.
 */
import { syncVault, getSettings } from "./shared.js";

const ALARM_NAME = "selfhostauth-sync";

async function runSync(): Promise<void> {
  const settings = await getSettings();
  if (!settings.token || !settings.serverUrl) return;
  await syncVault();
}

chrome.runtime.onInstalled.addListener(() => {
  void chrome.alarms.create(ALARM_NAME, { periodInMinutes: 5 });
  void runSync();
});

chrome.runtime.onStartup.addListener(() => {
  void chrome.alarms.create(ALARM_NAME, { periodInMinutes: 5 });
  void runSync();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM_NAME) void runSync();
});