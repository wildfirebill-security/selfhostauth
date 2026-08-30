import { contextBridge, ipcRenderer } from "electron";

export interface DesktopSettings {
  serverUrl: string;
  token: string | null;
  username: string | null;
  lastSyncAt: number | null;
  lastRevision: number;
}

const api = {
  getSettings: (): Promise<DesktopSettings> => ipcRenderer.invoke("settings:get"),
  setSettings: (patch: Partial<DesktopSettings>): Promise<DesktopSettings> =>
    ipcRenderer.invoke("settings:set", patch),
  clearSettings: (): Promise<DesktopSettings> => ipcRenderer.invoke("settings:clear"),
};

contextBridge.exposeInMainWorld("desktop", api);

export type DesktopApi = typeof api;