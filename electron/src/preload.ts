/**
 * Minimal preload API (CLAUDE.md §11). Exposes only the backend URL and session token —
 * no Node, no IPC passthrough.
 */
import { contextBridge, ipcRenderer } from "electron";

interface MagenConfig {
  apiBaseUrl: string;
  sessionToken: string;
  platform: string;
}

const config = ipcRenderer.sendSync("magen:get-config") as MagenConfig | null;
if (config) {
  contextBridge.exposeInMainWorld("magen", Object.freeze({ ...config }));
}
