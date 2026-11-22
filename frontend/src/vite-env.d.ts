/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Browser-only dev: backend URL (Electron provides it via preload instead). */
  readonly VITE_MAGEN_API_URL?: string;
  /** Browser-only dev: must equal the backend's MAGEN_SESSION_TOKEN. */
  readonly VITE_MAGEN_TOKEN?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

/** Minimal API exposed by electron/preload.ts via contextBridge. */
interface MagenBridge {
  readonly apiBaseUrl: string;
  readonly sessionToken: string;
  readonly platform: string;
}

interface Window {
  readonly magen?: MagenBridge;
}
