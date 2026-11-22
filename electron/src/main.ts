import { app, BrowserWindow, dialog, ipcMain, net, protocol, session } from "electron";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { startBackend, type BackendHandle } from "./backend";
import { resolveAppPath } from "./paths";

const APP_SCHEME = "app";
const APP_ORIGIN = `${APP_SCHEME}://magen`;
const isDev = process.argv.includes("--dev");
const DEV_URL = "http://127.0.0.1:5173";

// Must match frontend/vite.config.ts PRODUCTION_CSP.
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src http://127.0.0.1:*",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

protocol.registerSchemesAsPrivileged([
  { scheme: APP_SCHEME, privileges: { standard: true, secure: true, supportFetchAPI: true } },
]);

let backend: BackendHandle | null = null;
const repoRoot = join(__dirname, "..", "..");
const frontendDist = app.isPackaged
  ? join(process.resourcesPath, "frontend")
  : join(repoRoot, "frontend", "dist");

/** Serve the built frontend from app://magen/ with a strict CSP; refuse path traversal. */
function registerAppProtocol(): void {
  protocol.handle(APP_SCHEME, async (request) => {
    const { pathname } = new URL(request.url);
    const target = resolveAppPath(frontendDist, pathname);
    if (target === null) return new Response("Forbidden", { status: 403 });
    let res: Response;
    try {
      res = await net.fetch(pathToFileURL(target).toString());
    } catch {
      return new Response("Not found", { status: 404 });
    }
    const headers = new Headers(res.headers);
    headers.set("Content-Security-Policy", CSP);
    return new Response(res.body, { status: res.status, headers });
  });
}

function hardenSession(): void {
  // Deny every permission request (camera, notifications, geolocation, ...).
  session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => { cb(false); });
  session.defaultSession.setPermissionCheckHandler(() => false);
}

function createWindow(): void {
  const win = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 1024,
    minHeight: 680,
    title: "Magen",
    backgroundColor: "#0f1219", // neutral-950: avoids a white flash before CSS loads
    show: false,
    webPreferences: {
      preload: join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      spellcheck: false,
    },
  });
  win.once("ready-to-show", () => { win.show(); });

  // No remote content and no new windows (CLAUDE.md §11).
  const allowedPrefix = isDev ? DEV_URL : APP_ORIGIN;
  win.webContents.on("will-navigate", (event, url) => {
    if (!url.startsWith(allowedPrefix)) event.preventDefault();
  });
  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));

  void win.loadURL(isDev ? DEV_URL : `${APP_ORIGIN}/index.html`);
}

ipcMain.on("magen:get-config", (event) => {
  // Only hand the token to our own top-level frame (never to an unexpected origin).
  const senderUrl = event.senderFrame?.url ?? "";
  const trusted = senderUrl.startsWith(isDev ? DEV_URL : APP_ORIGIN);
  event.returnValue = backend && trusted
    ? { apiBaseUrl: backend.baseUrl, sessionToken: backend.token, platform: process.platform }
    : null;
});

void app.whenReady().then(async () => {
  hardenSession();
  registerAppProtocol();
  try {
    backend = await startBackend({
      repoRoot,
      resourcesPath: process.resourcesPath,
      isPackaged: app.isPackaged,
      dataDir: app.getPath("userData"),
      allowedOrigins: isDev ? [DEV_URL] : [APP_ORIGIN],
      log: (line) => { console.log(`[backend] ${line}`); },
    });
  } catch (err) {
    dialog.showErrorBox("Magen backend failed to start", err instanceof Error ? err.message : String(err));
    app.quit();
    return;
  }
  createWindow();
});

app.on("window-all-closed", () => { app.quit(); });
app.on("will-quit", () => { backend?.stop(); });
process.on("exit", () => { backend?.stop(); });
