/**
 * Backend process manager (CLAUDE.md §11): spawns the FastAPI process on a random free
 * loopback port with a per-session token, waits for it to be healthy, kills it on quit.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";

export interface BackendHandle {
  readonly baseUrl: string;
  readonly token: string;
  stop(): void;
}

export interface BackendOptions {
  /** Repo root (dev) — used to find backend/.venv. */
  repoRoot: string;
  /** Packaged resources directory (prod). */
  resourcesPath: string;
  isPackaged: boolean;
  dataDir: string;
  allowedOrigins: string[];
  log: (line: string) => void;
}

const HOST = "127.0.0.1";

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, HOST, () => {
      const addr = srv.address();
      srv.close(() => {
        if (addr && typeof addr === "object") resolve(addr.port);
        else reject(new Error("could not determine free port"));
      });
    });
  });
}

/** Command used to start the backend: the venv interpreter in dev, a bundled exe when packaged. */
export function backendCommand(opts: Pick<BackendOptions, "repoRoot" | "resourcesPath" | "isPackaged">): {
  command: string;
  args: string[];
  cwd: string;
} {
  const win = process.platform === "win32";
  if (opts.isPackaged) {
    // Bundled backend binary (built in roadmap wk 15-16 packaging step).
    const dir = join(opts.resourcesPath, "backend");
    return { command: join(dir, win ? "magen-backend.exe" : "magen-backend"), args: [], cwd: dir };
  }
  const backendDir = join(opts.repoRoot, "backend");
  const python = win
    ? join(backendDir, ".venv", "Scripts", "python.exe")
    : join(backendDir, ".venv", "bin", "python");
  // Spawn the interpreter directly (not `uv run`) so killing the child kills the server.
  return { command: python, args: ["-m", "app"], cwd: backendDir };
}

async function waitForHealth(baseUrl: string, token: string, child: ChildProcess, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`backend exited with code ${child.exitCode}`);
    try {
      const res = await fetch(`${baseUrl}/api/health`, { headers: { "X-Magen-Token": token } });
      if (res.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error("backend did not become healthy in time");
}

export async function startBackend(opts: BackendOptions): Promise<BackendHandle> {
  const { command, args, cwd } = backendCommand(opts);
  if (!existsSync(command)) {
    throw new Error(`backend executable not found: ${command} (run \`uv sync\` in backend/)`);
  }
  const port = await freePort();
  const token = randomBytes(32).toString("base64url");
  const baseUrl = `http://${HOST}:${port}`;

  const child = spawn(command, args, {
    cwd,
    env: {
      ...process.env,
      MAGEN_PORT: String(port),
      MAGEN_SESSION_TOKEN: token,
      MAGEN_DATA_DIR: opts.dataDir,
      MAGEN_ALLOWED_ORIGINS: JSON.stringify(opts.allowedOrigins),
      PYTHONUNBUFFERED: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  // Backend logs are JSON and already redacted; never log the token here.
  child.stdout.on("data", (b: Buffer) => { opts.log(b.toString().trimEnd()); });
  child.stderr.on("data", (b: Buffer) => { opts.log(b.toString().trimEnd()); });

  const stop = () => {
    if (child.exitCode === null && !child.killed) child.kill();
  };
  try {
    await waitForHealth(baseUrl, token, child, 20_000);
  } catch (err) {
    stop();
    throw err;
  }
  return { baseUrl, token, stop };
}
