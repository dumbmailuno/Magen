import type { ApiErrorBody, Health, NginxResult, OpenApiResult, RuleInfo } from "./types";

/** Error raised for any non-2xx response, carrying the backend's `{code, message}`. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly detail: unknown = null,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

interface Connection {
  baseUrl: string;
  token: string;
}

/** Electron's preload provides the connection; browser-only dev falls back to Vite env. */
export function resolveConnection(): Connection | null {
  if (window.magen) {
    return { baseUrl: window.magen.apiBaseUrl, token: window.magen.sessionToken };
  }
  const baseUrl = import.meta.env.VITE_MAGEN_API_URL;
  const token = import.meta.env.VITE_MAGEN_TOKEN;
  if (baseUrl && token) return { baseUrl, token };
  return null;
}

function isApiErrorBody(value: unknown): value is ApiErrorBody {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as Record<string, unknown>).code === "string" &&
    typeof (value as Record<string, unknown>).message === "string"
  );
}

export async function request<T>(
  path: string,
  init: RequestInit = {},
  connection: Connection | null = resolveConnection(),
): Promise<T> {
  if (!connection) {
    throw new ApiError(0, "not_configured", "Backend connection is not configured");
  }
  const headers = new Headers(init.headers);
  headers.set("X-Magen-Token", connection.token);
  if (init.body !== undefined) headers.set("Content-Type", "application/json");

  let res: Response;
  try {
    res = await fetch(`${connection.baseUrl}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "unreachable", "Backend is not reachable");
  }
  const body: unknown = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    if (isApiErrorBody(body)) throw new ApiError(res.status, body.code, body.message, body.detail);
    throw new ApiError(res.status, "http_error", `Request failed (${res.status})`);
  }
  return body as T;
}

const post = (body: unknown): RequestInit => ({ method: "POST", body: JSON.stringify(body) });

export const api = {
  health: () => request<Health>("/api/health"),
  rules: () => request<RuleInfo[]>("/api/rules"),
  analyzeOpenapi: (filename: string, content: string) =>
    request<OpenApiResult>("/api/analyze/openapi", post({ filename, content })),
  analyzeNginx: (filename: string, content: string) =>
    request<NginxResult>("/api/analyze/nginx", post({ filename, content })),
};
