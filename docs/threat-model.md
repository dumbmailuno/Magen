# Threat model

Scope: Magen v1 desktop app (Electron + local FastAPI + SQLite + optional local Ollama).
Method: assets → trust boundaries → STRIDE per boundary → mitigations → residual risk.
Status column: ✅ implemented · 🟡 planned (roadmap week).

## Assets

1. User-supplied auth header (Bearer / API key) for the scanned API.
2. Scanned specs/configs (may contain internal hostnames, secrets).
3. Findings, audit log, reports.
4. The user's reputation/legal position (scanner misuse against third parties).
5. The user's machine (the local API must not become a remote-control surface).

## Trust boundaries

| # | Boundary | Untrusted side |
|---|---|---|
| B1 | Renderer ↔ local backend (HTTP on loopback) | Other local processes, web pages in the user's browser |
| B2 | Backend ↔ scanned files | File contents (spec/config) |
| B3 | Backend ↔ target API (runtime probes) | The target and its redirects/DNS |
| B4 | Backend ↔ LLM | Model output; prompt content derived from B2/B3 |
| B5 | Electron main ↔ renderer | Renderer content |

## Threats & mitigations

| Threat (STRIDE) | Boundary | Mitigation | Status |
|---|---|---|---|
| Other local process / malicious website drives the scanner (S, E) | B1 | Backend binds 127.0.0.1 only (not configurable); per-session 256-bit token in `X-Magen-Token`, constant-time compare; CORS allowlist (`app://magen`, Vite dev origin); no docs/OpenAPI endpoints | ✅ |
| DNS rebinding to the loopback API (S) | B1 | `TrustedHostMiddleware` accepts only `127.0.0.1`/`localhost` Host headers; token still required | ✅ |
| Auth header leaks to DB/logs/exports (I) | all | Held in memory only; no DB column (test-enforced); JSON logger redacts every message/extra; `Evidence` and `Location.url` redact on construction; validation errors strip input values | ✅ |
| Scanning hosts the user isn't authorized for (misuse) (E) | B3 | Explicit allowlist with authorization checkbox + timestamp; reject non-allowlisted targets | 🟡 wk 7–8 |
| SSRF into internal network / cloud metadata (E, I) | B3 | Resolve DNS, block private/link-local/metadata ranges (169.254.169.254, etc.) unless target is explicitly local; re-check on every redirect; cap redirects | 🟡 wk 7–8 |
| Scanner causes harm/DoS to target (D) | B3 | GET/HEAD/OPTIONS only; global ≤5 req/s; per-scan cap; timeouts; Stop button cancels in-flight work; no fuzzing/brute force | 🟡 wk 7–8 |
| Repudiation of probes sent (R) | B3 | `probe_audit` table: method, redacted URL, status, timestamp per probe | ✅ schema / 🟡 writer |
| Prompt injection via spec/config content (T, E) | B4 | Content sent as delimited data block; system prompt declares it data; model output never triggers actions; Pydantic-validated JSON; fallback to template | 🟡 wk 11–12 |
| LLM "decides" a vulnerability (integrity of results) (T) | B4 | Architecture: findings only from pure rules; AI output stored only in `ai_explanation`/`ai_fix`, always labelled | ✅ by design |
| Malicious generated fix (T) | B4 | Fixes validated (re-parse / `nginx -t`), shown as diff, never written to user files (no "Apply" button) | 🟡 wk 9–10 |
| Data sent to cloud AI (I) | B4 | `ollama_url` must be loopback (settings validator); cloud off by default, requires explicit opt-in with preview | ✅ / 🟡 |
| Malicious spec/config exploits parser (T, D) | B2 | Safe YAML loading only; size limits; no `$ref` fetching over network | 🟡 wk 3–4 |
| Renderer compromise escalates to Node (E) | B5 | `contextIsolation`, `nodeIntegration: false`, `sandbox: true`; preload exposes only URL + token; navigation & `window.open` blocked; all permission requests denied; strict CSP (no remote content) | ✅ |
| Path traversal via `app://` protocol (I) | B5 | `resolveAppPath` (pure, unit-tested incl. encoded `..`, backslashes, NUL, malformed escapes): resolved path must stay inside `frontend/dist`, else 403 | ✅ |
| Token handed to an unexpected frame (I) | B5 | IPC handler returns config only if the sender frame URL is our own origin | ✅ |

## Residual risks / limitations

- A process running as the same OS user can read Electron's memory or environment and
  obtain the session token. Out of scope: same-user malware already owns the account.
- The session token is passed to the backend via environment variable, visible to same-user
  processes on some OSes (same rationale as above).
- Runtime evidence may contain secrets in shapes the redactor doesn't recognise; redaction is
  pattern-based plus exact-match on the known auth value. Mitigated by exact-match redaction
  of the user's own header value (`extra_secrets`).
- `/dev/components` exists only in dev builds.
