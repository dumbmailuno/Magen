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
| Credential sent where it shouldn't be (I) | B3 | Auth header never sent over plain HTTP to non-local targets, never on the `plain-http` probe; exact value redacted from every observation/audit/finding; only the header *name* is stored | ✅ |
| Exposed secret files stored by Magen (I) | B3 | `/.env` bodies masked to `KEY=••••` at capture (no value ever held) and omitted from evidence | ✅ |
| Scanning hosts the user isn't authorized for (misuse) (E) | B3 | Allowlist requires `authorization_confirmed: true` (timestamp recorded); scans reference a target id and the base URL host must equal it exactly (no subdomains/lookalikes); hosts normalised (IDNA, no scheme/port/path/wildcards) | ✅ |
| SSRF into internal network / cloud metadata (E, I) | B3 | Every resolved address validated (all must pass — mixed public/internal answers rejected); internal ranges only for targets added as local; metadata IPs (incl. IPv4-mapped) blocked always; **connect to the validated IP** with Host/SNI = name (defeats DNS rebinding); redirects followed manually, same host only, re-resolved and re-checked, max 3; no proxy from environment | ✅ |
| Scanner causes harm/DoS to target (D) | B3 | Single client method rejects anything but GET/HEAD/OPTIONS before any socket opens; global token bucket ≤ 5 req/s plus per-scan rate; per-scan cap (default 50, max 200, TLS handshakes count); 5 s connect / 10 s read timeouts; 64 KB body cap; one scan at a time; Stop cancels the task and the in-flight request; fixed ≤ 13-probe plan | ✅ |
| Repudiation of probes sent (R) | B3 | Every HTTP request and TLS handshake written to `probe_audit` (method, redacted URL, status/error, timestamp); `GET /api/scans/{id}/audit` | ✅ |
| Prompt injection via spec/config/response content (T, E) | B4 | Untrusted text only inside nonce-delimited blocks (nonce = content hash; delimiter look-alikes defanged); system prompt declares it data; finding title treated as untrusted; minimal redacted evidence (≤1500 chars), never whole files; JSON-schema output with extra fields forbidden (a model cannot smuggle `status`/`severity`); output only ever stored in `ai_explanation` / `ai_fix`, never triggers actions; advisory injection heuristic shown in the UI. Tested with an "obedient" fake model | ✅ |
| LLM "decides" a vulnerability (integrity of results) (T) | B4 | Architecture: findings only from pure rules; AI output stored only in `ai_explanation`/`ai_fix`, always labelled | ✅ by design |
| Bad or malicious fix (T) | B2/B4 | Deterministic line edits only; validated by re-parse + re-running every rule (any new finding fails validation) and `nginx -t` in a temp dir (test mode, timeout) when installed; shown as a difflib diff; exported as `*.magen-fixed.*`, never written over user files (no Apply action anywhere) | ✅ (template and AI fixes: AI may only rewrite the finding's own lines, then the same validator; unvalidated AI fixes are not exportable) |
| Scanned file contents persisted (I) | B2 | Sessions store file name + SHA-256 only (test asserts a content marker never reaches the DB file); contents stay in renderer memory for fix generation | ✅ |
| Misleading retest ("resolved" while still exploitable) | — | Linked static ⇄ runtime matching: config-fixed issues still observed live are reported as persisting (`still_observed`), not resolved | ✅ |
| Data sent to cloud AI (I) | B4 | Ollama URL must be loopback at config time and on every settings change (non-loopback → 422); no proxy from environment; no cloud provider implemented in v1 | ✅ |
| Malicious spec exploits parser (T, D) | B2 | OpenAPI: `yaml.SafeLoader`, non-standard tags rejected, 5 MB cap, depth ≤ 64, node budget ≤ 200k (alias bombs), external `$ref` never fetched, ref cycles bounded. Nginx: own text-only parser (no filesystem; `include` never followed), 5 MB / depth 32 / 500k-token caps. All tested | ✅ |
| Renderer compromise escalates to Node (E) | B5 | `contextIsolation`, `nodeIntegration: false`, `sandbox: true`; preload exposes only URL + token; navigation & `window.open` blocked; all permission requests denied; strict CSP (no remote content) | ✅ |
| Path traversal via `app://` protocol (I) | B5 | `resolveAppPath` (pure, unit-tested incl. encoded `..`, backslashes, NUL, malformed escapes): resolved path must stay inside `frontend/dist`, else 403 | ✅ |
| Token handed to an unexpected frame (I) | B5 | IPC handler returns config only if the sender frame URL is our own origin | ✅ |
| Spec/config content opens arbitrary URLs via reference links (S, I) | B5 | `window.open` always denied; only `https` URLs on a fixed documentation-host allowlist (no credentials/ports) are handed to the system browser (`isAllowedExternalUrl`, unit-tested) | ✅ |

## Residual risks / limitations

- A process running as the same OS user can read Electron's memory or environment and
  obtain the session token. Out of scope: same-user malware already owns the account.
- The session token is passed to the backend via environment variable, visible to same-user
  processes on some OSes (same rationale as above).
- Runtime evidence may contain secrets in shapes the redactor doesn't recognise; redaction is
  pattern-based plus exact-match on the known auth value. Mitigated by exact-match redaction
  of the user's own header value (`extra_secrets`).
- `/dev/components` exists only in dev builds.
