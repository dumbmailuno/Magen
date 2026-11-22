# Changelog

## 0.1.0 — unreleased

- **MVP (roadmap wk 9–10).** Correlation engine (static ⇄ runtime link table with host /
  listener / path scoping; confirmed / inconclusive-by-contradiction; static ids kept),
  correlation corpus (3 cases). Remediation: 14 deterministic fixers, difflib diffs,
  validation (re-parse + re-run rules + optional nginx -t), `POST /api/remediation/preview`.
  Retest: persisted sessions (hashes, not contents; migration 0002 stores recorded runtime
  observations), baseline comparison with "still observed live" detection.
  UI: DiffView, RemediationPanel, CompareView, Compare page, Retest flow, correlation and
  retest summaries. Design system 0.4.0.
- Fixed: runtime findings were tagged `source: static`; finding-list "New" markers.

- Runtime analysis (roadmap wk 7–8): allowlist API (authorization confirmation + timestamp),
  safety core (host normalisation, IP validation incl. metadata block, DNS-rebinding-proof
  IP pinning, same-host redirects ≤ 3, safe methods only, global ≤ 5 req/s + per-scan rate,
  request cap, timeouts, body cap), SafeHttpClient, TLS handshakes, fixed probe plan,
  11 runtime rules (API-RT-*), scan manager with Stop and audit log, recorded-observation
  runtime corpus (4 files, 16 findings). Adds httpx (runtime) and trustme (tests).
- Runtime UI: Targets page (allowlist form with required authorization checkbox), Live API
  section on New Scan (target, base URL, in-memory auth header, rate, cap), ScanProgress with
  determinate bar, live text and Stop, coverage notes and a ProbeLog of every request sent.
  Cancelled in-flight requests are audited too. Design system 0.3.0 (ProbeLog).

- Findings UI (roadmap wk 5–6): New Scan (OpenAPI + Nginx file inputs, local 5 MB check),
  Findings page with summary strip, URL-persisted filters, keyboard listbox, finding detail
  (evidence → why it matters → fix → references), FixCard copy/export (no apply), loading /
  empty / error+retry / partial / coverage states. Reference links open in the system
  browser only for allowlisted https documentation hosts.

- Design system 0.2.0: FileField, SummaryStrip, FilterBar, Alert components; FindingTable
  realised as a keyboard listbox; `split` (1100px) screen for master–detail.

- Nginx static analysis (roadmap wk 5–6): text-only parser with structural pointers,
  inheritance-aware config model (incl. `add_header` all-or-nothing), 11 rules (NGX-*),
  `POST /api/analyze/nginx` (reports unresolved includes), `inconclusive` status when config
  is partially invisible, corpus v1 Nginx (7 files, 19 expected findings).
- Finding ids no longer depend on line numbers when a structural pointer exists; sort order
  is numeric by line.

- OpenAPI static analysis (roadmap wk 3–4): position-tracking safe loader, document model,
  10 rules (API-OAS-001…010), analyzer service, `POST /api/analyze/openapi`, corpus v1
  (9 labelled specs, 25 expected findings) with an exact-match regression gate.

- Scaffold (roadmap wk 1–2): Finding schema with stable IDs and redaction, rule registry,
  SQLite + Alembic, FastAPI with session-token auth, Electron shell, design tokens, base
  components, `/dev/components`, CI.
- Design system 0.1.1: `ThemeProvider` resolves `system` → `dark`/`light` (tokens.css had
  no light palette under `data-theme="system"`); added `scripts/check_contrast.py`;
  added Skeleton, CopyButton, Logo and BackendStatus to the component table.
