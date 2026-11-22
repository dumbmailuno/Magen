# Changelog

## 0.1.0 — unreleased

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
