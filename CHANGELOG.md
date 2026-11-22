# Changelog

## 0.1.0 — unreleased

- OpenAPI static analysis (roadmap wk 3–4): position-tracking safe loader, document model,
  10 rules (API-OAS-001…010), analyzer service, `POST /api/analyze/openapi`, corpus v1
  (9 labelled specs, 25 expected findings) with an exact-match regression gate.

- Scaffold (roadmap wk 1–2): Finding schema with stable IDs and redaction, rule registry,
  SQLite + Alembic, FastAPI with session-token auth, Electron shell, design tokens, base
  components, `/dev/components`, CI.
- Design system 0.1.1: `ThemeProvider` resolves `system` → `dark`/`light` (tokens.css had
  no light palette under `data-theme="system"`); added `scripts/check_contrast.py`;
  added Skeleton, CopyButton, Logo and BackendStatus to the component table.
