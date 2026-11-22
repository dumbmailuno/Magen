# Rules catalogue

Every rule lives in `backend/app/rules/` (one file per rule), is pure, and has ≥1 positive
and ≥1 negative fixture. Rule IDs are **never reused**: deprecate, don't delete.

## ID scheme

`<AREA>-<SOURCE>-<NNN>`, matching `^[A-Z]{2,5}-[A-Z]{2,5}-\d{3}$`

| Prefix | Meaning |
|---|---|
| `API-OAS-` | OpenAPI static rules |
| `NGX-<topic>-` | Nginx static rules (e.g. `NGX-TLS-`, `NGX-HDR-`) |
| `API-RT-` | Runtime probe rules |

Each rule declares: `id`, `title`, `category`, `severity`, `description`, `target`,
`references` (OWASP API Top 10 2023 id **required**, CWE where applicable, doc links) and
`remediation_template`. The registry rejects rules missing any of these.

## Finding schema

See `docs/finding.schema.json` (generated from `backend/app/models/finding.py` by
`scripts/export_schema.py`; a test fails if it is stale).

## Rules

_None yet — the first OpenAPI rules land in roadmap week 3–4._

| ID | Title | Severity | Target | OWASP | CWE | Status |
|---|---|---|---|---|---|---|
