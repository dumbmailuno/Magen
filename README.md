# Magen

**AI-assisted API security misconfiguration detection & remediation.**

Magen (Hebrew: "shield") is a desktop app that scans OpenAPI 3.x specs, Nginx configs and
(allowlisted) live APIs for security misconfigurations.

> **Rules find → AI explains → Human reviews → Retest verifies.**
> Detection is 100% deterministic; the optional local LLM (Ollama) only explains and drafts
> fixes. Everything works with Ollama stopped.

Final-year academic project — see [`CLAUDE.md`](CLAUDE.md) for the full engineering spec and
[`docs/`](docs/) for architecture, threat model, rules and evaluation.

## Status

Roadmap week 1–2 (scaffold): finding schema, SQLite + migrations, FastAPI skeleton with
session-token auth, Electron shell, design tokens, base components, `/dev/components`, CI.
Roadmap week 3–4: OpenAPI parser + 10 rules (`API-OAS-001`…`010`, see
[`docs/rules.md`](docs/rules.md)) and labelled corpus v1. Week 5–6: Nginx parser + 11 rules (`NGX-*`) and the findings UI — pick a spec and/or
config under **New scan**, review results under **Findings**.

## Layout

| Path | What |
|---|---|
| `backend/` | Python 3.11+ FastAPI service (`app/`), tests, `uv.lock` |
| `frontend/` | React + Vite + TypeScript (strict) + Tailwind (token preset) |
| `electron/` | Main process, preload, backend process manager |
| `docs/` | Architecture, threat model, rules, evaluation, design system |
| `corpus/` | Labelled evaluation corpus (`labels.yaml`) |
| `scripts/` | Design-token lint, contrast check, schema and UI-fixture export, Electron launcher |

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (installs Python 3.12 for you)
- Node.js 22+ and npm

## Setup

```sh
# backend
cd backend
uv sync                     # creates backend/.venv from uv.lock
uv run pytest --cov=app
uv run ruff check . && uv run ruff format --check . && uv run mypy

# frontend
cd ../frontend
npm install
npm run lint && npm test

# desktop (from repo root)
cd ..
npm install
npm run electron:dev        # Vite + Electron; Electron spawns the backend itself
npm run electron:start      # production build loaded via app:// with strict CSP
npm run test:electron       # app:// path-traversal guard tests
```

`npm run electron:dev` starts the Vite dev server and Electron. Electron picks a free
loopback port, generates a per-session token, starts `backend/.venv` Python with
`python -m app`, waits for `/api/health`, and kills the backend on quit.

### Browser-only frontend development

```sh
# terminal 1 — pick any 32+ char token
cd backend
MAGEN_SESSION_TOKEN=<token> uv run python -m app        # PowerShell: $env:MAGEN_SESSION_TOKEN="<token>"; uv run python -m app

# terminal 2
cd frontend
cp .env.example .env.local   # set VITE_MAGEN_TOKEN=<same token>
npm run dev                  # http://127.0.0.1:5173/#/dev/components
```

## Quality gates (run in CI)

| Check | Command |
|---|---|
| Python lint / format / types | `ruff check .` · `ruff format --check .` · `mypy` (strict) |
| Python tests + coverage | `pytest --cov=app` |
| Token contrast (WCAG AA) | `python scripts/check_contrast.py` |
| TS types | `npm run typecheck` |
| ESLint + Prettier + token guard | `npm run lint` (no hex / arbitrary values / raw palette classes) |
| UI tests | `npm test` (Vitest) |

## Troubleshooting

- **Vitest: "failed to find the current suite" on Windows** — your shell's working directory
  uses a lowercase drive letter (`c:\...`, common in VS Code terminals), so Vitest loads
  itself twice. `cd C:\Users\...` (uppercase) and re-run.
- **Electron: "backend executable not found"** — run `uv sync` in `backend/` first.
- **Electron: `Cannot read properties of undefined (reading 'registerSchemesAsPrivileged')`**
  — `ELECTRON_RUN_AS_NODE=1` is set (VS Code exports it to its terminals). The npm scripts
  launch through `scripts/electron.mjs`, which strips it; don't run `electron .` directly.
- **Fresh clone: Electron binary missing** — npm 11 blocks install scripts unless approved;
  `package.json` `allowScripts` approves `electron`. If you bump Electron, re-run
  `npm approve-scripts electron`.

## Safety

Magen only probes hosts you add to its allowlist and confirm you're authorized to test.
Probes are safe-method only (GET/HEAD/OPTIONS), rate-limited, capped and cancellable. Auth
headers you supply are kept in memory only and redacted everywhere. See
[`docs/threat-model.md`](docs/threat-model.md).
