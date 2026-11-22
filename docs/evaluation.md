# Evaluation plan

Graded component — see CLAUDE.md §9. Runner: `scripts/eval.py` (roadmap week 13–14).

## Corpus

`corpus/{openapi,nginx,runtime}/` with ground truth in `corpus/labels.yaml`:

```yaml
- file: openapi/http-server.yaml
  expected:
    - rule_id: API-OAS-001
      location: { pointer: /servers/0/url }
      status: potential
```

Each rule gets deliberately vulnerable, clean, and tricky/borderline cases. Runtime targets:
intentionally vulnerable apps (crAPI, VAmPI, OWASP Juice Shop) run locally via Docker.

### Corpus v1 (2026-11-22) — OpenAPI

| File | Kind | Expected findings | Exercises |
|---|---|---|---|
| `clean-bearer.yaml` | clean | 0 | loopback http server, `traceId`, 429 via `$ref` |
| `clean.json` | clean | 0 | JSON input path |
| `tricky-refs.yaml` | tricky | 0 | path-item `$ref`, external `$ref` (not fetched), ref cycle, YAML 1.1 keys, webhooks |
| `insecure-transport.yaml` | vulnerable | 3 | 001 at root / templated scheme / path-item level |
| `no-auth.yaml` | vulnerable | 5 | 002, 003 ×3, 008 |
| `weak-schemes.yaml` | vulnerable | 6 | 004, 005, 006 ×2, 007 ×2 (incl. case-sensitive name) |
| `public-endpoints.yaml` | tricky | 3 (2 borderline) | 003 opt-outs and optional auth |
| `leaky-errors.yaml` | vulnerable | 2 | 009 via `$ref`, dedup across ops; `traceId`/`debugMode`/unused schema negatives |
| `credentials-in-query.yaml` | vulnerable | 3 | 010 in query/path, shared `$ref` param reported once; header/near-miss negatives |

25 expected findings; every OpenAPI rule has ≥ 1 positive in the corpus.

### Corpus v1 (2026-11-22) — Nginx

| File | Kind | Expected findings | Exercises |
|---|---|---|---|
| `clean-tls.conf` | clean | 0 | redirect server, modern TLS, headers, `limit_req`, restricted `stub_status`, denied `.git`, per-location body limit |
| `legacy-tls.conf` | vulnerable | 3 | TLS-001, TLS-002, TLS-003 |
| `plaintext.conf` | vulnerable | 2 | TLS-004 incl. implicit port 80; loopback and `location /` redirect negatives |
| `exposure.conf` | vulnerable | 5 | CFG-001, CFG-002 ×2, CFG-003 ×2; denied/auth/off/health-path negatives |
| `header-inheritance.conf` | tricky | 3 | `add_header` inheritance drop (TLS-003 + HDR-002), HSTS `max-age=0`; inherit and re-declare negatives |
| `cors.conf` | vulnerable | 2 | CORS-001 wildcard and reflection with credentials; `map` and `if`-guarded negatives |
| `site-snippet.conf` | tricky | 4 (all inconclusive) | snippet without `http` + unresolved `include` → `inconclusive` status |

19 expected findings; every Nginx rule has ≥ 1 positive. Corpus v1 total: 16 files, 44
expected findings, 21 rules. Same labelling procedure and validity caveats as above; Nginx
also matched on first comparison (including expected status).

### Corpus v1 (2026-11-22) — Runtime (recorded observations)

Runtime fixtures are recorded, redacted probe observations (`app/runtime/recording.py`)
replayed through the runtime rules: deterministic and network-free, so they run in CI. Live
targets (VAmPI, crAPI, Juice Shop in Docker) are for the evaluation milestone; their scans
can be recorded into this format and replayed.

| File | Kind | Expected | Exercises |
|---|---|---|---|
| `hardened-api.json` | clean | 0 | good headers, https redirect, SPA fallback on `/server-status` (no marker), TLS 1.0 refused / 1.1 not testable |
| `legacy-server.json` | vulnerable | 9 | RT-001…008, RT-011 |
| `exposed-files.json` | vulnerable | 4 | RT-009 (.git, masked .env), RT-010 (stub_status, actuator) |
| `local-http-lab.json` | tricky | 3 | VAmPI-style `http://localhost` lab: RT-001, RT-005, RT-006; HSTS correctly not applicable |

16 expected findings. Corpus v1 total: 20 files, 60 expected findings, 32 rules.

**Labelling procedure.** Single labeller (the author). Each file was written to target
specific rules; expected `(rule_id, pointer, status)` tuples were written from the rule
definitions in `docs/rules.md` *before* running the analyzer, then compared. Corpus v1
matched on first comparison. `borderline: true` marks findings that are correct per the
rule's definition but that a reviewer may accept (intentionally public endpoints).

**Gate.** `backend/tests/test_corpus.py` requires an exact match (no FP, no FN), a label for
every file, ≥ 1 corpus positive per rule, and identical ids across runs, CRLF/LF and `\` vs `/`
paths.

**Threats to validity.** Corpus v1 was written by the rule author alongside the rules, so it
is a *development set*: a perfect score shows the rules do what they claim, not that they
generalise. Planned for the evaluation milestone: (1) a held-out set from public real-world
specs (e.g. APIs.guru) labelled independently, ideally by a second labeller with
inter-rater agreement reported; (2) borderline-case analysis per rule.

### Known false-positive sources

| Rule | Source |
|---|---|
| API-OAS-003 | Intentionally public operations (health, login, docs) |
| API-OAS-008 | Rate limits enforced by a gateway but not documented in the spec |
| API-OAS-009 | Fields named `debug`/`trace` that hold non-sensitive data |
| API-OAS-010 | Path/query params named `token` that are one-time, non-secret identifiers |
| NGX-HDR-002, NGX-TLS-003 | Headers added by an upstream app or CDN rather than nginx |
| NGX-CFG-002 | `/metrics` or `/debug` protected by a firewall/network policy outside nginx |
| NGX-RL-001 | Rate limiting in a gateway/WAF in front of nginx |
| All "missing" Nginx rules | Settings in included files (mitigated: reported as `inconclusive`) |
| API-RT-003 | Local lab targets with self-signed certificates (expected; severity stays high for production hosts) |
| API-RT-005, API-RT-004 | JSON-only APIs where browser headers matter less (still recommended) |
| API-RT-008 | Signatures inside legitimate content (e.g. a docs page quoting a traceback) |

### Corpus v1 (2026-11-22) — Correlation

`labels.yaml → correlation:` cases pair static inputs with a recorded runtime scan and
label the expected final `(rule_id, pointer, status, source)`.

| Case | Inputs | Exercises |
|---|---|---|
| `agreement` | `nginx/legacy-tls.conf` + `runtime/legacy-server.json` | TLS-001, TLS-003 confirmed (correlated); TLS-002 stays potential (no runtime link); runtime-only findings kept; config says `server_tokens off` yet a version is served → runtime finding kept |
| `contradiction` | `correlation/cdn-headers.conf` + `correlation/cdn-headers.json` | HSTS, headers and `/nginx_status` missing/open in config but provided/blocked upstream → inconclusive with contradicting evidence |
| `different-host` | `nginx/legacy-tls.conf` + `runtime/hardened-api.json` | config for another host: no correlation at all |

All three matched (status and source) after two engine bugs surfaced by the corpus were
fixed: runtime findings were tagged `source: static`, and an unmatched host name fell back
to a config's only server (now only IP targets use nginx's default-server semantics).

## Metrics

| Metric | Definition |
|---|---|
| Precision / recall / F1 | Per rule and overall; match = same `rule_id` + location |
| Correlation accuracy | Predicted vs labelled `confirmed / potential / inconclusive` |
| Remediation success rate | Fix applied → retest marks finding *resolved*. Static part measured on the corpus: every auto-fix validates (`test_every_applied_fix_validates`: finding gone, nothing introduced); session-level rate = resolved / (resolved + persists), with config-fixed-but-still-live findings counted as persisting |
| Auto-fix coverage | Share of findings with a deterministic fix vs template-only (per rule, see `docs/rules.md` → Remediation) |
| AI explanation quality | Rubric (correctness, actionability; 1–5) on a fixed sample |
| Scan time | Wall-clock per input, median of N runs |

## Ablations

- With vs without correlation (static-only vs static+runtime).
- Template fixes vs AI fixes (validation pass rate, remediation success).

## Reproducibility

Report (JSON + Markdown) records: commit hash, Magen version, Python/Node versions, model
name + prompt version, seed, and corpus hash.
