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

## Metrics

| Metric | Definition |
|---|---|
| Precision / recall / F1 | Per rule and overall; match = same `rule_id` + location |
| Correlation accuracy | Predicted vs labelled `confirmed / potential / inconclusive` |
| Remediation success rate | Fix applied → retest marks finding *resolved* |
| AI explanation quality | Rubric (correctness, actionability; 1–5) on a fixed sample |
| Scan time | Wall-clock per input, median of N runs |

## Ablations

- With vs without correlation (static-only vs static+runtime).
- Template fixes vs AI fixes (validation pass rate, remediation success).

## Reproducibility

Report (JSON + Markdown) records: commit hash, Magen version, Python/Node versions, model
name + prompt version, seed, and corpus hash.
