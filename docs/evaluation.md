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
Labelling procedure, labeller(s) and disagreements are recorded here as the corpus grows.

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
