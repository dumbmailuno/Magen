"""Corpus regression gate: analyzer output must match corpus/labels.yaml exactly.

Also checks reproducibility (CLAUDE.md §1): same input → same findings, ids and order,
regardless of line endings or the platform's path separator.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.static.openapi.analyzer import analyze_openapi

CORPUS = Path(__file__).resolve().parents[2] / "corpus"
LABELS: dict[str, Any] = yaml.safe_load((CORPUS / "labels.yaml").read_text(encoding="utf-8"))
ENTRIES: list[dict[str, Any]] = [e for e in LABELS["files"] if e["file"].startswith("openapi/")]


def _analyze(rel: str, text: str | None = None) -> Any:
    text = text if text is not None else (CORPUS / rel).read_text(encoding="utf-8")
    return analyze_openapi(text, f"corpus/{rel}")


def _got(rel: str) -> set[tuple[str, str]]:
    return {(f.rule_id, f.evidence[0].location.pointer or "") for f in _analyze(rel).findings}


def test_every_corpus_file_is_labelled() -> None:
    on_disk = {p.relative_to(CORPUS).as_posix() for p in (CORPUS / "openapi").iterdir()}
    assert on_disk == {e["file"] for e in ENTRIES}


@pytest.mark.parametrize("entry", ENTRIES, ids=[e["file"] for e in ENTRIES])
def test_findings_match_labels(entry: dict[str, Any]) -> None:
    expected = {(e["rule_id"], e["pointer"]) for e in entry["expected"]}
    got = _got(entry["file"])
    assert got - expected == set(), "false positives"
    assert expected - got == set(), "false negatives"


@pytest.mark.parametrize("entry", ENTRIES, ids=[e["file"] for e in ENTRIES])
def test_expected_status_matches(entry: dict[str, Any]) -> None:
    statuses = {
        (f.rule_id, f.evidence[0].location.pointer): f.status.value
        for f in _analyze(entry["file"]).findings
    }
    for e in entry["expected"]:
        assert statuses[(e["rule_id"], e["pointer"])] == e["status"]


def test_every_openapi_rule_has_corpus_coverage() -> None:
    covered = Counter(e["rule_id"] for entry in ENTRIES for e in entry["expected"])
    missing = [f"API-OAS-{i:03d}" for i in range(1, 11) if not covered[f"API-OAS-{i:03d}"]]
    assert missing == []


@pytest.mark.parametrize("entry", ENTRIES, ids=[e["file"] for e in ENTRIES])
def test_reproducible_across_runs_line_endings_and_separators(entry: dict[str, Any]) -> None:
    rel = entry["file"]
    text = (CORPUS / rel).read_text(encoding="utf-8")
    a = _analyze(rel, text).findings
    b = _analyze(rel, text).findings
    windows_name = "corpus\\" + rel.replace("/", "\\")
    crlf = analyze_openapi(text.replace("\n", "\r\n"), windows_name)
    assert a == b
    assert [f.id for f in a] == [f.id for f in crlf.findings]
    assert [f.model_dump() for f in a] == [f.model_dump() for f in crlf.findings]


def test_every_finding_has_located_evidence() -> None:
    for entry in ENTRIES:
        for f in _analyze(entry["file"]).findings:
            loc = f.evidence[0].location
            assert loc.file == f"corpus/{entry['file']}"
            assert loc.pointer is not None
            if entry["file"].endswith(".yaml"):
                assert loc.line is not None
            assert f.evidence[0].excerpt.strip()


def test_hostile_spec_content_is_bounded_and_redacted() -> None:
    long_host = "a" * 400
    text = f"""openapi: 3.0.3
info: {{title: t, version: "1"}}
servers:
  - url: http://admin:hunter2@api.example.com
  - url: http://{long_host}.example.com
paths: {{}}
"""
    findings = analyze_openapi(text, "hostile.yaml").findings
    assert len(findings) == 2
    for f in findings:
        assert "hunter2" not in f.title
        assert "hunter2" not in f.evidence[0].excerpt
        assert len(f.title) <= 200


def test_minified_json_excerpt_is_the_node_not_the_file() -> None:
    spec = (
        '{"openapi":"3.0.3","info":{"title":"t","version":"1"},"servers":[{"url":"http://x.example.com"}],'
        + '"x-pad":"'
        + "p" * 2000
        + '","paths":{}}'
    )
    f = analyze_openapi(spec, "min.json").findings[0]
    assert f.rule_id == "API-OAS-001"
    assert f.evidence[0].excerpt == '"http://x.example.com"'
