from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.redaction import REDACTED
from app.models.finding import (
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    Location,
    References,
    Severity,
    Source,
    compute_finding_id,
    make_finding,
    sort_findings,
)

SCHEMA_FILE = Path(__file__).resolve().parents[2] / "docs" / "finding.schema.json"


def _ev(excerpt: str = "server: http://api.example.com", file: str = "spec.yaml") -> Evidence:
    return Evidence(
        kind=EvidenceKind.OPENAPI,
        location=Location(file=file, line=3, pointer="/servers/0/url"),
        excerpt=excerpt,
    )


def _finding(rule_id: str = "API-OAS-001", sev: Severity = Severity.HIGH, **kw: str) -> Finding:
    return make_finding(
        rule_id=rule_id,
        title="Server uses plain HTTP",
        category="transport",
        severity=sev,
        status=FindingStatus.POTENTIAL,
        source=Source.STATIC,
        evidence=[_ev(**kw)],
        references=References(owasp_api=["API8:2023"], cwe=["CWE-319"]),
    )


def test_id_is_deterministic() -> None:
    assert _finding().id == _finding().id
    assert len(_finding().id) == 20


def test_id_stable_across_line_endings_and_path_separators() -> None:
    a = _finding(excerpt="a: 1\nb: 2", file="specs/api.yaml")
    b = _finding(excerpt="a: 1\r\nb: 2  \r\n", file="specs\\api.yaml")
    assert a.id == b.id


def test_id_changes_with_rule_location_or_evidence() -> None:
    base = _finding()
    assert _finding(rule_id="API-OAS-002").id != base.id
    assert _finding(file="other.yaml").id != base.id
    assert _finding(excerpt="different").id != base.id


def test_id_ignores_evidence_order() -> None:
    e1, e2 = _ev("one"), _ev("two", file="b.yaml")
    assert compute_finding_id("API-OAS-001", [e1, e2]) == compute_finding_id(
        "API-OAS-001", [e2, e1]
    )


def test_id_ignores_volatile_request_response() -> None:
    loc = Location(url="https://api.example.com/")
    a = Evidence(kind=EvidenceKind.HTTP, location=loc, excerpt="x", response="Date: Mon")
    b = Evidence(kind=EvidenceKind.HTTP, location=loc, excerpt="x", response="Date: Tue")
    assert compute_finding_id("API-RT-001", [a]) == compute_finding_id("API-RT-001", [b])


def test_evidence_is_redacted_on_construction() -> None:
    ev = Evidence(
        kind=EvidenceKind.HTTP,
        location=Location(url="https://h/x?api_key=SECRET123"),
        excerpt="ok",
        request="GET / HTTP/1.1\nAuthorization: Bearer abc.def.ghi\nCookie: sid=zzz",
    )
    assert ev.request is not None
    assert "abc.def.ghi" not in ev.request
    assert "zzz" not in ev.request
    assert ev.location.url is not None and "SECRET123" not in ev.location.url
    assert REDACTED in ev.request


def test_finding_requires_evidence() -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="0" * 20,
            rule_id="API-OAS-001",
            title="t",
            category="c",
            severity=Severity.LOW,
            status=FindingStatus.POTENTIAL,
            source=Source.STATIC,
            evidence=[],
        )


@pytest.mark.parametrize("bad", ["api-oas-001", "API-OAS-1", "APIOAS001", "X-Y-001"])
def test_rule_id_format_enforced(bad: str) -> None:
    with pytest.raises(ValidationError):
        _finding(rule_id=bad)


def test_reference_formats_enforced() -> None:
    with pytest.raises(ValidationError):
        References(owasp_api=["API11:2023"])
    with pytest.raises(ValidationError):
        References(cwe=["319"])


def test_sort_is_canonical_and_dedupes() -> None:
    low = _finding(rule_id="API-OAS-005", sev=Severity.LOW)
    crit = _finding(rule_id="API-OAS-009", sev=Severity.CRITICAL)
    high_b = _finding(rule_id="API-OAS-002", sev=Severity.HIGH)
    high_a = _finding(rule_id="API-OAS-001", sev=Severity.HIGH)
    ordered = sort_findings([low, high_b, crit, high_a, low])
    assert [f.rule_id for f in ordered] == [
        "API-OAS-009",
        "API-OAS-001",
        "API-OAS-002",
        "API-OAS-005",
    ]
    assert sort_findings(reversed(ordered)) == ordered


def test_finding_round_trips_json() -> None:
    f = _finding()
    assert Finding.model_validate_json(f.model_dump_json()) == f


def test_committed_json_schema_is_current() -> None:
    """The schema is mirrored in the frontend; a change here must be deliberate."""
    current = json.dumps(Finding.model_json_schema(), indent=2, sort_keys=True) + "\n"
    assert SCHEMA_FILE.read_text(encoding="utf-8") == current, (
        "Finding schema changed: run `python ../scripts/export_schema.py` and update "
        "frontend/src/lib/types.ts and docs/rules.md"
    )


def test_id_ignores_line_numbers_when_a_pointer_exists() -> None:
    """Editing unrelated lines above a finding must not change its id (retest relies on it)."""

    def ev(line: int) -> Evidence:
        return Evidence(
            kind=EvidenceKind.OPENAPI,
            location=Location(file="s.yaml", line=line, end_line=line + 2, pointer="/servers/0/url"),
            excerpt="url: http://x",
        )

    assert compute_finding_id("API-OAS-001", [ev(3)]) == compute_finding_id("API-OAS-001", [ev(40)])


def test_id_uses_line_when_no_pointer() -> None:
    def ev(line: int) -> Evidence:
        return Evidence(kind=EvidenceKind.NGINX, location=Location(file="n.conf", line=line), excerpt="x")

    assert compute_finding_id("NGX-CFG-001", [ev(3)]) != compute_finding_id("NGX-CFG-001", [ev(4)])


def test_sort_orders_lines_numerically() -> None:
    def at(line: int) -> Finding:
        return make_finding(
            rule_id="API-OAS-003",
            title="t",
            category="c",
            severity=Severity.MEDIUM,
            status=FindingStatus.POTENTIAL,
            source=Source.STATIC,
            evidence=[
                Evidence(
                    kind=EvidenceKind.OPENAPI,
                    location=Location(file="s.yaml", line=line, pointer=f"/p{line}"),
                    excerpt="x",
                )
            ],
        )

    assert [f.evidence[0].location.line for f in sort_findings([at(10), at(9)])] == [9, 10]
