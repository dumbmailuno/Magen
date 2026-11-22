"""Scan sessions (static + runtime, correlated, persisted) and retest comparison."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.models.finding import Finding
from app.retest.compare import Comparison, compare
from app.retest.sessions import StaticInput, create_session, require_session
from app.static.openapi.loader import MAX_BYTES
from app.storage.repositories import ScanRepository
from app.version import generated_by

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


class InputIn(BaseModel):
    """A file read by the renderer; content is analysed and discarded (never stored)."""

    kind: Literal["openapi", "nginx"]
    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=MAX_BYTES)


class SessionIn(BaseModel):
    """Inputs, an optional finished runtime scan, and an optional baseline to compare with."""

    inputs: list[InputIn] = Field(default_factory=list, max_length=10)
    runtime_scan_id: int | None = None
    baseline_id: int | None = None


class InputOut(BaseModel):
    """Persisted facts about an input."""

    kind: str
    filename: str
    sha256: str
    ok: bool
    error: str | None
    notes: list[str]


class CorrelationOut(BaseModel):
    """Correlation counts."""

    confirmed: int
    contradicted: int
    runtime_only: int
    static_only: int


class StatusChangeOut(BaseModel):
    """A persisting finding whose status changed."""

    finding_id: str
    rule_id: str
    title: str
    before: str
    after: str


class ComparisonOut(BaseModel):
    """Baseline vs current."""

    baseline_id: int
    current_id: int
    resolved: list[Finding]
    persists: list[Finding]
    new: list[Finding]
    status_changes: list[StatusChangeOut]
    remediation_rate: float | None
    #: Inputs (by file name) whose content hash differs between the two sessions.
    changed_inputs: list[str]


class SessionOut(BaseModel):
    """A session with its findings and (if it has a baseline) the comparison."""

    id: int
    created_at: datetime
    generated_by: str
    baseline_id: int | None
    inputs: list[InputOut]
    runtime_scan_id: int | None
    runtime_notes: list[str]
    correlation: CorrelationOut
    findings: list[Finding]
    comparison: ComparisonOut | None


class SessionSummary(BaseModel):
    """Row for the session picker."""

    id: int
    created_at: datetime
    inputs: list[str]
    runtime_scan_id: int | None
    baseline_id: int | None
    total: int
    by_severity: dict[str, int]


def _repo(request: Request) -> ScanRepository:
    return ScanRepository(request.app.state.db)


def _input_hashes(repo: ScanRepository, session_id: int) -> dict[str, str]:
    options: dict[str, Any] = repo.get(session_id).options or {}
    return {str(i["filename"]): str(i["sha256"]) for i in options.get("inputs", [])}


def _comparison(repo: ScanRepository, baseline_id: int, current_id: int) -> ComparisonOut:
    require_session(repo, baseline_id)
    require_session(repo, current_id)
    c: Comparison = compare(repo.findings(baseline_id), repo.findings(current_id))
    hashes = [_input_hashes(repo, sid) for sid in (baseline_id, current_id)]
    changed = sorted(n for n in hashes[1] if n in hashes[0] and hashes[0][n] != hashes[1][n])
    return ComparisonOut(
        baseline_id=baseline_id,
        current_id=current_id,
        resolved=c.resolved,
        persists=c.persists,
        new=c.new,
        status_changes=[
            StatusChangeOut(
                finding_id=s.finding.id,
                rule_id=s.finding.rule_id,
                title=s.finding.title,
                before=s.before,
                after=s.after,
            )
            for s in c.status_changes
        ],
        remediation_rate=c.remediation_rate,
        changed_inputs=changed,
    )


def _session_out(repo: ScanRepository, session_id: int) -> SessionOut:
    scan = repo.get(session_id)
    options: dict[str, Any] = scan.options or {}
    return SessionOut(
        id=scan.id,
        created_at=scan.started_at,
        generated_by=generated_by(),
        baseline_id=scan.baseline_scan_id,
        inputs=[InputOut(**i) for i in options.get("inputs", [])],
        runtime_scan_id=options.get("runtime_scan_id"),
        runtime_notes=list(options.get("runtime_notes", [])),
        correlation=CorrelationOut(**options.get("correlation", {})),
        findings=repo.findings(session_id),
        comparison=(
            _comparison(repo, scan.baseline_scan_id, scan.id)
            if scan.baseline_scan_id is not None
            else None
        ),
    )


@router.post("", status_code=201)
def create(body: SessionIn, request: Request) -> SessionOut:
    """Analyse inputs, correlate with the runtime scan, persist, compare with the baseline."""
    repo = _repo(request)
    result = create_session(
        repo,
        [StaticInput(i.kind, i.filename, i.content) for i in body.inputs],
        runtime_scan_id=body.runtime_scan_id,
        baseline_id=body.baseline_id,
    )
    return _session_out(repo, result.id)


@router.get("")
def list_sessions(request: Request) -> list[SessionSummary]:
    """All sessions, newest first."""
    repo = _repo(request)
    out = []
    for scan in repo.sessions():
        options: dict[str, Any] = scan.options or {}
        findings = repo.findings(scan.id)
        out.append(
            SessionSummary(
                id=scan.id,
                created_at=scan.started_at,
                inputs=[i["filename"] for i in options.get("inputs", [])],
                runtime_scan_id=options.get("runtime_scan_id"),
                baseline_id=scan.baseline_scan_id,
                total=len(findings),
                by_severity=dict(Counter(f.severity.value for f in findings)),
            )
        )
    return out


@router.get("/compare")
def compare_sessions(base: int, head: int, request: Request) -> ComparisonOut:
    """Compare any two sessions."""
    return _comparison(_repo(request), base, head)


@router.get("/{session_id}")
def get_session(session_id: int, request: Request) -> SessionOut:
    """One session with findings and its baseline comparison."""
    repo = _repo(request)
    require_session(repo, session_id)
    return _session_out(repo, session_id)
