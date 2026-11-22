"""Scan sessions: static inputs + optional runtime scan → correlated, persisted findings.

Input *contents* are never stored (they may contain secrets): only file name, kind and a
SHA-256, which lets a retest show whether the same file changed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

from app import __version__
from app.core.errors import MagenError, NotFoundError, ValidationFailedError
from app.correlation.engine import CorrelationResult, RuntimeSource, StaticSource, correlate
from app.models.finding import Finding
from app.runtime.recording import loads
from app.static.nginx.analyzer import analyze_nginx
from app.static.nginx.config import NginxConfig
from app.static.openapi.analyzer import analyze_openapi
from app.static.openapi.document import OpenApiDocument
from app.storage.repositories import ScanRepository
from app.version import commit_hash

Kind = Literal["openapi", "nginx"]


@dataclass(frozen=True)
class StaticInput:
    """One file submitted for a session (content held in memory only)."""

    kind: Kind
    filename: str
    content: str


@dataclass(frozen=True)
class InputRecord:
    """What is persisted about an input."""

    kind: Kind
    filename: str
    sha256: str
    ok: bool
    error: str | None
    #: Coverage caveats (snippet / unresolved includes) for the UI.
    notes: tuple[str, ...]


@dataclass(frozen=True)
class SessionResult:
    """A finished session."""

    id: int
    inputs: list[InputRecord]
    runtime_scan_id: int | None
    runtime_notes: list[str]
    findings: list[Finding]
    correlation: CorrelationResult


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _analyze(inp: StaticInput) -> tuple[StaticSource | None, InputRecord]:
    digest = _sha(inp.content)
    try:
        if inp.kind == "openapi":
            oa = analyze_openapi(inp.content, inp.filename)
            source = StaticSource(OpenApiDocument(inp.filename, inp.content), oa.findings)
            notes: tuple[str, ...] = ()
        else:
            na = analyze_nginx(inp.content, inp.filename)
            source = StaticSource(NginxConfig(inp.filename, inp.content), na.findings)
            snippet = f"{na.source_name} has no http block: main-config settings were not checked."
            includes = [
                f"{na.source_name} includes {i.path} (line {i.line}), which was not analyzed."
                for i in na.unresolved_includes
            ]
            notes = tuple(([snippet] if na.is_snippet else []) + includes)
    except MagenError as exc:
        return None, InputRecord(inp.kind, inp.filename, digest, False, exc.message, ())
    return source, InputRecord(inp.kind, inp.filename, digest, True, None, notes)


def create_session(
    repo: ScanRepository,
    inputs: list[StaticInput],
    *,
    runtime_scan_id: int | None,
    baseline_id: int | None,
) -> SessionResult:
    """Analyse, correlate and persist a session."""
    if not inputs and runtime_scan_id is None:
        raise ValidationFailedError("A session needs at least one input or a runtime scan")
    if baseline_id is not None:
        base = repo.get(baseline_id)
        if (base.options or {}).get("kind") != "session":
            raise ValidationFailedError("The baseline must be a previous scan session")

    statics: list[StaticSource] = []
    records: list[InputRecord] = []
    for inp in inputs:
        source, record = _analyze(inp)
        records.append(record)
        if source is not None:
            statics.append(source)

    runtime: RuntimeSource | None = None
    runtime_notes: list[str] = []
    target_id: int | None = None
    if runtime_scan_id is not None:
        scan = repo.get(runtime_scan_id)
        scan_options = scan.options or {}
        if scan_options.get("kind") != "runtime":
            raise ValidationFailedError("runtime_scan_id is not a runtime scan")
        if scan.status in ("running", "cancelling"):
            raise ValidationFailedError("The runtime scan has not finished yet")
        target_id = scan.target_id
        if scan.status == "cancelled":
            runtime_notes.append("Runtime scan was stopped early; correlation uses partial probes.")
        if scan.observations:
            runtime = RuntimeSource(loads(scan.observations), tuple(repo.findings(runtime_scan_id)))
        else:
            runtime_notes.append("Runtime scan has no recorded observations; not correlated.")

    result = correlate(statics, runtime)
    options: dict[str, object] = {
        "kind": "session",
        "inputs": [
            {
                "kind": r.kind,
                "filename": r.filename,
                "sha256": r.sha256,
                "ok": r.ok,
                "error": r.error,
                "notes": list(r.notes),
            }
            for r in records
        ],
        "runtime_scan_id": runtime_scan_id,
        "runtime_notes": runtime_notes,
        "correlation": {
            "confirmed": result.confirmed,
            "contradicted": result.contradicted,
            "runtime_only": result.runtime_only,
            "static_only": result.static_only,
        },
    }
    session_id = repo.create(
        target_id=target_id,
        options=options,
        version=__version__,
        commit=commit_hash(),
        baseline_scan_id=baseline_id,
    )
    repo.finish(session_id, "done", result.findings)
    return SessionResult(
        id=session_id,
        inputs=records,
        runtime_scan_id=runtime_scan_id,
        runtime_notes=runtime_notes,
        findings=list(result.findings),
        correlation=result,
    )


def require_session(repo: ScanRepository, session_id: int) -> None:
    """404 unless ``session_id`` is a session."""
    scan = repo.get(session_id)
    if (scan.options or {}).get("kind") != "session":
        raise NotFoundError("Session not found")
