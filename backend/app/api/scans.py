"""Runtime scan endpoints: start, poll, stop, audit trail."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Final

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field, SecretStr, field_validator

from app.core.safety import AuthorizedTarget, clamp_cap, clamp_rate
from app.models.finding import Finding
from app.runtime.client import AuthHeader
from app.runtime.scanner import ScanJob, ScanManager
from app.storage.repositories import ScanRepository, TargetRepository

router = APIRouter(prefix="/api/scans", tags=["scans"])

_HEADER_NAME: Final = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_FORBIDDEN_HEADERS: Final = frozenset(
    {"host", "content-length", "transfer-encoding", "connection", "origin", "user-agent"}
)


class AuthHeaderIn(BaseModel):
    """One optional header (e.g. ``Authorization: Bearer …``). Never stored or logged."""

    name: str
    value: SecretStr = Field(max_length=4096)

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        if not _HEADER_NAME.match(v) or v.lower() in _FORBIDDEN_HEADERS:
            raise ValueError("invalid header name")
        return v

    @field_validator("value")
    @classmethod
    def _no_newlines(cls, v: SecretStr) -> SecretStr:
        raw = v.get_secret_value()
        if not raw or "\r" in raw or "\n" in raw:
            raise ValueError("header value must be a single non-empty line")
        return v


class RuntimeScanIn(BaseModel):
    """Start a runtime scan of one allowlisted target."""

    target_id: int
    base_url: str = Field(min_length=8, max_length=2048)
    auth_header: AuthHeaderIn | None = None
    rate_per_second: float | None = None
    request_cap: int | None = None


class Progress(BaseModel):
    """Probe progress for the UI (``aria-live`` text)."""

    done: int
    total: int
    current: str


class ScanOut(BaseModel):
    """Scan state; ``findings`` is filled once the scan has finished."""

    id: int
    status: str
    target_host: str | None
    base_url: str | None
    progress: Progress | None
    started_at: datetime
    finished_at: datetime | None
    error: str | None
    notes: list[str]
    findings: list[Finding]


class AuditOut(BaseModel):
    """One probe from the audit log."""

    sent_at: datetime
    method: str
    url: str
    status_code: int | None
    error: str | None


def _manager(request: Request) -> ScanManager:
    manager: ScanManager = request.app.state.scans
    return manager


def _from_job(job: ScanJob) -> ScanOut:
    return ScanOut(
        id=job.id,
        status=job.status,
        target_host=job.target.host,
        base_url=job.base_url,
        progress=Progress(done=job.done, total=job.total, current=job.current),
        started_at=job.started_at,
        finished_at=job.finished_at,
        error=job.error,
        notes=list(job.notes),
        findings=job.findings if job.finished_at else [],
    )


@router.post("/runtime", status_code=202)
async def start_runtime_scan(body: RuntimeScanIn, request: Request) -> ScanOut:
    """Validate against the allowlist and safety limits, then start probing."""
    row = TargetRepository(request.app.state.db).get(body.target_id)
    target = AuthorizedTarget(id=row.id, host=row.host, is_local=row.is_local)
    auth = (
        AuthHeader(name=body.auth_header.name, value=body.auth_header.value)
        if body.auth_header
        else None
    )
    job = _manager(request).start(
        target,
        body.base_url.strip(),
        auth=auth,
        rate=clamp_rate(body.rate_per_second),
        cap=clamp_cap(body.request_cap),
    )
    return _from_job(job)


@router.get("/{scan_id}")
def get_scan(scan_id: int, request: Request) -> ScanOut:
    """Live state for scans of this session; stored state otherwise."""
    job = _manager(request).jobs.get(scan_id)
    if job is not None:
        return _from_job(job)
    repo = ScanRepository(request.app.state.db)
    scan = repo.get(scan_id)
    options = scan.options or {}
    return ScanOut(
        id=scan.id,
        status=scan.status,
        target_host=None,
        base_url=str(options.get("base_url")) if options.get("base_url") else None,
        progress=None,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        error=None,
        notes=[],
        findings=repo.findings(scan_id),
    )


@router.post("/{scan_id}/stop", status_code=202)
def stop_scan(scan_id: int, request: Request) -> ScanOut:
    """Cancel a running scan (in-flight requests are aborted)."""
    return _from_job(_manager(request).stop(scan_id))


@router.get("/{scan_id}/audit")
def get_audit(scan_id: int, request: Request) -> list[AuditOut]:
    """Every probe the scan sent, in order (URLs redacted)."""
    repo = ScanRepository(request.app.state.db)
    repo.get(scan_id)
    return [AuditOut.model_validate(a, from_attributes=True) for a in repo.audit(scan_id)]
