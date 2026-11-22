"""AI assistant endpoints (local Ollama only; optional)."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.ai.service import AiService
from app.api.remediation import SyntaxOut
from app.models.finding import Finding
from app.static.openapi.loader import MAX_BYTES

router = APIRouter(prefix="/api/ai", tags=["ai"])


class PullOut(BaseModel):
    """Model download progress."""

    model: str
    status: str
    percent: int | None
    error: str | None
    done: bool


class StatusOut(BaseModel):
    """AI availability for the UI."""

    state: Literal["disabled", "not_running", "model_missing", "downloading", "ready"]
    enabled: bool
    url: str
    model: str
    version: str | None
    models: list[str]
    pull: PullOut | None


class SettingsIn(BaseModel):
    """Preference changes (all optional)."""

    enabled: bool | None = None
    url: str | None = Field(default=None, max_length=200)
    model: str | None = Field(default=None, max_length=200)


class PullIn(BaseModel):
    """Which model to download (defaults to the configured one)."""

    model: str | None = Field(default=None, max_length=200)


class ExplainIn(BaseModel):
    """A stored finding to explain."""

    session_id: int
    finding_id: str = Field(min_length=1, max_length=64)
    force: bool = False


class ExplainOut(BaseModel):
    """Explanation (inside ``finding.ai_explanation``) or the deterministic fallback."""

    state: Literal["ready", "unavailable", "error"]
    message: str | None
    fallback: str
    injection_suspected: bool
    cached: bool
    finding: Finding


class FixIn(BaseModel):
    """A stored finding plus the file it came from (content is not stored)."""

    session_id: int
    finding_id: str = Field(min_length=1, max_length=64)
    kind: Literal["openapi", "nginx"]
    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=MAX_BYTES)


class FixValidationOut(BaseModel):
    """Same checks as template fixes."""

    parsed: bool
    error: str | None
    introduced: list[Finding]
    syntax: SyntaxOut


class FixOut(BaseModel):
    """AI-proposed corrected copy (never applied)."""

    state: Literal["ready", "unavailable", "error"]
    message: str | None
    fallback: str
    injection_suspected: bool
    explanation: str | None
    diff: str
    patched_content: str
    patched_filename: str
    validated: bool
    validation: FixValidationOut | None
    model: str
    prompt_version: str


def _ai(request: Request) -> AiService:
    service: AiService = request.app.state.ai
    return service


async def _status(service: AiService) -> StatusOut:
    s = await service.status()
    cfg = service.config()
    p = s.pull
    return StatusOut(
        state=s.state,
        enabled=cfg.enabled,
        url=s.url,
        model=s.model,
        version=s.version,
        models=s.models,
        pull=PullOut(model=p.model, status=p.status, percent=p.percent, error=p.error, done=p.done)
        if p
        else None,
    )


@router.get("/status")
async def status(request: Request) -> StatusOut:
    """Is the AI assistant usable right now?"""
    return await _status(_ai(request))


@router.put("/settings")
async def update_settings(body: SettingsIn, request: Request) -> StatusOut:
    """Enable/disable AI, choose the model or the (loopback) Ollama URL."""
    service = _ai(request)
    service.update(enabled=body.enabled, url=body.url, model=body.model)
    return await _status(service)


@router.post("/pull", status_code=202)
async def pull(body: PullIn, request: Request) -> StatusOut:
    """Start downloading a model (user-initiated; model output never triggers this)."""
    service = _ai(request)
    service.start_pull(body.model)
    return await _status(service)


@router.post("/explain")
async def explain(body: ExplainIn, request: Request) -> ExplainOut:
    """AI explanation for a stored finding, or the deterministic fallback."""
    r = await _ai(request).explain(body.session_id, body.finding_id, force=body.force)
    return ExplainOut(
        state=r.state,
        message=r.message,
        fallback=r.fallback,
        injection_suspected=r.injection_suspected,
        cached=r.cached,
        finding=r.finding,
    )


@router.post("/fix")
async def fix(body: FixIn, request: Request) -> FixOut:
    """AI-proposed rewrite of the finding's lines, validated like template fixes."""
    r = await _ai(request).fix(
        body.session_id,
        body.finding_id,
        kind=body.kind,
        filename=body.filename,
        content=body.content,
    )
    v = r.validation
    return FixOut(
        state=r.state,
        message=r.message,
        fallback=r.fallback,
        injection_suspected=r.injection_suspected,
        explanation=r.explanation,
        diff=r.diff,
        patched_content=r.patched_content,
        patched_filename=r.patched_filename,
        validated=r.validated,
        validation=FixValidationOut(
            parsed=v.parsed,
            error=v.error,
            introduced=v.introduced,
            syntax=SyntaxOut(status=v.syntax.status, message=v.syntax.message),
        )
        if v
        else None,
        model=r.model,
        prompt_version=r.prompt_version,
    )
