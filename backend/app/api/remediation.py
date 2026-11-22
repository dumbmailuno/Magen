"""Remediation preview endpoint (Option B: corrected copy for review/export, never applied)."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.models.finding import Finding
from app.remediation.service import preview
from app.static.openapi.loader import MAX_BYTES

router = APIRouter(prefix="/api/remediation", tags=["remediation"])


class PreviewIn(BaseModel):
    """The original text (read in the renderer) and which findings to fix."""

    kind: Literal["openapi", "nginx"]
    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=MAX_BYTES)
    #: Omit to fix every finding in the file.
    finding_ids: list[str] | None = Field(default=None, max_length=1000)


class FixOut(BaseModel):
    """Outcome for one finding."""

    finding_id: str
    rule_id: str
    title: str
    outcome: Literal["applied", "template_only", "conflict"]
    validated: bool | None


class SyntaxOut(BaseModel):
    """External syntax check (nginx -t)."""

    status: str
    message: str


class ValidationOut(BaseModel):
    """How the patched copy was validated."""

    parsed: bool
    error: str | None
    resolved: list[str]
    unresolved: list[str]
    introduced: list[Finding]
    syntax: SyntaxOut


class PreviewOut(BaseModel):
    """Corrected copy + unified diff + validation."""

    filename: str
    patched_filename: str
    patched_content: str
    diff: str
    fixes: list[FixOut]
    validation: ValidationOut


@router.post("/preview")
def preview_endpoint(body: PreviewIn) -> PreviewOut:
    """Generate a corrected copy. Nothing is written to disk."""
    p = preview(body.kind, body.filename, body.content, body.finding_ids)
    v = p.validation
    return PreviewOut(
        filename=p.filename,
        patched_filename=p.patched_filename,
        patched_content=p.patched,
        diff=p.diff,
        fixes=[
            FixOut(
                finding_id=fx.finding.id,
                rule_id=fx.finding.rule_id,
                title=fx.finding.title,
                outcome=fx.outcome,
                validated=fx.validated,
            )
            for fx in p.fixes
        ],
        validation=ValidationOut(
            parsed=v.parsed,
            error=v.error,
            resolved=v.resolved,
            unresolved=v.unresolved,
            introduced=v.introduced,
            syntax=SyntaxOut(status=v.syntax.status, message=v.syntax.message),
        ),
    )
