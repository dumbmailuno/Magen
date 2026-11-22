"""Health, version and rule catalogue endpoints."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

import app.rules.openapi  # noqa: F401  (register rules so /api/rules lists them)
from app import __version__
from app.models.finding import References, Severity
from app.rules.base import RuleTarget
from app.rules.registry import registry
from app.version import commit_hash, generated_by

router = APIRouter(prefix="/api", tags=["meta"])


class Health(BaseModel):
    """Liveness payload polled by Electron's backend manager."""

    status: str
    version: str
    commit: str
    generated_by: str


class RuleInfo(BaseModel):
    """Public description of a detection rule."""

    id: str
    title: str
    category: str
    severity: Severity
    target: RuleTarget
    description: str
    references: References
    deprecated: bool


@router.get("/health")
def health() -> Health:
    """Report that the backend is up, with build provenance."""
    return Health(
        status="ok", version=__version__, commit=commit_hash(), generated_by=generated_by()
    )


@router.get("/rules")
def list_rules() -> list[RuleInfo]:
    """List every registered rule (including deprecated), sorted by id."""
    return [
        RuleInfo(
            id=r.id,
            title=r.title,
            category=r.category,
            severity=r.severity,
            target=r.target,
            description=r.description,
            references=r.references,
            deprecated=r.deprecated,
        )
        for r in registry.all(include_deprecated=True)
    ]
