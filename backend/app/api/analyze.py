"""Stateless static-analysis endpoints (scan persistence arrives with the scan flow)."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.models.finding import Finding
from app.static.openapi.analyzer import analyze_openapi
from app.static.openapi.loader import MAX_BYTES
from app.version import generated_by

router = APIRouter(prefix="/api/analyze", tags=["analyze"])


class OpenApiInput(BaseModel):
    """An OpenAPI document submitted as text (the renderer reads the file locally)."""

    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=MAX_BYTES)


class OpenApiResult(BaseModel):
    """Findings for one spec, with provenance."""

    generated_by: str
    source_name: str
    openapi_version: str
    operation_count: int
    rules_run: list[str]
    findings: list[Finding]


@router.post("/openapi")
def analyze_openapi_endpoint(body: OpenApiInput) -> OpenApiResult:
    """Run every OpenAPI rule over the submitted document."""
    result = analyze_openapi(body.content, body.filename)
    return OpenApiResult(
        generated_by=generated_by(),
        source_name=result.source_name,
        openapi_version=result.openapi_version,
        operation_count=result.operation_count,
        rules_run=list(result.rules_run),
        findings=list(result.findings),
    )
