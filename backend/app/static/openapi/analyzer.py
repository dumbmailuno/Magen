"""OpenAPI analysis service: parse → run every active OpenAPI rule → canonical order."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import app.rules.openapi  # noqa: F401  (registers the OpenAPI rules)
from app.models.finding import Finding, sort_findings
from app.rules.base import RuleTarget
from app.rules.registry import registry
from app.static.openapi.document import OpenApiDocument

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class OpenApiAnalysis:
    """Result of analysing one spec."""

    source_name: str
    openapi_version: str
    operation_count: int
    rules_run: tuple[str, ...]
    findings: tuple[Finding, ...]


def analyze_openapi(text: str, source_name: str) -> OpenApiAnalysis:
    """Deterministically analyse an OpenAPI 3.x document (no network, no AI).

    Raises :class:`~app.static.openapi.document.OpenApiParseError` for unparseable input.
    """
    doc = OpenApiDocument(source_name, text)
    rules = registry.for_target(RuleTarget.OPENAPI)
    findings: list[Finding] = []
    for rule_cls in rules:
        findings.extend(rule_cls().check(doc))
    ordered = sort_findings(findings)
    log.info(
        "openapi analysis complete",
        extra={"source": doc.source_name, "rules": len(rules), "findings": len(ordered)},
    )
    return OpenApiAnalysis(
        source_name=doc.source_name,
        openapi_version=doc.version,
        operation_count=len(doc.operations()),
        rules_run=tuple(r.id for r in rules),
        findings=tuple(ordered),
    )
