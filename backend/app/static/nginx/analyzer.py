"""Nginx analysis service: parse → run every active Nginx rule → canonical order."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import app.rules.nginx  # noqa: F401  (registers the Nginx rules)
from app.models.finding import Finding, sort_findings
from app.rules.base import RuleTarget
from app.rules.registry import registry
from app.static.nginx.config import NginxConfig

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class UnresolvedInclude:
    """An ``include`` we did not follow (we only analyse the text provided)."""

    path: str
    line: int


@dataclass(frozen=True)
class NginxAnalysis:
    """Result of analysing one config."""

    source_name: str
    server_count: int
    is_snippet: bool
    unresolved_includes: tuple[UnresolvedInclude, ...]
    rules_run: tuple[str, ...]
    findings: tuple[Finding, ...]


def analyze_nginx(text: str, source_name: str) -> NginxAnalysis:
    """Deterministically analyse an Nginx config (no network, no filesystem, no AI)."""
    config = NginxConfig(source_name, text)
    rules = registry.for_target(RuleTarget.NGINX)
    findings: list[Finding] = []
    for rule_cls in rules:
        findings.extend(rule_cls().check(config))
    ordered = sort_findings(findings)
    log.info(
        "nginx analysis complete",
        extra={"source": config.source_name, "rules": len(rules), "findings": len(ordered)},
    )
    return NginxAnalysis(
        source_name=config.source_name,
        server_count=len(config.servers()),
        is_snippet=config.is_snippet,
        unresolved_includes=tuple(
            UnresolvedInclude(" ".join(d.args), d.line) for d in config.includes()
        ),
        rules_run=tuple(r.id for r in rules),
        findings=tuple(ordered),
    )
