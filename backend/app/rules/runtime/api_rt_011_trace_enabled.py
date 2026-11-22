"""API-RT-011 — TRACE/TRACK advertised as allowed."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, FindingStatus, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.registry import registry
from app.rules.runtime._common import OWASP_DOCS, http_evidence, ok
from app.runtime.observations import RuntimeObservations

_DANGEROUS = ("TRACE", "TRACK")


@registry.register
class TraceAdvertisedRule(Rule[RuntimeObservations]):
    """The OPTIONS response's Allow header lists TRACE or TRACK (never sent by Magen)."""

    id: ClassVar[str] = "API-RT-011"
    title: ClassVar[str] = "TRACE method is advertised"
    category: ClassVar[str] = "Security misconfiguration"
    severity: ClassVar[Severity] = Severity.LOW
    target: ClassVar[RuleTarget] = RuleTarget.RUNTIME
    description: ClassVar[str] = (
        "The Allow header lists TRACE/TRACK, which echo requests back (cross-site tracing "
        "can expose cookies and auth headers). Magen only reads the Allow header; it never "
        "sends TRACE."
    )
    references: ClassVar[References] = References(owasp_api=["API8:2023"], links=[OWASP_DOCS])
    remediation_template: ClassVar[str] = (
        "# nginx does not implement TRACE; disable it on the upstream app server, e.g. Apache:\n"
        "TraceEnable off"
    )

    def check(self, document: RuntimeObservations) -> list[Finding]:
        """Reads ``Allow`` from the OPTIONS response."""
        obs = document.get("base-options")
        if obs is None or not ok(obs):
            return []
        allow = obs.header("allow") or ""
        methods = [m.strip().upper() for m in allow.split(",")]
        found = [m for m in _DANGEROUS if m in methods]
        if not found:
            return []
        return [
            self.finding(
                [http_evidence(obs, f"Allow: {allow}")],
                status=FindingStatus.CONFIRMED,
                title=f"{' and '.join(found)} advertised in Allow header",
            )
        ]
