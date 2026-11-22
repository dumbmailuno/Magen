"""API-RT-005 — response lacks nosniff / clickjacking protection."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, FindingStatus, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.registry import registry
from app.rules.runtime._common import OWASP_DOCS, OWASP_HEADERS, http_evidence, ok
from app.runtime.observations import RuntimeObservations


@registry.register
class SecurityHeadersRuntimeRule(Rule[RuntimeObservations]):
    """Base response missing X-Content-Type-Options: nosniff and/or frame protection."""

    id: ClassVar[str] = "API-RT-005"
    title: ClassVar[str] = "Response is missing security headers"
    category: ClassVar[str] = "Security headers"
    severity: ClassVar[Severity] = Severity.LOW
    target: ClassVar[RuleTarget] = RuleTarget.RUNTIME
    description: ClassVar[str] = (
        "The response lacks X-Content-Type-Options: nosniff and/or clickjacking protection "
        "(X-Frame-Options or a CSP frame-ancestors directive)."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"], cwe=["CWE-693"], links=[OWASP_DOCS, OWASP_HEADERS]
    )
    remediation_template: ClassVar[str] = (
        'add_header X-Content-Type-Options "nosniff" always;\n'
        'add_header X-Frame-Options "DENY" always;'
    )

    def check(self, document: RuntimeObservations) -> list[Finding]:
        """Checks the base URL response (redirects excluded)."""
        obs = document.get("base-get")
        if obs is None or not ok(obs) or obs.status is None or 300 <= obs.status < 400:
            return []
        missing: list[str] = []
        if (obs.header("x-content-type-options") or "").strip().lower() != "nosniff":
            missing.append("X-Content-Type-Options")
        csp = (obs.header("content-security-policy") or "").lower()
        if obs.header("x-frame-options") is None and "frame-ancestors" not in csp:
            missing.append("X-Frame-Options / CSP frame-ancestors")
        if not missing:
            return []
        return [
            self.finding(
                [http_evidence(obs, "Missing: " + ", ".join(missing))],
                status=FindingStatus.CONFIRMED,
                title=f"Response is missing {', '.join(missing)}",
            )
        ]
