"""API-RT-004 — HTTPS response without HSTS."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, FindingStatus, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.registry import registry
from app.rules.runtime._common import OWASP_DOCS, hsts_enabled, http_evidence, ok
from app.runtime.observations import RuntimeObservations


@registry.register
class MissingHstsRuntimeRule(Rule[RuntimeObservations]):
    """The base URL's HTTPS response lacks Strict-Transport-Security (max-age > 0)."""

    id: ClassVar[str] = "API-RT-004"
    title: ClassVar[str] = "HTTPS response does not send HSTS"
    category: ClassVar[str] = "Transport security"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.RUNTIME
    description: ClassVar[str] = (
        "The HTTPS response has no Strict-Transport-Security header with max-age > 0, so "
        "browsers can be downgraded to HTTP by an active attacker."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"],
        cwe=["CWE-319"],
        links=[OWASP_DOCS, "https://www.rfc-editor.org/rfc/rfc6797"],
    )
    remediation_template: ClassVar[str] = (
        'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
    )

    def check(self, document: RuntimeObservations) -> list[Finding]:
        """Checks the base URL response."""
        obs = document.get("base-get")
        if obs is None or not ok(obs) or not obs.final_url.startswith("https://"):
            return []
        if hsts_enabled(obs):
            return []
        value = obs.header("strict-transport-security")
        excerpt = (
            f"Strict-Transport-Security: {value}"
            if value is not None
            else "Strict-Transport-Security: (absent)"
        )
        return [self.finding([http_evidence(obs, excerpt)], status=FindingStatus.CONFIRMED)]
