"""API-RT-001 — API answers over plain HTTP without redirecting to HTTPS."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, FindingStatus, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.registry import registry
from app.rules.runtime._common import OWASP_DOCS, http_evidence, ok
from app.runtime.observations import RuntimeObservations


@registry.register
class PlaintextHttpRuntimeRule(Rule[RuntimeObservations]):
    """Plain-HTTP responses that are not redirects to https://."""

    id: ClassVar[str] = "API-RT-001"
    title: ClassVar[str] = "API responds over plain HTTP"
    category: ClassVar[str] = "Transport security"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.RUNTIME
    description: ClassVar[str] = (
        "The host answered a plain-HTTP request with content instead of redirecting to "
        "HTTPS, so traffic (and any credentials) can be read or altered in transit."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"], cwe=["CWE-319"], links=[OWASP_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "server {\n    listen 80;\n    return 301 https://$host$request_uri;\n}"
    )

    def check(self, document: RuntimeObservations) -> list[Finding]:
        """Checks the dedicated http:// probe, or the base URL when it is http:// itself."""
        for probe_id in ("plain-http", "base-get"):
            obs = document.get(probe_id)
            if not ok(obs) or obs is None or obs.status is None:
                continue
            if not obs.final_url.startswith("http://"):
                continue
            location = obs.header("location") or ""
            if 300 <= obs.status < 400 and location.startswith("https://"):
                continue
            return [
                self.finding(
                    [http_evidence(obs, f"HTTP {obs.status} over plain HTTP (no HTTPS redirect)")],
                    status=FindingStatus.CONFIRMED,
                    title=f"{obs.final_url} responds over plain HTTP",
                )
            ]
        return []
