"""API-RT-010 — status / debug endpoint publicly reachable."""

from __future__ import annotations

from typing import ClassVar, Final

from app.models.finding import Finding, FindingStatus, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.registry import registry
from app.rules.runtime._common import OWASP_DOCS, http_evidence
from app.runtime.observations import RuntimeObservations

#: probe id → (path, content marker that proves it is the real thing)
_MARKERS: Final = {
    "path-nginx-status": ("/nginx_status", "Active connections:"),
    "path-server-status": ("/server-status", "Server Status"),
    "path-actuator": ("/actuator", '"_links"'),
    "path-phpinfo": ("/phpinfo.php", "PHP Version"),
}


@registry.register
class ExposedStatusRuntimeRule(Rule[RuntimeObservations]):
    """A well-known status/debug path returned 200 with its characteristic content."""

    id: ClassVar[str] = "API-RT-010"
    title: ClassVar[str] = "Status or debug endpoint is publicly reachable"
    category: ClassVar[str] = "Information disclosure"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.RUNTIME
    description: ClassVar[str] = (
        "A server-status, nginx stub_status, Spring actuator or phpinfo page is served to "
        "anonymous clients. A content marker is required, so generic 200 pages (SPA "
        "fallbacks) are not reported."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023", "API9:2023"], cwe=["CWE-200"], links=[OWASP_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "location = /nginx_status {\n    stub_status;\n    allow 127.0.0.1;\n    deny all;\n}"
    )

    def check(self, document: RuntimeObservations) -> list[Finding]:
        """One finding per exposed endpoint."""
        findings: list[Finding] = []
        for probe_id, (path, marker) in _MARKERS.items():
            obs = document.get(probe_id)
            if obs is None or obs.status != 200 or marker not in obs.body_excerpt:
                continue
            findings.append(
                self.finding(
                    [http_evidence(obs, f"GET {path} → 200 containing {marker!r}")],
                    status=FindingStatus.CONFIRMED,
                    title=f"{path} is publicly reachable",
                )
            )
        return findings
