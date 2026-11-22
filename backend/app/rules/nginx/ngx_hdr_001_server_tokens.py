"""NGX-HDR-001 — server_tokens not disabled."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, FindingStatus, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.nginx._common import NGINX_CORE_DOCS, OWASP_DOCS
from app.rules.registry import registry
from app.static.nginx.config import NginxConfig


@registry.register
class ServerTokensRule(Rule[NginxConfig]):
    """Flags servers that advertise the nginx version (``server_tokens`` defaults to on)."""

    id: ClassVar[str] = "NGX-HDR-001"
    title: ClassVar[str] = "Nginx version is disclosed"
    category: ClassVar[str] = "Information disclosure"
    severity: ClassVar[Severity] = Severity.LOW
    target: ClassVar[RuleTarget] = RuleTarget.NGINX
    description: ClassVar[str] = (
        "server_tokens is not set to off (its default is on), so nginx reveals its version "
        "in the Server header and on error pages, helping attackers pick known exploits."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"], cwe=["CWE-200"], links=[OWASP_DOCS, NGINX_CORE_DOCS]
    )
    remediation_template: ClassVar[str] = "http {\n    server_tokens off;\n}"

    def check(self, document: NginxConfig) -> list[Finding]:
        """One finding per offending definition (or per http block when left at default)."""
        findings: list[Finding] = []
        for server in document.servers():
            d = document.effective("server_tokens", server.chain)
            if d is not None and d.args and d.args[0] == "off":
                continue
            evidence_at = d or server.http or server.block
            title = (
                f"server_tokens is '{d.args[0] if d.args else ''}'"
                if d is not None
                else "server_tokens is not disabled (defaults to on)"
            )
            findings.append(
                self.finding(
                    [document.evidence(evidence_at)],
                    title=title,
                    status=document.status_for(server.chain)
                    if d is None
                    else FindingStatus.POTENTIAL,
                )
            )
        return findings
