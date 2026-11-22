"""NGX-CFG-001 — directory listing enabled."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.nginx._common import OWASP_DOCS
from app.rules.registry import registry
from app.static.nginx.config import NginxConfig


@registry.register
class AutoindexRule(Rule[NginxConfig]):
    """Flags ``autoindex on`` anywhere."""

    id: ClassVar[str] = "NGX-CFG-001"
    title: ClassVar[str] = "Directory listing is enabled"
    category: ClassVar[str] = "Information disclosure"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.NGINX
    description: ClassVar[str] = (
        "autoindex on lists every file in a directory, exposing backups, configs and other "
        "files that were never meant to be linked."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"],
        cwe=["CWE-548"],
        links=[OWASP_DOCS, "https://nginx.org/en/docs/http/ngx_http_autoindex_module.html"],
    )
    remediation_template: ClassVar[str] = "location /files/ {\n    autoindex off;\n}"

    def check(self, document: NginxConfig) -> list[Finding]:
        """One finding per ``autoindex on``."""
        findings: list[Finding] = []
        for d, ancestors in document.all_directives("autoindex"):
            if d.args and d.args[0] == "on":
                where = next((a for a in reversed(ancestors) if a.name == "location"), None)
                title = (
                    f"Directory listing is enabled for location {' '.join(where.args)}"
                    if where
                    else "Directory listing is enabled"
                )
                findings.append(self.finding([document.evidence(d)], title=title))
        return findings
