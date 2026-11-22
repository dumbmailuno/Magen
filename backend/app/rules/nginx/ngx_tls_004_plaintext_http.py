"""NGX-TLS-004 — content served over plain HTTP without an HTTPS redirect."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.nginx._common import NGINX_CORE_DOCS, OWASP_DOCS
from app.rules.registry import registry
from app.static.nginx.config import NginxConfig, redirects


@registry.register
class PlaintextHttpRule(Rule[NginxConfig]):
    """Flags non-loopback plain-HTTP listeners that serve content instead of redirecting."""

    id: ClassVar[str] = "NGX-TLS-004"
    title: ClassVar[str] = "Server accepts plain HTTP without redirecting to HTTPS"
    category: ClassVar[str] = "Transport security"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.NGINX
    description: ClassVar[str] = (
        "A server listens for plain HTTP on a non-loopback address and serves content "
        "instead of redirecting to HTTPS, so requests and credentials travel unencrypted. "
        "A server without listen defaults to port 80. Loopback and unix-socket listeners "
        "are ignored."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"], cwe=["CWE-319"], links=[OWASP_DOCS, NGINX_CORE_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "server {\n    listen 80;\n    server_name api.example.com;\n"
        "    return 301 https://$host$request_uri;\n}"
    )

    def check(self, document: NginxConfig) -> list[Finding]:
        """One finding per affected server."""
        return [
            self.finding(
                [document.evidence(server.block)],
                title=f"{server.label} serves plain HTTP without redirecting to HTTPS",
            )
            for server in document.servers()
            if document.serves_plaintext(server) and not redirects(server, https_only=True)
        ]
