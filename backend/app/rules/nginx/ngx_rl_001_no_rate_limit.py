"""NGX-RL-001 — no request rate limiting configured."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.nginx._common import OWASP_DOCS
from app.rules.registry import registry
from app.static.nginx.config import NginxConfig


@registry.register
class NoRateLimitRule(Rule[NginxConfig]):
    """Flags configs with servers but no ``limit_req`` applied anywhere."""

    id: ClassVar[str] = "NGX-RL-001"
    title: ClassVar[str] = "No request rate limiting is configured"
    category: ClassVar[str] = "Resource consumption"
    severity: ClassVar[Severity] = Severity.LOW
    target: ClassVar[RuleTarget] = RuleTarget.NGINX
    description: ClassVar[str] = (
        "No limit_req directive applies a rate limit (a limit_req_zone alone does nothing). "
        "Clients can send unlimited requests, enabling brute force and resource exhaustion. "
        "Limits may exist in an upstream gateway or an included file."
    )
    references: ClassVar[References] = References(
        owasp_api=["API4:2023"],
        cwe=["CWE-770"],
        links=[OWASP_DOCS, "https://nginx.org/en/docs/http/ngx_http_limit_req_module.html"],
    )
    remediation_template: ClassVar[str] = (
        "http {\n    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;\n"
        "    server {\n        location / {\n            limit_req zone=api burst=20 nodelay;\n"
        "        }\n    }\n}"
    )

    def check(self, document: NginxConfig) -> list[Finding]:
        """One document-level finding."""
        servers = document.servers()
        if not servers or document.all_directives("limit_req"):
            return []
        anchor = servers[0].http or servers[0].block
        chain = (anchor,)
        return [self.finding([document.evidence(anchor)], status=document.status_for(chain))]
