"""NGX-CFG-002 — status / debug endpoint exposed without access control."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.nginx._common import OWASP_DOCS
from app.rules.registry import registry
from app.static.nginx.config import Context, NginxConfig

_STATUS_DIRECTIVES = frozenset({"stub_status", "status", "vhost_traffic_status_display", "api"})
_SENSITIVE_PATHS = (
    "nginx_status",
    "server-status",
    "stub_status",
    "/actuator",
    "/debug",
    "phpinfo",
    "/metrics",
    "/.git",
    "/.env",
    "/.svn",
)


def _restricted(ctx: Context) -> bool:
    for level in ctx.chain:
        for d in level.children or ():
            if d.name == "deny" and d.args == ("all",):
                return True
            if d.name == "auth_basic" and d.args and d.args[0] != "off":
                return True
            if d.name in ("auth_request", "internal"):
                return True
            if (
                level is ctx.block
                and d.name == "return"
                and d.args
                and d.args[0] in ("403", "404", "444")
            ):
                return True
    return False


@registry.register
class ExposedStatusRule(Rule[NginxConfig]):
    """Flags status/debug/VCS locations reachable without allow/deny, auth or internal."""

    id: ClassVar[str] = "NGX-CFG-002"
    title: ClassVar[str] = "Status or debug endpoint is publicly reachable"
    category: ClassVar[str] = "Information disclosure"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.NGINX
    description: ClassVar[str] = (
        "A location serves server status (stub_status), a debug/metrics/actuator path, or "
        "a VCS/env file path without deny all, authentication, internal or a 403/404 "
        "return. These leak internals and sometimes allow control actions."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023", "API9:2023"],
        cwe=["CWE-200"],
        links=[OWASP_DOCS, "https://nginx.org/en/docs/http/ngx_http_stub_status_module.html"],
    )
    remediation_template: ClassVar[str] = (
        "location = /nginx_status {\n    stub_status;\n    allow 127.0.0.1;\n    deny all;\n}\n"
        "location ~ /\\.(git|svn|env) {\n    deny all;\n}"
    )

    def check(self, document: NginxConfig) -> list[Finding]:
        """One finding per exposed location."""
        findings: list[Finding] = []
        for server in document.servers():
            for ctx in document.contexts(server):
                if ctx.block.name != "location" or not ctx.block.args:
                    continue
                path = ctx.block.args[-1].lower().replace("\\", "")
                serves_status = any(c.name in _STATUS_DIRECTIVES for c in ctx.block.children or ())
                if not (serves_status or any(p in path for p in _SENSITIVE_PATHS)):
                    continue
                if _restricted(ctx):
                    continue
                findings.append(
                    self.finding(
                        [document.evidence(ctx.block)],
                        title=f"{ctx.label} is reachable without access control",
                        status=document.status_for(ctx.chain),
                    )
                )
        return findings
