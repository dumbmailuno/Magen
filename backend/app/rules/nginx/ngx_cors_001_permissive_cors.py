"""NGX-CORS-001 — CORS allows any origin."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.nginx._common import NGINX_HEADERS_DOCS, OWASP_DOCS
from app.rules.registry import registry
from app.static.nginx.config import NginxConfig

_ACAO = "access-control-allow-origin"
_ACAC = "access-control-allow-credentials"


@registry.register
class PermissiveCorsRule(Rule[NginxConfig]):
    """Flags ``Access-Control-Allow-Origin: *`` and unvalidated ``$http_origin`` reflection."""

    id: ClassVar[str] = "NGX-CORS-001"
    title: ClassVar[str] = "CORS allows any origin"
    category: ClassVar[str] = "CORS"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.NGINX
    description: ClassVar[str] = (
        "Access-Control-Allow-Origin is * or echoes the request's Origin ($http_origin) "
        "without validation, so any website can read responses. Reflection combined with "
        "Access-Control-Allow-Credentials: true exposes authenticated data. Reflection "
        "inside an if ($http_origin ~ ...) block, or via a map, is treated as validated."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"],
        cwe=["CWE-942"],
        links=[OWASP_DOCS, NGINX_HEADERS_DOCS, "https://portswigger.net/web-security/cors"],
    )
    remediation_template: ClassVar[str] = (
        'map $http_origin $cors_origin {\n    default "";\n'
        '    "~^https://app\\.example\\.com$" $http_origin;\n}\n'
        "add_header Access-Control-Allow-Origin $cors_origin always;\n"
        "add_header Vary Origin always;"
    )

    def check(self, document: NginxConfig) -> list[Finding]:
        """One finding per offending ``add_header``."""
        findings: list[Finding] = []
        for d, ancestors in document.all_directives("add_header"):
            if len(d.args) < 2 or d.args[0].lower() != _ACAO:
                continue
            value = d.args[1].strip()
            reflects = "$http_origin" in value
            if value != "*" and not reflects:
                continue
            guarded = any(a.name == "if" and "$http_origin" in " ".join(a.args) for a in ancestors)
            if guarded:
                continue
            parent = ancestors[-1] if ancestors else document.root
            creds = any(
                len(s.args) >= 2 and s.args[0].lower() == _ACAC and s.args[1].strip('"') == "true"
                for s in parent.find("add_header")
            )
            where = next(
                (
                    f" on location {' '.join(a.args)}"
                    for a in reversed(ancestors)
                    if a.name == "location"
                ),
                "",
            )
            if reflects:
                title = f"CORS reflects any Origin{where}" + (" with credentials" if creds else "")
            else:
                title = f"CORS allows any origin (*){where}"
            findings.append(self.finding([document.evidence(d)], title=title))
        return findings
