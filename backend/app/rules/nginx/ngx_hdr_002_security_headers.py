"""NGX-HDR-002 — missing browser security headers."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.nginx._common import NGINX_HEADERS_DOCS, OWASP_DOCS, OWASP_HEADERS
from app.rules.registry import registry
from app.static.nginx.config import NginxConfig, header_contexts, redirects
from app.static.nginx.parser import Directive


def _missing(headers: list[Directive]) -> list[str]:
    value = NginxConfig.header_value
    missing: list[str] = []
    if (value(headers, "X-Content-Type-Options") or "").strip('"').lower() != "nosniff":
        missing.append("X-Content-Type-Options")
    csp = (value(headers, "Content-Security-Policy") or "").lower()
    if value(headers, "X-Frame-Options") is None and "frame-ancestors" not in csp:
        missing.append("X-Frame-Options / CSP frame-ancestors")
    return missing


@registry.register
class SecurityHeadersRule(Rule[NginxConfig]):
    """Flags contexts without nosniff and clickjacking protection."""

    id: ClassVar[str] = "NGX-HDR-002"
    title: ClassVar[str] = "Security headers are missing"
    category: ClassVar[str] = "Security headers"
    severity: ClassVar[Severity] = Severity.LOW
    target: ClassVar[RuleTarget] = RuleTarget.NGINX
    description: ClassVar[str] = (
        "Responses lack X-Content-Type-Options: nosniff and/or clickjacking protection "
        "(X-Frame-Options or CSP frame-ancestors). Locations with their own add_header do "
        "not inherit the server's headers and are checked separately. Servers that only "
        "redirect are skipped."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"],
        cwe=["CWE-693"],
        links=[OWASP_DOCS, NGINX_HEADERS_DOCS, OWASP_HEADERS],
    )
    remediation_template: ClassVar[str] = (
        'add_header X-Content-Type-Options "nosniff" always;\n'
        'add_header X-Frame-Options "DENY" always;\n'
        "# Repeat in every location that has its own add_header (or use an include snippet)."
    )

    def check(self, document: NginxConfig) -> list[Finding]:
        """Server-level gaps, plus headers a location drops through inheritance."""
        findings: list[Finding] = []
        for server in document.servers():
            if redirects(server):
                continue
            for hc in header_contexts(document, server):
                missing = _missing(hc.headers)
                if hc.inherited is None:
                    if not missing:
                        continue
                    title = f"{server.label} is missing {', '.join(missing)}"
                else:
                    dropped = [h for h in missing if h not in _missing(hc.inherited)]
                    if not dropped:
                        continue
                    title = (
                        f"{hc.context.label} drops {', '.join(dropped)}: its add_header "
                        "replaces the inherited headers"
                    )
                findings.append(
                    self.finding(
                        [document.evidence(hc.context.block)],
                        title=title,
                        status=document.status_for(hc.context.chain),
                    )
                )
        return findings
