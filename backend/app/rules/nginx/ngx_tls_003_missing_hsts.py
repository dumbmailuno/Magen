"""NGX-TLS-003 — HTTPS server does not send HSTS."""

from __future__ import annotations

import re
from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.nginx._common import NGINX_HEADERS_DOCS, OWASP_DOCS
from app.rules.registry import registry
from app.static.nginx.config import NginxConfig, header_contexts
from app.static.nginx.parser import Directive

_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)


def _has_hsts(headers: list[Directive]) -> bool:
    value = NginxConfig.header_value(headers, "Strict-Transport-Security")
    m = _MAX_AGE.search(value or "")
    return bool(m and int(m.group(1)) > 0)


@registry.register
class MissingHstsRule(Rule[NginxConfig]):
    """Flags TLS servers (and locations dropping inherited headers) without HSTS."""

    id: ClassVar[str] = "NGX-TLS-003"
    title: ClassVar[str] = "HSTS header is not sent"
    category: ClassVar[str] = "Transport security"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.NGINX
    description: ClassVar[str] = (
        "Without Strict-Transport-Security (max-age > 0), clients can be downgraded to HTTP "
        "by an active attacker (SSL stripping). Note nginx's inheritance rule: a location "
        "with any add_header of its own does not inherit the server's headers, so it "
        "silently drops HSTS."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"],
        cwe=["CWE-319"],
        links=[OWASP_DOCS, NGINX_HEADERS_DOCS, "https://www.rfc-editor.org/rfc/rfc6797"],
    )
    remediation_template: ClassVar[str] = (
        'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n'
        "# Repeat in every location that has its own add_header (or use an include snippet)."
    )

    def check(self, document: NginxConfig) -> list[Finding]:
        """Server-level gaps, plus locations that drop an inherited HSTS header."""
        findings: list[Finding] = []
        for server in document.servers():
            if not document.is_tls(server):
                continue
            for hc in header_contexts(document, server):
                if _has_hsts(hc.headers):
                    continue
                declared = NginxConfig.header_value(hc.headers, "Strict-Transport-Security")
                where = hc.context.label if hc.inherited is not None else server.label
                if declared is not None and (hc.inherited is None or _has_hsts(hc.inherited)):
                    title = f"{where} disables HSTS (max-age is 0 or missing)"
                elif hc.inherited is None:
                    title = f"HTTPS server {server.label} does not send HSTS"
                elif _has_hsts(hc.inherited):
                    title = (
                        f"{hc.context.label} drops HSTS: its add_header replaces the "
                        "inherited headers"
                    )
                else:
                    continue  # already reported at the server level
                findings.append(
                    self.finding(
                        [document.evidence(hc.context.block)],
                        title=title,
                        status=document.status_for(hc.context.chain),
                    )
                )
        return findings
