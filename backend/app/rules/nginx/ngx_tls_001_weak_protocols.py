"""NGX-TLS-001 — obsolete SSL/TLS protocol versions enabled."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.nginx._common import NGINX_SSL_DOCS, OWASP_DOCS
from app.rules.registry import registry
from app.static.nginx.config import NginxConfig

_WEAK = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


@registry.register
class WeakTlsProtocolsRule(Rule[NginxConfig]):
    """Flags ``ssl_protocols`` that include SSLv2/3, TLS 1.0 or TLS 1.1."""

    id: ClassVar[str] = "NGX-TLS-001"
    title: ClassVar[str] = "Obsolete TLS protocol versions are enabled"
    category: ClassVar[str] = "Transport security"
    severity: ClassVar[Severity] = Severity.HIGH
    target: ClassVar[RuleTarget] = RuleTarget.NGINX
    description: ClassVar[str] = (
        "SSLv2, SSLv3, TLS 1.0 and TLS 1.1 have known attacks (POODLE, BEAST) and are "
        "deprecated (RFC 8996). Only TLS 1.2 and 1.3 should be offered. When ssl_protocols "
        "is not set, the default depends on the nginx version and is not reported."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"],
        cwe=["CWE-326"],
        links=[OWASP_DOCS, NGINX_SSL_DOCS, "https://www.rfc-editor.org/rfc/rfc8996"],
    )
    remediation_template: ClassVar[str] = "ssl_protocols TLSv1.2 TLSv1.3;"

    def check(self, document: NginxConfig) -> list[Finding]:
        """One finding per ``ssl_protocols`` directive offering a weak version."""
        findings: list[Finding] = []
        for d, _ in document.all_directives("ssl_protocols"):
            weak = [p for p in d.args if p in _WEAK]
            if weak:
                findings.append(
                    self.finding(
                        [document.evidence(d)],
                        title=f"Obsolete protocols enabled: {', '.join(weak)}",
                    )
                )
        return findings
