"""NGX-TLS-002 — weak cipher suites enabled."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.nginx._common import NGINX_SSL_DOCS, OWASP_DOCS
from app.rules.registry import registry
from app.static.nginx.config import NginxConfig

_MARKERS = ("RC4", "DES", "MD5", "NULL", "EXPORT", "ANON")


def _is_weak(token: str) -> bool:
    t = token.upper()
    if t.startswith(("!", "-")):
        return False  # excluded from the list
    t = t.lstrip("+")
    return (
        any(m in t for m in _MARKERS)
        or t.startswith(("EXP-", "EXP1024", "ADH", "AECDH"))
        or t in ("EXP", "ALL", "COMPLEMENTOFALL")
    )


@registry.register
class WeakCiphersRule(Rule[NginxConfig]):
    """Flags ``ssl_ciphers`` lists that enable broken cipher suites."""

    id: ClassVar[str] = "NGX-TLS-002"
    title: ClassVar[str] = "Weak cipher suites are enabled"
    category: ClassVar[str] = "Transport security"
    severity: ClassVar[Severity] = Severity.HIGH
    target: ClassVar[RuleTarget] = RuleTarget.NGINX
    description: ClassVar[str] = (
        "ssl_ciphers enables suites based on RC4, (3)DES, MD5, NULL/anonymous key exchange or "
        "export-grade crypto, which allow decryption or man-in-the-middle attacks. Entries "
        "excluded with ! or - are ignored."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"],
        cwe=["CWE-327"],
        links=[OWASP_DOCS, NGINX_SSL_DOCS, "https://ssl-config.mozilla.org/"],
    )
    remediation_template: ClassVar[str] = (
        "# Mozilla 'intermediate' profile\n"
        "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\n"
        "ssl_prefer_server_ciphers off;"
    )

    def check(self, document: NginxConfig) -> list[Finding]:
        """One finding per ``ssl_ciphers`` directive with weak entries."""
        findings: list[Finding] = []
        for d, _ in document.all_directives("ssl_ciphers"):
            tokens = [t for arg in d.args for t in arg.replace(",", ":").split(":") if t]
            weak = sorted({t.lstrip("+") for t in tokens if _is_weak(t)})
            if weak:
                findings.append(
                    self.finding(
                        [document.evidence(d)],
                        title=f"Weak cipher suites enabled: {', '.join(weak)}",
                    )
                )
        return findings
