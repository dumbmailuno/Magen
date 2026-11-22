"""API-RT-003 — certificate fails verification."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, FindingStatus, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.registry import registry
from app.rules.runtime._common import OWASP_DOCS, tls_evidence
from app.runtime.observations import RuntimeObservations


@registry.register
class UntrustedCertificateRule(Rule[RuntimeObservations]):
    """The default trust store rejected the server certificate."""

    id: ClassVar[str] = "API-RT-003"
    title: ClassVar[str] = "TLS certificate is not trusted"
    category: ClassVar[str] = "Transport security"
    severity: ClassVar[Severity] = Severity.HIGH
    target: ClassVar[RuleTarget] = RuleTarget.RUNTIME
    description: ClassVar[str] = (
        "Certificate verification failed (expired, self-signed, untrusted issuer or host "
        "name mismatch). Clients either fail or are trained to ignore warnings, which "
        "enables man-in-the-middle attacks. Expected for local lab targets."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"], cwe=["CWE-295"], links=[OWASP_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "# Use a certificate from a trusted CA (e.g. Let's Encrypt) covering this host name\n"
        "ssl_certificate     /etc/ssl/fullchain.pem;\nssl_certificate_key /etc/ssl/privkey.pem;"
    )

    def check(self, document: RuntimeObservations) -> list[Finding]:
        """One finding with the verification error."""
        tls = document.tls
        if tls is None or tls.verified is not False:
            return []
        reason = tls.verify_error or "verification failed"
        return [
            self.finding(
                [tls_evidence(tls, "tls-verify", f"Certificate verification failed: {reason}")],
                status=FindingStatus.CONFIRMED,
                title=f"TLS certificate is not trusted ({reason})",
            )
        ]
