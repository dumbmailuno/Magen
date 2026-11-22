"""API-RT-002 — server accepts TLS 1.0 / 1.1."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, FindingStatus, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.registry import registry
from app.rules.runtime._common import OWASP_DOCS, tls_evidence
from app.runtime.observations import RuntimeObservations


@registry.register
class LegacyTlsRuntimeRule(Rule[RuntimeObservations]):
    """A handshake restricted to a legacy protocol succeeded."""

    id: ClassVar[str] = "API-RT-002"
    title: ClassVar[str] = "Server accepts obsolete TLS versions"
    category: ClassVar[str] = "Transport security"
    severity: ClassVar[Severity] = Severity.HIGH
    target: ClassVar[RuleTarget] = RuleTarget.RUNTIME
    description: ClassVar[str] = (
        "A handshake limited to TLS 1.0 or 1.1 succeeded. Both are deprecated (RFC 8996). "
        "If the local TLS library cannot offer a legacy version, it is reported as not "
        "tested, never as refused."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"],
        cwe=["CWE-326"],
        links=[OWASP_DOCS, "https://www.rfc-editor.org/rfc/rfc8996"],
    )
    remediation_template: ClassVar[str] = "ssl_protocols TLSv1.2 TLSv1.3;"

    def check(self, document: RuntimeObservations) -> list[Finding]:
        """One finding listing every accepted legacy protocol."""
        tls = document.tls
        if tls is None:
            return []
        accepted = [name for name, ok in sorted(tls.legacy_protocols.items()) if ok]
        if not accepted:
            return []
        excerpt = "Handshake succeeded with: " + ", ".join(accepted)
        return [
            self.finding(
                [tls_evidence(tls, "tls-legacy", excerpt)],
                status=FindingStatus.CONFIRMED,
                title=f"Server accepts {', '.join(accepted)}",
            )
        ]
