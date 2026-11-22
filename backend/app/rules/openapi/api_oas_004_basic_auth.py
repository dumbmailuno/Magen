"""API-OAS-004 — HTTP Basic authentication scheme."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.openapi._common import OAS_SECURITY_DOCS, OWASP_DOCS
from app.rules.registry import registry
from app.static.openapi.document import OpenApiDocument


@registry.register
class BasicAuthRule(Rule[OpenApiDocument]):
    """Flags ``type: http, scheme: basic`` security schemes."""

    id: ClassVar[str] = "API-OAS-004"
    title: ClassVar[str] = "HTTP Basic authentication is used"
    category: ClassVar[str] = "Authentication"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.OPENAPI
    description: ClassVar[str] = (
        "HTTP Basic sends a reusable username and password (base64, not encrypted) with "
        "every request, cannot be scoped or expired, and invites brute force."
    )
    references: ClassVar[References] = References(
        owasp_api=["API2:2023"], cwe=["CWE-522"], links=[OWASP_DOCS, OAS_SECURITY_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "components:\n  securitySchemes:\n    bearerAuth:   # short-lived, scoped tokens\n"
        "      type: http\n      scheme: bearer\n      bearerFormat: JWT"
    )

    def check(self, document: OpenApiDocument) -> list[Finding]:
        """One finding per Basic scheme."""
        findings: list[Finding] = []
        for name, res in document.security_schemes().items():
            scheme = res.value
            if (
                isinstance(scheme, dict)
                and str(scheme.get("type", "")).lower() == "http"
                and str(scheme.get("scheme", "")).lower() == "basic"
            ):
                findings.append(
                    self.finding(
                        [document.evidence(res.pointer)],
                        title=f"Security scheme '{name}' uses HTTP Basic authentication",
                    )
                )
        return findings
