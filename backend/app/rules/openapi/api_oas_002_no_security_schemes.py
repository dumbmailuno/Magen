"""API-OAS-002 — no security schemes defined."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.openapi._common import OAS_SECURITY_DOCS, OWASP_DOCS
from app.rules.registry import registry
from app.static.openapi.document import OpenApiDocument


@registry.register
class NoSecuritySchemesRule(Rule[OpenApiDocument]):
    """Flags specs with operations but no ``components.securitySchemes``."""

    id: ClassVar[str] = "API-OAS-002"
    title: ClassVar[str] = "No security schemes are defined"
    category: ClassVar[str] = "Authentication"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.OPENAPI
    description: ClassVar[str] = (
        "The spec defines operations but no components.securitySchemes, so no operation can "
        "declare how callers authenticate. Either the API is entirely public or its "
        "authentication is undocumented."
    )
    references: ClassVar[References] = References(
        owasp_api=["API2:2023"], cwe=["CWE-306"], links=[OWASP_DOCS, OAS_SECURITY_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "components:\n  securitySchemes:\n    bearerAuth:\n      type: http\n"
        "      scheme: bearer\n      bearerFormat: JWT\nsecurity:\n  - bearerAuth: []"
    )

    def check(self, document: OpenApiDocument) -> list[Finding]:
        """One document-level finding."""
        if not document.operations() or document.security_schemes():
            return []
        components = document.data.get("components")
        if isinstance(components, dict) and "securitySchemes" in components:
            pointer = "/components/securitySchemes"
        elif isinstance(components, dict):
            pointer = "/components"
        else:
            pointer = "/openapi"
        return [self.finding([document.evidence(pointer)])]
