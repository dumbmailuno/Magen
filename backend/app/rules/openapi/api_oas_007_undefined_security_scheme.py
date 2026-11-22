"""API-OAS-007 — security requirement names an undefined scheme."""

from __future__ import annotations

from typing import Any, ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.openapi._common import OAS_SECURITY_DOCS, OWASP_DOCS
from app.rules.registry import registry
from app.static.openapi.document import OpenApiDocument
from app.static.openapi.loader import join_pointer


@registry.register
class UndefinedSecuritySchemeRule(Rule[OpenApiDocument]):
    """Flags security requirements referring to names missing from securitySchemes."""

    id: ClassVar[str] = "API-OAS-007"
    title: ClassVar[str] = "Security requirement references an undefined scheme"
    category: ClassVar[str] = "Security misconfiguration"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.OPENAPI
    description: ClassVar[str] = (
        "A security requirement names a scheme that is not defined in "
        "components.securitySchemes. Tooling and gateways generated from the spec may "
        "silently skip the requirement, leaving the operation unprotected."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"], links=[OWASP_DOCS, OAS_SECURITY_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "# Define every scheme you reference (names are case-sensitive):\n"
        "components:\n  securitySchemes:\n    bearerAuth:\n      type: http\n      scheme: bearer"
    )

    def check(self, document: OpenApiDocument) -> list[Finding]:
        """One finding per (requirement location, undefined name)."""
        defined = set(document.security_schemes())
        sources: list[tuple[Any, str]] = [(document.data.get("security"), "/security")]
        sources += [
            (op.node.get("security"), join_pointer(op.pointer, "security"))
            for op in document.operations()
        ]
        findings: list[Finding] = []
        for requirements, pointer in sources:
            if not isinstance(requirements, list):
                continue
            for i, req in enumerate(requirements):
                if not isinstance(req, dict):
                    continue
                for name in sorted(req):
                    if name not in defined:
                        ptr = join_pointer(pointer, i, name)
                        findings.append(
                            self.finding(
                                [document.evidence(ptr)],
                                title=f"Security requirement references undefined scheme '{name}'",
                            )
                        )
        return findings
