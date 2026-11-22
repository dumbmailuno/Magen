"""API-OAS-003 — operation can be called without authentication."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.openapi._common import OAS_SECURITY_DOCS, OWASP_DOCS
from app.rules.registry import registry
from app.static.openapi.document import OpenApiDocument


@registry.register
class UnauthenticatedOperationRule(Rule[OpenApiDocument]):
    """Flags operations whose effective security is absent, empty, or optional."""

    id: ClassVar[str] = "API-OAS-003"
    title: ClassVar[str] = "Operation does not require authentication"
    category: ClassVar[str] = "Authentication"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.OPENAPI
    description: ClassVar[str] = (
        "The operation's effective security requirement (its own, else the root one) is "
        "missing, empty (security: []), or contains {} which makes authentication optional. "
        "Intentionally public endpoints (health, login) also match; review and accept them."
    )
    references: ClassVar[References] = References(
        owasp_api=["API2:2023"], cwe=["CWE-306"], links=[OWASP_DOCS, OAS_SECURITY_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "# Require auth globally; opt specific public operations out explicitly.\n"
        "security:\n  - bearerAuth: []"
    )

    def check(self, document: OpenApiDocument) -> list[Finding]:
        """One finding per affected operation."""
        findings: list[Finding] = []
        for op in document.operations():
            security, pointer = document.effective_security(op)
            if isinstance(security, list) and security:
                if not any(req == {} for req in security):
                    continue
                title = f"{op.label} allows anonymous access (authentication is optional)"
            else:
                title = f"{op.label} does not require authentication"
            # The operation's own `security` is the most precise evidence. When the
            # requirement is inherited from the root, point at the operation so each
            # operation keeps a distinct, stable finding id.
            evidence_ptr = pointer if "security" in op.node else op.pointer
            findings.append(self.finding([document.evidence(evidence_ptr)], title=title))
        return findings
