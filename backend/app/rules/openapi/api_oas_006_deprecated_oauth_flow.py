"""API-OAS-006 — OAuth2 implicit or password flow."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.openapi._common import OWASP_DOCS
from app.rules.registry import registry
from app.static.openapi.document import OpenApiDocument
from app.static.openapi.loader import join_pointer

_DEPRECATED = ("implicit", "password")


@registry.register
class DeprecatedOAuthFlowRule(Rule[OpenApiDocument]):
    """Flags OAuth2 flows the OAuth 2.0 Security BCP (RFC 9700) says not to use."""

    id: ClassVar[str] = "API-OAS-006"
    title: ClassVar[str] = "OAuth2 flow is deprecated"
    category: ClassVar[str] = "Authentication"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.OPENAPI
    description: ClassVar[str] = (
        "The implicit flow returns tokens in the URL fragment, and the resource-owner "
        "password flow hands user credentials to the client. RFC 9700 (OAuth 2.0 Security "
        "BCP) says not to use either; use authorization code with PKCE."
    )
    references: ClassVar[References] = References(
        owasp_api=["API2:2023"],
        cwe=["CWE-1390"],
        links=[OWASP_DOCS, "https://www.rfc-editor.org/rfc/rfc9700"],
    )
    remediation_template: ClassVar[str] = (
        "flows:\n  authorizationCode:   # with PKCE\n"
        "    authorizationUrl: https://auth.example.com/authorize\n"
        "    tokenUrl: https://auth.example.com/token\n    scopes: {}"
    )

    def check(self, document: OpenApiDocument) -> list[Finding]:
        """One finding per deprecated flow."""
        findings: list[Finding] = []
        for name, res in document.security_schemes().items():
            scheme = res.value
            if not isinstance(scheme, dict) or str(scheme.get("type", "")).lower() != "oauth2":
                continue
            flows = scheme.get("flows")
            if not isinstance(flows, dict):
                continue
            for flow in _DEPRECATED:
                if flow in flows:
                    ptr = join_pointer(res.pointer, "flows", flow)
                    findings.append(
                        self.finding(
                            [document.evidence(ptr)],
                            title=f"Security scheme '{name}' uses the deprecated {flow} flow",
                        )
                    )
        return findings
