"""API-OAS-005 — API key passed in the query string."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.openapi._common import OAS_SECURITY_DOCS, OWASP_DOCS
from app.rules.registry import registry
from app.static.openapi.document import OpenApiDocument


@registry.register
class ApiKeyInQueryRule(Rule[OpenApiDocument]):
    """Flags ``type: apiKey, in: query`` security schemes."""

    id: ClassVar[str] = "API-OAS-005"
    title: ClassVar[str] = "API key is sent in the query string"
    category: ClassVar[str] = "Authentication"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.OPENAPI
    description: ClassVar[str] = (
        "Query strings are recorded in server and proxy logs, browser history and Referer "
        "headers, so an API key passed there leaks easily."
    )
    references: ClassVar[References] = References(
        owasp_api=["API2:2023"], cwe=["CWE-598"], links=[OWASP_DOCS, OAS_SECURITY_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "components:\n  securitySchemes:\n    apiKey:\n      type: apiKey\n"
        "      in: header\n      name: X-API-Key"
    )

    def check(self, document: OpenApiDocument) -> list[Finding]:
        """One finding per query-string API key scheme."""
        findings: list[Finding] = []
        for name, res in document.security_schemes().items():
            scheme = res.value
            if (
                isinstance(scheme, dict)
                and str(scheme.get("type", "")).lower() == "apikey"
                and str(scheme.get("in", "")).lower() == "query"
            ):
                findings.append(
                    self.finding(
                        [document.evidence(res.pointer)],
                        title=f"Security scheme '{name}' sends the API key in the query string",
                    )
                )
        return findings
