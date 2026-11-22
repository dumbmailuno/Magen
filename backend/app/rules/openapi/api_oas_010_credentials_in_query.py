"""API-OAS-010 — credential-like parameter passed in the URL."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.openapi._common import OWASP_DOCS, normalize_name
from app.rules.registry import registry
from app.static.openapi.document import OpenApiDocument

_SENSITIVE = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "clientsecret",
        "token",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "authtoken",
        "apikey",
        "sessionid",
        "sessiontoken",
    }
)


@registry.register
class CredentialsInQueryRule(Rule[OpenApiDocument]):
    """Flags query/path parameters whose names indicate credentials."""

    id: ClassVar[str] = "API-OAS-010"
    title: ClassVar[str] = "Credential is passed in the URL"
    category: ClassVar[str] = "Authentication"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.OPENAPI
    description: ClassVar[str] = (
        "A query or path parameter is named like a credential (password, token, apiKey, "
        "sessionId...). URLs are logged by servers and proxies and kept in browser history."
    )
    references: ClassVar[References] = References(
        owasp_api=["API2:2023"], cwe=["CWE-598"], links=[OWASP_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "# Send credentials in a header or request body, never the URL:\n"
        "components:\n  securitySchemes:\n    bearerAuth:\n      type: http\n      scheme: bearer"
    )

    def check(self, document: OpenApiDocument) -> list[Finding]:
        """One finding per parameter definition (a shared $ref'd parameter counts once)."""
        hits: dict[str, tuple[str, str]] = {}
        for op in document.operations():
            for res in document.parameters(op):
                param = res.value
                where = str(param.get("in", "")).lower()
                name = str(param.get("name", ""))
                if where in ("query", "path") and normalize_name(name) in _SENSITIVE:
                    hits.setdefault(res.pointer, (name, where))
        return [
            self.finding(
                [document.evidence(ptr)],
                title=f"Credential '{name}' is passed in the {where} string"
                if where == "query"
                else f"Credential '{name}' is passed in the URL path",
            )
            for ptr, (name, where) in sorted(hits.items())
        ]
