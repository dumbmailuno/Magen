"""API-OAS-008 — no rate-limiting documented."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.openapi._common import OWASP_DOCS, normalize_name
from app.rules.registry import registry
from app.static.openapi.document import OpenApiDocument

_HINT_HEADERS = ("ratelimit", "xratelimit", "retryafter")


@registry.register
class NoRateLimitHintsRule(Rule[OpenApiDocument]):
    """Flags specs where no operation documents a 429 response or rate-limit headers."""

    id: ClassVar[str] = "API-OAS-008"
    title: ClassVar[str] = "No rate limiting is documented"
    category: ClassVar[str] = "Resource consumption"
    severity: ClassVar[Severity] = Severity.LOW
    target: ClassVar[RuleTarget] = RuleTarget.OPENAPI
    description: ClassVar[str] = (
        "No operation documents a 429 Too Many Requests response or RateLimit / Retry-After "
        "headers. This is a hint, not proof: limits may be enforced by a gateway but are "
        "invisible to clients and reviewers."
    )
    references: ClassVar[References] = References(
        owasp_api=["API4:2023"], cwe=["CWE-770"], links=[OWASP_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "responses:\n  '429':\n    description: Too many requests\n    headers:\n"
        "      Retry-After:\n        schema: { type: integer }"
    )

    def check(self, document: OpenApiDocument) -> list[Finding]:
        """One document-level finding."""
        ops = document.operations()
        if not ops:
            return []
        for op in ops:
            for code, res in document.responses(op):
                if code == "429":
                    return []
                headers = res.value.get("headers")
                if isinstance(headers, dict) and any(
                    normalize_name(h).startswith(_HINT_HEADERS) for h in headers
                ):
                    return []
        return [self.finding([document.evidence("/paths")])]
