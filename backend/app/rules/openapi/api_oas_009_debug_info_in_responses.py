"""API-OAS-009 — response schema exposes stack traces or debug data."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.openapi._common import (
    OWASP_DOCS,
    media_schemas,
    normalize_name,
    walk_schema_properties,
)
from app.rules.registry import registry
from app.static.openapi.document import OpenApiDocument

#: Normalized property names that indicate internal error detail. Exact matches only, so
#: ``traceId`` / ``debugMode`` style fields are not flagged.
_LEAKY = frozenset(
    {
        "stacktrace",
        "stack",
        "trace",
        "backtrace",
        "exception",
        "innerexception",
        "exceptiontrace",
        "debug",
        "debuginfo",
        "debugmessage",
        "sqlquery",
        "sqlerror",
    }
)


@registry.register
class DebugInfoInResponsesRule(Rule[OpenApiDocument]):
    """Flags response properties such as ``stackTrace`` or ``exception``."""

    id: ClassVar[str] = "API-OAS-009"
    title: ClassVar[str] = "Response schema exposes internal error details"
    category: ClassVar[str] = "Information disclosure"
    severity: ClassVar[Severity] = Severity.LOW
    target: ClassVar[RuleTarget] = RuleTarget.OPENAPI
    description: ClassVar[str] = (
        "A response schema contains a field like stackTrace, exception or debug. Returning "
        "internal error detail helps attackers map the stack and craft further attacks."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"], cwe=["CWE-209"], links=[OWASP_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "# Return a generic problem object; log details server-side only.\n"
        "Problem:\n  type: object\n  properties:\n    type: { type: string }\n"
        "    title: { type: string }\n    status: { type: integer }\n    traceId: { type: string }"
    )

    def check(self, document: OpenApiDocument) -> list[Finding]:
        """One finding per leaky property location (deduplicated across operations)."""
        hits: dict[str, str] = {}
        for op in document.operations():
            for _code, res in document.responses(op):
                for schema, ptr in media_schemas(document, res):
                    for name, prop_ptr in walk_schema_properties(document, schema, ptr):
                        if normalize_name(name) in _LEAKY:
                            hits.setdefault(prop_ptr, name)
        return [
            self.finding(
                [document.evidence(ptr)],
                title=f"Response schema exposes '{name}'",
            )
            for ptr, name in sorted(hits.items())
        ]
