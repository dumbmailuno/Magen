"""API-RT-008 — error responses expose stack traces."""

from __future__ import annotations

import re
from typing import ClassVar, Final

from app.models.finding import Finding, FindingStatus, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.registry import registry
from app.rules.runtime._common import OWASP_DOCS, http_evidence, ok
from app.runtime.observations import RuntimeObservations

#: Signatures of framework stack traces / debug pages. Matched per line.
SIGNATURES: Final = (
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"File \"[^\"]+\", line \d+"),
    re.compile(r"\bat [\w$.]+\([\w$]+\.java:\d+\)"),
    re.compile(r"\bat [\w.<>]+ in [^\s]+\.cs:line \d+"),
    re.compile(r"Exception in thread \""),
    re.compile(r"Werkzeug Debugger"),
    re.compile(r"(?i)<title>[^<]*(exception|stack ?trace|error at)[^<]*</title>"),
    re.compile(r"\bat .+ \(.+\.(js|ts):\d+:\d+\)"),
)


@registry.register
class VerboseErrorsRule(Rule[RuntimeObservations]):
    """A stack trace or debug page in the not-found or base response."""

    id: ClassVar[str] = "API-RT-008"
    title: ClassVar[str] = "Error response exposes a stack trace"
    category: ClassVar[str] = "Information disclosure"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.RUNTIME
    description: ClassVar[str] = (
        "A response contains a stack trace or framework debug page, revealing file paths, "
        "library versions and code structure. Detected by fixed signatures (Python, Java, "
        ".NET, Node, Werkzeug)."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"], cwe=["CWE-209"], links=[OWASP_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "# Disable debug mode in production and return a generic error body, e.g.\n"
        '{"type": "about:blank", "title": "Not Found", "status": 404}'
    )

    def check(self, document: RuntimeObservations) -> list[Finding]:
        """First matching line in the not-found, then base, response."""
        for probe_id in ("not-found", "base-get"):
            obs = document.get(probe_id)
            if obs is None or not ok(obs) or obs.body_withheld:
                continue
            for line in obs.body_excerpt.splitlines():
                if any(sig.search(line) for sig in SIGNATURES):
                    return [
                        self.finding(
                            [http_evidence(obs, line.strip()[:200])],
                            status=FindingStatus.CONFIRMED,
                        )
                    ]
        return []
