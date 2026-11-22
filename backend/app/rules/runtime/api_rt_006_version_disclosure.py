"""API-RT-006 — software versions disclosed in response headers."""

from __future__ import annotations

import re
from typing import ClassVar, Final

from app.models.finding import Finding, FindingStatus, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.registry import registry
from app.rules.runtime._common import OWASP_DOCS, http_evidence, ok
from app.runtime.observations import RuntimeObservations

_VERSIONED: Final = re.compile(r"\d+\.\d+")
_ALWAYS_REVEALING: Final = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


@registry.register
class VersionDisclosureRule(Rule[RuntimeObservations]):
    """``Server`` with a version number, or framework headers such as X-Powered-By."""

    id: ClassVar[str] = "API-RT-006"
    title: ClassVar[str] = "Software version is disclosed"
    category: ClassVar[str] = "Information disclosure"
    severity: ClassVar[Severity] = Severity.LOW
    target: ClassVar[RuleTarget] = RuleTarget.RUNTIME
    description: ClassVar[str] = (
        "Response headers reveal server or framework versions (e.g. Server: nginx/1.18.0, "
        "X-Powered-By: Express), helping attackers match known vulnerabilities."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"], cwe=["CWE-200"], links=[OWASP_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "server_tokens off;            # nginx\nproxy_hide_header X-Powered-By;"
    )

    def check(self, document: RuntimeObservations) -> list[Finding]:
        """Checks the base and not-found responses; one finding listing the headers."""
        for probe_id in ("base-get", "not-found"):
            obs = document.get(probe_id)
            if obs is None or not ok(obs):
                continue
            lines: list[str] = []
            server = obs.header("server")
            if server and _VERSIONED.search(server):
                lines.append(f"Server: {server}")
            lines += [f"{h}: {obs.header(h)}" for h in _ALWAYS_REVEALING if obs.header(h)]
            if lines:
                return [
                    self.finding(
                        [http_evidence(obs, "\n".join(lines))],
                        status=FindingStatus.CONFIRMED,
                        title=f"Software version is disclosed ({lines[0]})",
                    )
                ]
        return []
