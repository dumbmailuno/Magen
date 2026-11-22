"""API-RT-007 — CORS allows any origin (observed)."""

from __future__ import annotations

from typing import ClassVar

from app.models.finding import Finding, FindingStatus, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.registry import registry
from app.rules.runtime._common import OWASP_DOCS, http_evidence, ok
from app.runtime.observations import CORS_PROBE_ORIGIN, RuntimeObservations


@registry.register
class PermissiveCorsRuntimeRule(Rule[RuntimeObservations]):
    """``Access-Control-Allow-Origin`` is ``*`` or echoes our unrelated probe origin."""

    id: ClassVar[str] = "API-RT-007"
    title: ClassVar[str] = "CORS allows any origin"
    category: ClassVar[str] = "CORS"
    severity: ClassVar[Severity] = Severity.MEDIUM
    target: ClassVar[RuleTarget] = RuleTarget.RUNTIME
    description: ClassVar[str] = (
        "Magen sent Origin: https://magen-cors-probe.invalid (a reserved, unrelated "
        "origin). The response allowed it — by echoing it back or with * — so any website "
        "can read responses; with Allow-Credentials: true, authenticated data too."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"],
        cwe=["CWE-942"],
        links=[OWASP_DOCS, "https://portswigger.net/web-security/cors"],
    )
    remediation_template: ClassVar[str] = (
        "# Allow only known origins (nginx)\nmap $http_origin $cors_origin {\n"
        '    default "";\n    "~^https://app\\.example\\.com$" $http_origin;\n}'
    )

    def check(self, document: RuntimeObservations) -> list[Finding]:
        """Checks the GET and preflight responses; first hit wins."""
        for probe_id in ("base-get", "base-options"):
            obs = document.get(probe_id)
            if obs is None or not ok(obs):
                continue
            acao = (obs.header("access-control-allow-origin") or "").strip()
            if acao not in ("*", CORS_PROBE_ORIGIN):
                continue
            creds = (obs.header("access-control-allow-credentials") or "").lower() == "true"
            lines = [f"Access-Control-Allow-Origin: {acao}"]
            if creds:
                lines.append("Access-Control-Allow-Credentials: true")
            kind = "reflects any Origin" if acao != "*" else "allows any origin (*)"
            title = f"CORS {kind}" + (" with credentials" if creds else "")
            return [
                self.finding(
                    [http_evidence(obs, "\n".join(lines))],
                    status=FindingStatus.CONFIRMED,
                    title=title,
                )
            ]
        return []
