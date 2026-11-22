"""NGX-CFG-003 — request body size unlimited or very large."""

from __future__ import annotations

import re
from typing import ClassVar, Final

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.nginx._common import NGINX_CORE_DOCS, OWASP_DOCS
from app.rules.registry import registry
from app.static.nginx.config import NginxConfig

LIMIT_BYTES: Final = 100 * 1024 * 1024
_SIZE = re.compile(r"^(\d+)([kKmMgG]?)$")
_UNITS: Final = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}


def parse_size(value: str) -> int | None:
    """Nginx size syntax (``10m``, ``512k``, ``1g``) to bytes; ``None`` if unparseable."""
    m = _SIZE.match(value)
    return int(m.group(1)) * _UNITS[m.group(2).lower()] if m else None


@registry.register
class BodySizeRule(Rule[NginxConfig]):
    """Flags ``client_max_body_size 0`` (unlimited) or limits above 100 MiB."""

    id: ClassVar[str] = "NGX-CFG-003"
    title: ClassVar[str] = "Request body size limit is unlimited or very large"
    category: ClassVar[str] = "Resource consumption"
    severity: ClassVar[Severity] = Severity.LOW
    target: ClassVar[RuleTarget] = RuleTarget.NGINX
    description: ClassVar[str] = (
        "client_max_body_size 0 disables the limit, and values above 100 MiB let a client "
        "tie up bandwidth, disk and upstream workers with huge requests. The default (1m) is "
        "not reported."
    )
    references: ClassVar[References] = References(
        owasp_api=["API4:2023"], cwe=["CWE-770"], links=[OWASP_DOCS, NGINX_CORE_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "client_max_body_size 10m;   # raise only on the locations that need uploads"
    )

    def check(self, document: NginxConfig) -> list[Finding]:
        """One finding per offending directive."""
        findings: list[Finding] = []
        for d, _ in document.all_directives("client_max_body_size"):
            size = parse_size(d.args[0]) if d.args else None
            if size is None:
                continue
            if size == 0:
                title = "Request body size is unlimited (client_max_body_size 0)"
            elif size > LIMIT_BYTES:
                title = f"Request body limit is very large ({d.args[0]})"
            else:
                continue
            findings.append(self.finding([document.evidence(d)], title=title))
        return findings
