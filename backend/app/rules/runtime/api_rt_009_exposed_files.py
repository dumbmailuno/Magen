"""API-RT-009 — VCS metadata or .env file is publicly served."""

from __future__ import annotations

import re
from typing import ClassVar, Final

from app.models.finding import Finding, FindingStatus, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.registry import registry
from app.rules.runtime._common import OWASP_DOCS, http_evidence
from app.runtime.observations import RuntimeObservations

_GIT_HEAD: Final = re.compile(r"^(ref: refs/|[0-9a-f]{40}$)")
_ENV_LINE: Final = re.compile(r"^[A-Z][A-Z0-9_]*=", re.MULTILINE)


@registry.register
class ExposedFilesRule(Rule[RuntimeObservations]):
    """``/.git/HEAD`` with git content, or ``/.env`` with KEY=VALUE lines."""

    id: ClassVar[str] = "API-RT-009"
    title: ClassVar[str] = "Repository or environment file is publicly readable"
    category: ClassVar[str] = "Information disclosure"
    severity: ClassVar[Severity] = Severity.HIGH
    target: ClassVar[RuleTarget] = RuleTarget.RUNTIME
    description: ClassVar[str] = (
        "A .git directory lets anyone reconstruct the source code; a .env file usually "
        "holds secrets. Only the file's shape is recorded: .env contents are never stored."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"], cwe=["CWE-538"], links=[OWASP_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "location ~ /\\.(git|env|svn) {\n    deny all;\n    return 404;\n}\n"
        "# and rotate any secret that was exposed"
    )

    def check(self, document: RuntimeObservations) -> list[Finding]:
        """One finding per exposed file."""
        findings: list[Finding] = []
        git = document.get("path-git-head")
        if git is not None and git.status == 200 and _GIT_HEAD.match(git.body_excerpt.strip()):
            findings.append(
                self.finding(
                    [http_evidence(git, "GET /.git/HEAD → 200 with git ref content")],
                    status=FindingStatus.CONFIRMED,
                    title="Git repository metadata is publicly readable (/.git/HEAD)",
                )
            )
        env = document.get("path-env")
        if env is not None and env.status == 200:
            count = len(_ENV_LINE.findall(env.body_excerpt))
            if count >= 2:
                findings.append(
                    self.finding(
                        [
                            http_evidence(
                                env, "GET /.env → 200 with KEY=VALUE lines (values not stored)"
                            )
                        ],
                        status=FindingStatus.CONFIRMED,
                        title=f"Environment file is publicly readable (/.env, {count}+ variables)",
                    )
                )
        return findings
