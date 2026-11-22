"""Fix validation (CLAUDE.md §2): re-parse, re-run the rules, optional ``nginx -t``.

A fix is *validated* only if the patched text parses, the targeted finding no longer
fires at that location, and no new finding appears anywhere in the file. Findings are
matched by (rule id, structural pointer) — not by id — because an edit may legitimately
change another finding's excerpt (and thus its id) without changing the issue.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from app.core.errors import MagenError
from app.models.finding import Finding
from app.static.nginx.analyzer import analyze_nginx
from app.static.nginx.config import NginxConfig
from app.static.openapi.analyzer import analyze_openapi

Kind = Literal["openapi", "nginx"]


def finding_key(f: Finding) -> tuple[str, str]:
    """Location-based identity used to compare before/after."""
    return (f.rule_id, f.evidence[0].location.pointer or "")


@dataclass(frozen=True)
class SyntaxCheck:
    """Result of the external ``nginx -t`` check."""

    status: Literal["passed", "failed", "inconclusive", "unavailable", "not_applicable"]
    message: str


@dataclass
class Validation:
    """Outcome of validating a patched file."""

    parsed: bool
    error: str | None = None
    resolved: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    introduced: list[Finding] = field(default_factory=list)
    syntax: SyntaxCheck = field(default_factory=lambda: SyntaxCheck("not_applicable", ""))

    def is_validated(self, finding_id: str) -> bool:
        """Parsed, this finding resolved, nothing new introduced, nginx -t not failing."""
        return (
            self.parsed
            and finding_id in self.resolved
            and not self.introduced
            and self.syntax.status != "failed"
        )


def analyze(kind: Kind, text: str, name: str) -> list[Finding]:
    """Run the static analyzer for ``kind``."""
    if kind == "openapi":
        return list(analyze_openapi(text, name).findings)
    return list(analyze_nginx(text, name).findings)


def _nginx_t(exe: str, text: str) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="magen-nginx-") as tmp:
        conf = Path(tmp) / "nginx.conf"
        conf.write_text(text, encoding="utf-8")
        (Path(tmp) / "logs").mkdir()
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, our temp file, no shell
                [exe, "-t", "-q", "-p", tmp, "-c", str(conf)],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, type(exc).__name__
        lines = [ln for ln in (proc.stderr or "").splitlines() if ln.strip()]
        return proc.returncode == 0, lines[-1] if lines else ""


def nginx_syntax_check(original: str, patched: str, *, is_snippet: bool) -> SyntaxCheck:
    """``nginx -t`` on the patched config, compared with the original.

    Real configs often reference certificates and includes that do not exist here, so a
    failure only counts against the fix if the *original* passes.
    """
    if is_snippet:
        return SyntaxCheck("not_applicable", "Site snippet: nginx -t needs the full nginx.conf")
    exe = shutil.which("nginx")
    if exe is None:
        return SyntaxCheck("unavailable", "nginx is not installed; validated by re-parsing only")
    patched_ok, patched_msg = _nginx_t(exe, patched)
    if patched_ok:
        return SyntaxCheck("passed", "nginx -t passed")
    original_ok, _ = _nginx_t(exe, original)
    if original_ok:
        return SyntaxCheck("failed", patched_msg or "nginx -t failed")
    return SyntaxCheck(
        "inconclusive",
        "nginx -t also fails on the original (missing certificates or includes?)",
    )


def validate(
    kind: Kind, name: str, original: str, patched: str, targets: list[Finding]
) -> Validation:
    """Compare findings before and after the patch."""
    before = analyze(kind, original, name)
    try:
        after = analyze(kind, patched, name)
    except MagenError as exc:
        return Validation(parsed=False, error=exc.message, unresolved=[f.id for f in targets])
    before_keys = {finding_key(f) for f in before}
    after_keys = {finding_key(f) for f in after}
    resolved = [f.id for f in targets if finding_key(f) not in after_keys]
    result = Validation(
        parsed=True,
        resolved=resolved,
        unresolved=[f.id for f in targets if f.id not in resolved],
        introduced=[f for f in after if finding_key(f) not in before_keys],
    )
    if kind == "nginx":
        result.syntax = nginx_syntax_check(
            original, patched, is_snippet=NginxConfig(name, original).is_snippet
        )
    return result
