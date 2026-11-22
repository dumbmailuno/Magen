"""Remediation preview: findings → patched copy + diff + validation. Never touches files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from app.models.finding import Finding
from app.remediation import nginx_fixes, openapi_fixes
from app.remediation.diff import unified_diff
from app.remediation.edits import Edit, apply_edits
from app.remediation.validate import Kind, Validation, analyze, validate
from app.static.nginx.config import NginxConfig
from app.static.openapi.document import OpenApiDocument

Outcome = Literal["applied", "template_only", "conflict"]


@dataclass(frozen=True)
class FixOutcome:
    """What happened to one requested finding."""

    finding: Finding
    outcome: Outcome
    validated: bool | None


@dataclass(frozen=True)
class Preview:
    """A corrected copy of one input, for review and export only."""

    filename: str
    patched_filename: str
    patched: str
    diff: str
    fixes: list[FixOutcome]
    validation: Validation


def corrected_name(filename: str) -> str:
    """``nginx.conf`` → ``nginx.magen-fixed.conf`` (never the original name)."""
    p = PurePosixPath(filename.replace("\\", "/"))
    return f"{p.stem}.magen-fixed{p.suffix}"


def _edits(kind: Kind, name: str, text: str, f: Finding) -> list[Edit] | None:
    if kind == "nginx":
        fixer = nginx_fixes.FIXERS.get(f.rule_id)
        return fixer(NginxConfig(name, text), f) if fixer else None
    ofixer = openapi_fixes.FIXERS.get(f.rule_id)
    return ofixer(OpenApiDocument(name, text), f) if ofixer else None


def preview(kind: Kind, filename: str, content: str, finding_ids: list[str] | None) -> Preview:
    """Build the corrected copy for the requested findings (all, if ``finding_ids`` is None)."""
    findings = analyze(kind, content, filename)
    wanted = set(finding_ids) if finding_ids is not None else None
    targets = [f for f in findings if wanted is None or f.id in wanted]
    edits: list[Edit] = []
    fixable: set[str] = set()
    for f in targets:
        e = _edits(kind, filename, content, f)
        if e:
            edits += e
            fixable.add(f.id)
    applied = apply_edits(content, edits)
    patched = applied.text
    attempted = [f for f in targets if f.id in applied.applied]
    validation = validate(kind, filename, content, patched, attempted)
    fixes: list[FixOutcome] = []
    for f in targets:
        if f.id in applied.conflicts:
            fixes.append(FixOutcome(f, "conflict", None))
        elif f.id in fixable:
            fixes.append(FixOutcome(f, "applied", validation.is_validated(f.id)))
        else:
            fixes.append(FixOutcome(f, "template_only", None))
    return Preview(
        filename=filename,
        patched_filename=corrected_name(filename),
        patched=patched,
        diff=unified_diff(content, patched, filename),
        fixes=fixes,
        validation=validation,
    )
