"""Compare two sessions: resolved / persists / new (CLAUDE.md §2 component 5).

Findings are matched by id first (ids ignore line numbers), then by rule + structural
location, so an issue whose excerpt changed (e.g. a neighbouring line was edited) still
counts as *persists* rather than *resolved + new*.

A third pass links correlated and runtime-only findings that share the same runtime
evidence through the correlation link table: e.g. HSTS fixed in nginx.conf (NGX-TLS-003
gone) while the live server still omits it (API-RT-004 now runtime-only). That is
reported as *persists*, and listed in ``still_observed`` — "fixed in config, not yet
deployed?" — never as resolved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.correlation.engine import LINKS
from app.models.finding import EvidenceKind, Finding, Source


@dataclass(frozen=True)
class StatusChange:
    """A persisting finding whose certainty changed (e.g. potential → confirmed)."""

    finding: Finding
    before: str
    after: str


@dataclass
class Comparison:
    """Baseline vs current."""

    resolved: list[Finding] = field(default_factory=list)
    persists: list[Finding] = field(default_factory=list)
    new: list[Finding] = field(default_factory=list)
    status_changes: list[StatusChange] = field(default_factory=list)
    #: Fixed in the config/spec, but the live system still shows the issue.
    still_observed: list[Finding] = field(default_factory=list)

    @property
    def remediation_rate(self) -> float | None:
        """Share of baseline findings resolved (None for an empty baseline)."""
        total = len(self.resolved) + len(self.persists)
        return None if total == 0 else len(self.resolved) / total


_FIXED_SUFFIX = re.compile(r"\.magen-fixed(?=\.[^./]*$|$)")


def canonical_filename(name: str) -> str:
    """``nginx.magen-fixed.conf`` → ``nginx.conf``: retesting Magen's exported copy
    compares against the original file."""
    return _FIXED_SUFFIX.sub("", name)


def _location_key(f: Finding) -> tuple[str, str]:
    loc = f.evidence[0].location
    file = canonical_filename(loc.file) if loc.file else loc.file
    return (f.rule_id, loc.model_copy(update={"file": file}).identity_key())


_LINKED: frozenset[tuple[str, str]] = frozenset(
    pair
    for link in LINKS
    for static_rule in link.static_rules
    for pair in ((link.runtime_rule, static_rule), (static_rule, link.runtime_rule))
)
_RUNTIME_KINDS = (EvidenceKind.HTTP, EvidenceKind.TLS)


def _runtime_keys(f: Finding) -> set[str]:
    return {e.location.identity_key() for e in f.evidence if e.kind in _RUNTIME_KINDS}


def _same_runtime_issue(a: Finding, b: Finding) -> bool:
    """Linked rules (static ⇄ runtime) observed on the same probe."""
    return (a.rule_id, b.rule_id) in _LINKED and bool(_runtime_keys(a) & _runtime_keys(b))


def compare(baseline: list[Finding], current: list[Finding]) -> Comparison:
    """Deterministic diff of two canonical finding lists (order is preserved)."""
    by_id = {f.id: f for f in current}
    by_loc: dict[tuple[str, str], Finding] = {}
    for f in current:
        by_loc.setdefault(_location_key(f), f)
    matched: set[str] = set()
    result = Comparison()
    for old in baseline:
        new = by_id.get(old.id)
        if new is None:
            candidate = by_loc.get(_location_key(old))
            new = candidate if candidate is not None and candidate.id not in matched else None
        if new is None:
            result.resolved.append(old)
            continue
        matched.add(new.id)
        result.persists.append(new)
        if new.status != old.status:
            result.status_changes.append(StatusChange(new, old.status.value, new.status.value))
    result.new = [f for f in current if f.id not in matched]

    # Third pass: correlated ⇄ runtime-only on the same probe (see module docstring).
    for old in list(result.resolved):
        if old.source not in (Source.CORRELATED, Source.RUNTIME):
            continue
        twin = next((n for n in result.new if _same_runtime_issue(old, n)), None)
        if twin is None:
            continue
        result.resolved.remove(old)
        result.new.remove(twin)
        result.persists.append(twin)
        if old.source is Source.CORRELATED and twin.source is Source.RUNTIME:
            result.still_observed.append(twin)
    return result
