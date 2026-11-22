"""Compare two sessions: resolved / persists / new (CLAUDE.md §2 component 5).

Findings are matched by id first (ids ignore line numbers), then by rule + structural
location, so an issue whose excerpt changed (e.g. a neighbouring line was edited) still
counts as *persists* rather than *resolved + new*.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models.finding import Finding


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

    @property
    def remediation_rate(self) -> float | None:
        """Share of baseline findings resolved (None for an empty baseline)."""
        total = len(self.resolved) + len(self.persists)
        return None if total == 0 else len(self.resolved) / total


def _location_key(f: Finding) -> tuple[str, str]:
    return (f.rule_id, f.evidence[0].location.identity_key())


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
    return result
