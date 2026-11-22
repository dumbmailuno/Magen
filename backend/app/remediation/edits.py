"""Line-based text edits: the only way Magen produces corrected files (never in place).

Edits address 1-based line numbers of the *original* text and are applied bottom-up, so
they never shift each other. Overlapping edits are detected deterministically; a finding
whose edit conflicts is reported, not partially applied.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Edit:
    """Replace lines ``start..end`` (inclusive) with ``lines``; ``end == start - 1`` inserts."""

    finding_id: str
    start: int
    end: int
    lines: tuple[str, ...]

    @property
    def is_insert(self) -> bool:
        """Pure insertion before ``start``."""
        return self.end == self.start - 1


@dataclass
class EditResult:
    """Patched text and which findings' edits were applied or conflicted."""

    text: str
    applied: set[str] = field(default_factory=set)
    conflicts: set[str] = field(default_factory=set)


def _overlaps(a: Edit, b: Edit) -> bool:
    if a.is_insert and b.is_insert:
        return False  # same-point inserts are merged
    if a.is_insert:
        return b.start < a.start <= b.end
    if b.is_insert:
        return a.start < b.start <= a.end
    return a.start <= b.end and b.start <= a.end


def apply_edits(text: str, edits: list[Edit]) -> EditResult:
    """Apply non-conflicting edits; identical replacements and duplicate insert lines merge."""
    normalized = text.replace("\r\n", "\n")
    lines = normalized.split("\n")
    ordered = sorted(edits, key=lambda e: (e.start, e.end, e.finding_id, e.lines))
    conflicts: set[str] = set()
    for i, a in enumerate(ordered):
        for b in ordered[:i]:
            same = (a.start, a.end, a.lines) == (b.start, b.end, b.lines)
            if b.finding_id not in conflicts and not same and _overlaps(a, b):
                conflicts.add(a.finding_id)
    kept = [e for e in ordered if e.finding_id not in conflicts]

    replacements: dict[tuple[int, int], tuple[str, ...]] = {}
    inserts: dict[int, list[str]] = {}
    for e in kept:
        if e.is_insert:
            bucket = inserts.setdefault(e.start, [])
            bucket.extend(line for line in e.lines if line not in bucket)
        else:
            replacements[(e.start, e.end)] = e.lines
    points = sorted(
        [(start, 1, (start, end)) for (start, end) in replacements]
        + [(start, 0, (start, start - 1)) for start in inserts],
        reverse=True,
    )
    for start, kind, (s, end) in points:
        if kind == 1:
            lines[s - 1 : end] = list(replacements[(s, end)])
        else:
            lines[start - 1 : start - 1] = inserts[start]
    return EditResult(
        text="\n".join(lines),
        applied={e.finding_id for e in kept},
        conflicts=conflicts,
    )
