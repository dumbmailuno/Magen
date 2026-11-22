"""Before/after diffs are produced by difflib, never by the LLM (CLAUDE.md §2)."""

from __future__ import annotations

import difflib


def unified_diff(before: str, after: str, filename: str, context: int = 3) -> str:
    """Standard unified diff (``a/`` and ``b/`` prefixes), empty when nothing changed."""
    a = before.replace("\r\n", "\n").split("\n")
    b = after.replace("\r\n", "\n").split("\n")
    lines = difflib.unified_diff(a, b, f"a/{filename}", f"b/{filename}", n=context, lineterm="")
    return "\n".join(lines)
