"""Deterministic OpenAPI fixers (line edits; YAML-only where structure changes)."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Final

from app.models.finding import Finding
from app.remediation.edits import Edit
from app.static.openapi.document import OpenApiDocument
from app.static.openapi.loader import join_pointer

Fixer = Callable[[OpenApiDocument, Finding], list[Edit] | None]


def _lines(doc: OpenApiDocument) -> list[str]:
    return doc.source_lines


def _is_json(doc: OpenApiDocument) -> bool:
    return "\n".join(_lines(doc)).lstrip().startswith("{")


def _line_edit(
    doc: OpenApiDocument, f: Finding, pointer: str, fn: Callable[[str], str]
) -> list[Edit] | None:
    loc = doc.location(pointer)
    if loc.line is None:
        return None
    old = _lines(doc)[loc.line - 1]
    new = fn(old)
    return None if new == old else [Edit(f.id, loc.line, loc.line, (new,))]


def fix_http_server(doc: OpenApiDocument, f: Finding) -> list[Edit] | None:
    """API-OAS-001: http:// → https:// on that server URL (templated schemes: template only)."""
    pointer = f.evidence[0].location.pointer or ""
    url = doc.get(pointer)
    if not isinstance(url, str) or not url.lower().startswith("http://"):
        return None
    return _line_edit(doc, f, pointer, lambda s: re.sub(r"(?i)http://", "https://", s, count=1))


def fix_api_key_in_query(doc: OpenApiDocument, f: Finding) -> list[Edit] | None:
    """API-OAS-005: ``in: query`` → ``in: header`` (same parameter name)."""
    pointer = join_pointer(f.evidence[0].location.pointer or "", "in")
    return _line_edit(doc, f, pointer, lambda s: re.sub(r"\bquery\b", "header", s, count=1))


def fix_debug_property(doc: OpenApiDocument, f: Finding) -> list[Edit] | None:
    """API-OAS-009: drop the leaky property from the response schema (YAML only)."""
    if _is_json(doc):
        return None
    loc = doc.location(f.evidence[0].location.pointer or "")
    if loc.line is None:
        return None
    return [Edit(f.id, loc.line, loc.end_line or loc.line, ())]


def fix_missing_global_security(doc: OpenApiDocument, f: Finding) -> list[Edit] | None:
    """API-OAS-003 when *nothing* sets security: require the first defined scheme globally.

    Operations that explicitly opt out (``security: []``) are left for a human decision.
    """
    if _is_json(doc) or "security" in doc.data or not doc.security_schemes():
        return None
    if (f.evidence[0].location.pointer or "").endswith("/security"):
        return None
    scheme = next(iter(doc.security_schemes()))
    lines = _lines(doc)
    end = len(lines) + 1 if lines[-1] != "" else len(lines)
    return [Edit(f.id, end, end - 1, ("security:", f"  - {scheme}: []"))]


FIXERS: Final[dict[str, Fixer]] = {
    "API-OAS-001": fix_http_server,
    "API-OAS-003": fix_missing_global_security,
    "API-OAS-005": fix_api_key_in_query,
    "API-OAS-009": fix_debug_property,
    # 002/004/006/007/008/010 change the API contract or need a design decision: template only.
}
