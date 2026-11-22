"""Shared pure helpers for OpenAPI rules."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any, Final

from app.static.openapi.document import OpenApiDocument, Resolved
from app.static.openapi.loader import join_pointer

OWASP_DOCS: Final = "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"
OAS_SECURITY_DOCS: Final = "https://spec.openapis.org/oas/v3.1.0#security-scheme-object"
_SCHEMA_MAX_DEPTH: Final = 24


def normalize_name(name: str) -> str:
    """Lowercase and drop separators: ``Stack_Trace`` / ``stack-trace`` → ``stacktrace``."""
    return re.sub(r"[\s_\-.]", "", name.lower())


def walk_schema_properties(
    doc: OpenApiDocument, schema: Any, pointer: str
) -> Iterator[tuple[str, str]]:
    """Yield ``(property name, pointer)`` for every property reachable from ``schema``.

    Follows local refs, ``allOf/oneOf/anyOf``, ``items`` and ``additionalProperties``; each
    schema location is visited once, so recursive schemas terminate.
    """
    seen: set[str] = set()
    stack: list[tuple[Any, str, int]] = [(schema, pointer, 0)]
    while stack:
        raw, ptr, depth = stack.pop()
        res: Resolved = doc.resolve(raw, ptr)
        node, ptr = res.value, res.pointer
        if not isinstance(node, dict) or ptr in seen or depth > _SCHEMA_MAX_DEPTH:
            continue
        seen.add(ptr)
        props = node.get("properties")
        if isinstance(props, dict):
            for name in sorted(props):
                prop_ptr = join_pointer(ptr, "properties", name)
                yield name, prop_ptr
                stack.append((props[name], prop_ptr, depth + 1))
        for combinator in ("allOf", "oneOf", "anyOf"):
            parts = node.get(combinator)
            if isinstance(parts, list):
                for i, part in enumerate(parts):
                    stack.append((part, join_pointer(ptr, combinator, i), depth + 1))
        for key in ("items", "additionalProperties"):
            if isinstance(node.get(key), dict):
                stack.append((node[key], join_pointer(ptr, key), depth + 1))


def media_schemas(doc: OpenApiDocument, owner: Resolved) -> Iterator[tuple[Any, str]]:
    """``content.<media>.schema`` entries of a response or request body."""
    content = owner.value.get("content") if isinstance(owner.value, dict) else None
    if not isinstance(content, dict):
        return
    for media in sorted(content):
        entry = content[media]
        if isinstance(entry, dict) and "schema" in entry:
            yield entry["schema"], join_pointer(owner.pointer, "content", media, "schema")
