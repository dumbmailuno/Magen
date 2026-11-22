"""Parsed OpenAPI 3.x document: the read-only input every OpenAPI rule receives."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Final

from app.core.errors import ValidationFailedError
from app.models.finding import Evidence, EvidenceKind, Location
from app.static.openapi.loader import (
    LineRange,
    LoadError,
    join_pointer,
    load_document,
    unescape_pointer_token,
)

#: Operation keys of a Path Item, in canonical (spec) order.
HTTP_METHODS: Final = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
EXCERPT_MAX_LINES: Final = 8
EXCERPT_MAX_LINE_CHARS: Final = 240
EXCERPT_JSON_CHARS: Final = 600
_MAX_REF_HOPS: Final = 32


class OpenApiParseError(ValidationFailedError):
    """Input is not a parseable OpenAPI 3.x document."""

    code = "invalid_openapi"


@dataclass(frozen=True)
class Operation:
    """One operation (``paths./users.get``)."""

    path: str
    method: str
    pointer: str
    node: dict[str, Any]
    path_item: dict[str, Any]
    path_item_pointer: str

    @property
    def label(self) -> str:
        """Human label, e.g. ``GET /users``."""
        return f"{self.method.upper()} {self.path}"


@dataclass(frozen=True)
class Resolved:
    """A value after following local ``$ref``s, and where it actually lives."""

    value: Any
    pointer: str


class OpenApiDocument:
    """Immutable view over a parsed spec with pointer → source-position lookups."""

    def __init__(self, source_name: str, text: str) -> None:
        try:
            loaded = load_document(text)
        except LoadError as exc:
            raise OpenApiParseError(str(exc)) from exc
        data = loaded.data
        if not isinstance(data, dict):
            raise OpenApiParseError("top level must be a mapping")
        if "swagger" in data:
            raise OpenApiParseError("Swagger 2.0 is not supported; convert to OpenAPI 3.x")
        version = data.get("openapi")
        if not isinstance(version, str) or not version.startswith("3."):
            raise OpenApiParseError("missing or unsupported 'openapi' version (need 3.x)")
        self.source_name = source_name.replace("\\", "/")
        self.version = version
        self.data: dict[str, Any] = data
        self._lines: dict[str, LineRange] = loaded.lines
        self._text_lines = text.removeprefix("﻿").replace("\r\n", "\n").split("\n")

    # ---- pointer access -------------------------------------------------------------

    def get(self, pointer: str) -> Any:
        """Value at an RFC 6901 pointer, or ``None`` if absent."""
        node: Any = self.data
        if pointer == "":
            return node
        for raw in pointer.lstrip("/").split("/"):
            token = unescape_pointer_token(raw)
            if isinstance(node, dict) and token in node:
                node = node[token]
            elif isinstance(node, list) and token.isdigit() and int(token) < len(node):
                node = node[int(token)]
            else:
                return None
        return node

    def resolve(self, value: Any, pointer: str) -> Resolved:
        """Follow local ``$ref`` chains. External refs are never fetched (left unresolved)."""
        seen: set[str] = set()
        for _ in range(_MAX_REF_HOPS):
            if not (isinstance(value, dict) and isinstance(value.get("$ref"), str)):
                break
            ref: str = value["$ref"]
            if not ref.startswith("#") or ref in seen:
                break  # external or cyclic
            seen.add(ref)
            target_pointer = ref[1:]
            target = self.get(target_pointer)
            if target is None:
                break
            value, pointer = target, target_pointer
        return Resolved(value, pointer)

    # ---- evidence -------------------------------------------------------------------

    def location(self, pointer: str) -> Location:
        """File + line range + pointer for evidence."""
        rng = self._lines.get(pointer)
        return Location(
            file=self.source_name,
            line=rng.start if rng else None,
            end_line=rng.end if rng and rng.end != rng.start else None,
            pointer=pointer,
        )

    def excerpt(self, pointer: str) -> str:
        """Source lines of the node (capped).

        Falls back to a JSON rendering of just this node when positions are unknown (JSON
        fallback parser) or the source is minified (a single line would be the whole file).
        """
        rng = self._lines.get(pointer)
        lines: list[str] = []
        truncated = False
        if rng is not None:
            end = min(rng.end, rng.start + EXCERPT_MAX_LINES - 1)
            lines = self._text_lines[rng.start - 1 : end]
            truncated = end < rng.end
        if rng is None or any(len(line) > EXCERPT_MAX_LINE_CHARS for line in lines):
            rendered = json.dumps(self.get(pointer), ensure_ascii=False, sort_keys=True)
            if len(rendered) > EXCERPT_JSON_CHARS:
                rendered = rendered[: EXCERPT_JSON_CHARS - 1] + "…"
            return rendered
        if truncated:
            lines.append("…")
        return "\n".join(lines)

    def evidence(self, pointer: str) -> Evidence:
        """Static evidence for the node at ``pointer``."""
        return Evidence(
            kind=EvidenceKind.OPENAPI,
            location=self.location(pointer),
            excerpt=self.excerpt(pointer),
        )

    # ---- OpenAPI structure ----------------------------------------------------------

    def operations(self) -> list[Operation]:
        """All operations, sorted by path then canonical method order."""
        paths = self.data.get("paths")
        if not isinstance(paths, dict):
            return []
        ops: list[Operation] = []
        for path in sorted(paths):
            item_pointer = join_pointer("/paths", path)
            resolved = self.resolve(paths[path], item_pointer)
            item = resolved.value
            if not isinstance(item, dict):
                continue
            for method in HTTP_METHODS:
                node = item.get(method)
                if isinstance(node, dict):
                    ops.append(
                        Operation(
                            path=path,
                            method=method,
                            pointer=join_pointer(resolved.pointer, method),
                            node=node,
                            path_item=item,
                            path_item_pointer=resolved.pointer,
                        )
                    )
        return ops

    def security_schemes(self) -> dict[str, Resolved]:
        """``components.securitySchemes`` with refs resolved, sorted by name."""
        components = self.data.get("components")
        schemes = components.get("securitySchemes") if isinstance(components, dict) else None
        if not isinstance(schemes, dict):
            return {}
        return {
            name: self.resolve(schemes[name], join_pointer("/components/securitySchemes", name))
            for name in sorted(schemes)
        }

    def effective_security(self, op: Operation) -> tuple[Any, str]:
        """Security requirements that apply to ``op`` and the pointer they come from.

        An operation-level ``security`` overrides the root one, even when it is ``[]``.
        """
        if "security" in op.node:
            return op.node["security"], join_pointer(op.pointer, "security")
        return self.data.get("security"), "/security"

    def parameters(self, op: Operation) -> Iterator[Resolved]:
        """Path-item + operation parameters, refs resolved. Operation params win by (name, in)."""
        merged: dict[tuple[str, str], Resolved] = {}
        for owner, owner_pointer in ((op.path_item, op.path_item_pointer), (op.node, op.pointer)):
            params = owner.get("parameters")
            if not isinstance(params, list):
                continue
            for i, raw in enumerate(params):
                res = self.resolve(raw, join_pointer(owner_pointer, "parameters", i))
                if isinstance(res.value, dict):
                    key = (str(res.value.get("name")), str(res.value.get("in")))
                    merged[key] = res
        yield from (merged[k] for k in sorted(merged))

    def responses(self, op: Operation) -> Iterator[tuple[str, Resolved]]:
        """``(status code, resolved response)`` pairs for an operation, sorted by code."""
        responses = op.node.get("responses")
        if not isinstance(responses, dict):
            return
        for code in sorted(responses):
            res = self.resolve(responses[code], join_pointer(op.pointer, "responses", code))
            if isinstance(res.value, dict):
                yield code, res
