"""Safe YAML/JSON loading with source positions for every JSON pointer.

Untrusted input (CLAUDE.md §8, threat model B2). Defences:

* ``yaml.SafeLoader`` only — no arbitrary object construction.
* Size cap, nesting-depth cap and a node budget (defeats alias "billion laughs" bombs, since
  every visit of an aliased node is counted).
* Mapping keys are taken as their *raw* text, so YAML 1.1 quirks (``on:`` → ``True``,
  ``200:`` → ``int``) never change a path or response code.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Final

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

MAX_BYTES: Final = 5 * 1024 * 1024
MAX_DEPTH: Final = 64
MAX_NODES: Final = 200_000
_STD_COLLECTION_TAGS: Final = frozenset({"tag:yaml.org,2002:map", "tag:yaml.org,2002:seq"})


class LoadError(ValueError):
    """The document could not be parsed safely."""


def escape_pointer_token(token: str) -> str:
    """RFC 6901 escaping of one reference token."""
    return token.replace("~", "~0").replace("/", "~1")


def unescape_pointer_token(token: str) -> str:
    """Inverse of :func:`escape_pointer_token`."""
    return token.replace("~1", "/").replace("~0", "~")


def join_pointer(base: str, *tokens: str | int) -> str:
    """Append tokens to a JSON pointer."""
    return base + "".join(f"/{escape_pointer_token(str(t))}" for t in tokens)


@dataclass(frozen=True)
class LineRange:
    """1-based inclusive line range of a node (starting at its key, if any)."""

    start: int
    end: int


@dataclass
class Loaded:
    """Parsed data plus pointer → line-range index."""

    data: Any
    lines: dict[str, LineRange] = field(default_factory=dict)


@dataclass
class _Budget:
    remaining: int = MAX_NODES

    def tick(self) -> None:
        self.remaining -= 1
        if self.remaining < 0:
            raise LoadError(f"document exceeds {MAX_NODES} nodes (possible alias bomb)")


def _end_line(node: Node) -> int:
    # end_mark is the position *after* the node; at column 0 the node ended on the line above.
    mark = node.end_mark
    return mark.line + (1 if mark.column > 0 else 0)


class _Builder:
    def __init__(self, loader: yaml.SafeLoader) -> None:
        self.loader = loader
        self.lines: dict[str, LineRange] = {}
        self.budget = _Budget()

    def build(self, node: Node, pointer: str, start_line: int, depth: int) -> Any:
        """Return the plain value; records the node's line range under ``pointer``."""
        value, end = self._build(node, pointer, start_line, depth)
        self.lines.setdefault(pointer, LineRange(start_line, max(start_line, end)))
        return value

    def _build(self, node: Node, pointer: str, start_line: int, depth: int) -> tuple[Any, int]:
        self.budget.tick()
        if depth > MAX_DEPTH:
            raise LoadError(f"document nesting exceeds {MAX_DEPTH} levels")
        # Block collections: end_mark is the *next* token (after its indentation), so the
        # real last line is that of the last descendant. Flow collections/scalars are exact.
        if isinstance(node, MappingNode | SequenceNode) and node.tag not in _STD_COLLECTION_TAGS:
            raise LoadError(f"unsupported YAML tag {node.tag!r}")
        block = isinstance(node, MappingNode | SequenceNode) and not node.flow_style
        end = start_line if block and node.value else _end_line(node)
        if isinstance(node, MappingNode):
            out: dict[str, Any] = {}
            for key_node, value_node in node.value:
                if not isinstance(key_node, ScalarNode):
                    raise LoadError("non-scalar mapping keys are not supported")
                key = str(key_node.value)
                child = join_pointer(pointer, key)
                out[key] = self.build(value_node, child, key_node.start_mark.line + 1, depth + 1)
                if block:
                    end = max(end, self.lines[child].end)
            return out, end
        if isinstance(node, SequenceNode):
            items: list[Any] = []
            for i, item in enumerate(node.value):
                child = join_pointer(pointer, i)
                items.append(self.build(item, child, item.start_mark.line + 1, depth + 1))
                if block:
                    end = max(end, self.lines[child].end)
            return items, end
        if isinstance(node, ScalarNode):
            return self.loader.construct_object(node, deep=True), end
        raise LoadError(f"unsupported YAML node {type(node).__name__}")


def load_document(text: str) -> Loaded:
    """Parse YAML (or JSON, a YAML subset) into plain data with line positions."""
    if len(text.encode("utf-8", errors="replace")) > MAX_BYTES:
        raise LoadError(f"document larger than {MAX_BYTES // (1024 * 1024)} MB")
    text = text.removeprefix("﻿")
    loader = yaml.SafeLoader(text)
    try:
        root = loader.get_single_node()
        if root is None:
            raise LoadError("document is empty")
        builder = _Builder(loader)
        data = builder.build(root, "", root.start_mark.line + 1, 0)
        return Loaded(data=data, lines=builder.lines)
    except yaml.YAMLError as yaml_err:
        # Some valid JSON is not valid YAML 1.1 (e.g. tab indentation); fall back without
        # positions so the file can still be analysed (evidence then carries pointers only).
        try:
            return Loaded(data=json.loads(text))
        except (ValueError, RecursionError):
            raise LoadError(f"not valid YAML or JSON: {yaml_err}") from yaml_err
    except RecursionError as exc:
        raise LoadError("document nesting too deep") from exc
    finally:
        loader.dispose()
