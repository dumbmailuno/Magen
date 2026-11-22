"""Nginx configuration tokenizer + parser (text in, directive tree out).

Written instead of using ``crossplane`` because that library reads ``include``d files and
globs from the filesystem; Magen analyses only the text the user supplied (threat model
B2). ``include`` directives are kept in the tree and reported, never followed.

Every directive gets a stable *pointer*: the path of directive names from the root with
the index among same-named siblings, e.g. ``/http/0/server/1/location/0/autoindex/0``.
Pointers do not depend on line numbers, so finding ids survive unrelated edits.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Final

MAX_BYTES: Final = 5 * 1024 * 1024
MAX_DEPTH: Final = 32
MAX_TOKENS: Final = 500_000


class NginxParseError(ValueError):
    """The configuration is not syntactically valid (or exceeds safety limits)."""

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(f"line {line}: {message}" if line else message)
        self.line = line


@dataclass(frozen=True)
class Token:
    """A lexical token. ``quoted`` tokens are always arguments, never ``;{}``."""

    value: str
    line: int
    quoted: bool = False


@dataclass(frozen=True)
class Directive:
    """One directive. ``children`` is ``None`` for simple directives, a tuple for blocks."""

    name: str
    args: tuple[str, ...]
    line: int
    end_line: int
    pointer: str
    children: tuple[Directive, ...] | None = None

    @property
    def is_block(self) -> bool:
        """True for ``name args { ... }`` directives."""
        return self.children is not None

    def find(self, name: str) -> list[Directive]:
        """Direct children with this name."""
        return [c for c in self.children or () if c.name == name]

    def first(self, name: str) -> Directive | None:
        """Last-wins is nginx semantics for most single-value directives; we return the last."""
        found = self.find(name)
        return found[-1] if found else None

    def walk(self) -> Iterator[tuple[Directive, tuple[Directive, ...]]]:
        """Yield ``(directive, ancestors)`` depth-first in source order (ancestors outer→inner)."""
        stack: list[tuple[Directive, tuple[Directive, ...]]] = [
            (c, ()) for c in reversed(self.children or ())
        ]
        while stack:
            node, ancestors = stack.pop()
            yield node, ancestors
            if node.children:
                stack.extend((c, (*ancestors, node)) for c in reversed(node.children))


def tokenize(text: str) -> Iterator[Token]:
    """Split nginx config text into tokens, dropping comments."""
    i, line, n, count = 0, 1, len(text), 0
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch in " \t\r":
            i += 1
            continue
        count += 1
        if count > MAX_TOKENS:
            raise NginxParseError(f"configuration exceeds {MAX_TOKENS} tokens")
        if ch == "#":
            while i < n and text[i] != "\n":
                i += 1
            count -= 1
            continue
        if ch in ";{}":
            yield Token(ch, line)
            i += 1
            continue
        if ch in "\"'":
            start_line, quote, i = line, ch, i + 1
            buf: list[str] = []
            while i < n and text[i] != quote:
                if text[i] == "\\" and i + 1 < n:
                    buf.append(text[i : i + 2] if text[i + 1] != quote else quote)
                    line += text[i + 1] == "\n"
                    i += 2
                    continue
                line += text[i] == "\n"
                buf.append(text[i])
                i += 1
            if i >= n:
                raise NginxParseError("unterminated quoted string", start_line)
            i += 1
            yield Token("".join(buf), start_line, quoted=True)
            continue
        start = i
        while i < n and text[i] not in " \t\r\n;{}\"'#":
            if text[i] == "\\" and i + 1 < n:
                i += 2
                continue
            # ${var} keeps its braces inside the word.
            if text[i] == "$" and i + 1 < n and text[i + 1] == "{":
                close = text.find("}", i)
                i = close + 1 if close != -1 else n
                continue
            i += 1
        yield Token(text[start:i], line)


class _Parser:
    def __init__(self, tokens: Iterator[Token]) -> None:
        self.tokens = tokens
        self.last_line = 1

    def _next(self) -> Token | None:
        tok = next(self.tokens, None)
        if tok is not None:
            self.last_line = tok.line
        return tok

    def block(self, pointer: str, depth: int, opened_at: int | None) -> tuple[list[Directive], int]:
        if depth > MAX_DEPTH:
            raise NginxParseError(f"nesting exceeds {MAX_DEPTH} levels", self.last_line)
        out: list[Directive] = []
        seen: dict[str, int] = {}
        while True:
            tok = self._next()
            if tok is None:
                if opened_at is not None:
                    raise NginxParseError("unexpected end of file, expecting '}'", opened_at)
                return out, self.last_line
            if not tok.quoted and tok.value == "}":
                if opened_at is None:
                    raise NginxParseError("unexpected '}'", tok.line)
                return out, tok.line
            if not tok.quoted and tok.value in ";{":
                raise NginxParseError(f"unexpected '{tok.value}'", tok.line)
            name, line = tok.value, tok.line
            args: list[str] = []
            while True:
                arg = self._next()
                if arg is None:
                    raise NginxParseError(f"unexpected end of file in '{name}'", line)
                if not arg.quoted and arg.value == ";":
                    index = seen.get(name, 0)
                    seen[name] = index + 1
                    ptr = f"{pointer}/{_escape(name)}/{index}"
                    out.append(Directive(name, tuple(args), line, arg.line, ptr))
                    break
                if not arg.quoted and arg.value == "{":
                    index = seen.get(name, 0)
                    seen[name] = index + 1
                    ptr = f"{pointer}/{_escape(name)}/{index}"
                    children, end = self.block(ptr, depth + 1, line)
                    out.append(Directive(name, tuple(args), line, end, ptr, tuple(children)))
                    break
                if not arg.quoted and arg.value == "}":
                    raise NginxParseError(f"unexpected '}}' in '{name}' (missing ';'?)", arg.line)
                args.append(arg.value)


def _escape(name: str) -> str:
    return name.replace("~", "~0").replace("/", "~1")


def parse(text: str) -> Directive:
    """Parse config text into a synthetic root block (name ``""``)."""
    if len(text.encode("utf-8", errors="replace")) > MAX_BYTES:
        raise NginxParseError(f"configuration larger than {MAX_BYTES // (1024 * 1024)} MB")
    text = text.removeprefix("﻿")
    parser = _Parser(tokenize(text))
    children, end = parser.block("", 0, None)
    if not children:
        raise NginxParseError("configuration is empty")
    return Directive("", (), 1, end, "", tuple(children))
