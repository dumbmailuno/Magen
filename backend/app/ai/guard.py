"""Prompt-injection defences for scanned content (CLAUDE.md §8, threat model B4).

Scanned specs/configs and HTTP responses are untrusted. They reach the model only inside
delimited data blocks with an unguessable nonce; anything resembling our delimiters is
neutralised first. Instruction-like text is also *detected* so the UI can warn the user —
detection is advisory, the delimiting and the output constraints are the actual defence.
"""

from __future__ import annotations

import hashlib
import re
from typing import Final

from app.core.redaction import redact_text

MAX_DATA_CHARS: Final = 1500
#: Visually similar but inert replacements for our block delimiters.
_DEFANGED_OPEN: Final = "\N{SINGLE LEFT-POINTING ANGLE QUOTATION MARK}" * 3
_DEFANGED_CLOSE: Final = "\N{SINGLE RIGHT-POINTING ANGLE QUOTATION MARK}" * 3

_INJECTION_PATTERNS: Final = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|all)\b.{0,20}"
        r"\b(instructions?|prompts?|rules?|messages?)\b",
        r"\byou are (now )?(an?|the|my)\b",
        r"\bsystem prompt\b",
        r"^\s*(system|assistant|user)\s*:",
        r"</?\s*(system|instructions?|prompt)\s*>",
        r"\b(respond|reply|answer|output)\b.{0,20}\bonly\b.{0,20}\bwith\b",
        r"\bdo not (report|flag|mention)\b",
        r"\b(not|isn't|is not) a (real )?(vulnerability|security issue|finding)\b",
        r"\bfalse positive\b",
        r"<<<|>>>",
    )
)


def looks_like_injection(text: str) -> bool:
    """True if ``text`` contains instruction-like phrasing aimed at a language model."""
    return any(p.search(line) for line in text.splitlines() for p in _INJECTION_PATTERNS)


def nonce_for(*parts: str) -> str:
    """Delimiter nonce derived from the content itself.

    The attacker controls the content, so they cannot embed the hash of the final content
    in that same content: the closing delimiter is unguessable to them.
    """
    digest = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def neutralise(text: str) -> str:
    """Redact, cap, and defang anything that could pose as our block delimiters."""
    text = redact_text(text)
    text = text.replace("<<<", _DEFANGED_OPEN).replace(">>>", _DEFANGED_CLOSE)
    if len(text) > MAX_DATA_CHARS:
        text = text[: MAX_DATA_CHARS - 1] + "…"
    return text


def data_block(label: str, text: str, nonce: str) -> str:
    """An untrusted data block the system prompt tells the model never to obey."""
    return f"<<<DATA {nonce} {label}>>>\n{neutralise(text)}\n<<<END {nonce}>>>"


_CONTROL: Final = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_output(text: str) -> str:
    """Model output is displayed only: strip control characters, redact secrets."""
    return redact_text(_CONTROL.sub("", text)).strip()


def clean_block(text: str) -> list[str]:
    """Sanitise model-proposed source lines: like :func:`clean_output` but keeps indentation.

    Strips control characters, trailing whitespace and surrounding blank lines only.
    """
    lines = [
        redact_text(_CONTROL.sub("", ln)).rstrip() for ln in text.replace("\r\n", "\n").split("\n")
    ]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines
