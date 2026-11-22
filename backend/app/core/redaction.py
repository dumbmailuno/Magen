"""Secret redaction for logs, DB rows and exports (CLAUDE.md §2 Auth, §7).

Redaction is applied defensively everywhere data leaves memory. It is deliberately
over-eager: a false redaction is harmless, a leaked token is not.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final

#: Placeholder rendered in place of secrets. The UI shows this as ``••••``.
REDACTED: Final = "••••"

SENSITIVE_HEADERS: Final = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-access-token",
        "x-magen-token",
    }
)

#: (pattern, replacement) pairs, applied in order. Replacements keep the non-secret part
#: (scheme, header name, key) so redacted evidence stays readable.
_RULES: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    # Authorization: Bearer abc / Basic abc / Token abc  → keep the scheme
    (re.compile(r"(?i)\b(bearer|basic|token|digest)\s+[A-Za-z0-9\-._~+/]+=*"), rf"\1 {REDACTED}"),
    # Header lines in raw HTTP excerpts: "Cookie: a=b; c=d"  → keep the header name
    (
        re.compile(
            r"(?im)^((?:proxy-)?authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token"
            r"|x-access-token|x-magen-token)\s*:\s*.+$"
        ),
        rf"\1: {REDACTED}",
    ),
    # key=value / "key": "value" style secrets in query strings, JSON or configs.
    # Same-line only ([ \t], not \s) and the value may not start with { or [ so that schema
    # excerpts like "password:\n  type: string" or '"password": {"type": ...}' are untouched.
    (
        re.compile(
            r"(?i)([\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password"
            r"|passwd|client[_-]?secret)[\"']?[ \t]*[:=][ \t]*[\"']?)([^\s\"'&,;{}\[\]]+)"
        ),
        rf"\1{REDACTED}",
    ),
    # JWTs anywhere
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), REDACTED),
    # Credentials embedded in URLs: scheme://user:password@host  → keep the scheme
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s:@]+:[^/\s@]+@"), rf"\1{REDACTED}@"),
)


def redact_text(text: str, extra_secrets: tuple[str, ...] = ()) -> str:
    """Return ``text`` with credentials replaced by :data:`REDACTED`.

    ``extra_secrets`` are exact values known to be secret (e.g. the user-supplied auth
    header value for the current scan) and are always removed, whatever their shape.
    """
    for secret in sorted(extra_secrets, key=len, reverse=True):
        if secret:
            text = text.replace(secret, REDACTED)
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


def redact_headers(
    headers: Mapping[str, str], extra_secrets: tuple[str, ...] = ()
) -> dict[str, str]:
    """Return a copy of ``headers`` with sensitive header values redacted."""
    out: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in SENSITIVE_HEADERS:
            out[name] = REDACTED
        else:
            out[name] = redact_text(value, extra_secrets)
    return out


_ASSIGNMENT: Final = re.compile(r"^(\s*[A-Za-z_][A-Za-z0-9_.\-]*\s*[=:])")


def mask_values(text: str) -> str:
    """Keep only the *shape* of a sensitive file: ``KEY=••••`` per assignment line.

    Used for bodies that must never be stored (e.g. a served ``.env``): rules can still
    count variables, but no value survives, not even in memory.
    """
    out: list[str] = []
    for line in text.splitlines():
        m = _ASSIGNMENT.match(line)
        if m:
            out.append(f"{m.group(1).strip()}{REDACTED}")
        elif line.strip():
            out.append(REDACTED)
        else:
            out.append("")
    return "\n".join(out)
