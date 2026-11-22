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

_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # Authorization: Bearer abc / Basic abc / Token abc
    re.compile(r"(?i)\b(bearer|basic|token|digest)\s+[A-Za-z0-9\-._~+/]+=*"),
    # Header lines in raw HTTP excerpts: "Cookie: a=b; c=d"
    re.compile(
        r"(?im)^((?:proxy-)?authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token"
        r"|x-access-token|x-magen-token)\s*:\s*.+$"
    ),
    # key=value / "key": "value" style secrets in query strings, JSON or configs.
    # Same-line only ([ \t], not \s) and the value may not start with { or [ so that schema
    # excerpts like "password:\n  type: string" or '"password": {"type": ...}' are untouched.
    re.compile(
        r"(?i)([\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password"
        r"|passwd|client[_-]?secret)[\"']?[ \t]*[:=][ \t]*[\"']?)([^\s\"'&,;{}\[\]]+)"
    ),
    # JWTs anywhere
    re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
)


def _sub(match: re.Match[str]) -> str:
    text = match.group(0)
    # Header line: keep the header name.
    if ":" in text and match.re is _PATTERNS[1]:
        name = text.split(":", 1)[0]
        return f"{name}: {REDACTED}"
    # key=value: keep the key and separator.
    if match.re is _PATTERNS[2]:
        return f"{match.group(1)}{REDACTED}"
    # Scheme + credential: keep the scheme.
    if match.re is _PATTERNS[0]:
        return f"{match.group(1)} {REDACTED}"
    return REDACTED


def redact_text(text: str, extra_secrets: tuple[str, ...] = ()) -> str:
    """Return ``text`` with credentials replaced by :data:`REDACTED`.

    ``extra_secrets`` are exact values known to be secret (e.g. the user-supplied auth
    header value for the current scan) and are always removed, whatever their shape.
    """
    for secret in sorted(extra_secrets, key=len, reverse=True):
        if secret:
            text = text.replace(secret, REDACTED)
    for pattern in _PATTERNS:
        text = pattern.sub(_sub, text)
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
