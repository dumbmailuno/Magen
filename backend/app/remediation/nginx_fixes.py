"""Deterministic Nginx fixers: finding → line edits against the original config text."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Final

from app.models.finding import Finding
from app.remediation.edits import Edit
from app.static.nginx.config import NginxConfig, directive_at
from app.static.nginx.parser import Directive

HSTS: Final = 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
NOSNIFF: Final = 'add_header X-Content-Type-Options "nosniff" always;'
FRAME: Final = 'add_header X-Frame-Options "DENY" always;'
PROTOCOLS: Final = "ssl_protocols TLSv1.2 TLSv1.3;"
CIPHERS: Final = (
    "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;"
)

Fixer = Callable[[NginxConfig, Finding], list[Edit] | None]


def _lines(config: NginxConfig) -> list[str]:
    return config.source_lines


def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _target(config: NginxConfig, f: Finding) -> Directive | None:
    return directive_at(config, f.evidence[0].location.pointer or "")


def _chain(config: NginxConfig, d: Directive) -> list[Directive]:
    for node, ancestors in config.root.walk():
        if node is d:
            return [*ancestors, node]
    return [d]


def replace_directive(config: NginxConfig, f: Finding, d: Directive, new: str) -> list[Edit] | None:
    """Rewrite a single-line simple directive, keeping its indentation."""
    if d.is_block or d.line != d.end_line:
        return None
    line = _lines(config)[d.line - 1]
    if not line.strip().startswith(d.name) or line.count(";") != 1:
        return None  # several directives on one line: leave it to the human
    return [Edit(f.id, d.line, d.line, (_indent(line) + new,))]


def insert_children(
    config: NginxConfig, f: Finding, block: Directive, new: list[str]
) -> list[Edit] | None:
    """Insert directives at the end of a block (before ``}``) so sibling pointers stay put."""
    lines = _lines(config)
    if not block.is_block or block.end_line <= block.line:
        return None
    closing = lines[block.end_line - 1]
    if not closing.strip().startswith("}"):
        return None
    children = block.children or ()
    indent = (
        _indent(lines[children[0].line - 1])
        if children
        else _indent(lines[block.line - 1]) + "    "
    )
    return [Edit(f.id, block.end_line, block.end_line - 1, tuple(indent + n for n in new))]


def _source_line(config: NginxConfig, d: Directive) -> str:
    return _lines(config)[d.line - 1].strip()


def _header_fix(config: NginxConfig, f: Finding, wanted: dict[str, str]) -> list[Edit] | None:
    """Add (or repair) headers in the finding's context, honouring add_header inheritance."""
    block = _target(config, f)
    if block is None or not block.is_block:
        return None
    own = block.find("add_header")
    edits: list[Edit] = []
    to_add: list[str] = []
    if not own:
        # Adding the first add_header here would drop everything inherited: copy it in.
        parents = tuple(reversed(_chain(config, block)[:-1]))
        _, inherited = config.effective_headers(parents) if parents else (block, [])
        to_add += [_source_line(config, h) for h in inherited if h.line == h.end_line]
    for name, line in wanted.items():
        existing = next((h for h in own if h.args and h.args[0].lower() == name), None)
        if existing is not None:
            fix = replace_directive(config, f, existing, line)
            if fix is None:
                return None
            edits += fix
        else:
            to_add.append(line)
    if to_add:
        insert = insert_children(config, f, block, to_add)
        if insert is None:
            return None
        edits += insert
    return edits


def fix_hsts(config: NginxConfig, f: Finding) -> list[Edit] | None:
    """NGX-TLS-003."""
    return _header_fix(config, f, {"strict-transport-security": HSTS})


def fix_security_headers(config: NginxConfig, f: Finding) -> list[Edit] | None:
    """NGX-HDR-002: add only what is missing."""
    block = _target(config, f)
    if block is None:
        return None
    _, headers = config.effective_headers(tuple(reversed(_chain(config, block))))
    value = NginxConfig.header_value
    wanted: dict[str, str] = {}
    if (value(headers, "X-Content-Type-Options") or "").strip('"').lower() != "nosniff":
        wanted["x-content-type-options"] = NOSNIFF
    csp = (value(headers, "Content-Security-Policy") or "").lower()
    if value(headers, "X-Frame-Options") is None and "frame-ancestors" not in csp:
        wanted["x-frame-options"] = FRAME
    return _header_fix(config, f, wanted) if wanted else None


def fix_server_tokens(config: NginxConfig, f: Finding) -> list[Edit] | None:
    """NGX-HDR-001: rewrite an explicit directive, or add one to the http block."""
    d = _target(config, f)
    if d is None:
        return None
    if d.name == "server_tokens":
        return replace_directive(config, f, d, "server_tokens off;")
    if d.name == "http":
        return insert_children(config, f, d, ["server_tokens off;"])
    return None  # snippet: belongs in the main nginx.conf


def fix_plaintext(config: NginxConfig, f: Finding) -> list[Edit] | None:
    """NGX-TLS-004: redirect a plain-HTTP-only server (never one that also serves TLS)."""
    d = _target(config, f)
    server = next((s for s in config.servers() if s.block is d), None)
    if d is None or server is None or config.is_tls(server):
        return None
    return insert_children(config, f, d, ["return 301 https://$host$request_uri;"])


def fix_rate_limit(config: NginxConfig, f: Finding) -> list[Edit] | None:
    """NGX-RL-001: define a zone (or reuse an existing one) and apply it in every server."""
    http = _target(config, f)
    if http is None or http.name != "http":
        return None
    zone = None
    for z in http.find("limit_req_zone"):
        m = next((re.match(r"zone=([^:]+):", a) for a in z.args if a.startswith("zone=")), None)
        if m:
            zone = m.group(1)
            break
    edits: list[Edit] = []
    if zone is None:
        zone = "magen_api"
        add = insert_children(
            config, f, http, [f"limit_req_zone $binary_remote_addr zone={zone}:10m rate=10r/s;"]
        )
        if add is None:
            return None
        edits += add
    for server in http.find("server"):
        add = insert_children(config, f, server, [f"limit_req zone={zone} burst=20 nodelay;"])
        if add is None:
            return None
        edits += add
    return edits


def _simple(new: str, name: str) -> Fixer:
    def fixer(config: NginxConfig, f: Finding) -> list[Edit] | None:
        d = _target(config, f)
        return replace_directive(config, f, d, new) if d is not None and d.name == name else None

    return fixer


def fix_exposed_status(config: NginxConfig, f: Finding) -> list[Edit] | None:
    """NGX-CFG-002: restrict to loopback."""
    d = _target(config, f)
    if d is None or d.name != "location":
        return None
    return insert_children(config, f, d, ["allow 127.0.0.1;", "deny all;"])


FIXERS: Final[dict[str, Fixer]] = {
    "NGX-HDR-001": fix_server_tokens,
    "NGX-HDR-002": fix_security_headers,
    "NGX-TLS-001": _simple(PROTOCOLS, "ssl_protocols"),
    "NGX-TLS-002": _simple(CIPHERS, "ssl_ciphers"),
    "NGX-TLS-003": fix_hsts,
    "NGX-TLS-004": fix_plaintext,
    "NGX-CFG-001": _simple("autoindex off;", "autoindex"),
    "NGX-CFG-002": fix_exposed_status,
    "NGX-CFG-003": _simple("client_max_body_size 10m;", "client_max_body_size"),
    "NGX-RL-001": fix_rate_limit,
    # NGX-CORS-001: needs the allowed origin(s) — template only.
}
