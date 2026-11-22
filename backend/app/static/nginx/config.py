"""Parsed Nginx config with the inheritance semantics rules need."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Final

from app.core.errors import ValidationFailedError
from app.models.finding import Evidence, EvidenceKind, FindingStatus, Location
from app.static.nginx.parser import Directive, NginxParseError, parse

EXCERPT_MAX_LINES: Final = 8
EXCERPT_MAX_LINE_CHARS: Final = 240
#: Stock includes that only define MIME types or upstream parameters; they cannot add
#: headers or security directives, so they don't make a context inconclusive.
_INERT_INCLUDES: Final = frozenset(
    {
        "mime.types",
        "fastcgi_params",
        "fastcgi.conf",
        "proxy_params",
        "uwsgi_params",
        "scgi_params",
        "fastcgi-php.conf",
    }
)
_LOOPBACK_LISTEN = re.compile(r"^(127\.\d+\.\d+\.\d+|localhost|\[::1\])(:\d+)?$", re.IGNORECASE)


class NginxConfigError(ValidationFailedError):
    """Input is not a parseable Nginx configuration."""

    code = "invalid_nginx"


@dataclass(frozen=True)
class Server:
    """A ``server`` block with its enclosing ``http`` context (``None`` in snippets)."""

    block: Directive
    http: Directive | None

    @property
    def chain(self) -> tuple[Directive, ...]:
        """Contexts from innermost to outermost."""
        return (self.block, self.http) if self.http else (self.block,)

    @property
    def label(self) -> str:
        """``server_name`` (first value) or ``server at line N``."""
        name = self.block.first("server_name")
        if name and name.args and name.args[0] not in ("_", '""', ""):
            return name.args[0]
        return f"server at line {self.block.line}"


@dataclass(frozen=True)
class Context:
    """A location (or the server itself) plus its full chain, innermost first."""

    block: Directive
    chain: tuple[Directive, ...]
    server: Server

    @property
    def label(self) -> str:
        """Human label, e.g. ``location /api`` or the server label."""
        if self.block.name == "location":
            return f"location {' '.join(self.block.args)}"
        return self.server.label


class NginxConfig:
    """Read-only view over a parsed config."""

    def __init__(self, source_name: str, text: str) -> None:
        try:
            self.root = parse(text)
        except NginxParseError as exc:
            raise NginxConfigError(str(exc)) from exc
        self.source_name = source_name.replace("\\", "/")
        self._text_lines = text.removeprefix("﻿").replace("\r\n", "\n").split("\n")
        self.http_blocks = self.root.find("http")
        #: Only server blocks, no ``http``: a sites-available style snippet. Main-config
        #: directives (server_tokens, limit_req_zone...) are then invisible to us.
        self.is_snippet = not self.http_blocks

    @property
    def source_lines(self) -> list[str]:
        """The original text split into lines (read-only by convention)."""
        return self._text_lines

    # ---- structure ----------------------------------------------------------------

    def servers(self) -> list[Server]:
        """Every server block, in source order."""
        if self.is_snippet:
            return [Server(s, None) for s in self.root.find("server")]
        return [Server(s, http) for http in self.http_blocks for s in http.find("server")]

    def contexts(self, server: Server) -> list[Context]:
        """The server itself followed by every (nested) location, in source order."""
        out = [Context(server.block, server.chain, server)]

        def visit(block: Directive, chain: tuple[Directive, ...]) -> None:
            for loc in block.find("location"):
                loc_chain = (loc, *chain)
                out.append(Context(loc, loc_chain, server))
                visit(loc, loc_chain)

        visit(server.block, server.chain)
        return out

    def all_directives(self, name: str) -> list[tuple[Directive, tuple[Directive, ...]]]:
        """Every directive called ``name`` with its ancestors (outer → inner)."""
        return [(d, anc) for d, anc in self.root.walk() if d.name == name]

    def includes(self) -> list[Directive]:
        """``include`` directives (never followed)."""
        return [d for d, _ in self.root.walk() if d.name == "include"]

    # ---- inheritance ----------------------------------------------------------------

    @staticmethod
    def effective(name: str, chain: tuple[Directive, ...]) -> Directive | None:
        """Nearest definition of an inheritable single-value directive."""
        for ctx in chain:
            found = ctx.first(name)
            if found is not None:
                return found
        return None

    @staticmethod
    def effective_headers(chain: tuple[Directive, ...]) -> tuple[Directive, list[Directive]]:
        """``add_header`` directives in effect and the context they come from.

        Nginx inherits ``add_header`` from the previous level *only if the current level
        defines none*: one ``add_header`` in a location silently drops every header set
        on the server/http level. Returns (owning context, its add_header directives).
        """
        for ctx in chain:
            headers = ctx.find("add_header")
            if headers:
                return ctx, headers
        return chain[-1], []

    @staticmethod
    def header_value(headers: list[Directive], name: str) -> str | None:
        """Value of header ``name`` (case-insensitive) among ``add_header`` directives."""
        for h in headers:
            if h.args and h.args[0].lower() == name.lower():
                return h.args[1] if len(h.args) > 1 else ""
        return None

    def status_for(self, chain: tuple[Directive, ...]) -> FindingStatus:
        """``inconclusive`` when part of the relevant config is invisible to us.

        That is the case for snippets (no ``http`` block) and for any context in the chain
        that pulls in an ``include`` we did not follow.
        """
        if self.is_snippet:
            return FindingStatus.INCONCLUSIVE
        for ctx in chain:
            for inc in ctx.find("include"):
                target = inc.args[0].replace("\\", "/").rsplit("/", 1)[-1] if inc.args else ""
                if target not in _INERT_INCLUDES:
                    return FindingStatus.INCONCLUSIVE
        return FindingStatus.POTENTIAL

    # ---- listen / TLS ---------------------------------------------------------------

    @staticmethod
    def listens(server: Server) -> list[Directive]:
        """``listen`` directives of a server."""
        return server.block.find("listen")

    def is_tls(self, server: Server) -> bool:
        """Any ``listen ... ssl|quic``, or legacy ``ssl on``."""
        if any({"ssl", "quic"} & set(d.args) for d in self.listens(server)):
            return True
        ssl = server.block.first("ssl")
        return bool(ssl and ssl.args and ssl.args[0] == "on")

    def serves_plaintext(self, server: Server) -> bool:
        """True if some non-loopback listener is plain HTTP (no listen = port 80)."""
        listens = self.listens(server)
        if not listens:
            return not self.is_tls(server)
        for d in listens:
            if not d.args or {"ssl", "quic"} & set(d.args):
                continue
            addr = d.args[0]
            if addr.startswith("unix:") or _LOOPBACK_LISTEN.match(addr):
                continue
            return True
        return False

    # ---- evidence -------------------------------------------------------------------

    def excerpt(self, d: Directive) -> str:
        """Source lines of the directive (block header + body, capped)."""
        end = min(d.end_line, d.line + EXCERPT_MAX_LINES - 1)
        lines = [ln[:EXCERPT_MAX_LINE_CHARS] for ln in self._text_lines[d.line - 1 : end]]
        if end < d.end_line:
            lines.append("…")
        return "\n".join(lines)

    def evidence(self, d: Directive) -> Evidence:
        """Static evidence for a directive."""
        return Evidence(
            kind=EvidenceKind.NGINX,
            location=Location(
                file=self.source_name,
                line=d.line,
                end_line=d.end_line if d.end_line != d.line else None,
                pointer=d.pointer,
            ),
            excerpt=self.excerpt(d),
        )


_REDIRECT_CODES: Final = frozenset({"301", "302", "303", "307", "308"})


def _is_redirect(d: Directive, *, https_only: bool) -> bool:
    if d.name == "return" and len(d.args) >= 2 and d.args[0] in _REDIRECT_CODES:
        return not https_only or d.args[1].lower().startswith("https://")
    if d.name == "rewrite" and len(d.args) >= 3 and d.args[-1] in ("permanent", "redirect"):
        return not https_only or d.args[1].lower().startswith("https://")
    return False


def redirects(server: Server, *, https_only: bool = False) -> bool:
    """Server answers everything with a redirect (server-level, or ``location /``)."""
    block = server.block
    if any(_is_redirect(d, https_only=https_only) for d in block.children or ()):
        return True
    for loc in block.find("location"):
        if loc.args and loc.args[-1] == "/" and len(block.find("location")) == 1:
            return any(_is_redirect(d, https_only=https_only) for d in loc.children or ())
    return False


@dataclass(frozen=True)
class HeaderContext:
    """A context whose ``add_header`` set must be evaluated on its own.

    ``inherited`` is the header set the context *would* have had from its parent; it is
    ``None`` for the server itself. A location whose own ``add_header`` replaces a parent
    set is where nginx's inheritance gotcha bites.
    """

    context: Context
    headers: list[Directive]
    inherited: list[Directive] | None


def header_contexts(config: NginxConfig, server: Server) -> list[HeaderContext]:
    """Server context plus every location that defines its own ``add_header``."""
    out: list[HeaderContext] = []
    for ctx in config.contexts(server):
        owner, headers = config.effective_headers(ctx.chain)
        if ctx.block.name == "server":
            out.append(HeaderContext(ctx, headers, None))
        elif owner is ctx.block:
            _, parent_headers = config.effective_headers(ctx.chain[1:])
            out.append(HeaderContext(ctx, headers, parent_headers))
    return out


def directive_at(config: NginxConfig, pointer: str) -> Directive | None:
    """The directive with this structural pointer (``""`` is the root)."""
    if pointer == "":
        return config.root
    return next((d for d, _ in config.root.walk() if d.pointer == pointer), None)


def _name_matches(pattern: str, host: str) -> bool:
    pattern = pattern.lower()
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    if pattern.startswith("."):
        return host == pattern[1:] or host.endswith(pattern)
    if pattern.startswith("~"):
        return False  # regex server names are not evaluated
    return pattern == host


def servers_for_host(config: NginxConfig, host: str) -> list[Server]:
    """Servers nginx would use for ``host``: explicit server_name matches, else catch-alls.

    A catch-all is a server with no/empty/``_`` server_name or a ``default_server`` listener.
    For an IP target with no match, nginx's default (first) server applies.
    """
    host = host.lower()
    servers = config.servers()
    named = [
        s
        for s in servers
        if any(_name_matches(n, host) for d in s.block.find("server_name") for n in d.args)
    ]
    if named:
        return named
    catch_all = [
        s
        for s in servers
        if not s.block.find("server_name")
        or all(n in ("_", "", '""') for d in s.block.find("server_name") for n in d.args)
        or any("default_server" in d.args for d in s.block.find("listen"))
    ]
    if catch_all:
        return catch_all
    # Scanning by IP: the Host header is the IP, so nginx falls back to the default (first)
    # server. For a host *name* we never assume an unrelated config is deployed there.
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return []
    return servers[:1]


def location_covers(location: Directive, path: str) -> bool:
    """Does this ``location`` match the request path? (prefix, exact and regex forms)."""
    args = location.args
    if not args:
        return False
    if len(args) == 1:
        return path.startswith(args[0])
    modifier, value = args[0], args[-1]
    if modifier == "=":
        return path == value
    if modifier == "^~":
        return path.startswith(value)
    if modifier in ("~", "~*"):
        try:
            return re.search(value, path, re.IGNORECASE if modifier == "~*" else 0) is not None
        except re.error:
            return False
    return False
