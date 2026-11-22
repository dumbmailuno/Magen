"""API-OAS-001 — server URL uses plain HTTP."""

from __future__ import annotations

from typing import Any, ClassVar
from urllib.parse import urlsplit

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.openapi._common import OWASP_DOCS
from app.rules.registry import registry
from app.static.openapi.document import OpenApiDocument
from app.static.openapi.loader import join_pointer

_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def _server_lists(doc: OpenApiDocument) -> list[tuple[Any, str]]:
    found: list[tuple[Any, str]] = [(doc.data.get("servers"), "/servers")]
    seen_items: set[str] = set()
    for op in doc.operations():
        if op.path_item_pointer not in seen_items:
            seen_items.add(op.path_item_pointer)
            found.append(
                (op.path_item.get("servers"), join_pointer(op.path_item_pointer, "servers"))
            )
        found.append((op.node.get("servers"), join_pointer(op.pointer, "servers")))
    return found


def _effective_url(server: dict[str, Any]) -> tuple[str, bool]:
    """Expand a leading ``{var}://`` with its default. Returns (url, scheme_may_be_http)."""
    url = str(server.get("url", ""))
    if url.startswith("{") and "}://" in url:
        var = url[1 : url.index("}")]
        spec = (server.get("variables") or {}).get(var) or {}
        options = {str(spec.get("default", ""))} | {str(e) for e in spec.get("enum") or []}
        rest = url[url.index("}://") + 1 :]
        return f"http{rest}", any(o.lower() == "http" for o in options)
    return url, url.lower().startswith("http://")


def _is_loopback(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host in _LOOPBACK or host.endswith(".localhost")


@registry.register
class HttpServerRule(Rule[OpenApiDocument]):
    """Flags non-loopback servers reachable over cleartext HTTP."""

    id: ClassVar[str] = "API-OAS-001"
    title: ClassVar[str] = "Server URL uses plain HTTP"
    category: ClassVar[str] = "Transport security"
    severity: ClassVar[Severity] = Severity.HIGH
    target: ClassVar[RuleTarget] = RuleTarget.OPENAPI
    description: ClassVar[str] = (
        "A declared server uses http://, so credentials and data can be read or modified "
        "in transit. Loopback hosts (localhost, 127.0.0.1) are ignored as local development "
        "servers. A templated scheme ({scheme}://) is flagged if its default or enum allows http."
    )
    references: ClassVar[References] = References(
        owasp_api=["API8:2023"], cwe=["CWE-319"], links=[OWASP_DOCS]
    )
    remediation_template: ClassVar[str] = (
        "servers:\n  - url: https://api.example.com/v1   # serve the API over TLS only"
    )

    def check(self, document: OpenApiDocument) -> list[Finding]:
        """Inspect root, path-item and operation-level ``servers``."""
        findings: list[Finding] = []
        for servers, pointer in _server_lists(document):
            if not isinstance(servers, list):
                continue
            for i, server in enumerate(servers):
                if not isinstance(server, dict):
                    continue
                url, may_be_http = _effective_url(server)
                if may_be_http and not _is_loopback(url):
                    ptr = join_pointer(pointer, i, "url")
                    findings.append(
                        self.finding(
                            [document.evidence(ptr)],
                            title=f"Server {server.get('url')} uses plain HTTP",
                        )
                    )
        return findings
