"""SafeHttpClient against a mock transport and a fake resolver (no network)."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Callable

import httpx
import pytest
from pydantic import SecretStr

from app.core.redaction import REDACTED
from app.core.safety import (
    AuthorizedTarget,
    BudgetExceededError,
    RateLimiter,
    RequestBudget,
    UnsafeTargetError,
)
from app.runtime.client import MAX_BODY_BYTES, AuditEntry, AuthHeader, SafeHttpClient

SECRET = "Bearer s3cr3t-T0KEN-value"
FAST = RateLimiter(5)


class FakeResolver:
    def __init__(self, table: dict[str, list[str]]) -> None:
        self.table = table
        self.calls: list[str] = []

    async def resolve(
        self, host: str, port: int
    ) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        self.calls.append(host)
        return [ipaddress.ip_address(a) for a in self.table.get(host, [])]


def make(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    host: str = "api.example.com",
    is_local: bool = False,
    table: dict[str, list[str]] | None = None,
    cap: int = 50,
    auth: bool = True,
) -> tuple[SafeHttpClient, list[AuditEntry], list[httpx.Request]]:
    audit: list[AuditEntry] = []
    seen: list[httpx.Request] = []

    def record(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return handler(req)

    async def sink(e: AuditEntry) -> None:
        audit.append(e)

    client = SafeHttpClient(
        AuthorizedTarget(1, host, is_local),
        resolver=FakeResolver(table or {host: ["93.184.216.34"]}),
        budget=RequestBudget(cap),
        limiter=FAST,
        global_limiter=RateLimiter(5),
        audit=sink,
        auth=AuthHeader("Authorization", SecretStr(SECRET)) if auth else None,
        transport=httpx.MockTransport(record),
    )
    return client, audit, seen


def run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def test_pins_resolved_ip_and_keeps_host_and_sni() -> None:
    client, audit, seen = make(lambda r: httpx.Response(200, text="ok"))
    obs = run(client.request("p", "GET", "https://api.example.com/v1?x=1"))
    req = seen[0]
    assert req.url.host == "93.184.216.34"  # connected to the validated IP
    assert req.headers["host"] == "api.example.com"
    assert req.extensions["sni_hostname"] == "api.example.com"
    assert obs.status == 200 and obs.url == "https://api.example.com/v1?x=1"
    assert [(a.method, a.status) for a in audit] == [("GET", 200)]


def test_auth_header_sent_but_redacted_everywhere() -> None:
    client, audit, seen = make(
        lambda r: httpx.Response(200, text=f"echo {SECRET}", headers={"X-Echo": SECRET})
    )
    obs = run(client.request("p", "GET", "https://api.example.com/"))
    assert seen[0].headers["authorization"] == SECRET  # actually sent
    blob = obs.request_text() + obs.response_text() + obs.body_excerpt + repr(audit)
    assert "s3cr3t-T0KEN-value" not in blob
    assert REDACTED in obs.request_text()


def test_auth_never_sent_over_plain_http_to_public_target() -> None:
    client, _, seen = make(lambda r: httpx.Response(200))
    run(client.request("p", "GET", "http://api.example.com/"))
    assert "authorization" not in seen[0].headers


def test_auth_sent_over_http_to_local_lab_target() -> None:
    client, _, seen = make(
        lambda r: httpx.Response(200),
        host="localhost",
        is_local=True,
        table={"localhost": ["127.0.0.1"]},
    )
    run(client.request("p", "GET", "http://localhost:5000/"))
    assert seen[0].headers["authorization"] == SECRET


def test_send_auth_false_respected() -> None:
    client, _, seen = make(lambda r: httpx.Response(200))
    run(client.request("p", "GET", "https://api.example.com/", send_auth=False))
    assert "authorization" not in seen[0].headers


@pytest.mark.parametrize("method", ["POST", "DELETE", "PUT"])
def test_unsafe_method_never_reaches_the_network(method: str) -> None:
    client, audit, seen = make(lambda r: httpx.Response(200))
    with pytest.raises(UnsafeTargetError):
        run(client.request("p", method, "https://api.example.com/"))
    assert seen == [] and audit == []


def test_other_host_never_reaches_the_network() -> None:
    client, _, seen = make(lambda r: httpx.Response(200))
    with pytest.raises(UnsafeTargetError):
        run(client.request("p", "GET", "https://evil.example.com/"))
    assert seen == []


def test_internal_resolution_blocked_for_public_target() -> None:
    client, _, seen = make(
        lambda r: httpx.Response(200), table={"api.example.com": ["169.254.169.254"]}
    )
    with pytest.raises(UnsafeTargetError, match="metadata"):
        run(client.request("p", "GET", "https://api.example.com/"))
    assert seen == []


def test_same_host_redirects_followed_and_rechecked() -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        if r.url.path == "/a":
            return httpx.Response(302, headers={"Location": "/b"})
        return httpx.Response(200, text="final")

    client, audit, seen = make(handler)
    obs = run(client.request("p", "GET", "https://api.example.com/a"))
    assert obs.status == 200 and obs.final_url == "https://api.example.com/b"
    assert obs.redirects == ("https://api.example.com/b",)
    assert len(seen) == 2 and len(audit) == 2
    assert client.resolver.calls == ["api.example.com", "api.example.com"]  # type: ignore[attr-defined]


def test_cross_host_redirect_not_followed() -> None:
    client, _, seen = make(
        lambda r: httpx.Response(301, headers={"Location": "https://evil.example.com/steal"})
    )
    obs = run(client.request("p", "GET", "https://api.example.com/"))
    assert len(seen) == 1
    assert obs.status == 301 and obs.error is not None and "not followed" in obs.error


def test_redirect_loop_capped() -> None:
    client, _, seen = make(lambda r: httpx.Response(302, headers={"Location": r.url.path + "x"}))
    obs = run(client.request("p", "GET", "https://api.example.com/"))
    assert len(seen) == 4  # first request + MAX_REDIRECTS
    assert obs.error is not None and "Stopped after 3 redirects" in obs.error


def test_redirect_to_non_http_scheme_not_followed() -> None:
    client, _, seen = make(
        lambda r: httpx.Response(302, headers={"Location": "file:///etc/passwd"})
    )
    obs = run(client.request("p", "GET", "https://api.example.com/"))
    assert len(seen) == 1 and obs.error is not None


def test_budget_enforced_per_request_and_hop() -> None:
    client, _, seen = make(lambda r: httpx.Response(302, headers={"Location": "/next"}), cap=2)
    with pytest.raises(BudgetExceededError):
        run(client.request("p", "GET", "https://api.example.com/"))
    assert len(seen) == 2


def test_body_is_capped() -> None:
    client, _, _ = make(lambda r: httpx.Response(200, content=b"x" * (MAX_BODY_BYTES * 3)))
    obs = run(client.request("p", "GET", "https://api.example.com/"))
    assert obs.body_bytes == MAX_BODY_BYTES
    assert len(obs.body_excerpt) <= 1024


def test_withheld_body_is_masked_and_never_in_evidence() -> None:
    client, _, _ = make(lambda r: httpx.Response(200, text="DB_PASSWORD=hunter2\nAPI_KEY=abc\n"))
    obs = run(client.request("p", "GET", "https://api.example.com/.env", withhold_body=True))
    assert "hunter2" not in obs.body_excerpt and "abc" not in obs.body_excerpt
    assert obs.body_excerpt.startswith("DB_PASSWORD=")
    assert "DB_PASSWORD" not in obs.response_text()


def test_network_errors_become_observations_and_are_audited() -> None:
    def boom(r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow")

    client, audit, _ = make(boom)
    obs = run(client.request("p", "GET", "https://api.example.com/"))
    assert obs.status is None and obs.error == "Timed out"
    assert audit[0].error == "Timed out"


def test_set_cookie_redacted() -> None:
    client, _, _ = make(
        lambda r: httpx.Response(200, headers={"Set-Cookie": "sid=abc123; HttpOnly"})
    )
    obs = run(client.request("p", "GET", "https://api.example.com/"))
    assert obs.header("set-cookie") == REDACTED
