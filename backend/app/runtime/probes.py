"""The fixed, bounded probe plan. Same target → same probes in the same order.

Probes are read-only requests a browser could make (GET/HEAD/OPTIONS) plus TLS handshakes.
No payloads, no credentials guessing, no fuzzing (CLAUDE.md §7).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from typing import Final
from urllib.parse import urlsplit, urlunsplit

from app.core.safety import BudgetExceededError
from app.runtime.client import CANCELLED, AuditEntry, SafeHttpClient
from app.runtime.observations import CORS_PROBE_ORIGIN, RuntimeObservations, TlsObservation
from app.runtime.tls import (
    LEGACY_PROTOCOLS,
    HandshakeResult,
    legacy_handshake,
    verify_handshake,
)

#: Deterministic path that should not exist, to observe error handling.
NOT_FOUND_PATH: Final = "/magen-probe-not-found-7f3a"


@dataclass(frozen=True)
class PathProbe:
    """A well-known sensitive path fetched from the site root."""

    probe_id: str
    path: str
    withhold_body: bool = False


SENSITIVE_PATHS: Final = (
    PathProbe("path-git-head", "/.git/HEAD"),
    PathProbe("path-env", "/.env", withhold_body=True),
    PathProbe("path-nginx-status", "/nginx_status"),
    PathProbe("path-server-status", "/server-status"),
    PathProbe("path-actuator", "/actuator"),
    PathProbe("path-phpinfo", "/phpinfo.php"),
)

Progress = Callable[[int, int, str], Awaitable[None]]


def plan_size(base_url: str) -> int:
    """Number of probes the plan will attempt (for progress display)."""
    https = urlsplit(base_url).scheme == "https"
    http_probes = 3 + len(SENSITIVE_PATHS) + (1 if https else 0)
    tls_probes = (1 + len(LEGACY_PROTOCOLS)) if https else 0
    return http_probes + tls_probes


def _origin(base_url: str, scheme: str | None = None, *, drop_port: bool = False) -> str:
    p = urlsplit(base_url)
    netloc = p.hostname or "" if drop_port else p.netloc
    if ":" in (p.hostname or "") and drop_port:
        netloc = f"[{p.hostname}]"
    return urlunsplit((scheme or p.scheme, netloc, "", "", ""))


async def collect(
    client: SafeHttpClient,
    base_url: str,
    obs: RuntimeObservations,
    progress: Progress,
) -> None:
    """Run the plan, filling ``obs`` as it goes (so a Stop keeps partial results).

    Stops early (without raising) when the request budget is exhausted; the remaining
    probes are listed in ``obs.skipped``.
    """
    total = plan_size(base_url)
    https = urlsplit(base_url).scheme == "https"
    root = _origin(base_url)

    @dataclass(frozen=True)
    class Step:
        probe_id: str
        label: str
        method: str
        url: str
        headers: dict[str, str] | None = None
        send_auth: bool = True
        follow_redirects: bool = True
        withhold_body: bool = False

    cors = {"Origin": CORS_PROBE_ORIGIN}
    steps = [
        Step("base-get", f"GET {base_url}", "GET", base_url, headers=cors),
        Step(
            "base-options",
            f"OPTIONS {base_url}",
            "OPTIONS",
            base_url,
            headers={**cors, "Access-Control-Request-Method": "GET"},
            follow_redirects=False,
        ),
        Step(
            "not-found",
            f"GET {NOT_FOUND_PATH}",
            "GET",
            root + NOT_FOUND_PATH,
            follow_redirects=False,
        ),
    ]
    if https:
        plain = _origin(base_url, "http", drop_port=True) + "/"
        steps.append(
            Step(
                "plain-http", f"GET {plain}", "GET", plain, send_auth=False, follow_redirects=False
            )
        )
    steps += [
        Step(
            p.probe_id,
            f"GET {p.path}",
            "GET",
            root + p.path,
            follow_redirects=False,
            withhold_body=p.withhold_body,
        )
        for p in SENSITIVE_PATHS
    ]

    done = 0
    for step in steps:
        await progress(done, total, step.label)
        try:
            obs.http[step.probe_id] = await client.request(
                step.probe_id,
                step.method,
                step.url,
                headers=step.headers,
                send_auth=step.send_auth,
                follow_redirects=step.follow_redirects,
                withhold_body=step.withhold_body,
            )
        except BudgetExceededError:
            obs.skipped.append(step.label)
        done += 1

    if https:
        await _collect_tls(client, base_url, obs, progress, done, total)
    await progress(total, total, "Done")


async def _collect_tls(
    client: SafeHttpClient,
    base_url: str,
    obs: RuntimeObservations,
    progress: Progress,
    done: int,
    total: int,
) -> None:
    parts = urlsplit(base_url)
    host = parts.hostname or ""
    port = parts.port or 443
    ip = await client.resolve_checked(base_url)

    async def handshake(label: str, fn: Callable[[], HandshakeResult]) -> HandshakeResult | None:
        nonlocal done
        await progress(done, total, label)
        done += 1
        try:
            client.budget.take()
        except BudgetExceededError:
            obs.skipped.append(label)
            return None
        await client.global_limiter.acquire()
        await client.limiter.acquire()
        sent_at = datetime.now(tz=UTC)
        where = f"tls://{host}:{port} ({label})"
        try:
            result = await asyncio.to_thread(fn)
        except asyncio.CancelledError:
            await client.audit(AuditEntry(sent_at, "TLS", where, None, CANCELLED))
            raise
        await client.audit(AuditEntry(sent_at, "TLS", where, None, result.error))
        return result

    verify = await handshake("TLS verify", partial(verify_handshake, host, ip, port))
    legacy: dict[str, bool | None] = {}
    for name in LEGACY_PROTOCOLS:
        res = await handshake(f"TLS {name}", partial(legacy_handshake, host, ip, port, name))
        if res is None or res.client_unsupported or not res.connected:
            legacy[name] = None  # not testable — never reported as "refused"
        else:
            legacy[name] = res.ok
    if verify is None or not verify.connected:
        obs.tls = TlsObservation(
            host=host,
            port=port,
            verified=None,
            legacy_protocols=legacy,
            error="not tested" if verify is None else verify.error,
        )
        return
    obs.tls = TlsObservation(
        host=host,
        port=port,
        verified=verify.ok,
        verify_error=None if verify.ok else verify.error,
        protocol=verify.protocol,
        legacy_protocols=legacy,
    )
