"""SafeHttpClient: the only code in Magen that sends HTTP requests.

Per request it: checks the method, checks the host is the authorized target, resolves DNS
and validates *every* address, connects to the validated IP (Host header + SNI keep the
name, so DNS rebinding cannot redirect it), consumes budget, waits for the rate limiters,
caps the body, follows at most MAX_REDIRECTS same-host redirects (re-checking each hop),
redacts everything it records and writes an audit entry for every request sent.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from pydantic import SecretStr

from app.core.redaction import mask_values, redact_headers, redact_text
from app.core.safety import (
    GLOBAL_LIMITER,
    MAX_REDIRECTS,
    AuthorizedTarget,
    IPAddress,
    RateLimiter,
    RequestBudget,
    UnsafeTargetError,
    check_addresses,
    host_of,
    require_safe_method,
    require_same_host,
)
from app.runtime.observations import HttpObservation
from app.runtime.resolver import Resolver

log = logging.getLogger(__name__)

MAX_BODY_BYTES: Final = 64 * 1024
BODY_EXCERPT_CHARS: Final = 1024
USER_AGENT: Final = "Magen/0.1 (authorized security scan; safe methods only)"
_REDIRECT_CODES: Final = frozenset({301, 302, 303, 307, 308})
CANCELLED: Final = "Cancelled (scan stopped)"


@dataclass(frozen=True)
class AuditEntry:
    """One request actually sent (or attempted)."""

    sent_at: datetime
    method: str
    url: str
    status: int | None
    error: str | None


AuditSink = Callable[[AuditEntry], Awaitable[None]]


@dataclass(frozen=True)
class AuthHeader:
    """The single optional user-supplied header. Lives in memory only."""

    name: str
    value: SecretStr


def _pinned_url(url: str, ip: IPAddress) -> str:
    parts = urlsplit(url)
    literal = f"[{ip}]" if isinstance(ip, ipaddress.IPv6Address) else str(ip)
    netloc = f"{literal}:{parts.port}" if parts.port else literal
    return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))


def _host_header(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    host = f"[{host}]" if ":" in host else host
    return f"{host}:{parts.port}" if parts.port else host


def _default_port(url: str) -> int:
    parts = urlsplit(url)
    return parts.port or (443 if parts.scheme == "https" else 80)


class SafeHttpClient:
    """Guarded HTTP client bound to one authorized target and one scan's budget."""

    def __init__(
        self,
        target: AuthorizedTarget,
        *,
        resolver: Resolver,
        budget: RequestBudget,
        limiter: RateLimiter,
        audit: AuditSink,
        auth: AuthHeader | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        global_limiter: RateLimiter = GLOBAL_LIMITER,
        timeout: httpx.Timeout | None = None,
    ) -> None:
        self.target = target
        self.resolver = resolver
        self.budget = budget
        self.limiter = limiter
        self.global_limiter = global_limiter
        self.audit = audit
        self.auth = auth
        self._secrets = (auth.value.get_secret_value(),) if auth else ()
        # Local lab targets commonly use self-signed certificates; public targets must
        # present a valid one (certificate problems are reported by the TLS probe).
        self._client = httpx.AsyncClient(
            transport=transport,
            verify=not target.is_local,
            follow_redirects=False,
            timeout=timeout or httpx.Timeout(10.0, connect=5.0),
            trust_env=False,  # never route probes through an environment proxy
        )

    async def aclose(self) -> None:
        """Close pooled connections."""
        await self._client.aclose()

    async def resolve_checked(self, url: str) -> IPAddress:
        """Validate host + DNS for ``url`` and return the address to connect to."""
        host = require_same_host(self.target, url)
        addresses = await self.resolver.resolve(host, _default_port(url))
        return check_addresses(host, addresses, is_local=self.target.is_local)

    def _request_headers(
        self, url: str, extra: dict[str, str] | None, send_auth: bool
    ) -> dict[str, str]:
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*", **(extra or {})}
        plaintext = urlsplit(url).scheme == "http"
        # Never send the credential over plain HTTP to a non-local target.
        if self.auth and send_auth and (not plaintext or self.target.is_local):
            headers[self.auth.name] = self.auth.value.get_secret_value()
        return headers

    def _redact(self, text: str) -> str:
        return redact_text(text, self._secrets)

    async def request(
        self,
        probe_id: str,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        send_auth: bool = True,
        follow_redirects: bool = True,
        withhold_body: bool = False,
    ) -> HttpObservation:
        """Send one probe. Network errors become observations; safety violations raise.

        A redirect that would leave the authorized host, change scheme to something other
        than http(s), or exceed MAX_REDIRECTS is *not* followed and is recorded instead.
        """
        method = require_safe_method(method)
        current = url
        redirects: list[str] = []
        sent_headers: dict[str, str] = {}
        while True:
            ip = await self.resolve_checked(current)
            self.budget.take()
            await self.global_limiter.acquire()
            await self.limiter.acquire()
            sent_headers = self._request_headers(current, headers, send_auth)
            sni = urlsplit(current).hostname or ""
            request = self._client.build_request(
                method,
                _pinned_url(current, ip),
                headers={**sent_headers, "Host": _host_header(current)},
                extensions={"sni_hostname": sni} if current.startswith("https") else {},
            )
            sent_at = datetime.now(tz=UTC)
            try:
                response = await self._client.send(request, stream=True)
            except httpx.HTTPError as exc:
                error = self._describe(exc)
                await self.audit(AuditEntry(sent_at, method, self._redact(current), None, error))
                return self._observation(
                    probe_id, method, url, current, redirects, sent_headers, error=error
                )
            except asyncio.CancelledError:
                # Stop pressed while in flight: the request may have reached the target,
                # so it must still be in the audit log.
                await self.audit(
                    AuditEntry(sent_at, method, self._redact(current), None, CANCELLED)
                )
                raise
            try:
                body = await self._read_capped(response)
            except asyncio.CancelledError:
                await self.audit(
                    AuditEntry(
                        sent_at, method, self._redact(current), response.status_code, CANCELLED
                    )
                )
                raise
            finally:
                await response.aclose()
            await self.audit(
                AuditEntry(sent_at, method, self._redact(current), response.status_code, None)
            )
            location = response.headers.get("location")
            if follow_redirects and response.status_code in _REDIRECT_CODES and location:
                next_url = urljoin(current, location)
                stop = self._redirect_problem(next_url, len(redirects))
                if stop is None:
                    redirects.append(self._redact(next_url))
                    current = next_url
                    continue
                return self._observation(
                    probe_id,
                    method,
                    url,
                    current,
                    redirects,
                    sent_headers,
                    response=response,
                    body=body,
                    withhold_body=withhold_body,
                    error=stop,
                )
            return self._observation(
                probe_id,
                method,
                url,
                current,
                redirects,
                sent_headers,
                response=response,
                body=body,
                withhold_body=withhold_body,
            )

    def _redirect_problem(self, next_url: str, hops: int) -> str | None:
        if hops >= MAX_REDIRECTS:
            return f"Stopped after {MAX_REDIRECTS} redirects"
        try:
            if host_of(next_url) != self.target.host:
                where = self._redact(next_url)
                return f"Redirect to {where} not followed (outside the authorized host)"
        except Exception:  # noqa: BLE001 - any malformed Location is simply not followed
            return "Redirect with an invalid Location not followed"
        return None

    @staticmethod
    async def _read_capped(response: httpx.Response) -> bytes:
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            chunks.append(chunk)
            size += len(chunk)
            if size >= MAX_BODY_BYTES:
                break
        return b"".join(chunks)[:MAX_BODY_BYTES]

    @staticmethod
    def _describe(exc: httpx.HTTPError) -> str:
        if isinstance(exc, httpx.TimeoutException):
            return "Timed out"
        if isinstance(exc, httpx.ConnectError):
            return "Connection failed"
        return type(exc).__name__

    def _observation(
        self,
        probe_id: str,
        method: str,
        url: str,
        final: str,
        redirects: list[str],
        sent_headers: dict[str, str],
        *,
        response: httpx.Response | None = None,
        body: bytes = b"",
        withhold_body: bool = False,
        error: str | None = None,
    ) -> HttpObservation:
        req = redact_headers(sent_headers, self._secrets)
        if response is None:
            return HttpObservation(
                probe_id=probe_id,
                method=method,
                url=self._redact(url),
                status=None,
                request_headers=tuple((k, v) for k, v in req.items()),
                final_url=self._redact(final),
                redirects=tuple(redirects),
                error=error,
            )
        resp = redact_headers(dict(response.headers.multi_items()), self._secrets)
        text = body.decode("utf-8", errors="replace")
        return HttpObservation(
            probe_id=probe_id,
            method=method,
            url=self._redact(url),
            status=response.status_code,
            headers=tuple((k.lower(), v) for k, v in resp.items()),
            request_headers=tuple((k, v) for k, v in req.items()),
            # Withheld bodies keep only their shape (KEY=••••) so rules can classify them;
            # response_text() still omits them from evidence entirely.
            body_excerpt=(
                mask_values(text[:BODY_EXCERPT_CHARS])
                if withhold_body
                else self._redact(text[:BODY_EXCERPT_CHARS])
            ),
            body_bytes=len(body),
            final_url=self._redact(final),
            redirects=tuple(redirects),
            error=error,
            body_withheld=withhold_body,
        )


__all__ = ["AuditEntry", "AuditSink", "AuthHeader", "SafeHttpClient", "UnsafeTargetError"]
