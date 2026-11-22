"""Runtime safety guardrails (CLAUDE.md §7). Pure functions + small async primitives.

Everything that decides *whether* Magen may send a request lives here so it can be
reviewed and tested in one place. ``app/runtime`` calls these; nothing else may send
network traffic.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

from app.core.errors import TargetNotAllowedError, ValidationFailedError

#: Only these methods may ever be sent in v1.
SAFE_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS"})

#: Hard ceilings the user cannot exceed (defaults are lower or equal).
MAX_RATE_PER_SECOND: Final = 5.0
DEFAULT_RATE_PER_SECOND: Final = 5.0
MAX_REQUEST_CAP: Final = 200
DEFAULT_REQUEST_CAP: Final = 50
MAX_REDIRECTS: Final = 3

#: Cloud metadata endpoints: blocked even for targets marked local.
METADATA_ADDRESSES: Final = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),  # AWS / GCP / Azure / OpenStack
        ipaddress.ip_address("169.254.170.2"),  # AWS ECS task metadata
        ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud
        ipaddress.ip_address("fd00:ec2::254"),  # AWS IPv6
    }
)

_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class UnsafeTargetError(TargetNotAllowedError):
    """A request would violate a runtime safety rule."""

    code = "unsafe_target"


class InvalidHostError(ValidationFailedError):
    """Host string is not a valid hostname or IP literal."""

    code = "invalid_host"


# ---- hosts ---------------------------------------------------------------------------


def normalize_host(raw: str) -> str:
    """Canonical host: lowercase, IDNA-encoded, no trailing dot, IPv6 without brackets.

    Rejects schemes, paths, ports, credentials and wildcards: an allowlist entry is exactly
    one host.
    """
    host = raw.strip().lower()
    if not host or any(c in host for c in "/@?#*\\ \t") or "://" in host:
        raise InvalidHostError("Enter a bare host name or IP address (no scheme, path or port)")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if ":" in host:
        raise InvalidHostError("Enter the host without a port")
    host = host.rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidHostError("Host name is not valid") from exc
    labels = host.split(".")
    if len(host) > 253 or not all(_HOST_LABEL.match(label) for label in labels):
        raise InvalidHostError("Host name is not valid")
    return host


def host_of(url: str) -> str:
    """Normalized host of an http(s) URL; rejects other schemes and credentials in URLs."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        raise ValidationFailedError("URL must start with http:// or https://")
    if parts.username or parts.password:
        raise ValidationFailedError("Put credentials in the auth header field, not the URL")
    if not parts.hostname:
        raise ValidationFailedError("URL has no host")
    return normalize_host(parts.hostname)


# ---- IP classification ---------------------------------------------------------------


def is_metadata(ip: IPAddress) -> bool:
    """Cloud metadata service address."""
    return ip in METADATA_ADDRESSES


def is_internal(ip: IPAddress) -> bool:
    """Loopback, private, link-local, CGNAT, unspecified, multicast or reserved."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return is_internal(ip.ipv4_mapped)
    cgnat = isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10")
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
        or cgnat
    )


def check_addresses(host: str, addresses: Iterable[IPAddress], *, is_local: bool) -> IPAddress:
    """Validate every resolved address and return the one to connect to.

    *All* addresses must pass: a hostname that resolves to one public and one internal IP
    is rejected (a classic SSRF trick). Metadata addresses are never allowed. Internal
    addresses are allowed only for targets explicitly allowlisted as local.
    """
    resolved = sorted(set(addresses), key=lambda a: (a.version, int(a)))
    if not resolved:
        raise UnsafeTargetError(f"{host} did not resolve to any address")
    for ip in resolved:
        mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
        if is_metadata(ip) or (mapped is not None and is_metadata(mapped)):
            raise UnsafeTargetError(f"{host} resolves to a cloud metadata address ({ip})")
        if is_internal(ip) and not is_local:
            raise UnsafeTargetError(
                f"{host} resolves to an internal address ({ip}). "
                "Add it as a local lab target if you intend to scan it."
            )
    # Prefer IPv4 for predictability; order is deterministic.
    return resolved[0]


# ---- authorization ---------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizedTarget:
    """An allowlist entry as the runtime layer sees it."""

    id: int
    host: str
    is_local: bool


def require_same_host(target: AuthorizedTarget, url: str) -> str:
    """The URL's host must be exactly the authorized host (no subdomains, no lookalikes)."""
    host = host_of(url)
    if host != target.host:
        raise UnsafeTargetError(f"{host} is not the authorized target {target.host}")
    return host


def require_safe_method(method: str) -> str:
    """Only GET, HEAD and OPTIONS may be sent."""
    upper = method.upper()
    if upper not in SAFE_METHODS:
        raise UnsafeTargetError(f"HTTP method {upper} is not allowed (safe methods only)")
    return upper


def clamp_rate(rate: float | None) -> float:
    """User rate within (0, MAX_RATE_PER_SECOND]."""
    if rate is None:
        return DEFAULT_RATE_PER_SECOND
    if not 0 < rate <= MAX_RATE_PER_SECOND:
        raise ValidationFailedError(f"Rate must be between 0 and {MAX_RATE_PER_SECOND} req/s")
    return rate


def clamp_cap(cap: int | None) -> int:
    """User request cap within [1, MAX_REQUEST_CAP]."""
    if cap is None:
        return DEFAULT_REQUEST_CAP
    if not 1 <= cap <= MAX_REQUEST_CAP:
        raise ValidationFailedError(f"Request cap must be between 1 and {MAX_REQUEST_CAP}")
    return cap


# ---- pacing ----------------------------------------------------------------------------


class RateLimiter:
    """Async token bucket (burst 1): at most ``rate`` acquisitions per second.

    One process-wide instance enforces the global ceiling across concurrent scans; a scan
    may additionally use its own, slower limiter.
    """

    def __init__(self, rate: float) -> None:
        self.interval = 1.0 / clamp_rate(rate)
        self._next = 0.0

    async def acquire(self) -> None:
        """Wait until the next request may be sent.

        The slot is reserved before the first ``await``, so concurrent callers on the event
        loop can never share a slot (no lock needed, and none bound to a specific loop).
        """
        now = time.monotonic()
        slot = max(now, self._next)
        self._next = slot + self.interval
        if slot > now:
            await asyncio.sleep(slot - now)


class BudgetExceededError(UnsafeTargetError):
    """The per-scan request cap was reached."""

    code = "request_cap_reached"


class RequestBudget:
    """Per-scan request cap. Every network attempt (HTTP or TLS handshake) consumes one."""

    def __init__(self, cap: int) -> None:
        self.cap = clamp_cap(cap)
        self.used = 0

    def take(self) -> None:
        """Consume one request or raise when the cap is reached."""
        if self.used >= self.cap:
            raise BudgetExceededError(f"Request cap of {self.cap} reached")
        self.used += 1


#: Shared ceiling for the whole backend process.
GLOBAL_LIMITER = RateLimiter(MAX_RATE_PER_SECOND)
