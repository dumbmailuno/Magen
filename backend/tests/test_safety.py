"""Safety guardrails (CLAUDE.md §7). Coverage target ≥ 80% on core/safety."""

from __future__ import annotations

import asyncio
import ipaddress
import time

import pytest

from app.core.errors import ValidationFailedError
from app.core.safety import (
    MAX_RATE_PER_SECOND,
    MAX_REQUEST_CAP,
    AuthorizedTarget,
    BudgetExceededError,
    InvalidHostError,
    RateLimiter,
    RequestBudget,
    UnsafeTargetError,
    check_addresses,
    clamp_cap,
    clamp_rate,
    host_of,
    is_internal,
    normalize_host,
    require_safe_method,
    require_same_host,
)

ip = ipaddress.ip_address


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("API.Example.COM", "api.example.com"),
        ("api.example.com.", "api.example.com"),
        ("  localhost ", "localhost"),
        ("127.0.0.1", "127.0.0.1"),
        ("[::1]", "::1"),
        ("bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_normalize_host(raw: str, expected: str) -> None:
    assert normalize_host(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "https://api.example.com",
        "api.example.com/path",
        "api.example.com:8443",
        "user@api.example.com",
        "*.example.com",
        "-bad.example.com",
        "a" * 64 + ".example.com",
        "exa mple.com",
        "api.example.com?x",
    ],
)
def test_normalize_host_rejects(raw: str) -> None:
    with pytest.raises(InvalidHostError):
        normalize_host(raw)


def test_host_of() -> None:
    assert host_of("https://API.example.com:8443/v1?x=1") == "api.example.com"
    assert host_of("http://[::1]:5000/") == "::1"
    for bad in (
        "ftp://x.example.com",
        "file:///etc/passwd",
        "https://u:p@x.example.com/",
        "https:///x",
    ):
        with pytest.raises(ValidationFailedError):
            host_of(bad)


@pytest.mark.parametrize(
    ("addr", "internal"),
    [
        ("8.8.8.8", False),
        ("93.184.216.34", False),
        ("127.0.0.1", True),
        ("10.1.2.3", True),
        ("172.16.0.1", True),
        ("192.168.1.1", True),
        ("169.254.1.1", True),
        ("100.64.0.1", True),
        ("0.0.0.0", True),  # noqa: S104 - classifying, not binding
        ("224.0.0.1", True),
        ("::1", True),
        ("fe80::1", True),
        ("fc00::1", True),
        ("::ffff:127.0.0.1", True),
        ("2606:4700:4700::1111", False),
    ],
)
def test_is_internal(addr: str, internal: bool) -> None:
    assert is_internal(ip(addr)) is internal


class TestCheckAddresses:
    def test_public_target_public_ip_ok(self) -> None:
        assert check_addresses("x", [ip("93.184.216.34")], is_local=False) == ip("93.184.216.34")

    def test_public_target_internal_ip_rejected(self) -> None:
        with pytest.raises(UnsafeTargetError, match="internal address"):
            check_addresses("x", [ip("10.0.0.5")], is_local=False)

    def test_mixed_resolution_rejected(self) -> None:
        """DNS returning one public and one internal address is a classic SSRF trick."""
        with pytest.raises(UnsafeTargetError):
            check_addresses("x", [ip("93.184.216.34"), ip("127.0.0.1")], is_local=False)

    def test_local_target_may_use_loopback_and_private(self) -> None:
        assert check_addresses("x", [ip("::1"), ip("127.0.0.1")], is_local=True) == ip("127.0.0.1")
        assert check_addresses("x", [ip("192.168.1.10")], is_local=True) == ip("192.168.1.10")

    @pytest.mark.parametrize(
        "meta", ["169.254.169.254", "100.100.100.200", "fd00:ec2::254", "::ffff:169.254.169.254"]
    )
    def test_metadata_blocked_even_for_local_targets(self, meta: str) -> None:
        with pytest.raises(UnsafeTargetError, match="metadata"):
            check_addresses("x", [ip(meta)], is_local=True)

    def test_no_addresses(self) -> None:
        with pytest.raises(UnsafeTargetError, match="did not resolve"):
            check_addresses("x", [], is_local=True)

    def test_choice_is_deterministic(self) -> None:
        addrs = [ip("2606:4700::1"), ip("93.184.216.35"), ip("93.184.216.34")]
        assert check_addresses("x", addrs, is_local=False) == ip("93.184.216.34")
        assert check_addresses("x", list(reversed(addrs)), is_local=False) == ip("93.184.216.34")


def test_require_same_host() -> None:
    t = AuthorizedTarget(1, "api.example.com", is_local=False)
    assert require_same_host(t, "https://API.example.com/v1") == "api.example.com"
    for other in (
        "https://evil.example.com/",
        "https://api.example.com.evil.net/",
        "https://sub.api.example.com/",
    ):
        with pytest.raises(UnsafeTargetError):
            require_same_host(t, other)


@pytest.mark.parametrize("method", ["GET", "head", "Options"])
def test_safe_methods_allowed(method: str) -> None:
    assert require_safe_method(method) == method.upper()


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"])
def test_unsafe_methods_rejected(method: str) -> None:
    with pytest.raises(UnsafeTargetError, match="not allowed"):
        require_safe_method(method)


def test_clamps() -> None:
    assert clamp_rate(None) == MAX_RATE_PER_SECOND
    assert clamp_rate(1.5) == 1.5
    assert clamp_cap(None) == 50 and clamp_cap(MAX_REQUEST_CAP) == MAX_REQUEST_CAP
    for bad_rate in (0, -1, MAX_RATE_PER_SECOND + 0.1, 1000):
        with pytest.raises(ValidationFailedError):
            clamp_rate(bad_rate)
    for bad_cap in (0, -5, MAX_REQUEST_CAP + 1):
        with pytest.raises(ValidationFailedError):
            clamp_cap(bad_cap)


def test_budget() -> None:
    b = RequestBudget(2)
    b.take()
    b.take()
    with pytest.raises(BudgetExceededError):
        b.take()
    assert b.used == 2


def test_rate_limiter_spaces_requests() -> None:
    async def run() -> float:
        limiter = RateLimiter(5)
        start = time.monotonic()
        await asyncio.gather(*(limiter.acquire() for _ in range(4)))
        return time.monotonic() - start

    elapsed = asyncio.run(run())
    assert elapsed >= 0.6 - 0.02  # 4 requests at 5/s: 0, 0.2, 0.4, 0.6


def test_rate_limiter_works_across_event_loops() -> None:
    limiter = RateLimiter(5)
    asyncio.run(limiter.acquire())
    asyncio.run(limiter.acquire())  # would fail with a loop-bound asyncio.Lock
