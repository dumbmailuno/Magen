"""What runtime probes saw. Rules consume these; they never touch the network themselves.

Every string here is already redacted (``app.core.redaction``) — including the exact value
of the user's auth header — before it is stored on an observation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

#: Origin sent to detect CORS reflection. ``.invalid`` is reserved and never resolves.
CORS_PROBE_ORIGIN: Final = "https://magen-cors-probe.invalid"


@dataclass(frozen=True)
class HttpObservation:
    """One HTTP exchange (after following allowed redirects)."""

    probe_id: str
    method: str
    url: str
    status: int | None
    #: Lower-cased header names, redacted values, in response order.
    headers: tuple[tuple[str, str], ...] = ()
    request_headers: tuple[tuple[str, str], ...] = ()
    body_excerpt: str = ""
    body_bytes: int = 0
    final_url: str = ""
    redirects: tuple[str, ...] = ()
    error: str | None = None
    #: True when the body must never be stored (e.g. a served .env file). The excerpt then
    #: holds only the masked shape (``KEY=••••``) and evidence never includes it.
    body_withheld: bool = False

    def header(self, name: str) -> str | None:
        """First value of a response header (case-insensitive)."""
        lname = name.lower()
        return next((v for k, v in self.headers if k == lname), None)

    def request_text(self) -> str:
        """Redacted request line + headers, for evidence."""
        lines = [f"{self.method} {self.url}"] + [f"{k}: {v}" for k, v in self.request_headers]
        return "\n".join(lines)

    def response_text(self) -> str:
        """Redacted status line + headers + body excerpt, for evidence."""
        if self.status is None:
            return f"(no response: {self.error})"
        lines = [f"HTTP {self.status}"] + [f"{k}: {v}" for k, v in self.headers]
        body = "(body withheld)" if self.body_withheld else self.body_excerpt
        return "\n".join(lines) + ("\n\n" + body if body else "")


@dataclass(frozen=True)
class TlsObservation:
    """Results of the TLS handshakes against the target."""

    host: str
    port: int
    #: None = could not connect at all.
    verified: bool | None
    verify_error: str | None = None
    protocol: str | None = None
    #: Protocol name → accepted (True), refused (False), not testable from this client (None).
    legacy_protocols: dict[str, bool | None] = field(default_factory=dict)
    error: str | None = None


@dataclass
class RuntimeObservations:
    """Everything one runtime scan observed. Built incrementally, read by rules."""

    target_host: str
    base_url: str
    http: dict[str, HttpObservation] = field(default_factory=dict)
    tls: TlsObservation | None = None
    #: Probes that could not run (budget, cancellation, unsafe redirect...).
    skipped: list[str] = field(default_factory=list)

    def get(self, probe_id: str) -> HttpObservation | None:
        """Observation for a probe, if it ran."""
        return self.http.get(probe_id)
