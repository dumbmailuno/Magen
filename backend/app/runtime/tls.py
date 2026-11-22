"""TLS handshakes (ssl + socket). Blocking; callers run them via ``asyncio.to_thread``.

Each function performs exactly one handshake against an already-validated IP, using the
host name only for SNI / certificate matching. No application data is sent.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import Final

from app.core.safety import IPAddress

LEGACY_PROTOCOLS: Final = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
}


@dataclass(frozen=True)
class HandshakeResult:
    """Outcome of one handshake."""

    connected: bool
    ok: bool
    protocol: str | None = None
    error: str | None = None
    #: The client itself cannot offer this protocol (e.g. OpenSSL policy forbids it).
    client_unsupported: bool = False


def _connect(ip: IPAddress, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((str(ip), port), timeout=timeout)


def verify_handshake(host: str, ip: IPAddress, port: int, timeout: float = 5.0) -> HandshakeResult:
    """Handshake with full verification (trust chain + host name)."""
    ctx = ssl.create_default_context()
    try:
        sock = _connect(ip, port, timeout)
    except OSError as exc:
        return HandshakeResult(connected=False, ok=False, error=type(exc).__name__)
    try:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return HandshakeResult(connected=True, ok=True, protocol=tls.version())
    except ssl.SSLCertVerificationError as exc:
        return HandshakeResult(
            connected=True, ok=False, error=exc.verify_message or "verification failed"
        )
    except (ssl.SSLError, OSError) as exc:
        return HandshakeResult(connected=True, ok=False, error=type(exc).__name__)
    finally:
        sock.close()


def legacy_handshake(
    host: str, ip: IPAddress, port: int, protocol: str, timeout: float = 5.0
) -> HandshakeResult:
    """Try to negotiate exactly ``protocol`` (TLSv1 / TLSv1.1), without verification.

    ``client_unsupported`` is set when the local TLS library refuses to offer the protocol,
    so the result means "not testable", never "server refused".
    """
    version = LEGACY_PROTOCOLS[protocol]
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return HandshakeResult(connected=False, ok=False, client_unsupported=True)
    try:
        sock = _connect(ip, port, timeout)
    except OSError as exc:
        return HandshakeResult(connected=False, ok=False, error=type(exc).__name__)
    try:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            negotiated = tls.version()
            return HandshakeResult(connected=True, ok=negotiated == protocol, protocol=negotiated)
    except ssl.SSLError as exc:
        reason = (exc.reason or "").upper()
        unsupported = "NO_PROTOCOLS_AVAILABLE" in reason or "NO_CIPHERS_AVAILABLE" in reason
        return HandshakeResult(
            connected=True, ok=False, error=exc.reason or "SSLError", client_unsupported=unsupported
        )
    except OSError as exc:
        return HandshakeResult(connected=True, ok=False, error=type(exc).__name__)
    finally:
        sock.close()
