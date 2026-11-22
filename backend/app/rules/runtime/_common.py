"""Shared helpers for runtime rules (pure: observations in, findings out)."""

from __future__ import annotations

import re
from typing import Final

from app.models.finding import Evidence, EvidenceKind, Location
from app.runtime.observations import HttpObservation, TlsObservation

OWASP_DOCS: Final = "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"
OWASP_HEADERS: Final = "https://owasp.org/www-project-secure-headers/"
_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)


def http_evidence(obs: HttpObservation, excerpt: str) -> Evidence:
    """Runtime evidence. ``excerpt`` must be the *stable* fact (it is hashed into the id);
    the full request/response (dates, request ids...) goes in fields excluded from the id.
    """
    return Evidence(
        kind=EvidenceKind.HTTP,
        location=Location(url=obs.url, pointer=f"probe:{obs.probe_id}"),
        excerpt=excerpt,
        request=obs.request_text(),
        response=obs.response_text(),
    )


def tls_evidence(tls: TlsObservation, probe: str, excerpt: str) -> Evidence:
    """Evidence for a TLS handshake observation."""
    return Evidence(
        kind=EvidenceKind.TLS,
        location=Location(url=f"https://{tls.host}:{tls.port}/", pointer=f"probe:{probe}"),
        excerpt=excerpt,
    )


def ok(obs: HttpObservation | None) -> bool:
    """A response was received (any status)."""
    return obs is not None and obs.status is not None


def hsts_enabled(obs: HttpObservation) -> bool:
    """HSTS with max-age > 0."""
    m = _MAX_AGE.search(obs.header("strict-transport-security") or "")
    return bool(m and int(m.group(1)) > 0)
