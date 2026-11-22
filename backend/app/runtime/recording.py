"""(De)serialize runtime observations so scans can be recorded and replayed offline.

Recorded observations are already redacted. Replaying them through the runtime rules is
deterministic and needs no network — this is how the runtime corpus is evaluated.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from app.runtime.observations import HttpObservation, RuntimeObservations, TlsObservation


def to_dict(obs: RuntimeObservations) -> dict[str, Any]:
    """JSON-ready representation (withheld bodies are already value-masked)."""
    http = {}
    for probe_id, o in sorted(obs.http.items()):
        d = asdict(o)
        d["headers"] = [list(h) for h in o.headers]
        d["request_headers"] = [list(h) for h in o.request_headers]
        http[probe_id] = d
    return {
        "target_host": obs.target_host,
        "base_url": obs.base_url,
        "http": http,
        "tls": asdict(obs.tls) if obs.tls else None,
        "skipped": list(obs.skipped),
    }


def from_dict(data: dict[str, Any]) -> RuntimeObservations:
    """Inverse of :func:`to_dict`."""
    http: dict[str, HttpObservation] = {}
    for probe_id, d in data.get("http", {}).items():
        fields = dict(d)
        fields["headers"] = tuple((str(k).lower(), str(v)) for k, v in d.get("headers", []))
        fields["request_headers"] = tuple((str(k), str(v)) for k, v in d.get("request_headers", []))
        fields["redirects"] = tuple(d.get("redirects", []))
        fields.setdefault("probe_id", probe_id)
        fields.setdefault("final_url", d.get("url", ""))
        http[probe_id] = HttpObservation(**fields)
    tls_data = data.get("tls")
    return RuntimeObservations(
        target_host=data["target_host"],
        base_url=data["base_url"],
        http=http,
        tls=TlsObservation(**tls_data) if tls_data else None,
        skipped=list(data.get("skipped", [])),
    )


def dumps(obs: RuntimeObservations) -> str:
    """Stable JSON text."""
    return json.dumps(to_dict(obs), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def loads(text: str) -> RuntimeObservations:
    """Parse JSON text."""
    return from_dict(json.loads(text))
