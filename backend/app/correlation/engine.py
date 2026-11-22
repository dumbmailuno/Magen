"""Correlation engine: merges static and runtime evidence (CLAUDE.md §2 component 3).

Pure and deterministic: parsed static inputs + their findings + recorded runtime
observations/findings in, one canonical findings list out. No network, no AI.

Status semantics (docs/architecture.md "Correlation"):

* static issue + same issue observed at runtime on the matching scope → ``confirmed``
  (source ``correlated``; static + runtime evidence; the static finding's id is kept so
  retest comparisons stay stable)
* static issue + the relevant probe ran on that scope and did **not** observe it →
  ``inconclusive`` (source ``correlated``; the contradicting runtime evidence is attached)
* static issue + runtime did not test that scope → unchanged (``potential`` /
  ``inconclusive`` as produced by the static rule)
* runtime-only issue → ``confirmed`` (source ``runtime``), unless it confirmed a static one
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal
from urllib.parse import urlsplit

from app.core.safety import host_of
from app.models.finding import Evidence, Finding, FindingStatus, Source, sort_findings
from app.rules.runtime._common import http_evidence, tls_evidence
from app.runtime.observations import RuntimeObservations
from app.static.nginx.config import (
    NginxConfig,
    Server,
    location_covers,
    servers_for_host,
)
from app.static.nginx.parser import Directive
from app.static.openapi.document import OpenApiDocument

Side = Literal["tls", "plain", "any"]


@dataclass(frozen=True)
class Link:
    """A runtime rule and the static rules that describe the same misconfiguration."""

    runtime_rule: str
    static_rules: tuple[str, ...]
    #: Which listener the static scope must be on.
    side: Side
    #: May a probe that ran without observing the issue contradict the static finding?
    refutes: bool = True


LINKS: Final = (
    Link("API-RT-001", ("API-OAS-001", "NGX-TLS-004"), "plain"),
    Link("API-RT-002", ("NGX-TLS-001",), "tls"),
    Link("API-RT-004", ("NGX-TLS-003",), "tls"),
    Link("API-RT-005", ("NGX-HDR-002",), "any"),
    Link("API-RT-006", ("NGX-HDR-001",), "any"),
    Link("API-RT-007", ("NGX-CORS-001",), "any"),
    # A spec declaring debug fields is not contradicted by one clean 404.
    Link("API-RT-008", ("API-OAS-009",), "any", refutes=False),
    Link("API-RT-010", ("NGX-CFG-002",), "any"),
)

#: Nginx location path fragment → the runtime probe that requests that path.
STATUS_PROBES: Final = (
    ("nginx_status", "path-nginx-status", "/nginx_status"),
    ("server-status", "path-server-status", "/server-status"),
    ("actuator", "path-actuator", "/actuator"),
    ("phpinfo", "path-phpinfo", "/phpinfo.php"),
)


@dataclass(frozen=True)
class StaticSource:
    """One analysed static input."""

    doc: OpenApiDocument | NginxConfig
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class RuntimeSource:
    """One runtime scan: recorded observations and the findings they produced."""

    observations: RuntimeObservations
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class CorrelationResult:
    """Merged findings plus counts for the evaluation report."""

    findings: tuple[Finding, ...]
    confirmed: int
    contradicted: int
    runtime_only: int
    static_only: int


# ---- probe coverage --------------------------------------------------------------------


def _https(obs: RuntimeObservations) -> bool:
    return urlsplit(obs.base_url).scheme == "https"


def _probe_for(link: Link, obs: RuntimeObservations, static_path: str | None) -> str | None:
    """The probe whose (non-)observation speaks for this link, if it ran."""
    rule = link.runtime_rule
    if rule == "API-RT-001":
        return "plain-http" if _https(obs) else "base-get"
    if rule == "API-RT-002":
        return "tls-legacy"
    if rule == "API-RT-010":
        for fragment, probe, _ in STATUS_PROBES:
            if static_path and fragment in static_path:
                return probe
        return None
    return "base-get"


def _covered(link: Link, obs: RuntimeObservations, probe: str) -> bool:
    """Did the probe run in a way that makes *absence* of the issue meaningful?"""
    if probe == "tls-legacy":
        return obs.tls is not None and any(v is not None for v in obs.tls.legacy_protocols.values())
    o = obs.get(probe)
    if o is None or o.status is None:
        return False
    if link.runtime_rule == "API-RT-004":
        return o.final_url.startswith("https://")
    if link.runtime_rule == "API-RT-005":
        return not 300 <= o.status < 400
    return True


def _probe_path(obs: RuntimeObservations, probe: str) -> str:
    if probe == "plain-http":
        return "/"
    for _, probe_id, path in STATUS_PROBES:
        if probe_id == probe:
            return path
    return urlsplit(obs.base_url).path or "/"


# ---- scope matching ------------------------------------------------------------------------


def _chain(config: NginxConfig, pointer: str) -> list[Directive] | None:
    for d, ancestors in config.root.walk():
        if d.pointer == pointer:
            return [*ancestors, d]
    return None


def _side_ok(config: NginxConfig, server: Server, side: Side) -> bool:
    if side == "tls":
        return config.is_tls(server)
    if side == "plain":
        return config.serves_plaintext(server)
    return True


def _location_path(config: NginxConfig, finding: Finding) -> str | None:
    """Path argument of the innermost location around the finding, if any."""
    chain = _chain(config, finding.evidence[0].location.pointer or "") or []
    locations = [d for d in chain if d.name == "location" and d.args]
    return locations[-1].args[-1] if locations else None


def _nginx_scope(
    config: NginxConfig, finding: Finding, link: Link, obs: RuntimeObservations, probe: str
) -> bool:
    """Does the finding apply to the probed host, listener side and path?"""
    chain = _chain(config, finding.evidence[0].location.pointer or "")
    if chain is None:
        return False
    candidates = [
        s for s in servers_for_host(config, obs.target_host) if _side_ok(config, s, link.side)
    ]
    server_block = next((d for d in chain if d.name == "server"), None)
    if server_block is not None:
        if not any(s.block.pointer == server_block.pointer for s in candidates):
            return False
    else:
        http_block = next((d for d in chain if d.name == "http"), None)
        if not any(http_block is None or s.http is http_block for s in candidates):
            return False
    path = _probe_path(obs, probe)
    return all(location_covers(d, path) for d in chain if d.name == "location")


def _host_or_none(url: object) -> str | None:
    """Host of an absolute http(s) URL; None for templated, relative or invalid URLs."""
    try:
        return host_of(str(url)) if isinstance(url, str) else None
    except Exception:  # noqa: BLE001 - such URLs simply carry no comparable host
        return None


def _openapi_scope(doc: OpenApiDocument, finding: Finding, obs: RuntimeObservations) -> bool:
    """OAS-001: that server URL's host; spec-wide rules: any absolute server host (or none)."""
    host = obs.target_host
    if finding.rule_id == "API-OAS-001":
        return _host_or_none(doc.get(finding.evidence[0].location.pointer or "")) == host
    servers = doc.data.get("servers")
    entries = servers if isinstance(servers, list) else []
    hosts = {
        h
        for h in (_host_or_none(e.get("url")) for e in entries if isinstance(e, dict))
        if h is not None
    }
    return not hosts or host in hosts


# ---- merging -----------------------------------------------------------------------------


def _contradiction(link: Link, obs: RuntimeObservations, probe: str) -> Evidence:
    note = f"Not observed at runtime ({link.runtime_rule})"
    if probe == "tls-legacy" and obs.tls is not None:
        return tls_evidence(obs.tls, "tls-legacy", f"{note}: legacy TLS handshakes refused")
    o = obs.get(probe)
    if o is None:  # pragma: no cover - only called after _covered() saw this probe
        raise ValueError(f"probe {probe} has no observation")
    return http_evidence(o, f"{note} on {o.url}")


def _dedupe(evidence: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Evidence] = []
    for e in evidence:
        key = (e.kind.value, e.location.identity_key(), e.excerpt)
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out


def correlate(statics: list[StaticSource], runtime: RuntimeSource | None) -> CorrelationResult:
    """Merge static and runtime findings into one canonical list."""
    static_findings = [f for s in statics for f in s.findings]
    if runtime is None:
        return CorrelationResult(
            tuple(sort_findings(static_findings)), 0, 0, 0, len(static_findings)
        )

    obs = runtime.observations
    links_by_static: dict[str, list[Link]] = {}
    for link in LINKS:
        for rule in link.static_rules:
            links_by_static.setdefault(rule, []).append(link)

    out: list[Finding] = []
    consumed: set[str] = set()
    confirmed = contradicted = 0
    for source in statics:
        for f in source.findings:
            matches: list[Finding] = []
            contradictions: list[Evidence] = []
            for link in links_by_static.get(f.rule_id, []):
                if isinstance(source.doc, NginxConfig):
                    probe = _probe_for(link, obs, _location_path(source.doc, f))
                    if probe is None:
                        continue
                    in_scope = _nginx_scope(source.doc, f, link, obs, probe)
                else:
                    probe = _probe_for(link, obs, None)
                    if probe is None:
                        continue
                    in_scope = _openapi_scope(source.doc, f, obs)
                if not in_scope:
                    continue
                hits = [
                    r
                    for r in runtime.findings
                    if r.rule_id == link.runtime_rule
                    and (
                        link.runtime_rule != "API-RT-010"
                        or r.evidence[0].location.pointer == f"probe:{probe}"
                    )
                ]
                if hits:
                    matches.extend(hits)
                elif link.refutes and _covered(link, obs, probe):
                    contradictions.append(_contradiction(link, obs, probe))
            if matches:
                consumed.update(r.id for r in matches)
                confirmed += 1
                evidence = _dedupe([*f.evidence, *(e for r in matches for e in r.evidence)])
                out.append(
                    f.model_copy(
                        update={
                            "status": FindingStatus.CONFIRMED,
                            "source": Source.CORRELATED,
                            "evidence": evidence,
                        }
                    )
                )
            elif contradictions:
                contradicted += 1
                out.append(
                    f.model_copy(
                        update={
                            "status": FindingStatus.INCONCLUSIVE,
                            "source": Source.CORRELATED,
                            "title": f"{f.title} — not observed at runtime",
                            "evidence": _dedupe([*f.evidence, *contradictions]),
                        }
                    )
                )
            else:
                out.append(f)
    runtime_only = [r for r in runtime.findings if r.id not in consumed]
    out.extend(runtime_only)
    return CorrelationResult(
        findings=tuple(sort_findings(out)),
        confirmed=confirmed,
        contradicted=contradicted,
        runtime_only=len(runtime_only),
        static_only=len(static_findings) - confirmed - contradicted,
    )
