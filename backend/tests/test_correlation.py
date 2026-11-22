"""Correlation engine edge cases (synthetic observations; complements the corpus cases)."""

from __future__ import annotations

from app.correlation.engine import RuntimeSource, StaticSource, correlate
from app.models.finding import Finding
from app.runtime.observations import HttpObservation, RuntimeObservations, TlsObservation
from app.runtime.scanner import run_runtime_rules
from app.static.nginx.analyzer import analyze_nginx
from app.static.nginx.config import NginxConfig, location_covers, servers_for_host
from app.static.nginx.parser import parse
from app.static.openapi.analyzer import analyze_openapi
from app.static.openapi.document import OpenApiDocument


def obs(
    host: str,
    base: str,
    probes: dict[str, tuple[int, list[tuple[str, str]], str]],
    tls: TlsObservation | None = None,
) -> RuntimeObservations:
    http = {
        pid: HttpObservation(
            probe_id=pid,
            method="GET",
            url=url if pid != "base-get" else base,
            status=status,
            headers=tuple((k.lower(), v) for k, v in headers),
            final_url=url if pid != "base-get" else base,
        )
        for pid, (status, headers, url) in probes.items()
    }
    return RuntimeObservations(host, base, http, tls)


def run(statics: list[StaticSource], o: RuntimeObservations) -> dict[str, Finding]:
    result = correlate(statics, RuntimeSource(o, tuple(run_runtime_rules(o))))
    return {f"{f.rule_id} {f.evidence[0].location.pointer}": f for f in result.findings}


def nginx(text: str) -> StaticSource:
    return StaticSource(NginxConfig("n.conf", text), analyze_nginx(text, "n.conf").findings)


def openapi(text: str) -> StaticSource:
    return StaticSource(OpenApiDocument("a.yaml", text), analyze_openapi(text, "a.yaml").findings)


STACK_TRACE = (
    "API-OAS-009 /paths/~1x/get/responses/500/content/application~1json"
    "/schema/properties/stackTrace"
)

SPEC = """openapi: 3.0.3
info: {title: t, version: '1'}
servers:
  - url: http://api.example.com/v1
  - url: http://other.example.com/v1
security: [{b: []}]
paths:
  /x:
    get:
      responses:
        '200': {description: ok}
        '429': {description: slow}
        '500':
          description: e
          content:
            application/json:
              schema: {properties: {stackTrace: {type: string}}}
components: {securitySchemes: {b: {type: http, scheme: bearer}}}
"""


def test_openapi_http_server_confirmed_only_for_the_probed_host() -> None:
    o = obs("api.example.com", "http://api.example.com/v1", {"base-get": (200, [], "")})
    found = run([openapi(SPEC)], o)
    assert found["API-OAS-001 /servers/0/url"].status.value == "confirmed"
    assert found["API-OAS-001 /servers/1/url"].status.value == "potential"  # other host


def test_openapi_http_server_contradicted_by_https_redirect() -> None:
    o = obs(
        "api.example.com",
        "https://api.example.com/v1",
        {
            "base-get": (
                200,
                [
                    ("Strict-Transport-Security", "max-age=1"),
                    ("X-Content-Type-Options", "nosniff"),
                    ("X-Frame-Options", "DENY"),
                ],
                "",
            ),
            "plain-http": (
                301,
                [("Location", "https://api.example.com/")],
                "http://api.example.com/",
            ),
        },
    )
    found = run([openapi(SPEC)], o)
    f = found["API-OAS-001 /servers/0/url"]
    assert f.status.value == "inconclusive" and f.title.endswith("not observed at runtime")


def test_spec_debug_fields_confirmed_but_never_refuted() -> None:
    clean_404 = obs(
        "api.example.com",
        "http://api.example.com/v1",
        {"not-found": (404, [], "http://api.example.com/x")},
    )
    assert run([openapi(SPEC)], clean_404)[STACK_TRACE].status.value == "potential"
    trace = RuntimeObservations(
        "api.example.com",
        "http://api.example.com/v1",
        {
            "not-found": HttpObservation(
                probe_id="not-found",
                method="GET",
                url="http://api.example.com/x",
                status=500,
                body_excerpt='Traceback (most recent call last):\n  File "a.py", line 1',
                final_url="http://api.example.com/x",
            )
        },
    )
    found = run([openapi(SPEC)], trace)
    assert found[STACK_TRACE].status.value == "confirmed"
    assert not any(k.startswith("API-RT-008") for k in found)


STATUS_CONF = """http {
    server_tokens off;
    limit_req_zone $binary_remote_addr zone=a:1m rate=1r/s;
    server {
        listen 443 ssl;
        server_name s.example.com;
        limit_req zone=a;
        add_header Strict-Transport-Security "max-age=1" always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options DENY always;
        location /nginx_status { stub_status; }
        location /debug/ { proxy_pass http://x; }
    }
}
"""


def test_status_location_matched_to_its_own_probe() -> None:
    o = obs(
        "s.example.com",
        "https://s.example.com/",
        {"path-nginx-status": (200, [], "https://s.example.com/nginx_status")},
    )
    o.http["path-nginx-status"] = HttpObservation(
        probe_id="path-nginx-status",
        method="GET",
        url="https://s.example.com/nginx_status",
        status=200,
        body_excerpt="Active connections: 1",
        final_url="https://s.example.com/nginx_status",
    )
    found = run([nginx(STATUS_CONF)], o)
    assert found["NGX-CFG-002 /http/0/server/0/location/0"].status.value == "confirmed"
    # /debug/ has no runtime probe: neither confirmed nor contradicted.
    assert found["NGX-CFG-002 /http/0/server/0/location/1"].status.value == "potential"


def test_location_level_finding_untouched_when_probe_path_outside_it() -> None:
    conf = STATUS_CONF.replace(
        "location /debug/ { proxy_pass http://x; }",
        "location /api/ { add_header Cache-Control no-store; }",
    )
    o = obs("s.example.com", "https://s.example.com/", {"base-get": (200, [], "")})
    found = run([nginx(conf)], o)
    # Base path "/" is not under /api/, so the runtime absence of HSTS says nothing about it.
    assert found["NGX-TLS-003 /http/0/server/0/location/1"].status.value == "potential"


def test_plain_side_vs_tls_side() -> None:
    conf = "http {\n server { listen 80; server_name p.example.com; root /srv; }\n}\n"
    o = obs(
        "p.example.com",
        "https://p.example.com/",
        {"plain-http": (200, [], "http://p.example.com/")},
    )
    found = run([nginx(conf)], o)
    assert found["NGX-TLS-004 /http/0/server/0"].status.value == "confirmed"


def test_no_runtime_means_static_unchanged() -> None:
    result = correlate([nginx(STATUS_CONF)], None)
    assert result.static_only == len(result.findings) and result.confirmed == 0


def test_tls_contradiction_uses_tls_evidence() -> None:
    conf = STATUS_CONF.replace(
        "listen 443 ssl;", "listen 443 ssl;\n        ssl_protocols TLSv1 TLSv1.2;"
    )
    tls = TlsObservation(
        "s.example.com", 443, verified=True, legacy_protocols={"TLSv1": False, "TLSv1.1": False}
    )
    found = run([nginx(conf)], obs("s.example.com", "https://s.example.com/", {}, tls))
    f = found["NGX-TLS-001 /http/0/server/0/ssl_protocols/0"]
    assert f.status.value == "inconclusive"
    assert f.evidence[-1].kind.value == "tls"


def test_servers_for_host_semantics() -> None:
    c = NginxConfig(
        "n",
        "http { server { server_name a.example.com; } server { listen 80 default_server; }"
        " server { server_name *.b.example.com; } }",
    )
    assert [s.block.pointer for s in servers_for_host(c, "a.example.com")] == ["/http/0/server/0"]
    assert [s.block.pointer for s in servers_for_host(c, "x.b.example.com")] == ["/http/0/server/2"]
    assert [s.block.pointer for s in servers_for_host(c, "zzz.example.com")] == ["/http/0/server/1"]
    only_named = NginxConfig("n", "http { server { server_name a.example.com; } }")
    assert servers_for_host(only_named, "other.example.com") == []
    assert [s.block.pointer for s in servers_for_host(only_named, "10.0.0.1")] == [
        "/http/0/server/0"
    ]


def test_location_covers() -> None:
    root = parse(
        "a { location /api/ {} location = /x {} location ^~ /s/ {}"
        " location ~* \\.php$ {} location ~ ([ {} }"
    )
    locs = root.find("a")[0].find("location")
    assert location_covers(locs[0], "/api/v1") and not location_covers(locs[0], "/apix")
    assert location_covers(locs[1], "/x") and not location_covers(locs[1], "/x/y")
    assert location_covers(locs[2], "/s/a")
    assert location_covers(locs[3], "/INDEX.PHP")
    assert not location_covers(locs[4], "/anything")  # invalid regex never matches
