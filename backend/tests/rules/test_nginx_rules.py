"""Positive + negative fixtures for every Nginx rule (CLAUDE.md §6)."""

from __future__ import annotations

import pytest

from app.models.finding import Finding, FindingStatus
from app.rules.base import RuleTarget
from app.rules.catalog import load_rules
from app.rules.registry import registry
from app.static.nginx.config import NginxConfig

load_rules()

NGX_RULES = [
    "NGX-CFG-001",
    "NGX-CFG-002",
    "NGX-CFG-003",
    "NGX-CORS-001",
    "NGX-HDR-001",
    "NGX-HDR-002",
    "NGX-RL-001",
    "NGX-TLS-001",
    "NGX-TLS-002",
    "NGX-TLS-003",
    "NGX-TLS-004",
]

HEADERS = (
    'add_header Strict-Transport-Security "max-age=31536000" always;'
    " add_header X-Content-Type-Options nosniff always;"
    " add_header X-Frame-Options DENY always;"
)


def clean(server_body: str = "", http_body: str = "") -> str:
    """A config that is clean for every Nginx rule, with injection points."""
    return (
        "http { server_tokens off; limit_req_zone $binary_remote_addr zone=a:1m rate=1r/s;"
        f" {http_body}"
        " server { listen 443 ssl; server_name api.example.com; limit_req zone=a;"
        f" {HEADERS} {server_body} }} }}"
    )


def run(rule_id: str, text: str) -> list[Finding]:
    rule = registry.get(rule_id)
    assert rule is not None
    return rule().check(NginxConfig("n.conf", text))


def ptrs(rule_id: str, text: str) -> list[str]:
    return [f.evidence[0].location.pointer or "" for f in run(rule_id, text)]


def test_all_rules_registered() -> None:
    assert sorted(r.id for r in registry.for_target(RuleTarget.NGINX)) == NGX_RULES


@pytest.mark.parametrize("rule_id", NGX_RULES)
def test_clean_config_has_no_findings(rule_id: str) -> None:
    assert run(rule_id, clean()) == []


@pytest.mark.parametrize("rule_id", NGX_RULES)
def test_rule_metadata(rule_id: str) -> None:
    rule = registry.get(rule_id)
    assert rule is not None and rule.references.owasp_api and rule.remediation_template.strip()


class TestServerTokens:
    def test_positive_default(self) -> None:
        f = run("NGX-HDR-001", clean().replace("server_tokens off;", ""))
        assert [x.evidence[0].location.pointer for x in f] == ["/http/0"]
        assert f[0].status is FindingStatus.POTENTIAL

    def test_positive_explicit_on_in_server_overrides_http(self) -> None:
        assert ptrs("NGX-HDR-001", clean("server_tokens on;")) == [
            "/http/0/server/0/server_tokens/0"
        ]

    def test_default_reported_once_for_many_servers(self) -> None:
        text = "http { server { listen 80; } server { listen 81; } }"
        assert ptrs("NGX-HDR-001", text) == ["/http/0", "/http/0"]  # same evidence → same id
        assert len({f.id for f in run("NGX-HDR-001", text)}) == 1


class TestAutoindex:
    def test_positive(self) -> None:
        f = run("NGX-CFG-001", clean("location /f/ { autoindex on; }"))
        assert len(f) == 1 and "location /f/" in f[0].title

    def test_negative_off(self) -> None:
        assert run("NGX-CFG-001", clean("location /f/ { autoindex off; }")) == []


class TestTls:
    @pytest.mark.parametrize("protos", ["SSLv3 TLSv1.2", "TLSv1 TLSv1.1 TLSv1.2", "SSLv2"])
    def test_weak_protocols_positive(self, protos: str) -> None:
        assert len(run("NGX-TLS-001", clean(f"ssl_protocols {protos};"))) == 1

    def test_weak_protocols_negative(self) -> None:
        assert run("NGX-TLS-001", clean("ssl_protocols TLSv1.2 TLSv1.3;")) == []

    @pytest.mark.parametrize(
        "ciphers", ["RC4-SHA", "HIGH:3DES", "ALL", "EXP-RC4-MD5", "ADH-AES128-SHA", "+NULL-SHA"]
    )
    def test_weak_ciphers_positive(self, ciphers: str) -> None:
        assert len(run("NGX-TLS-002", clean(f"ssl_ciphers '{ciphers}';"))) == 1

    @pytest.mark.parametrize(
        "ciphers", ["HIGH:!aNULL:!MD5", "ECDHE-RSA-AES256-GCM-SHA384:-RC4:!3DES", "EECDH+AESGCM"]
    )
    def test_weak_ciphers_negative(self, ciphers: str) -> None:
        assert run("NGX-TLS-002", clean(f"ssl_ciphers '{ciphers}';")) == []

    def test_hsts_missing_at_server(self) -> None:
        text = clean().replace(
            'add_header Strict-Transport-Security "max-age=31536000" always;', ""
        )
        f = run("NGX-TLS-003", text)
        assert [x.evidence[0].location.pointer for x in f] == ["/http/0/server/0"]
        assert "does not send HSTS" in f[0].title

    def test_hsts_dropped_by_location_add_header(self) -> None:
        f = run("NGX-TLS-003", clean("location /x { add_header Cache-Control no-store; }"))
        assert len(f) == 1 and "drops HSTS" in f[0].title

    def test_hsts_max_age_zero(self) -> None:
        text = clean().replace("max-age=31536000", "max-age=0")
        assert "disables HSTS" in run("NGX-TLS-003", text)[0].title

    def test_hsts_not_required_on_plain_http(self) -> None:
        assert run("NGX-TLS-003", "http { server { listen 80; return 301 https://x; } }") == []

    def test_plaintext_positive_and_redirect_negative(self) -> None:
        assert len(run("NGX-TLS-004", "http { server { listen 80; root /srv; } }")) == 1
        assert run("NGX-TLS-004", "http { server { listen 80; return 301 https://$host; } }") == []
        assert len(run("NGX-TLS-004", "http { server { listen 80; return 301 http://x; } }")) == 1


class TestSecurityHeaders:
    def test_missing_at_server(self) -> None:
        text = clean().replace("add_header X-Content-Type-Options nosniff always;", "")
        f = run("NGX-HDR-002", text)
        assert len(f) == 1 and "X-Content-Type-Options" in f[0].title

    def test_csp_frame_ancestors_satisfies_clickjacking(self) -> None:
        text = clean().replace(
            "add_header X-Frame-Options DENY always;",
            "add_header Content-Security-Policy \"frame-ancestors 'none'\";",
        )
        assert run("NGX-HDR-002", text) == []

    def test_location_drop(self) -> None:
        f = run("NGX-HDR-002", clean("location /x { add_header Cache-Control no-store; }"))
        assert [x.evidence[0].location.pointer for x in f] == ["/http/0/server/0/location/0"]

    def test_redirect_only_server_skipped(self) -> None:
        assert run("NGX-HDR-002", "http { server { listen 80; return 301 https://x; } }") == []


class TestCors:
    def test_wildcard(self) -> None:
        assert (
            "(*)"
            in run("NGX-CORS-001", clean('add_header Access-Control-Allow-Origin "*";'))[0].title
        )

    def test_reflection_with_credentials(self) -> None:
        body = (
            "add_header Access-Control-Allow-Origin $http_origin;"
            " add_header Access-Control-Allow-Credentials true;"
        )
        assert run("NGX-CORS-001", clean(body))[0].title.endswith("with credentials")

    @pytest.mark.parametrize(
        "body",
        [
            "add_header Access-Control-Allow-Origin https://app.example.com;",
            "add_header Access-Control-Allow-Origin $cors_origin;",
            'if ($http_origin ~* "^https://app\\.example\\.com$") '
            "{ add_header Access-Control-Allow-Origin $http_origin; }",
        ],
    )
    def test_negative(self, body: str) -> None:
        assert run("NGX-CORS-001", clean(body)) == []


class TestExposedStatus:
    @pytest.mark.parametrize(
        "loc",
        [
            "location /nginx_status { stub_status; }",
            "location = /basic { stub_status; }",
            "location /actuator/ { proxy_pass http://a; }",
            "location ~ /\\.git { root /srv; }",
            "location /debug/pprof { proxy_pass http://a; }",
        ],
    )
    def test_positive(self, loc: str) -> None:
        assert len(run("NGX-CFG-002", clean(loc))) == 1

    @pytest.mark.parametrize(
        "loc",
        [
            "location /nginx_status { stub_status; allow 127.0.0.1; deny all; }",
            "location /metrics { auth_basic on; proxy_pass http://p; }",
            "location /actuator/ { internal; }",
            "location ~ /\\.git { return 404; }",
            "location /status { proxy_pass http://app; }",
        ],
    )
    def test_negative(self, loc: str) -> None:
        assert run("NGX-CFG-002", clean(loc)) == []

    def test_server_level_deny_restricts(self) -> None:
        assert run("NGX-CFG-002", clean("deny all; location /nginx_status { stub_status; }")) == []


class TestBodySize:
    @pytest.mark.parametrize("size", ["0", "101m", "1g", "200000k"])
    def test_positive(self, size: str) -> None:
        assert len(run("NGX-CFG-003", clean(f"client_max_body_size {size};"))) == 1

    @pytest.mark.parametrize("size", ["1m", "100m", "10M", "weird"])
    def test_negative(self, size: str) -> None:
        assert run("NGX-CFG-003", clean(f"client_max_body_size {size};")) == []


class TestRateLimit:
    def test_positive_zone_without_limit_req(self) -> None:
        text = clean().replace("limit_req zone=a;", "")
        f = run("NGX-RL-001", text)
        assert [x.evidence[0].location.pointer for x in f] == ["/http/0"]

    def test_inconclusive_with_conf_d_include(self) -> None:
        text = (
            clean()
            .replace("limit_req zone=a;", "")
            .replace("http {", "http { include conf.d/*.conf;")
        )
        assert run("NGX-RL-001", text)[0].status is FindingStatus.INCONCLUSIVE

    def test_negative_no_servers(self) -> None:
        assert run("NGX-RL-001", "events { worker_connections 10; }") == []
