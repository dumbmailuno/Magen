from __future__ import annotations

import pytest

from app.models.finding import FindingStatus
from app.static.nginx.config import NginxConfig, NginxConfigError, header_contexts, redirects


def cfg(text: str) -> NginxConfig:
    return NginxConfig("nginx.conf", text)


def test_invalid_config_raises_api_error() -> None:
    with pytest.raises(NginxConfigError) as exc:
        cfg("http {")
    assert exc.value.code == "invalid_nginx"


def test_snippet_detection() -> None:
    assert cfg("server { listen 80; }").is_snippet
    assert not cfg("http { server { listen 80; } }").is_snippet


def test_add_header_inheritance_is_all_or_nothing() -> None:
    c = cfg(
        "http { add_header A 1; server { add_header B 2;"
        " location /x { } location /y { add_header C 3; } } }"
    )
    server = c.servers()[0]
    ctxs = {ctx.label: ctx for ctx in c.contexts(server)}
    _, x_headers = c.effective_headers(ctxs["location /x"].chain)
    _, y_headers = c.effective_headers(ctxs["location /y"].chain)
    assert [h.args[0] for h in x_headers] == ["B"]  # inherits server, NOT http (server has its own)
    assert [h.args[0] for h in y_headers] == ["C"]  # loses B entirely
    hcs = header_contexts(c, server)
    assert [hc.context.label for hc in hcs] == [server.label, "location /y"]
    assert hcs[1].inherited is not None and [h.args[0] for h in hcs[1].inherited] == ["B"]


def test_effective_single_value_directive() -> None:
    c = cfg("http { server_tokens on; server { server_tokens off; } server { } }")
    a, b = c.servers()
    assert c.effective("server_tokens", a.chain).args == ("off",)  # type: ignore[union-attr]
    assert c.effective("server_tokens", b.chain).args == ("on",)  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("listen", "tls", "plaintext"),
    [
        ("listen 443 ssl;", True, False),
        ("listen 443 quic reuseport;", True, False),
        ("listen 80;", False, True),
        ("listen 127.0.0.1:80;", False, False),
        ("listen [::1]:8080;", False, False),
        ("listen unix:/run/app.sock;", False, False),
        ("", False, True),
        ("listen 80; listen 443 ssl;", True, True),
        ("listen 443; ssl on;", True, True),
    ],
)
def test_listen_classification(listen: str, tls: bool, plaintext: bool) -> None:
    c = cfg(f"http {{ server {{ {listen} }} }}")
    s = c.servers()[0]
    assert c.is_tls(s) is tls
    assert c.serves_plaintext(s) is plaintext


@pytest.mark.parametrize(
    ("body", "any_redirect", "https_redirect"),
    [
        ("return 301 https://$host$request_uri;", True, True),
        ("return 302 http://other;", True, False),
        ("rewrite ^ https://example.com permanent;", True, True),
        ("location / { return 308 https://x; }", True, True),
        ("location / { return 301 https://x; } location /a { }", False, False),
        ("return 200 ok;", False, False),
    ],
)
def test_redirect_detection(body: str, any_redirect: bool, https_redirect: bool) -> None:
    s = cfg(f"http {{ server {{ {body} }} }}").servers()[0]
    assert redirects(s) is any_redirect
    assert redirects(s, https_only=True) is https_redirect


@pytest.mark.parametrize(
    ("text", "status"),
    [
        ("http { include mime.types; server { } }", FindingStatus.POTENTIAL),
        ("http { include /etc/nginx/fastcgi_params; server { } }", FindingStatus.POTENTIAL),
        ("http { include conf.d/*.conf; server { } }", FindingStatus.INCONCLUSIVE),
        ("http { server { include snippets/headers.conf; } }", FindingStatus.INCONCLUSIVE),
        ("server { }", FindingStatus.INCONCLUSIVE),
    ],
)
def test_status_reflects_visibility(text: str, status: FindingStatus) -> None:
    c = cfg(text)
    assert c.status_for(c.servers()[0].chain) is status


def test_evidence_and_excerpt() -> None:
    c = cfg("http {\n  server {\n    autoindex on;\n  }\n}\n")
    d = c.servers()[0].block.find("autoindex")[0]
    ev = c.evidence(d)
    assert ev.location.file == "nginx.conf"
    assert (ev.location.line, ev.location.end_line) == (3, None)
    assert ev.location.pointer == "/http/0/server/0/autoindex/0"
    assert ev.excerpt == "    autoindex on;"
