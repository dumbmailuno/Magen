from __future__ import annotations

import pytest

from app.static.nginx.parser import MAX_BYTES, NginxParseError, parse, tokenize


def test_directives_blocks_lines_and_pointers() -> None:
    root = parse(
        "events {}\n"
        "http {\n"
        "    server_tokens off;\n"
        "    server {\n"
        "        listen 80;\n"
        "        location / { root /srv; }\n"
        "    }\n"
        "    server { listen 443 ssl; }\n"
        "}\n"
    )
    http = root.find("http")[0]
    assert (http.line, http.end_line, http.pointer) == (2, 9, "/http/0")
    servers = http.find("server")
    assert [s.pointer for s in servers] == ["/http/0/server/0", "/http/0/server/1"]
    assert servers[1].find("listen")[0].args == ("443", "ssl")
    loc = servers[0].find("location")[0]
    assert loc.args == ("/",) and loc.pointer == "/http/0/server/0/location/0"
    assert loc.find("root")[0].pointer == "/http/0/server/0/location/0/root/0"


def test_quotes_escapes_comments_and_variables() -> None:
    root = parse(
        'add_header X-A "a; b {c}" always; # trailing comment\n'
        "add_header X-B 'it\\'s';\n"
        "set $x ${host}suffix;\n"
        'location ~ ^/(a|b)\\.json$ { return 200 "ok"; }\n'
    )
    a, b = root.find("add_header")
    assert a.args == ("X-A", "a; b {c}", "always")
    assert b.args == ("X-B", "it's")
    assert root.find("set")[0].args == ("$x", "${host}suffix")
    assert root.find("location")[0].args == ("~", "^/(a|b)\\.json$")


def test_multiline_quoted_value_keeps_start_line() -> None:
    root = parse("add_header CSP \"default-src 'self';\n  img-src *\";\nlisten 80;\n")
    assert root.find("add_header")[0].line == 1
    assert root.find("listen")[0].line == 3


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("", "empty"),
        ("# only a comment\n", "empty"),
        ("http {\n listen 80;\n", "expecting '}'"),
        ("listen 80;\n}\n", "unexpected '}'"),
        ("listen 80\n", "end of file"),
        ("server { listen 80 }", "missing ';'"),
        ('add_header X "unterminated;\n', "unterminated"),
        ("; listen 80;", "unexpected ';'"),
    ],
)
def test_syntax_errors(text: str, match: str) -> None:
    with pytest.raises(NginxParseError, match=match):
        parse(text)


def test_error_reports_line() -> None:
    with pytest.raises(NginxParseError) as exc:
        parse("events {}\nhttp {\n  listen 80;\n  }\n}\n")
    assert exc.value.line == 5


def test_depth_and_size_limits() -> None:
    with pytest.raises(NginxParseError, match="nesting"):
        parse("a {" * 40 + "}" * 40)
    with pytest.raises(NginxParseError, match="larger"):
        parse("a " + "x" * (MAX_BYTES + 1) + ";")


def test_tokenizer_skips_comments() -> None:
    assert [t.value for t in tokenize("a b; # c d;\ne;")] == ["a", "b", ";", "e", ";"]


def test_walk_yields_ancestors() -> None:
    root = parse("http { server { location / { autoindex on; } } }")
    found = [(d.name, [a.name for a in anc]) for d, anc in root.walk() if d.name == "autoindex"]
    assert found == [("autoindex", ["http", "server", "location"])]
