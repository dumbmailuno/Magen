from __future__ import annotations

import json
import logging

import pytest

from app.core.logging import JsonFormatter
from app.core.redaction import REDACTED, redact_headers, redact_text


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        ("Authorization: Bearer abcdef123", "abcdef123"),
        ("authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("Cookie: session=s3cr3t; theme=dark", "s3cr3t"),
        ("X-API-Key: k-999", "k-999"),
        ("https://x/y?api_key=QWERTY&page=2", "QWERTY"),
        ('{"password": "hunter2"}', "hunter2"),
        ("client_secret=abc123", "abc123"),
        ("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "eyJzdWIiOiIxIn0"),
    ],
)
def test_redacts_known_secret_shapes(raw: str, secret: str) -> None:
    out = redact_text(raw)
    assert secret not in out
    assert REDACTED in out


def test_keeps_non_secret_text() -> None:
    text = "GET /v1/users HTTP/1.1\nHost: api.example.com\nAccept: */*"
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "schema_excerpt",
    [
        "password:\n  type: string\n  format: password",
        '"password": {"type": "string"}',
        "token:\n  $ref: '#/components/schemas/Token'",
        "  api_key:\n    type: apiKey\n    in: header",
        "secret: [a, b]",
    ],
)
def test_does_not_mangle_schema_definitions(schema_excerpt: str) -> None:
    """Spec excerpts that merely *name* secret fields are evidence and must stay intact."""
    assert redact_text(schema_excerpt) == schema_excerpt


def test_keeps_header_name_and_query_key() -> None:
    assert redact_text("Authorization: Bearer x1") == f"Authorization: {REDACTED}"
    assert redact_text("?api_key=abc&page=2") == f"?api_key={REDACTED}&page=2"


def test_extra_secrets_always_removed() -> None:
    assert "weird!!value" not in redact_text("got weird!!value back", ("weird!!value",))


def test_redact_headers() -> None:
    out = redact_headers({"Authorization": "Bearer x", "Accept": "json", "Set-Cookie": "a=b"})
    assert out == {"Authorization": REDACTED, "Accept": "json", "Set-Cookie": REDACTED}


def test_json_log_formatter_redacts_message_and_extras() -> None:
    record = logging.makeLogRecord(
        {
            "msg": "probe with Authorization: Bearer topsecret",
            "levelname": "INFO",
            "name": "t",
            "url": "https://h/?token=abc",
        }
    )
    line = JsonFormatter().format(record)
    payload = json.loads(line)
    assert "topsecret" not in line
    assert "abc" not in payload["url"]
