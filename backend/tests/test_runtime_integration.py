"""End-to-end runtime scans against real local servers (loopback only, no external network)."""

from __future__ import annotations

import contextlib
import ssl
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest
import trustme
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.runtime.tls import legacy_handshake, verify_handshake
from tests.conftest import TEST_TOKEN

SECRET = "Bearer integration-SECRET-9f8e7d"


class Handler(BaseHTTPRequestHandler):
    """A deliberately misconfigured app. Records every request it receives."""

    seen: ClassVar[list[tuple[str, str, str | None]]] = []
    delay: ClassVar[float] = 0.0

    def log_message(self, *args: Any) -> None:  # silence stderr
        pass

    def _send(self, status: int, body: str, headers: dict[str, str] | None = None) -> None:
        data = body.encode()
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            # The client may already have aborted (Stop test); that is expected.
            with contextlib.suppress(ConnectionError):
                self.wfile.write(data)

    def _record(self) -> None:
        Handler.seen.append((self.command, self.path, self.headers.get("Authorization")))
        if Handler.delay:
            time.sleep(Handler.delay)

    def do_GET(self) -> None:
        self._record()
        origin = self.headers.get("Origin")
        if self.path == "/":
            hdrs = {"Server": "TestServer/1.2.3", "Content-Type": "application/json"}
            if origin:
                hdrs |= {
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                }
            echo = self.headers.get("Authorization")
            self._send(200, f'{{"echo": "{echo}"}}', hdrs)
        elif self.path.startswith("/magen-probe-not-found"):
            self._send(
                500, 'Traceback (most recent call last):\n  File "/app/x.py", line 3, in y\n'
            )
        elif self.path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n")
        elif self.path == "/.env":
            self._send(200, "DB_PASSWORD=supersecret\nAPI_KEY=zzz\n")
        else:
            self._send(404, "nope")

    def do_OPTIONS(self) -> None:
        self._record()
        self._send(204, "", {"Allow": "GET, HEAD, OPTIONS, TRACE"})

    def do_POST(self) -> None:
        self._record()
        self._send(500, "POST must never be sent")


@pytest.fixture
def http_server() -> Iterator[int]:
    Handler.seen, Handler.delay = [], 0.0
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()


@pytest.fixture
def https_server(tmp_path: Path) -> Iterator[tuple[int, trustme.CA]]:
    Handler.seen, Handler.delay = [], 0.0
    ca = trustme.CA()
    cert = ca.issue_cert("localhost", "127.0.0.1")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    cert.configure_cert(ctx)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1], ca
    server.shutdown()


def add_target(client: TestClient, host: str = "127.0.0.1", *, is_local: bool = True) -> int:
    res = client.post(
        "/api/targets", json={"host": host, "is_local": is_local, "authorization_confirmed": True}
    )
    assert res.status_code == 201, res.text
    return int(res.json()["id"])


def wait_finished(client: TestClient, scan_id: int, timeout: float = 30.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"/api/scans/{scan_id}").json()
        if body["status"] in ("done", "failed", "cancelled"):
            return dict(body)
        time.sleep(0.1)
    raise AssertionError("scan did not finish")


# ---- allowlist API ------------------------------------------------------------------------


class TestTargets:
    def test_authorization_confirmation_required(self, client: TestClient) -> None:
        for body in (
            {"host": "api.example.com"},
            {"host": "api.example.com", "authorization_confirmed": False},
        ):
            assert client.post("/api/targets", json=body).status_code == 422

    def test_records_timestamp_and_normalizes(self, client: TestClient) -> None:
        res = client.post(
            "/api/targets", json={"host": "API.Example.com.", "authorization_confirmed": True}
        )
        body = res.json()
        assert body["host"] == "api.example.com" and body["authorized_at"]
        assert [t["host"] for t in client.get("/api/targets").json()] == ["api.example.com"]

    @pytest.mark.parametrize(
        "host", ["https://x.example.com", "x.example.com/path", "*.example.com", "x:8080"]
    )
    def test_rejects_non_bare_hosts(self, client: TestClient, host: str) -> None:
        res = client.post("/api/targets", json={"host": host, "authorization_confirmed": True})
        assert res.status_code == 422 and res.json()["code"] == "invalid_host"

    def test_internal_ip_requires_local_flag(self, client: TestClient) -> None:
        res = client.post(
            "/api/targets", json={"host": "10.0.0.5", "authorization_confirmed": True}
        )
        assert res.status_code == 422 and "local lab target" in res.json()["message"]
        assert add_target(client, "10.0.0.5", is_local=True) > 0

    def test_metadata_ip_never_allowed(self, client: TestClient) -> None:
        res = client.post(
            "/api/targets",
            json={"host": "169.254.169.254", "is_local": True, "authorization_confirmed": True},
        )
        assert res.status_code == 422 and "metadata" in res.json()["message"]

    def test_duplicate_and_delete(self, client: TestClient) -> None:
        tid = add_target(client, "api.example.com", is_local=False)
        assert (
            client.post(
                "/api/targets", json={"host": "api.example.com", "authorization_confirmed": True}
            ).status_code
            == 422
        )
        assert client.delete(f"/api/targets/{tid}").status_code == 204
        assert client.get("/api/targets").json() == []
        assert client.delete(f"/api/targets/{tid}").status_code == 404


# ---- scan API -----------------------------------------------------------------------------


class TestScanValidation:
    def test_unknown_target(self, client: TestClient) -> None:
        assert (
            client.post(
                "/api/scans/runtime", json={"target_id": 99, "base_url": "http://127.0.0.1/"}
            ).status_code
            == 404
        )

    def test_base_url_must_be_on_target_host(self, client: TestClient) -> None:
        tid = add_target(client)
        res = client.post(
            "/api/scans/runtime", json={"target_id": tid, "base_url": "http://localhost:1/"}
        )
        assert res.status_code == 403 and res.json()["code"] == "unsafe_target"

    @pytest.mark.parametrize(
        "extra",
        [
            {"rate_per_second": 50},
            {"request_cap": 10_000},
            {"auth_header": {"name": "Host", "value": "x"}},
            {"auth_header": {"name": "Authorization", "value": "a\r\nX-Injected: 1"}},
            {"auth_header": {"name": "Bad Name", "value": "x"}},
        ],
    )
    def test_rejects_unsafe_options(self, client: TestClient, extra: dict[str, Any]) -> None:
        tid = add_target(client)
        res = client.post(
            "/api/scans/runtime",
            json={"target_id": tid, "base_url": "http://127.0.0.1:1/", **extra},
        )
        assert res.status_code == 422
        assert "X-Injected" not in res.text  # input values are never echoed back

    def test_credentials_in_url_rejected(self, client: TestClient) -> None:
        tid = add_target(client)
        res = client.post(
            "/api/scans/runtime", json={"target_id": tid, "base_url": "http://u:p@127.0.0.1/"}
        )
        assert res.status_code == 422


class TestRuntimeScan:
    def test_full_scan_findings_audit_and_secret_handling(
        self, client: TestClient, http_server: int, settings: Any
    ) -> None:
        tid = add_target(client)
        base = f"http://127.0.0.1:{http_server}/"
        res = client.post(
            "/api/scans/runtime",
            json={
                "target_id": tid,
                "base_url": base,
                "auth_header": {"name": "Authorization", "value": SECRET},
            },
        )
        assert res.status_code == 202, res.text
        assert res.json()["progress"]["total"] == 9
        body = wait_finished(client, res.json()["id"])
        assert body["status"] == "done", body

        rules = sorted(f["rule_id"] for f in body["findings"])
        assert rules == sorted(
            [
                "API-RT-001",
                "API-RT-005",
                "API-RT-006",
                "API-RT-007",
                "API-RT-008",
                "API-RT-009",
                "API-RT-009",
                "API-RT-011",
            ]
        )
        assert {f["status"] for f in body["findings"]} == {"confirmed"}

        # Only safe methods were ever sent, and the credential reached the local lab server.
        methods = {m for m, _, _ in Handler.seen}
        assert methods <= {"GET", "HEAD", "OPTIONS"}
        assert any(a == SECRET for _, _, a in Handler.seen)

        # Every probe is in the audit log, in order, with redacted URLs.
        audit = client.get(f"/api/scans/{body['id']}/audit").json()
        assert len(audit) == len(Handler.seen) == 9
        assert audit[0]["method"] == "GET" and audit[0]["url"] == base

        # The secret and the .env values appear nowhere: API response, DB, audit.
        everything = res.text + str(body) + str(audit)
        for leaked in ("integration-SECRET-9f8e7d", "supersecret", "zzz"):
            assert leaked not in everything
        db_dump = Path(settings.db_path).read_bytes()
        for leaked in (b"integration-SECRET-9f8e7d", b"supersecret"):
            assert leaked not in db_dump
        # The header *name* is recorded for provenance; its value is not.
        with client.app.state.db.session() as s:  # type: ignore[attr-defined]
            options = s.execute(text("select options from scans")).scalar_one()
        assert "Authorization" in options and "integration" not in options

    def test_stored_scan_readable_after_session(self, client: TestClient, http_server: int) -> None:
        tid = add_target(client)
        res = client.post(
            "/api/scans/runtime",
            json={"target_id": tid, "base_url": f"http://127.0.0.1:{http_server}/"},
        )
        scan_id = wait_finished(client, res.json()["id"])["id"]
        client.app.state.scans.jobs.clear()  # type: ignore[attr-defined]  # simulate restart
        stored = client.get(f"/api/scans/{scan_id}").json()
        assert stored["status"] == "done" and len(stored["findings"]) >= 1

    def test_stop_cancels_in_flight_and_keeps_partial_results(
        self, client: TestClient, http_server: int
    ) -> None:
        Handler.delay = 1.0
        tid = add_target(client)
        res = client.post(
            "/api/scans/runtime",
            json={"target_id": tid, "base_url": f"http://127.0.0.1:{http_server}/"},
        )
        scan_id = res.json()["id"]
        time.sleep(1.5)  # first probe done, second in flight
        stopped = client.post(f"/api/scans/{scan_id}/stop")
        assert stopped.status_code == 202
        started = time.monotonic()
        body = wait_finished(client, scan_id, timeout=5)
        assert time.monotonic() - started < 2.0  # did not wait for remaining probes
        assert body["status"] == "cancelled"
        assert any("Stopped by user" in n for n in body["notes"])
        assert len(Handler.seen) < 9
        # Every request that reached the server is audited, including the cancelled one.
        time.sleep(1.2)  # let the server finish handling the aborted request
        audit = client.get(f"/api/scans/{scan_id}/audit").json()
        assert len(audit) == len(Handler.seen)
        assert audit[-1]["error"] == "Cancelled (scan stopped)"

    def test_only_one_scan_at_a_time(self, client: TestClient, http_server: int) -> None:
        Handler.delay = 0.5
        tid = add_target(client)
        payload = {"target_id": tid, "base_url": f"http://127.0.0.1:{http_server}/"}
        first = client.post("/api/scans/runtime", json=payload)
        second = client.post("/api/scans/runtime", json=payload)
        assert second.status_code == 422 and "already running" in second.json()["message"]
        client.post(f"/api/scans/{first.json()['id']}/stop")
        wait_finished(client, first.json()["id"])

    def test_request_cap_stops_early_with_note(self, client: TestClient, http_server: int) -> None:
        tid = add_target(client)
        res = client.post(
            "/api/scans/runtime",
            json={
                "target_id": tid,
                "base_url": f"http://127.0.0.1:{http_server}/",
                "request_cap": 3,
            },
        )
        body = wait_finished(client, res.json()["id"])
        assert body["status"] == "done"
        assert len(Handler.seen) == 3
        assert any("Request cap reached" in n for n in body["notes"])

    def test_public_target_resolving_to_loopback_fails_safely(
        self, client: TestClient, http_server: int
    ) -> None:
        tid = add_target(client, "localhost", is_local=False)
        res = client.post(
            "/api/scans/runtime",
            json={"target_id": tid, "base_url": f"http://localhost:{http_server}/"},
        )
        body = wait_finished(client, res.json()["id"])
        assert body["status"] == "failed" and "internal address" in body["error"]
        assert Handler.seen == []

    def test_rate_limit_respected(self, client: TestClient, http_server: int) -> None:
        tid = add_target(client)
        started = time.monotonic()
        res = client.post(
            "/api/scans/runtime",
            json={
                "target_id": tid,
                "base_url": f"http://127.0.0.1:{http_server}/",
                "rate_per_second": 4,
            },
        )
        wait_finished(client, res.json()["id"])
        assert time.monotonic() - started >= (9 - 1) / 4 - 0.1


class TestTls:
    def test_untrusted_certificate_reported_over_https(
        self, client: TestClient, https_server: tuple[int, Any]
    ) -> None:
        port, _ = https_server
        tid = add_target(client, "localhost", is_local=True)
        res = client.post(
            "/api/scans/runtime", json={"target_id": tid, "base_url": f"https://localhost:{port}/"}
        )
        body = wait_finished(client, res.json()["id"])
        assert body["status"] == "done", body
        by_rule = {f["rule_id"]: f for f in body["findings"]}
        assert "API-RT-003" in by_rule  # trustme CA is not in the system store
        assert "API-RT-004" in by_rule  # no HSTS on the HTTPS response
        assert "API-RT-002" not in by_rule  # server only allows TLS 1.2+
        audit = client.get(f"/api/scans/{body['id']}/audit").json()
        assert [a["method"] for a in audit].count("TLS") == 3

    def test_handshake_helpers(self, https_server: tuple[int, Any]) -> None:
        import ipaddress

        port, _ = https_server
        ip = ipaddress.ip_address("127.0.0.1")
        v = verify_handshake("localhost", ip, port)
        assert v.connected and not v.ok and v.error
        for proto in ("TLSv1", "TLSv1.1"):
            r = legacy_handshake("localhost", ip, port, proto)
            assert not r.ok  # refused by the server, or not testable from this client
        closed = verify_handshake("localhost", ip, 1)
        assert not closed.connected


def test_token_required_for_scan_endpoints(anon_client: TestClient) -> None:
    assert anon_client.get("/api/targets").status_code == 401
    assert anon_client.post("/api/scans/runtime", json={}).status_code == 401


def test_secret_not_in_logs(
    client: TestClient, http_server: int, caplog: pytest.LogCaptureFixture
) -> None:
    tid = add_target(client)
    res = client.post(
        "/api/scans/runtime",
        json={
            "target_id": tid,
            "base_url": f"http://127.0.0.1:{http_server}/",
            "auth_header": {"name": "X-Api-Key", "value": "k-LOGLEAK-1"},
        },
    )
    wait_finished(client, res.json()["id"])
    assert "k-LOGLEAK-1" not in caplog.text


_ = TEST_TOKEN
