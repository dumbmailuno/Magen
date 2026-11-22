"""Sessions, correlation via the API, and baseline comparison (the full retest loop)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.models.finding import (
    Evidence,
    EvidenceKind,
    FindingStatus,
    Location,
    Severity,
    Source,
    make_finding,
)
from app.retest.compare import compare
from app.runtime.recording import loads
from app.runtime.scanner import run_runtime_rules
from app.storage.repositories import ScanRepository

CORPUS = Path(__file__).resolve().parents[2] / "corpus"
MARKER = "magen-content-marker-5d1c"


def read(rel: str) -> str:
    return (CORPUS / rel).read_text(encoding="utf-8")


def f(
    rule: str, pointer: str, excerpt: str = "x", status: FindingStatus = FindingStatus.POTENTIAL
) -> Any:
    return make_finding(
        rule_id=rule,
        title=rule,
        category="c",
        severity=Severity.LOW,
        status=status,
        source=Source.STATIC,
        evidence=[
            Evidence(
                kind=EvidenceKind.NGINX,
                location=Location(file="n.conf", line=3, pointer=pointer),
                excerpt=excerpt,
            )
        ],
    )


class TestCompare:
    def test_resolved_persists_new_and_rate(self) -> None:
        a, b, c = f("NGX-CFG-001", "/a"), f("NGX-CFG-002", "/b"), f("NGX-CFG-003", "/c")
        d = f("NGX-TLS-001", "/d")
        result = compare([a, b, c], [b, d])
        assert [x.id for x in result.resolved] == [a.id, c.id]
        assert [x.id for x in result.persists] == [b.id]
        assert [x.id for x in result.new] == [d.id]
        assert result.remediation_rate == pytest.approx(2 / 3)

    def test_changed_excerpt_same_location_persists(self) -> None:
        before = f("NGX-TLS-003", "/http/0/server/0", excerpt="server {\n  listen 443 ssl;")
        after = f(
            "NGX-TLS-003", "/http/0/server/0", excerpt="server {\n  listen 443 ssl;\n  limit_req z;"
        )
        assert before.id != after.id
        result = compare([before], [after])
        assert result.resolved == [] and result.new == [] and len(result.persists) == 1

    def test_status_change_reported(self) -> None:
        before = f("NGX-TLS-003", "/s")
        after = before.model_copy(update={"status": FindingStatus.CONFIRMED})
        result = compare([before], [after])
        assert [(s.before, s.after) for s in result.status_changes] == [("potential", "confirmed")]

    def test_empty_baseline(self) -> None:
        assert compare([], [f("NGX-CFG-001", "/a")]).remediation_rate is None


def _runtime_scan(client: TestClient, recording: str, host: str) -> int:
    """Persist a finished runtime scan from a recorded corpus fixture (no network)."""
    repo = ScanRepository(client.app.state.db)  # type: ignore[attr-defined]
    target = client.post(
        "/api/targets", json={"host": host, "authorization_confirmed": True}
    ).json()
    text = read(recording)
    findings = run_runtime_rules(loads(text))
    scan_id = repo.create(
        target_id=target["id"],
        options={"kind": "runtime", "base_url": f"https://{host}/"},
        version="t",
        commit="t",
    )
    repo.finish(scan_id, "done", findings, observations=text)
    return scan_id


def post_session(client: TestClient, **body: Any) -> dict[str, Any]:
    res = client.post("/api/sessions", json=body)
    assert res.status_code == 201, res.text
    return dict(res.json())


class TestSessions:
    def test_static_session_persists_hashes_not_contents(
        self, client: TestClient, settings: Any
    ) -> None:
        content = read("nginx/legacy-tls.conf") + f"\n# {MARKER}\n"
        body = post_session(
            client, inputs=[{"kind": "nginx", "filename": "legacy-tls.conf", "content": content}]
        )
        assert [x["rule_id"] for x in body["findings"]] == [
            "NGX-TLS-001",
            "NGX-TLS-002",
            "NGX-TLS-003",
        ]
        assert body["inputs"][0]["ok"] and len(body["inputs"][0]["sha256"]) == 64
        assert body["comparison"] is None
        assert MARKER.encode() not in Path(settings.db_path).read_bytes()
        assert client.get(f"/api/sessions/{body['id']}").json()["findings"] == body["findings"]

    def test_bad_input_is_recorded_not_fatal(self, client: TestClient) -> None:
        body = post_session(
            client,
            inputs=[
                {"kind": "nginx", "filename": "bad.conf", "content": "http {"},
                {
                    "kind": "nginx",
                    "filename": "legacy-tls.conf",
                    "content": read("nginx/legacy-tls.conf"),
                },
            ],
        )
        assert [(i["filename"], i["ok"]) for i in body["inputs"]] == [
            ("bad.conf", False),
            ("legacy-tls.conf", True),
        ]
        assert "expecting '}'" in body["inputs"][0]["error"]
        assert len(body["findings"]) == 3

    def test_snippet_notes_kept(self, client: TestClient) -> None:
        body = post_session(
            client,
            inputs=[
                {"kind": "nginx", "filename": "s.conf", "content": read("nginx/site-snippet.conf")}
            ],
        )
        assert any("snippets/security-headers.conf" in n for n in body["inputs"][0]["notes"])

    def test_session_correlates_with_runtime_scan(self, client: TestClient) -> None:
        scan_id = _runtime_scan(client, "runtime/legacy-server.json", "legacy.example.com")
        body = post_session(
            client,
            inputs=[
                {
                    "kind": "nginx",
                    "filename": "legacy-tls.conf",
                    "content": read("nginx/legacy-tls.conf"),
                }
            ],
            runtime_scan_id=scan_id,
        )
        by_rule = {x["rule_id"]: x for x in body["findings"]}
        assert (
            by_rule["NGX-TLS-001"]["status"] == "confirmed"
            and by_rule["NGX-TLS-001"]["source"] == "correlated"
        )
        assert by_rule["NGX-TLS-002"]["status"] == "potential"
        assert "API-RT-002" not in by_rule  # merged into NGX-TLS-001
        assert by_rule["API-RT-003"]["source"] == "runtime"
        assert body["correlation"] == {
            "confirmed": 2,
            "contradicted": 0,
            "runtime_only": 7,
            "static_only": 1,
        }

    def test_full_retest_loop_fix_then_resolved(self, client: TestClient) -> None:
        """Scan → generate the corrected copy → rescan it with the first as baseline."""
        original = read("nginx/exposure.conf")
        first = post_session(
            client, inputs=[{"kind": "nginx", "filename": "exposure.conf", "content": original}]
        )
        fixed = client.post(
            "/api/remediation/preview",
            json={"kind": "nginx", "filename": "exposure.conf", "content": original},
        ).json()["patched_content"]
        second = post_session(
            client,
            inputs=[{"kind": "nginx", "filename": "exposure.conf", "content": fixed}],
            baseline_id=first["id"],
        )
        cmp = second["comparison"]
        assert cmp["baseline_id"] == first["id"]
        assert len(cmp["resolved"]) == len(first["findings"]) == 5
        assert cmp["persists"] == [] and cmp["new"] == []
        assert cmp["remediation_rate"] == 1.0
        assert cmp["changed_inputs"] == ["exposure.conf"]
        assert second["findings"] == []

    def test_partial_fix_shows_persists(self, client: TestClient) -> None:
        original = read("nginx/legacy-tls.conf")
        first = post_session(
            client, inputs=[{"kind": "nginx", "filename": "l.conf", "content": original}]
        )
        protocols_only = original.replace("SSLv3 TLSv1 TLSv1.2", "TLSv1.2 TLSv1.3")
        second = post_session(
            client,
            inputs=[{"kind": "nginx", "filename": "l.conf", "content": protocols_only}],
            baseline_id=first["id"],
        )
        cmp = second["comparison"]
        assert [x["rule_id"] for x in cmp["resolved"]] == ["NGX-TLS-001"]
        assert sorted(x["rule_id"] for x in cmp["persists"]) == ["NGX-TLS-002", "NGX-TLS-003"]
        assert cmp["remediation_rate"] == pytest.approx(1 / 3)

    def test_compare_endpoint_and_list(self, client: TestClient) -> None:
        a = post_session(
            client,
            inputs=[
                {"kind": "nginx", "filename": "l.conf", "content": read("nginx/legacy-tls.conf")}
            ],
        )
        b = post_session(
            client,
            inputs=[
                {"kind": "nginx", "filename": "c.conf", "content": read("nginx/clean-tls.conf")}
            ],
        )
        cmp = client.get(f"/api/sessions/compare?base={a['id']}&head={b['id']}").json()
        assert len(cmp["resolved"]) == 3 and cmp["new"] == []
        listing = client.get("/api/sessions").json()
        assert [s["id"] for s in listing] == [b["id"], a["id"]]
        assert listing[1]["by_severity"] == {"high": 2, "medium": 1}

    def test_validation_errors(self, client: TestClient) -> None:
        assert client.post("/api/sessions", json={"inputs": []}).status_code == 422
        scan_id = _runtime_scan(client, "runtime/hardened-api.json", "api.example.com")
        res = client.post(
            "/api/sessions", json={"inputs": [], "runtime_scan_id": scan_id, "baseline_id": scan_id}
        )
        assert res.status_code == 422 and "baseline" in res.json()["message"]
        assert (
            client.get(f"/api/sessions/{scan_id}").status_code == 404
        )  # a runtime scan, not a session
        assert client.get("/api/sessions/9999").status_code == 404

    def test_running_runtime_scan_rejected(self, client: TestClient) -> None:
        repo = ScanRepository(client.app.state.db)  # type: ignore[attr-defined]
        scan_id = repo.create(target_id=None, options={"kind": "runtime"}, version="t", commit="t")
        res = client.post("/api/sessions", json={"runtime_scan_id": scan_id})
        assert res.status_code == 422 and "not finished" in res.json()["message"]

    def test_runtime_only_session(self, client: TestClient) -> None:
        scan_id = _runtime_scan(client, "runtime/exposed-files.json", "files.example.com")
        body = post_session(client, runtime_scan_id=scan_id)
        assert {x["source"] for x in body["findings"]} == {"runtime"}
        assert len(body["findings"]) == 4
