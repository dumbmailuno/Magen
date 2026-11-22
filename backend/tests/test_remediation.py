"""Remediation: edits, fixers, validation, nginx -t handling, API. Nothing touches disk."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.remediation import validate as validate_mod
from app.remediation.diff import unified_diff
from app.remediation.edits import Edit, apply_edits
from app.remediation.service import corrected_name, preview
from app.remediation.validate import nginx_syntax_check

CORPUS = Path(__file__).resolve().parents[2] / "corpus"


def read(rel: str) -> str:
    return (CORPUS / rel).read_text(encoding="utf-8")


# ---- edits -------------------------------------------------------------------------------


class TestEdits:
    TEXT = "a\nb\nc\nd\n"

    def test_replace_insert_and_delete_bottom_up(self) -> None:
        r = apply_edits(
            self.TEXT,
            [Edit("f1", 2, 2, ("B",)), Edit("f2", 4, 3, ("x", "y")), Edit("f3", 1, 1, ())],
        )
        assert r.text == "B\nc\nx\ny\nd\n"
        assert r.applied == {"f1", "f2", "f3"} and not r.conflicts

    def test_same_point_inserts_merge_without_duplicates(self) -> None:
        r = apply_edits(self.TEXT, [Edit("f1", 3, 2, ("h1", "h2")), Edit("f2", 3, 2, ("h2", "h3"))])
        assert r.text == "a\nb\nh1\nh2\nh3\nc\nd\n"

    def test_identical_replacements_merge(self) -> None:
        r = apply_edits(self.TEXT, [Edit("f1", 2, 2, ("B",)), Edit("f2", 2, 2, ("B",))])
        assert r.text == "a\nB\nc\nd\n" and not r.conflicts

    def test_overlap_is_a_conflict_and_drops_all_of_that_findings_edits(self) -> None:
        r = apply_edits(
            self.TEXT,
            [Edit("f1", 2, 3, ("X",)), Edit("f2", 3, 3, ("Y",)), Edit("f2", 1, 0, ("top",))],
        )
        assert r.conflicts == {"f2"}
        assert r.text == "a\nX\nd\n"  # f2's insert at the top was not applied either

    def test_insert_inside_replaced_range_conflicts(self) -> None:
        r = apply_edits(self.TEXT, [Edit("f1", 2, 3, ("X",)), Edit("f2", 3, 2, ("i",))])
        assert r.conflicts == {"f2"}

    def test_crlf_normalised(self) -> None:
        assert apply_edits("a\r\nb\r\n", [Edit("f", 1, 1, ("A",))]).text == "A\nb\n"


def test_unified_diff_and_names() -> None:
    d = unified_diff("a\nb\n", "a\nB\n", "nginx.conf")
    assert d.splitlines()[:2] == ["--- a/nginx.conf", "+++ b/nginx.conf"]
    assert "-b" in d and "+B" in d
    assert unified_diff("same", "same", "x") == ""
    assert corrected_name("dir\\nginx.conf") == "nginx.magen-fixed.conf"
    assert corrected_name("api.yaml") == "api.magen-fixed.yaml"


# ---- fixers over the corpus ----------------------------------------------------------------

FIXABLE = [
    ("nginx", "nginx/legacy-tls.conf"),
    ("nginx", "nginx/plaintext.conf"),
    ("nginx", "nginx/exposure.conf"),
    ("nginx", "nginx/header-inheritance.conf"),
    ("nginx", "correlation/cdn-headers.conf"),
    ("openapi", "openapi/insecure-transport.yaml"),
    ("openapi", "openapi/leaky-errors.yaml"),
    ("openapi", "openapi/weak-schemes.yaml"),
]


@pytest.mark.parametrize(("kind", "rel"), FIXABLE, ids=[r for _, r in FIXABLE])
def test_every_applied_fix_validates(kind: Any, rel: str) -> None:
    """Remediation success on the corpus: each auto-fix removes its finding, adds nothing."""
    p = preview(kind, Path(rel).name, read(rel), None)
    applied = [fx for fx in p.fixes if fx.outcome == "applied"]
    assert applied, "expected at least one auto-fix"
    assert all(fx.validated for fx in applied), [
        (fx.finding.rule_id, fx.validated) for fx in applied
    ]
    assert p.validation.parsed and not p.validation.introduced


def test_preview_is_deterministic_and_never_returns_the_original_name() -> None:
    a = preview("nginx", "exposure.conf", read("nginx/exposure.conf"), None)
    b = preview("nginx", "exposure.conf", read("nginx/exposure.conf"), None)
    assert (a.patched, a.diff) == (b.patched, b.diff)
    assert a.patched_filename == "exposure.magen-fixed.conf"


def test_selected_findings_only() -> None:
    full = preview("nginx", "legacy-tls.conf", read("nginx/legacy-tls.conf"), None)
    one = full.fixes[0].finding.id
    p = preview("nginx", "legacy-tls.conf", read("nginx/legacy-tls.conf"), [one])
    assert [fx.finding.id for fx in p.fixes] == [one]
    added = [ln for ln in p.diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    assert len(added) == 1  # only that directive changed


@pytest.mark.parametrize(
    ("kind", "rel", "rule"),
    [
        ("nginx", "nginx/cors.conf", "NGX-CORS-001"),
        ("openapi", "openapi/no-auth.yaml", "API-OAS-002"),
        ("openapi", "openapi/weak-schemes.yaml", "API-OAS-004"),
        ("nginx", "nginx/site-snippet.conf", "NGX-HDR-001"),
        ("nginx", "nginx/site-snippet.conf", "NGX-RL-001"),
    ],
)
def test_human_decisions_stay_template_only(kind: Any, rel: str, rule: str) -> None:
    p = preview(kind, Path(rel).name, read(rel), None)
    assert {fx.outcome for fx in p.fixes if fx.finding.rule_id == rule} == {"template_only"}


def test_header_fix_copies_inherited_headers() -> None:
    """Adding the first add_header to a block would drop inherited ones: they are copied."""
    text = (
        "http {\n    limit_req_zone $binary_remote_addr zone=a:1m rate=1r/s;\n"
        "    server_tokens off;\n"
        '    add_header X-Content-Type-Options "nosniff" always;\n'
        '    add_header X-Frame-Options "DENY" always;\n'
        "    server {\n        listen 443 ssl;\n        limit_req zone=a;\n    }\n}\n"
    )
    p = preview("nginx", "n.conf", text, None)
    assert [fx.outcome for fx in p.fixes] == ["applied"]
    assert p.fixes[0].validated
    server_part = p.patched.split("server {")[1]
    assert "X-Content-Type-Options" in server_part and "Strict-Transport-Security" in server_part


def test_rate_limit_fix_reuses_existing_zone_and_adds_zone_otherwise() -> None:
    with_zone = (
        "http {\n    limit_req_zone $binary_remote_addr zone=mine:10m rate=1r/s;\n"
        "    server {\n        listen 80;\n        return 301 https://$host;\n    }\n}\n"
    )
    p = preview("nginx", "n.conf", with_zone, None)
    rl = next(fx for fx in p.fixes if fx.finding.rule_id == "NGX-RL-001")
    assert rl.validated and "limit_req zone=mine" in p.patched
    without = with_zone.replace(
        "    limit_req_zone $binary_remote_addr zone=mine:10m rate=1r/s;\n", ""
    )
    p2 = preview("nginx", "n.conf", without, None)
    assert "zone=magen_api:10m" in p2.patched and "limit_req zone=magen_api" in p2.patched


def test_plaintext_fix_skips_mixed_listeners() -> None:
    text = (
        "http {\n    server {\n        listen 80;\n        listen 443 ssl;\n"
        "        root /srv;\n    }\n}\n"
    )
    p = preview("nginx", "n.conf", text, None)
    assert {fx.outcome for fx in p.fixes if fx.finding.rule_id == "NGX-TLS-004"} == {
        "template_only"
    }


def test_json_openapi_structural_fix_is_template_only() -> None:
    text = (
        '{"openapi": "3.0.0", "info": {"title": "t", "version": "1"},\n'
        ' "paths": {"/x": {"get": {"responses": {"500": {"description": "e",\n'
        ' "content": {"application/json":\n'
        ' {"schema": {"properties": {"stackTrace": {"type": "string"}}}}}}}}}}}\n'
    )
    p = preview("openapi", "a.json", text, None)
    assert {fx.outcome for fx in p.fixes if fx.finding.rule_id == "API-OAS-009"} == {
        "template_only"
    }


def test_missing_global_security_fix() -> None:
    text = (
        "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /x:\n    get:\n"
        "      responses:\n        '200': {description: ok}\n        '429': {description: slow}\n"
        "components:\n  securitySchemes:\n    bearerAuth: {type: http, scheme: bearer}\n"
    )
    p = preview("openapi", "a.yaml", text, None)
    oas3 = next(fx for fx in p.fixes if fx.finding.rule_id == "API-OAS-003")
    assert oas3.outcome == "applied" and oas3.validated
    assert p.patched.rstrip().endswith("security:\n  - bearerAuth: []")


def test_broken_patch_is_not_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.remediation import service

    monkeypatch.setattr(
        service, "apply_edits", lambda text, edits: apply_edits(text + "\n}", edits)
    )
    p = preview("nginx", "legacy-tls.conf", read("nginx/legacy-tls.conf"), None)
    assert not p.validation.parsed and p.validation.error
    assert all(fx.validated is False for fx in p.fixes if fx.outcome == "applied")


def test_new_findings_block_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.remediation import service

    monkeypatch.setattr(
        service,
        "apply_edits",
        lambda text, edits: apply_edits(text.replace("server_tokens off;", ""), edits),
    )
    p = preview("nginx", "legacy-tls.conf", read("nginx/legacy-tls.conf"), None)
    assert [f.rule_id for f in p.validation.introduced] == ["NGX-HDR-001"]
    assert all(fx.validated is False for fx in p.fixes if fx.outcome == "applied")


# ---- nginx -t ----------------------------------------------------------------------------


class TestNginxSyntax:
    def test_unavailable_and_snippet(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(validate_mod.shutil, "which", lambda name: None)
        assert nginx_syntax_check("x", "y", is_snippet=False).status == "unavailable"
        assert nginx_syntax_check("x", "y", is_snippet=True).status == "not_applicable"

    @pytest.mark.parametrize(
        ("orig_rc", "patched_rc", "expected"),
        [(0, 0, "passed"), (0, 1, "failed"), (1, 1, "inconclusive"), (1, 0, "passed")],
    )
    def test_outcomes(
        self, monkeypatch: pytest.MonkeyPatch, orig_rc: int, patched_rc: int, expected: str
    ) -> None:
        monkeypatch.setattr(validate_mod.shutil, "which", lambda name: "/usr/sbin/nginx")
        calls: list[list[str]] = []

        def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
            calls.append(argv)
            text = Path(argv[-1]).read_text(encoding="utf-8")
            rc = patched_rc if "PATCHED" in text else orig_rc
            return subprocess.CompletedProcess(
                argv, rc, "", "" if rc == 0 else "nginx: [emerg] bad\n"
            )

        monkeypatch.setattr(validate_mod.subprocess, "run", fake_run)
        result = nginx_syntax_check("# ORIGINAL", "# PATCHED", is_snippet=False)
        assert result.status == expected
        assert all(argv[1:3] == ["-t", "-q"] for argv in calls)  # test mode only, never a reload


# ---- API -----------------------------------------------------------------------------------


def test_preview_endpoint(client: TestClient) -> None:
    res = client.post(
        "/api/remediation/preview",
        json={
            "kind": "nginx",
            "filename": "legacy-tls.conf",
            "content": read("nginx/legacy-tls.conf"),
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["patched_filename"] == "legacy-tls.magen-fixed.conf"
    assert body["diff"].startswith("--- a/legacy-tls.conf")
    assert {f["outcome"] for f in body["fixes"]} == {"applied"}
    assert all(f["validated"] for f in body["fixes"])
    assert body["validation"]["syntax"]["status"] in ("unavailable", "passed", "inconclusive")


def test_preview_endpoint_bad_input(client: TestClient) -> None:
    res = client.post(
        "/api/remediation/preview",
        json={"kind": "nginx", "filename": "n.conf", "content": "http {"},
    )
    assert res.status_code == 422 and res.json()["code"] == "invalid_nginx"
