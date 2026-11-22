"""docs/rules.md must list every registered rule (CLAUDE.md §16: docs updated per rule)."""

from __future__ import annotations

from pathlib import Path

import app.rules.openapi  # noqa: F401
from app.rules.registry import registry

RULES_MD = Path(__file__).resolve().parents[2] / "docs" / "rules.md"


def test_rules_md_lists_every_rule_with_its_metadata() -> None:
    table_rows = {
        line.split("|")[1].strip(): line
        for line in RULES_MD.read_text(encoding="utf-8").splitlines()
        if line.startswith("| API-") or line.startswith("| NGX-")
    }
    for rule in registry.all(include_deprecated=True):
        assert rule.id in table_rows, f"{rule.id} missing from docs/rules.md"
        row = table_rows[rule.id]
        assert rule.severity.value in row.lower(), f"{rule.id}: severity mismatch in docs"
        for ref in rule.references.owasp_api + rule.references.cwe:
            assert ref in row, f"{rule.id}: {ref} missing from docs row"
    assert set(table_rows) == {r.id for r in registry.all(include_deprecated=True)}
