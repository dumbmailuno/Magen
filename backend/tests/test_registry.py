from __future__ import annotations

from typing import ClassVar

import pytest

from app.models.finding import Finding, References, Severity
from app.rules.base import Rule, RuleTarget
from app.rules.registry import RuleRegistrationError, RuleRegistry


def _rule(rule_id: str, **overrides: object) -> type[Rule[dict[str, object]]]:
    attrs: dict[str, object] = {
        "id": rule_id,
        "title": "t",
        "category": "c",
        "severity": Severity.LOW,
        "description": "d",
        "target": RuleTarget.OPENAPI,
        "references": References(owasp_api=["API8:2023"]),
        "remediation_template": "fix",
        "check": lambda self, doc: [],
    }
    attrs.update(overrides)
    return type(f"R_{rule_id.replace('-', '_')}", (Rule,), attrs)


def test_register_and_sorted_lookup() -> None:
    reg = RuleRegistry()
    reg.register(_rule("API-OAS-002"))
    reg.register(_rule("API-OAS-001"))
    reg.register(_rule("NGX-TLS-001", target=RuleTarget.NGINX))
    assert [r.id for r in reg.all()] == ["API-OAS-001", "API-OAS-002", "NGX-TLS-001"]
    assert [r.id for r in reg.for_target(RuleTarget.NGINX)] == ["NGX-TLS-001"]
    assert reg.get("API-OAS-001") is not None


def test_duplicate_id_rejected() -> None:
    reg = RuleRegistry()
    reg.register(_rule("API-OAS-001"))
    with pytest.raises(RuleRegistrationError, match="already registered"):
        reg.register(_rule("API-OAS-001"))


def test_malformed_id_rejected() -> None:
    with pytest.raises(RuleRegistrationError, match="malformed"):
        RuleRegistry().register(_rule("oas-1"))


def test_owasp_mapping_required() -> None:
    with pytest.raises(RuleRegistrationError, match="OWASP"):
        RuleRegistry().register(_rule("API-OAS-001", references=References()))


def test_deprecated_rules_kept_but_not_run() -> None:
    reg = RuleRegistry()
    reg.register(_rule("API-OAS-001", deprecated=True))
    assert reg.all() == []
    assert [r.id for r in reg.all(include_deprecated=True)] == ["API-OAS-001"]
    with pytest.raises(RuleRegistrationError):
        reg.register(_rule("API-OAS-001"))  # deprecated ids are never reused


def test_missing_attribute_rejected() -> None:
    class Incomplete(Rule[dict[str, object]]):
        id: ClassVar[str] = "API-OAS-001"

        def check(self, document: dict[str, object]) -> list[Finding]:
            return []

    with pytest.raises(RuleRegistrationError, match="missing"):
        RuleRegistry().register(Incomplete)
