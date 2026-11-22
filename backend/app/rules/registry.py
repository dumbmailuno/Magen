"""Rule registry: the one place that knows which rules exist."""

from __future__ import annotations

import re
from typing import Any, TypeVar

from app.models.finding import RULE_ID_PATTERN
from app.rules.base import Rule, RuleTarget

_REQUIRED_ATTRS = (
    "id",
    "title",
    "category",
    "severity",
    "description",
    "target",
    "references",
    "remediation_template",
)

RuleClass = TypeVar("RuleClass", bound=type[Rule[Any]])


class RuleRegistrationError(ValueError):
    """Raised when a rule is malformed or its id collides with another rule."""


class RuleRegistry:
    """Holds rule classes keyed by id. Ids may never be registered twice."""

    def __init__(self) -> None:
        self._rules: dict[str, type[Rule[Any]]] = {}

    def register(self, cls: RuleClass) -> RuleClass:
        """Class decorator adding ``cls`` to the registry after validating it."""
        missing = [a for a in _REQUIRED_ATTRS if not hasattr(cls, a)]
        if missing:
            raise RuleRegistrationError(f"{cls.__name__} missing attributes: {missing}")
        if not re.fullmatch(RULE_ID_PATTERN, cls.id):
            raise RuleRegistrationError(f"{cls.__name__} has malformed id {cls.id!r}")
        if cls.id in self._rules:
            raise RuleRegistrationError(f"rule id {cls.id} already registered")
        if not cls.references.owasp_api:
            raise RuleRegistrationError(f"{cls.id} must map to an OWASP API Top 10 (2023) id")
        self._rules[cls.id] = cls
        return cls

    def all(self, *, include_deprecated: bool = False) -> list[type[Rule[Any]]]:
        """All rules, sorted by id for deterministic execution order."""
        rules = sorted(self._rules.values(), key=lambda r: r.id)
        return [r for r in rules if include_deprecated or not r.deprecated]

    def for_target(self, target: RuleTarget) -> list[type[Rule[Any]]]:
        """Active rules for one analyzer, sorted by id."""
        return [r for r in self.all() if r.target is target]

    def get(self, rule_id: str) -> type[Rule[Any]] | None:
        """Look up a rule by id (including deprecated rules)."""
        return self._rules.get(rule_id)


#: Process-wide registry. Rule modules register themselves on import.
registry = RuleRegistry()
