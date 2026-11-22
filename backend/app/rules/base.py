"""Rule contract (CLAUDE.md §6).

One rule = one file = one subclass of :class:`Rule`. Rules are pure: they receive a parsed,
in-memory document and return findings. They must never touch the network, the
filesystem, the clock, randomness, or the LLM — that is what makes detection reproducible.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import ClassVar, Generic, TypeVar

from app.models.finding import Finding, References, Severity

InputT = TypeVar("InputT")


class RuleTarget(StrEnum):
    """Which analyzer feeds the rule."""

    OPENAPI = "openapi"
    NGINX = "nginx"
    RUNTIME = "runtime"


class Rule(ABC, Generic[InputT]):
    """Base class for every detection rule."""

    #: Stable, never-reused id such as ``API-OAS-001`` or ``NGX-TLS-003``.
    id: ClassVar[str]
    title: ClassVar[str]
    category: ClassVar[str]
    severity: ClassVar[Severity]
    description: ClassVar[str]
    target: ClassVar[RuleTarget]
    references: ClassVar[References]
    #: Deterministic fix template shown before any AI suggestion.
    remediation_template: ClassVar[str]
    #: Deprecated rules stay registered (ids are never reused) but are not run.
    deprecated: ClassVar[bool] = False

    @abstractmethod
    def check(self, document: InputT) -> list[Finding]:
        """Return findings for ``document``. Must be pure and deterministic."""
