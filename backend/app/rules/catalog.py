"""Loads every rule package so the registry is complete."""

from __future__ import annotations

import importlib
from typing import Final

RULE_PACKAGES: Final = ("app.rules.openapi", "app.rules.nginx")


def load_rules() -> None:
    """Import all rule packages (idempotent); each rule module registers itself."""
    for package in RULE_PACKAGES:
        importlib.import_module(package)
