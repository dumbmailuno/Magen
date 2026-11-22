from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

import pytest
import yaml

import app.rules.openapi  # noqa: F401  (register rules)
from app.models.finding import Finding
from app.rules.registry import registry
from app.static.openapi.document import OpenApiDocument

#: A spec that is clean for every OpenAPI rule. Tests mutate a deep copy.
CLEAN: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {"title": "t", "version": "1"},
    "servers": [{"url": "https://api.example.com"}],
    "security": [{"bearerAuth": []}],
    "paths": {
        "/items": {
            "get": {
                "parameters": [{"name": "page", "in": "query"}],
                "responses": {
                    "200": {
                        "description": "ok",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"id": {"type": "string"}},
                                }
                            }
                        },
                    },
                    "429": {"description": "slow down"},
                },
            }
        }
    },
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
}

Mutator = Callable[[dict[str, Any]], None]


def run_rule(rule_id: str, mutate: Mutator | None = None) -> list[Finding]:
    spec = copy.deepcopy(CLEAN)
    if mutate:
        mutate(spec)
    doc = OpenApiDocument("spec.yaml", yaml.safe_dump(spec, sort_keys=False))
    rule = registry.get(rule_id)
    assert rule is not None, rule_id
    return rule().check(doc)


@pytest.fixture
def check() -> Callable[[str, Mutator | None], list[Finding]]:
    return run_rule
