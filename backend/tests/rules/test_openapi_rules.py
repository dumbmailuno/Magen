"""Positive + negative fixtures for every OpenAPI rule (CLAUDE.md §6)."""

from __future__ import annotations

from typing import Any

import pytest

import app.rules.openapi  # noqa: F401
from app.rules.base import RuleTarget
from app.rules.registry import registry
from tests.rules.conftest import CLEAN, run_rule

OAS_RULES = [f"API-OAS-{i:03d}" for i in range(1, 11)]


def ptrs(rule_id: str, mutate: Any = None) -> list[str]:
    return [f.evidence[0].location.pointer or "" for f in run_rule(rule_id, mutate)]


@pytest.mark.parametrize("rule_id", OAS_RULES)
def test_clean_spec_has_no_findings(rule_id: str) -> None:
    assert run_rule(rule_id) == []


@pytest.mark.parametrize("rule_id", OAS_RULES)
def test_rule_metadata(rule_id: str) -> None:
    rule = registry.get(rule_id)
    assert rule is not None
    assert rule.target is RuleTarget.OPENAPI
    assert rule.references.owasp_api
    assert rule.remediation_template.strip()
    assert rule.title[0].isupper() and not rule.title.endswith(".")


def _ops(spec: dict[str, Any]) -> dict[str, Any]:
    paths: dict[str, Any] = spec["paths"]
    return paths


def get_op(spec: dict[str, Any]) -> dict[str, Any]:
    op: dict[str, Any] = _ops(spec)["/items"]["get"]
    return op


def schemes(spec: dict[str, Any]) -> dict[str, Any]:
    s: dict[str, Any] = spec["components"]["securitySchemes"]
    return s


# --- API-OAS-001 --------------------------------------------------------------------------


class TestHttpServer:
    def test_positive_root_path_and_operation_levels(self) -> None:
        def m(s: dict[str, Any]) -> None:
            s["servers"].append({"url": "HTTP://api.example.com"})
            _ops(s)["/items"]["servers"] = [{"url": "http://a.example.com"}]
            get_op(s)["servers"] = [{"url": "http://b.example.com"}]

        assert ptrs("API-OAS-001", m) == [
            "/servers/1/url",
            "/paths/~1items/servers/0/url",
            "/paths/~1items/get/servers/0/url",
        ]

    def test_positive_templated_scheme_allowing_http(self) -> None:
        def m(s: dict[str, Any]) -> None:
            s["servers"] = [
                {"url": "{proto}://x.example.com", "variables": {"proto": {"default": "http"}}}
            ]

        assert ptrs("API-OAS-001", m) == ["/servers/0/url"]

    @pytest.mark.parametrize(
        "server",
        [
            {"url": "http://localhost:8080"},
            {"url": "http://127.0.0.1"},
            {"url": "http://[::1]:3000"},
            {"url": "http://app.localhost"},
            {"url": "/v1"},
            {"url": "{p}://x.example.com", "variables": {"p": {"default": "https"}}},
        ],
    )
    def test_negative(self, server: dict[str, Any]) -> None:
        def m(s: dict[str, Any]) -> None:
            s["servers"] = [server]

        assert ptrs("API-OAS-001", m) == []


# --- API-OAS-002 --------------------------------------------------------------------------


class TestNoSecuritySchemes:
    def test_positive_missing_components(self) -> None:
        def m(s: dict[str, Any]) -> None:
            del s["components"]
            del s["security"]

        assert ptrs("API-OAS-002", m) == ["/openapi"]

    def test_positive_empty_schemes(self) -> None:
        def m(s: dict[str, Any]) -> None:
            s["components"]["securitySchemes"] = {}

        assert ptrs("API-OAS-002", m) == ["/components/securitySchemes"]

    def test_negative_no_operations(self) -> None:
        def m(s: dict[str, Any]) -> None:
            del s["components"]
            s["paths"] = {}

        assert ptrs("API-OAS-002", m) == []


# --- API-OAS-003 --------------------------------------------------------------------------


class TestUnauthenticatedOperation:
    def test_positive_no_security_anywhere(self) -> None:
        def m(s: dict[str, Any]) -> None:
            del s["security"]

        findings = run_rule("API-OAS-003", m)
        assert [f.evidence[0].location.pointer for f in findings] == ["/paths/~1items/get"]
        assert findings[0].title == "GET /items does not require authentication"

    def test_positive_explicit_opt_out(self) -> None:
        def m(s: dict[str, Any]) -> None:
            get_op(s)["security"] = []

        assert ptrs("API-OAS-003", m) == ["/paths/~1items/get/security"]

    def test_positive_optional_auth_inherited_gives_distinct_ids(self) -> None:
        def m(s: dict[str, Any]) -> None:
            s["security"] = [{}, {"bearerAuth": []}]
            _ops(s)["/items"]["post"] = {"responses": {"200": {"description": "ok"}}}

        findings = run_rule("API-OAS-003", m)
        assert len({f.id for f in findings}) == 2
        assert all("optional" in f.title for f in findings)

    def test_negative_operation_overrides_empty_root(self) -> None:
        def m(s: dict[str, Any]) -> None:
            s["security"] = []
            get_op(s)["security"] = [{"bearerAuth": []}]

        assert ptrs("API-OAS-003", m) == []


# --- API-OAS-004 / 005 / 006 --------------------------------------------------------------


class TestSchemeRules:
    def test_basic_positive_case_insensitive_and_via_ref(self) -> None:
        def m(s: dict[str, Any]) -> None:
            schemes(s)["basic"] = {"$ref": "#/components/x-schemes/b"}
            s["components"]["x-schemes"] = {"b": {"type": "HTTP", "scheme": "BASIC"}}

        assert ptrs("API-OAS-004", m) == ["/components/x-schemes/b"]

    def test_basic_negative_digest(self) -> None:
        def m(s: dict[str, Any]) -> None:
            schemes(s)["d"] = {"type": "http", "scheme": "digest"}

        assert ptrs("API-OAS-004", m) == []

    def test_api_key_query_positive(self) -> None:
        def m(s: dict[str, Any]) -> None:
            schemes(s)["k"] = {"type": "apiKey", "in": "query", "name": "key"}

        assert ptrs("API-OAS-005", m) == ["/components/securitySchemes/k"]

    @pytest.mark.parametrize("where", ["header", "cookie"])
    def test_api_key_negative(self, where: str) -> None:
        def m(s: dict[str, Any]) -> None:
            schemes(s)["k"] = {"type": "apiKey", "in": where, "name": "key"}

        assert ptrs("API-OAS-005", m) == []

    def test_oauth_deprecated_flows_positive(self) -> None:
        def m(s: dict[str, Any]) -> None:
            schemes(s)["o"] = {
                "type": "oauth2",
                "flows": {"password": {"tokenUrl": "https://t", "scopes": {}}},
            }

        assert ptrs("API-OAS-006", m) == ["/components/securitySchemes/o/flows/password"]

    def test_oauth_negative_code_and_client_credentials(self) -> None:
        def m(s: dict[str, Any]) -> None:
            schemes(s)["o"] = {
                "type": "oauth2",
                "flows": {
                    "authorizationCode": {"authorizationUrl": "https://a", "tokenUrl": "https://t"},
                    "clientCredentials": {"tokenUrl": "https://t"},
                },
            }

        assert ptrs("API-OAS-006", m) == []


# --- API-OAS-007 --------------------------------------------------------------------------


class TestUndefinedScheme:
    def test_positive_root_and_operation(self) -> None:
        def m(s: dict[str, Any]) -> None:
            s["security"] = [{"bearerAuth": [], "ghost": []}]
            get_op(s)["security"] = [{"BearerAuth": []}]

        assert ptrs("API-OAS-007", m) == [
            "/security/0/ghost",
            "/paths/~1items/get/security/0/BearerAuth",
        ]

    def test_negative_all_defined_or_anonymous(self) -> None:
        def m(s: dict[str, Any]) -> None:
            s["security"] = [{}, {"bearerAuth": []}]

        assert ptrs("API-OAS-007", m) == []


# --- API-OAS-008 --------------------------------------------------------------------------


class TestNoRateLimitHints:
    def test_positive_no_429_no_headers(self) -> None:
        def m(s: dict[str, Any]) -> None:
            del get_op(s)["responses"]["429"]

        assert ptrs("API-OAS-008", m) == ["/paths"]

    def test_positive_4xx_wildcard_is_not_a_hint(self) -> None:
        def m(s: dict[str, Any]) -> None:
            del get_op(s)["responses"]["429"]
            get_op(s)["responses"]["4XX"] = {"description": "client error"}

        assert ptrs("API-OAS-008", m) == ["/paths"]

    @pytest.mark.parametrize("header", ["X-RateLimit-Limit", "RateLimit-Policy", "Retry-After"])
    def test_negative_rate_limit_headers(self, header: str) -> None:
        def m(s: dict[str, Any]) -> None:
            del get_op(s)["responses"]["429"]
            get_op(s)["responses"]["200"]["headers"] = {header: {"schema": {"type": "integer"}}}

        assert ptrs("API-OAS-008", m) == []

    def test_negative_429_via_ref(self) -> None:
        def m(s: dict[str, Any]) -> None:
            get_op(s)["responses"]["429"] = {"$ref": "#/components/responses/Slow"}
            s["components"]["responses"] = {"Slow": {"description": "slow"}}

        assert ptrs("API-OAS-008", m) == []


# --- API-OAS-009 --------------------------------------------------------------------------


def _set_schema(s: dict[str, Any], schema: dict[str, Any]) -> None:
    get_op(s)["responses"]["200"]["content"]["application/json"]["schema"] = schema


class TestDebugInfo:
    def test_positive_nested_in_allof_and_items(self) -> None:
        def m(s: dict[str, Any]) -> None:
            _set_schema(
                s,
                {
                    "allOf": [
                        {"properties": {"Stack_Trace": {"type": "string"}}},
                        {
                            "properties": {
                                "errors": {
                                    "type": "array",
                                    "items": {"properties": {"exception": {"type": "string"}}},
                                }
                            }
                        },
                    ]
                },
            )

        content = "/paths/~1items/get/responses/200/content/application~1json/schema"
        assert sorted(ptrs("API-OAS-009", m)) == sorted(
            [
                f"{content}/allOf/0/properties/Stack_Trace",
                f"{content}/allOf/1/properties/errors/items/properties/exception",
            ]
        )

    @pytest.mark.parametrize("name", ["traceId", "debugMode", "stackName", "message"])
    def test_negative_similar_names(self, name: str) -> None:
        def m(s: dict[str, Any]) -> None:
            _set_schema(s, {"properties": {name: {"type": "string"}}})

        assert ptrs("API-OAS-009", m) == []

    def test_negative_request_body_only(self) -> None:
        def m(s: dict[str, Any]) -> None:
            get_op(s)["requestBody"] = {
                "content": {"application/json": {"schema": {"properties": {"debug": {}}}}}
            }

        assert ptrs("API-OAS-009", m) == []

    def test_recursive_schema_terminates(self) -> None:
        def m(s: dict[str, Any]) -> None:
            s["components"]["schemas"] = {
                "N": {"properties": {"next": {"$ref": "#/components/schemas/N"}, "trace": {}}}
            }
            _set_schema(s, {"$ref": "#/components/schemas/N"})

        assert ptrs("API-OAS-009", m) == ["/components/schemas/N/properties/trace"]


# --- API-OAS-010 --------------------------------------------------------------------------


class TestCredentialsInUrl:
    @pytest.mark.parametrize("name", ["password", "access_token", "apiKey", "Session-Id", "TOKEN"])
    def test_positive_query(self, name: str) -> None:
        def m(s: dict[str, Any]) -> None:
            get_op(s)["parameters"].append({"name": name, "in": "query"})

        findings = run_rule("API-OAS-010", m)
        assert [f.evidence[0].location.pointer for f in findings] == [
            "/paths/~1items/get/parameters/1"
        ]
        assert "query string" in findings[0].title

    def test_positive_path(self) -> None:
        def m(s: dict[str, Any]) -> None:
            _ops(s)["/reset/{token}"] = {
                "parameters": [{"name": "token", "in": "path", "required": True}],
                "post": {"responses": {"204": {"description": "ok"}}},
            }

        findings = run_rule("API-OAS-010", m)
        assert len(findings) == 1 and "URL path" in findings[0].title

    @pytest.mark.parametrize(
        "param",
        [
            {"name": "Authorization", "in": "header"},
            {"name": "token", "in": "cookie"},
            {"name": "tokens_count", "in": "query"},
            {"name": "password_policy", "in": "query"},
        ],
    )
    def test_negative(self, param: dict[str, Any]) -> None:
        def m(s: dict[str, Any]) -> None:
            get_op(s)["parameters"].append(param)

        assert ptrs("API-OAS-010", m) == []


def test_clean_fixture_is_not_mutated_by_tests() -> None:
    assert CLEAN["paths"]["/items"]["get"]["responses"].keys() == {"200", "429"}
