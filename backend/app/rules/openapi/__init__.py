"""OpenAPI rules. Importing this package registers every rule (one module per rule)."""

from app.rules.openapi import (
    api_oas_001_http_server,
    api_oas_002_no_security_schemes,
    api_oas_003_unauthenticated_operation,
    api_oas_004_basic_auth,
    api_oas_005_api_key_in_query,
    api_oas_006_deprecated_oauth_flow,
    api_oas_007_undefined_security_scheme,
    api_oas_008_no_rate_limit_hints,
    api_oas_009_debug_info_in_responses,
    api_oas_010_credentials_in_query,
)

__all__ = [
    "api_oas_001_http_server",
    "api_oas_002_no_security_schemes",
    "api_oas_003_unauthenticated_operation",
    "api_oas_004_basic_auth",
    "api_oas_005_api_key_in_query",
    "api_oas_006_deprecated_oauth_flow",
    "api_oas_007_undefined_security_scheme",
    "api_oas_008_no_rate_limit_hints",
    "api_oas_009_debug_info_in_responses",
    "api_oas_010_credentials_in_query",
]
