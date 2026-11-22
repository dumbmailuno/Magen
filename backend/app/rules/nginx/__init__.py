"""Nginx rules. Importing this package registers every rule (one module per rule)."""

from app.rules.nginx import (
    ngx_cfg_001_autoindex,
    ngx_cfg_002_exposed_status,
    ngx_cfg_003_body_size,
    ngx_cors_001_permissive_cors,
    ngx_hdr_001_server_tokens,
    ngx_hdr_002_security_headers,
    ngx_rl_001_no_rate_limit,
    ngx_tls_001_weak_protocols,
    ngx_tls_002_weak_ciphers,
    ngx_tls_003_missing_hsts,
    ngx_tls_004_plaintext_http,
)

__all__ = [
    "ngx_cfg_001_autoindex",
    "ngx_cfg_002_exposed_status",
    "ngx_cfg_003_body_size",
    "ngx_cors_001_permissive_cors",
    "ngx_hdr_001_server_tokens",
    "ngx_hdr_002_security_headers",
    "ngx_rl_001_no_rate_limit",
    "ngx_tls_001_weak_protocols",
    "ngx_tls_002_weak_ciphers",
    "ngx_tls_003_missing_hsts",
    "ngx_tls_004_plaintext_http",
]
