# Rules catalogue

Every rule lives in `backend/app/rules/` (one file per rule), is pure, and has ≥1 positive
and ≥1 negative fixture. Rule IDs are **never reused**: deprecate, don't delete.

## ID scheme

`<AREA>-<SOURCE>-<NNN>`, matching `^[A-Z]{2,5}-[A-Z]{2,5}-\d{3}$`

| Prefix | Meaning |
|---|---|
| `API-OAS-` | OpenAPI static rules |
| `NGX-<topic>-` | Nginx static rules (e.g. `NGX-TLS-`, `NGX-HDR-`) |
| `API-RT-` | Runtime probe rules |

Each rule declares: `id`, `title`, `category`, `severity`, `description`, `target`,
`references` (OWASP API Top 10 2023 id **required**, CWE where applicable, doc links) and
`remediation_template`. The registry rejects rules missing any of these.

## Finding schema

See `docs/finding.schema.json` (generated from `backend/app/models/finding.py` by
`scripts/export_schema.py`; a test fails if it is stale).

## Rules

Static findings are `potential` by default: a spec or config states intent, and only runtime
correlation (week 9–10) can confirm what the deployed system does. Nginx findings that
depend on something being *absent* are `inconclusive` when part of the config is invisible:
the file is a snippet (no `http` block), or the context pulls in an `include` (other than
stock `mime.types` / `*_params` files), which Magen never follows.

| ID | Title | Severity | Target | OWASP | CWE | Status |
|---|---|---|---|---|---|---|
| API-OAS-001 | Server URL uses plain HTTP | high | openapi | API8:2023 | CWE-319 | active |
| API-OAS-002 | No security schemes are defined | medium | openapi | API2:2023 | CWE-306 | active |
| API-OAS-003 | Operation does not require authentication | medium | openapi | API2:2023 | CWE-306 | active |
| API-OAS-004 | HTTP Basic authentication is used | medium | openapi | API2:2023 | CWE-522 | active |
| API-OAS-005 | API key is sent in the query string | medium | openapi | API2:2023 | CWE-598 | active |
| API-OAS-006 | OAuth2 flow is deprecated | medium | openapi | API2:2023 | CWE-1390 | active |
| API-OAS-007 | Security requirement references an undefined scheme | medium | openapi | API8:2023 | — | active |
| API-OAS-008 | No rate limiting is documented | low | openapi | API4:2023 | CWE-770 | active |
| API-OAS-009 | Response schema exposes internal error details | low | openapi | API8:2023 | CWE-209 | active |
| API-OAS-010 | Credential is passed in the URL | medium | openapi | API2:2023 | CWE-598 | active |
| NGX-CFG-001 | Directory listing is enabled | medium | nginx | API8:2023 | CWE-548 | active |
| NGX-CFG-002 | Status or debug endpoint is publicly reachable | medium | nginx | API8:2023, API9:2023 | CWE-200 | active |
| NGX-CFG-003 | Request body size limit is unlimited or very large | low | nginx | API4:2023 | CWE-770 | active |
| NGX-CORS-001 | CORS allows any origin | medium | nginx | API8:2023 | CWE-942 | active |
| NGX-HDR-001 | Nginx version is disclosed | low | nginx | API8:2023 | CWE-200 | active |
| NGX-HDR-002 | Security headers are missing | low | nginx | API8:2023 | CWE-693 | active |
| NGX-RL-001 | No request rate limiting is configured | low | nginx | API4:2023 | CWE-770 | active |
| NGX-TLS-001 | Obsolete TLS protocol versions are enabled | high | nginx | API8:2023 | CWE-326 | active |
| NGX-TLS-002 | Weak cipher suites are enabled | high | nginx | API8:2023 | CWE-327 | active |
| NGX-TLS-003 | HSTS header is not sent | medium | nginx | API8:2023 | CWE-319 | active |
| NGX-TLS-004 | Server accepts plain HTTP without redirecting to HTTPS | medium | nginx | API8:2023 | CWE-319 | active |
| API-RT-001 | API responds over plain HTTP | medium | runtime | API8:2023 | CWE-319 | active |
| API-RT-002 | Server accepts obsolete TLS versions | high | runtime | API8:2023 | CWE-326 | active |
| API-RT-003 | TLS certificate is not trusted | high | runtime | API8:2023 | CWE-295 | active |
| API-RT-004 | HTTPS response does not send HSTS | medium | runtime | API8:2023 | CWE-319 | active |
| API-RT-005 | Response is missing security headers | low | runtime | API8:2023 | CWE-693 | active |
| API-RT-006 | Software version is disclosed | low | runtime | API8:2023 | CWE-200 | active |
| API-RT-007 | CORS allows any origin | medium | runtime | API8:2023 | CWE-942 | active |
| API-RT-008 | Error response exposes a stack trace | medium | runtime | API8:2023 | CWE-209 | active |
| API-RT-009 | Repository or environment file is publicly readable | high | runtime | API8:2023 | CWE-538 | active |
| API-RT-010 | Status or debug endpoint is publicly reachable | medium | runtime | API8:2023, API9:2023 | CWE-200 | active |
| API-RT-011 | TRACE method is advertised | low | runtime | API8:2023 | — | active |

`tests/test_rules_docs.py` fails if this table and the registry disagree.

### Rule details

**API-OAS-001 — Server URL uses plain HTTP.** Checks `servers` at root, path-item and
operation level. A templated scheme (`{scheme}://`) is flagged if its default or enum allows
`http`. *Not flagged:* loopback hosts (`localhost`, `127.0.0.1`, `::1`, `*.localhost`),
relative URLs. *Evidence:* `/servers/<i>/url`.

**API-OAS-002 — No security schemes are defined.** The spec has operations but
`components.securitySchemes` is missing or empty. One document-level finding.

**API-OAS-003 — Operation does not require authentication.** Effective security (operation's
own `security`, else root) is missing, `[]`, or contains `{}` (optional auth).
*Known false-positive source:* intentionally public endpoints (`/health`, `/login`) — they are
reported for human review by design. *Evidence:* the operation's `security`, or the operation.

**API-OAS-004 — HTTP Basic.** `type: http`, `scheme: basic` (case-insensitive).

**API-OAS-005 — API key in query.** `type: apiKey`, `in: query`.

**API-OAS-006 — Deprecated OAuth2 flow.** `implicit` or `password` flows (RFC 9700). One
finding per flow.

**API-OAS-007 — Undefined scheme.** A security requirement (root or operation) names a scheme
missing from `components.securitySchemes`. Names are case-sensitive.

**API-OAS-008 — No rate limiting documented.** No operation documents `429` or a
`RateLimit*` / `X-RateLimit*` / `Retry-After` response header. `4XX` does not count. A hint
only: a gateway may still enforce limits. One document-level finding at `/paths`.

**API-OAS-009 — Internal error details in responses.** A property reachable from a response
schema (via `$ref`, `allOf/oneOf/anyOf`, `items`, `additionalProperties`) is named exactly
(after lowercasing and removing `_ - .`) `stacktrace`, `stack`, `trace`, `backtrace`,
`exception`, `innerexception`, `exceptiontrace`, `debug`, `debuginfo`, `debugmessage`,
`sqlquery` or `sqlerror`. `traceId`, `debugMode` are not flagged. Request bodies and
unreferenced schemas are ignored. One finding per property location.

**API-OAS-010 — Credential in the URL.** A `query` or `path` parameter (path-item or
operation level, `$ref` resolved) named, after normalization, `password`, `passwd`, `pwd`,
`secret`, `clientsecret`, `token`, `accesstoken`, `refreshtoken`, `idtoken`, `authtoken`,
`apikey`, `sessionid` or `sessiontoken`. Header/cookie parameters are not flagged. A shared
`$ref` parameter is reported once, at its definition.

### Nginx rule details

Nginx semantics the rules model: single-value directives (`server_tokens`,
`client_max_body_size`...) inherit from the nearest enclosing context; **`add_header` is
all-or-nothing** — a level with any `add_header` inherits none from its parent, so header
rules evaluate the server *and every location that declares its own `add_header`*.

**NGX-HDR-001 — Version disclosed.** Effective `server_tokens` is not `off` (default `on`).
When left at default, reported once at the `http` block (one id however many servers).

**NGX-CFG-001 — `autoindex on`** anywhere.

**NGX-TLS-001 — Obsolete protocols.** `ssl_protocols` includes `SSLv2`, `SSLv3`, `TLSv1`,
`TLSv1.1`. Absent `ssl_protocols` is not reported (default varies by nginx version).

**NGX-TLS-002 — Weak ciphers.** An `ssl_ciphers` entry not excluded with `!`/`-` contains
`RC4`, `DES` (incl. 3DES), `MD5`, `NULL`, `EXPORT`/`EXP-`, `ADH`/`AECDH`, or is `ALL`.

**NGX-TLS-003 — No HSTS.** TLS server (`listen … ssl|quic` or `ssl on`) whose effective
headers lack `Strict-Transport-Security` with `max-age > 0`; locations that drop an
inherited HSTS header or set `max-age=0` are reported separately.

**NGX-TLS-004 — Plain HTTP without redirect.** A non-loopback, non-unix plain listener (no
`listen` = port 80) without a server-level or sole `location /` redirect to `https://`.

**NGX-HDR-002 — Security headers.** Missing `X-Content-Type-Options: nosniff` and/or
clickjacking protection (`X-Frame-Options` or CSP `frame-ancestors`). Redirect-only servers
are skipped; locations are reported only for headers they *drop*.

**NGX-CORS-001 — Permissive CORS.** `add_header Access-Control-Allow-Origin` with `*` or
`$http_origin`. Reflection inside `if ($http_origin ~ …)` or through a `map` variable is
treated as validated. Title notes `Access-Control-Allow-Credentials: true` alongside.

**NGX-CFG-002 — Exposed status/debug.** A location with `stub_status` / `status` /
`vhost_traffic_status_display` / `api`, or a path containing `nginx_status`,
`server-status`, `/actuator`, `/debug`, `phpinfo`, `/metrics`, `/.git`, `/.env`, `/.svn`,
with no `deny all`, `auth_basic`, `auth_request` or `internal` in its chain and no
`return 403|404|444`. A generic `/status` health path is not flagged.

**NGX-CFG-003 — Body size.** `client_max_body_size 0` or > 100 MiB.

**NGX-RL-001 — No rate limiting.** Servers exist but no `limit_req` anywhere
(`limit_req_zone` alone does nothing). One finding at the `http` block.

### Runtime rule details

Runtime rules are pure functions over recorded probe observations (`app/runtime/observations.py`);
the network lives only in `app/runtime/`. Directly observed issues are `confirmed`.
Evidence: `location.url` + `pointer: probe:<id>`; the hashed `excerpt` is the stable fact
(e.g. `Server: nginx/1.18.0`), full redacted request/response are attached but excluded
from the id.

**Probe plan** (fixed order, ≤ 13 requests): `base-get` (GET base URL with
`Origin: https://magen-cors-probe.invalid`), `base-options` (OPTIONS, preflight headers),
`not-found` (GET `/magen-probe-not-found-7f3a`), `plain-http` (GET `http://host/`, https
targets only, no credentials), six well-known paths (`/.git/HEAD`, `/.env` — body masked to
`KEY=••••` at capture —, `/nginx_status`, `/server-status`, `/actuator`, `/phpinfo.php`),
then TLS: one verifying handshake and one each limited to TLS 1.0 / 1.1.

| Rule | Fires when |
|---|---|
| `API-RT-001` | `plain-http` (or an `http://` base URL) returns content, not a redirect to `https://` |
| `API-RT-002` | a TLS 1.0/1.1-only handshake succeeds (client-side refusal = not tested, never "refused") |
| `API-RT-003` | the verifying handshake fails (expired, self-signed, untrusted, name mismatch) |
| `API-RT-004` | the HTTPS base response lacks HSTS with `max-age > 0` |
| `API-RT-005` | the base response lacks `nosniff` and/or `X-Frame-Options` / CSP `frame-ancestors` |
| `API-RT-006` | `Server` contains a version number, or `X-Powered-By` / `X-AspNet(Mvc)-Version` present |
| `API-RT-007` | `Access-Control-Allow-Origin` is `*` or echoes the probe origin (title notes credentials) |
| `API-RT-008` | a stack-trace / debug-page signature appears in the not-found or base body |
| `API-RT-009` | `/.git/HEAD` → 200 with git ref content, or `/.env` → 200 with ≥ 2 `KEY=` lines |
| `API-RT-010` | a status path → 200 **with** its content marker (`Active connections:`, `Server Status`, `"_links"`, `PHP Version`) — SPA fallbacks don't count |
| `API-RT-011` | the OPTIONS `Allow` header lists TRACE or TRACK (Magen never sends them) |

## Parser guarantees

`backend/app/static/openapi/loader.py`: `yaml.SafeLoader` only, non-standard tags rejected,
5 MB cap, nesting ≤ 64, ≤ 200 000 nodes (alias-bomb defence), mapping keys kept as raw text
(YAML 1.1 `on:`/`200:` are not coerced). Only local `#/` refs are resolved; external refs are
never fetched. Swagger 2.0 is rejected with a clear error.

`backend/app/static/nginx/parser.py`: own tokenizer/parser over the supplied text (no
filesystem access; `crossplane` was not used because it reads included files and globs).
5 MB cap, nesting ≤ 32, ≤ 500 000 tokens; syntax errors report the line. `include`
directives are returned as `unresolved_includes` and never followed.
