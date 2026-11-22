"""Session-token authentication for the local API (CLAUDE.md §11).

Electron generates a random token per session and passes it to both the backend (env)
and the renderer (preload). Every request must send it in ``X-Magen-Token``. This stops
other local processes and web pages (via DNS rebinding / CSRF) from driving the scanner.
"""

from __future__ import annotations

import hmac
from typing import Final

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.errors import error_response

TOKEN_HEADER: Final = "x-magen-token"  # noqa: S105 - header name, not a secret


class SessionTokenMiddleware:
    """Reject any HTTP request without the correct session token.

    CORS preflight (``OPTIONS``) is answered by the CORS middleware placed *outside* this
    one, so browsers can discover that the header is allowed.
    """

    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app = app
        self._token = token.encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        supplied = b""
        for name, value in scope.get("headers", []):
            if name == TOKEN_HEADER.encode():
                supplied = value
                break
        if not hmac.compare_digest(supplied, self._token):
            response = error_response(401, "unauthorized", "Missing or invalid session token")
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
