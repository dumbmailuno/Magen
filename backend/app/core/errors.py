"""Typed exceptions and the consistent API error shape ``{code, message, detail}``."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger(__name__)


class ErrorBody(BaseModel):
    """Error payload returned by every failing endpoint."""

    code: str
    message: str
    detail: Any | None = None


class MagenError(Exception):
    """Base class for all expected application errors."""

    code: str = "internal_error"
    status_code: int = 500

    def __init__(self, message: str, detail: Any | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


class NotFoundError(MagenError):
    """Requested resource does not exist."""

    code = "not_found"
    status_code = 404


class ValidationFailedError(MagenError):
    """Input was syntactically valid but semantically rejected."""

    code = "validation_failed"
    status_code = 422


class UnauthorizedError(MagenError):
    """Missing or wrong session token."""

    code = "unauthorized"
    status_code = 401


class TargetNotAllowedError(MagenError):
    """Runtime probe target is not on the confirmed allowlist (CLAUDE.md §7)."""

    code = "target_not_allowed"
    status_code = 403


def error_response(status_code: int, code: str, message: str, detail: Any = None) -> JSONResponse:
    """Build a JSON response in the standard error shape."""
    body = ErrorBody(code=code, message=message, detail=detail)
    return JSONResponse(status_code=status_code, content=body.model_dump())


def install_error_handlers(app: FastAPI) -> None:
    """Register handlers so every error leaves the API as :class:`ErrorBody`."""

    @app.exception_handler(MagenError)
    async def _magen(_: Request, exc: MagenError) -> JSONResponse:
        return error_response(exc.status_code, exc.code, exc.message, exc.detail)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return error_response(exc.status_code, code, str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Strip the raw input values: they may contain user secrets.
        detail = [{"loc": e.get("loc"), "msg": e.get("msg")} for e in exc.errors()]
        return error_response(422, "invalid_request", "Request validation failed", detail)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", extra={"error_type": type(exc).__name__})
        return error_response(500, "internal_error", "Internal server error")
