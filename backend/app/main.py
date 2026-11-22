"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import __version__
from app.api import meta
from app.core.config import Settings, get_settings
from app.core.errors import install_error_handlers
from app.core.logging import configure_logging
from app.core.security import TOKEN_HEADER, SessionTokenMiddleware
from app.storage.database import Database


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the app. ``settings`` defaults to environment configuration."""
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    db = Database(settings.db_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        db.migrate()
        yield
        db.dispose()

    app = FastAPI(
        title="Magen",
        version=__version__,
        lifespan=lifespan,
        # No public docs UI: the API is a private channel to the Electron renderer.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.db = db

    install_error_handlers(app)
    app.include_router(meta.router)

    # Middleware order: the last added runs first (outermost).
    app.add_middleware(SessionTokenMiddleware, token=settings.session_token.get_secret_value())
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["content-type", TOKEN_HEADER],
        allow_credentials=False,
    )
    # Defeats DNS-rebinding: only loopback Host headers are accepted.
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"]
    )
    return app
