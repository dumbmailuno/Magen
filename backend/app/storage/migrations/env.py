"""Alembic environment. The engine is injected by ``app.storage.database.migrate``."""

from __future__ import annotations

from alembic import context
from sqlalchemy import Engine, create_engine

from app.models.db import Base

config = context.config
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit SQL without a DB connection."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run against the injected engine (or one built from the configured URL)."""
    engine = config.attributes.get("engine")
    if not isinstance(engine, Engine):
        engine = create_engine(config.get_main_option("sqlalchemy.url") or "")
    with engine.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata, render_as_batch=True
        )
        with context.begin_transaction():
            context.run_migrations()
        connection.commit()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
