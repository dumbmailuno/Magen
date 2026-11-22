"""SQLite engine, sessions and migrations."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

_MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def make_engine(db_path: Path) -> Engine:
    """Create an engine for ``db_path`` with foreign keys enforced."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{db_path.as_posix()}", future=True)

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn: Any, _: Any) -> None:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    return engine


def alembic_config(engine: Engine) -> Config:
    """Programmatic Alembic config (no alembic.ini needed in packaged builds)."""
    cfg = Config()
    cfg.set_main_option("script_location", _MIGRATIONS_DIR.as_posix())
    # ConfigParser treats "%" as interpolation; Windows paths render as "C%3A/...".
    url = engine.url.render_as_string(hide_password=False).replace("%", "%%")
    cfg.set_main_option("sqlalchemy.url", url)
    cfg.attributes["engine"] = engine
    return cfg


def migrate(engine: Engine) -> None:
    """Upgrade the database schema to the latest revision."""
    command.upgrade(alembic_config(engine), "head")


class Database:
    """Owns the engine and hands out sessions."""

    def __init__(self, db_path: Path) -> None:
        self.engine = make_engine(db_path)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    def migrate(self) -> None:
        """Apply pending migrations."""
        migrate(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Transactional session: commits on success, rolls back on error."""
        with self._sessions() as s, s.begin():
            yield s

    def dispose(self) -> None:
        """Close all pooled connections (required on Windows before deleting the file)."""
        self.engine.dispose()
