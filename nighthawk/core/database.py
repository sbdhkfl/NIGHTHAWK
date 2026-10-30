"""SQLAlchemy engine, session and database initialization."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from nighthawk.core.config import get_settings
from nighthawk.core.models import Base

_engines: dict[str, Any] = {}
_SessionLocals: dict[str, sessionmaker] = {}


def get_engine():
    """Create the SQLAlchemy engine, cached per database URL.

    Caching per URL lets tests swap NIGHTHAWK_DATABASE_URL between runs and
    get a fresh database file each time.
    """
    settings = get_settings()
    db_url = settings.DATABASE_URL
    if db_url not in _engines:
        connect_args = {}
        if db_url.startswith("sqlite"):
            if "///" in db_url:
                db_path = db_url.split("///", 1)[1]
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            connect_args["check_same_thread"] = False
        _engines[db_url] = create_engine(db_url, connect_args=connect_args, pool_pre_ping=True)
    return _engines[db_url]


def get_session_factory(db_url: str | None = None) -> sessionmaker:
    """Return a sessionmaker bound to the engine for the configured URL."""
    url = db_url or get_settings().DATABASE_URL
    if url not in _SessionLocals:
        _SessionLocals[url] = sessionmaker(bind=get_engine(), autoflush=False, autocommit=False)
    return _SessionLocals[url]


def get_session() -> Session:
    """Open a new database session. Caller must close it."""
    return get_session_factory()()


def init_db() -> None:
    """Initialize tables and apply small backward-compatible schema fixes."""
    engine = get_engine()
    Base.metadata.create_all(engine)

    # Earlier versions accidentally mapped Finding.target as a relationship,
    # so existing SQLite databases may not have the target text column.
    # Add it in place and recover its value from the linked Target row.
    if engine.dialect.name == "sqlite":
        columns = {column["name"] for column in inspect(engine).get_columns("findings")}
        if "target" not in columns:
            with engine.begin() as connection:
                connection.execute(text("ALTER TABLE findings ADD COLUMN target VARCHAR(1000)"))
                connection.execute(
                    text(
                        """
                        UPDATE findings
                        SET target = (
                            SELECT targets.value
                            FROM targets
                            WHERE targets.id = findings.target_id
                        )
                        WHERE target IS NULL
                        """
                    )
                )
