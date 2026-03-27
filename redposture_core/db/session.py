"""SQLAlchemy engine/session helpers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool, StaticPool

from .config import ensure_sqlite_parent_dir


def build_engine(db_url: str) -> Engine:
    """Build SQLAlchemy engine for the configured backend."""
    ensure_sqlite_parent_dir(db_url)
    connect_args: dict[str, object] = {}
    engine_kwargs: dict[str, object] = {}
    if db_url.startswith("sqlite:///"):
        connect_args["check_same_thread"] = False
        if db_url.endswith(":memory:"):
            engine_kwargs["poolclass"] = StaticPool
        else:
            # File-backed sqlite is used by the DB subsystem at runtime. Avoid pooled
            # idle connections so short-lived CLI invocations do not leak sqlite handles.
            engine_kwargs["poolclass"] = NullPool
    return create_engine(db_url, future=True, connect_args=connect_args, **engine_kwargs)


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Build a session factory bound to the given engine."""
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)


@contextmanager
def session_scope(session_factory: sessionmaker[Session], *, read_only: bool = False) -> Iterator[Session]:
    """Provide transactional session scope."""
    session = session_factory()
    try:
        yield session
        if read_only:
            session.rollback()
        else:
            session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
