"""Shared repository helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session


def dialect_insert(session: Session, model: type[Any]) -> Any:
    """Return a dialect-aware insert construct for upsert flows."""
    bind = session.get_bind()
    if bind is None:
        raise RuntimeError("session is not bound to an engine")
    if bind.dialect.name == "sqlite":
        from sqlalchemy.dialects.sqlite import insert

        return insert(model.__table__)
    if bind.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert

        return insert(model.__table__)
    raise RuntimeError(f"unsupported upsert dialect: {bind.dialect.name}")
