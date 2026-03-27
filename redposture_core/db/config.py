"""Database configuration helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_DB_URL = "sqlite:///./.redposture/redposture.db"
_DB_ENV = "REDPOSTURE_DB_URL"


@dataclass(frozen=True)
class DatabaseSettings:
    """Resolved database settings for DB commands."""

    db_url: str


def resolve_database_settings(*, db_url: str | None = None, workspace: str | None = None) -> DatabaseSettings:
    """Resolve DB configuration from CLI and environment."""
    resolved_db_url = str(db_url or os.getenv(_DB_ENV, _DEFAULT_DB_URL)).strip() or _DEFAULT_DB_URL
    return DatabaseSettings(db_url=resolved_db_url)


def ensure_sqlite_parent_dir(db_url: str) -> None:
    """Create parent directory for a sqlite path if needed."""
    path = sqlite_db_path(db_url)
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)


def sqlite_db_path(db_url: str) -> Path | None:
    """Resolve a file-backed sqlite path from a DB URL."""
    if not db_url.startswith("sqlite:///"):
        return None
    raw_path = db_url.removeprefix("sqlite:///")
    if raw_path == ":memory:" or not raw_path:
        return None
    path = Path(raw_path)
    if not path.is_absolute():
        path = Path.cwd() / path
    return path
