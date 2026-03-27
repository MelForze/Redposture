"""Database and migration services."""

from __future__ import annotations

import contextlib
import sqlite3
import threading
from pathlib import Path

from alembic.config import Config
from sqlalchemy import text

from alembic import command

from ..config import ensure_sqlite_parent_dir, sqlite_db_path
from ..repositories import AppMetadataRepository
from ..session import build_engine, build_session_factory, session_scope

_SCHEMA_SEMVER = "1.0.0"
_RUNTIME_INIT_LOCK = threading.Lock()
_RUNTIME_INITIALIZED_DB_URLS: set[str] = set()


class MigrationService:
    def __init__(self, db_url: str) -> None:
        self.db_url = db_url

    def _config(self) -> Config:
        base_dir = Path(__file__).resolve().parents[3]
        config = Config(str(base_dir / "alembic.ini"))
        config.set_main_option("sqlalchemy.url", self.db_url)
        config.set_main_option("script_location", str(base_dir / "alembic"))
        config.attributes["configure_logger"] = False
        return config

    def upgrade_head(self) -> None:
        ensure_sqlite_parent_dir(self.db_url)
        command.upgrade(self._config(), "head")


class DatabaseService:
    def __init__(self, db_url: str) -> None:
        self.db_url = db_url
        self.engine = build_engine(db_url)
        self.session_factory = build_session_factory(self.engine)

    def close(self) -> None:
        self.engine.dispose()

    def migrate(self) -> None:
        MigrationService(self.db_url).upgrade_head()

    def init_database(self) -> None:
        self.migrate()
        with session_scope(self.session_factory) as session:
            metadata_repo = AppMetadataRepository(session)
            if metadata_repo.get("schema_semver") is None:
                metadata_repo.set("schema_semver", _SCHEMA_SEMVER)

    def health(self) -> bool:
        with session_scope(self.session_factory, read_only=True) as session:
            session.execute(text("SELECT 1"))
        return True

    def export_database(self, output_path: str) -> str:
        source_path = self._sqlite_path_or_die()
        target_path = Path(output_path).expanduser()
        if not target_path.is_absolute():
            target_path = Path.cwd() / target_path
        if source_path == target_path:
            raise ValueError("export target must be different from the current DB path")
        if not source_path.exists():
            self.init_database()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        self.engine.dispose()
        with (
            contextlib.closing(sqlite3.connect(source_path)) as source_conn,
            contextlib.closing(sqlite3.connect(target_path)) as target_conn,
        ):
            source_conn.backup(target_conn)
        return str(target_path)

    def import_database(self, input_path: str) -> str:
        source_path = Path(input_path).expanduser()
        if not source_path.is_absolute():
            source_path = Path.cwd() / source_path
        if not source_path.exists():
            raise FileNotFoundError(str(source_path))
        target_path = self._sqlite_path_or_die()
        if source_path == target_path:
            raise ValueError("import source must be different from the current DB path")
        ensure_sqlite_parent_dir(self.db_url)
        self.engine.dispose()
        with (
            contextlib.closing(sqlite3.connect(source_path)) as source_conn,
            contextlib.closing(sqlite3.connect(target_path)) as target_conn,
        ):
            source_conn.backup(target_conn)
        self.init_database()
        return str(target_path)

    def _sqlite_path_or_die(self) -> Path:
        path = sqlite_db_path(self.db_url)
        if path is None:
            raise ValueError("whole-db import/export currently supports only file-backed sqlite databases")
        return path


def initialize_runtime_database(db_url: str) -> None:
    """Initialize/migrate a DB URL once per process."""
    with _RUNTIME_INIT_LOCK:
        if db_url in _RUNTIME_INITIALIZED_DB_URLS:
            return
        db = DatabaseService(db_url)
        try:
            db.init_database()
            _RUNTIME_INITIALIZED_DB_URLS.add(db_url)
        finally:
            db.close()
