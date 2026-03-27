from __future__ import annotations

import contextlib
import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import func, select

from redposture_core.db.config import ensure_sqlite_parent_dir, resolve_database_settings
from redposture_core.db.models import AppMetadata, Workspace
from redposture_core.db.repositories import AppMetadataRepository
from redposture_core.db.services import DatabaseService, initialize_runtime_database
from redposture_core.db.services.database import _RUNTIME_INITIALIZED_DB_URLS
from redposture_core.db.session import build_engine, build_session_factory, session_scope


def test_resolve_database_settings_prefers_cli_over_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDPOSTURE_DB_URL", "sqlite:///env.db")

    settings = resolve_database_settings(db_url="sqlite:///cli.db", workspace="cli-workspace")

    assert settings.db_url == "sqlite:///cli.db"


def test_resolve_database_settings_falls_back_to_environment_and_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REDPOSTURE_DB_URL", raising=False)

    default_settings = resolve_database_settings()
    assert default_settings.db_url.endswith(".redposture/redposture.db")

    monkeypatch.setenv("REDPOSTURE_DB_URL", "sqlite:///env.db")
    env_settings = resolve_database_settings()

    assert env_settings.db_url == "sqlite:///env.db"


def test_ensure_sqlite_parent_dir_creates_relative_and_absolute_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    relative_url = "sqlite:///nested/relative.db"
    ensure_sqlite_parent_dir(relative_url)
    assert (tmp_path / "nested").is_dir()

    absolute_target = tmp_path / "deep" / "absolute.db"
    ensure_sqlite_parent_dir(f"sqlite:///{absolute_target}")
    assert absolute_target.parent.is_dir()


def test_ensure_sqlite_parent_dir_ignores_memory_and_non_sqlite(tmp_path: Path) -> None:
    ensure_sqlite_parent_dir("sqlite:///:memory:")
    ensure_sqlite_parent_dir("postgresql://example")
    assert not (tmp_path / "postgresql:").exists()


def test_build_engine_and_session_scope_rolls_back_on_exception(db_url: str) -> None:
    engine = build_engine(db_url)
    session_factory = build_session_factory(engine)
    db = DatabaseService(db_url)
    try:
        db.migrate()

        with pytest.raises(RuntimeError):
            with session_scope(session_factory) as session:
                session.add(Workspace(slug="rolled-back", display_name="Rolled Back"))
                raise RuntimeError("boom")

        with session_scope(session_factory) as session:
            count = session.scalar(select(func.count()).select_from(Workspace))
        assert count == 0
    finally:
        db.close()
        engine.dispose()


def test_database_service_init_database_sets_schema_semver_once(db_service: DatabaseService) -> None:
    with session_scope(db_service.session_factory) as session:
        repo = AppMetadataRepository(session)
        assert repo.get("schema_semver") == "1.0.0"

    db_service.init_database()
    with session_scope(db_service.session_factory) as session:
        assert session.scalar(select(func.count()).select_from(AppMetadata)) == 1
        repo = AppMetadataRepository(session)
        assert repo.get("schema_semver") == "1.0.0"


def test_database_service_health_returns_true(db_service: DatabaseService) -> None:
    assert db_service.health() is True


def test_database_service_export_import_validates_sqlite_paths(db_url: str, tmp_path: Path) -> None:
    db = DatabaseService(db_url)
    db.init_database()

    backup_path = tmp_path / "backup.sqlite3"
    exported = db.export_database(str(backup_path))
    assert exported == str(backup_path)
    assert backup_path.exists()

    imported_db_path = tmp_path / "imported.sqlite3"
    imported_db = DatabaseService(f"sqlite:///{imported_db_path}")
    try:
        imported = imported_db.import_database(str(backup_path))
        assert imported == str(imported_db_path)
        with contextlib.closing(sqlite3.connect(imported_db_path)) as conn:
            assert conn.execute("SELECT COUNT(*) FROM alembic_version").fetchone()[0] == 1
    finally:
        imported_db.close()

    with pytest.raises(ValueError, match="export target must be different"):
        db.export_database(str(Path(db_url.removeprefix("sqlite:///"))))

    memory_db = DatabaseService("sqlite:///:memory:")
    try:
        with pytest.raises(
            ValueError, match="whole-db import/export currently supports only file-backed sqlite databases"
        ):
            memory_db.export_database(str(tmp_path / "memory.sqlite3"))
    finally:
        memory_db.close()

    with pytest.raises(FileNotFoundError):
        db.import_database(str(tmp_path / "missing.sqlite3"))

    with pytest.raises(ValueError, match="import source must be different"):
        db.import_database(str(Path(db_url.removeprefix("sqlite:///"))))

    db.close()


def test_initialize_runtime_database_is_cached_per_process(monkeypatch: pytest.MonkeyPatch, db_url: str) -> None:
    _RUNTIME_INITIALIZED_DB_URLS.discard(db_url)
    calls: list[str] = []
    closes: list[str] = []

    original_init = DatabaseService.init_database
    original_close = DatabaseService.close

    def _wrapped_init(self: DatabaseService) -> None:
        calls.append(self.db_url)
        original_init(self)

    def _wrapped_close(self: DatabaseService) -> None:
        closes.append(self.db_url)
        original_close(self)

    monkeypatch.setattr(DatabaseService, "init_database", _wrapped_init)
    monkeypatch.setattr(DatabaseService, "close", _wrapped_close)

    initialize_runtime_database(db_url)
    initialize_runtime_database(db_url)

    assert calls == [db_url]
    assert closes == [db_url]
    _RUNTIME_INITIALIZED_DB_URLS.discard(db_url)
