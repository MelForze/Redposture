from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from pathlib import Path

import pytest

from redposture_core.db.services import DatabaseService, WorkspaceService

_FIXTURES_DB_DIR = Path(__file__).resolve().parent / "fixtures" / "db"


@pytest.fixture
def db_fixture_dir() -> Path:
    return _FIXTURES_DB_DIR


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'redposture.db'}"


@pytest.fixture
def db_service(db_url: str) -> DatabaseService:
    db = DatabaseService(db_url)
    db.init_database()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def session_factory(db_service: DatabaseService):
    return db_service.session_factory


@pytest.fixture
def workspace_service(session_factory) -> WorkspaceService:
    return WorkspaceService(session_factory)


@pytest.fixture
def workspace(workspace_service: WorkspaceService):
    return workspace_service.create(slug="acme", display_name="Acme")


@pytest.fixture
def workspace_id(workspace) -> int:
    return int(workspace.id)


@pytest.fixture
def write_json_payload(tmp_path: Path) -> Callable[[str, object], Path]:
    def _write(name: str, payload: object) -> Path:
        path = tmp_path / name
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    return _write


@pytest.fixture
def write_jsonl_payload(tmp_path: Path) -> Callable[[str, Iterable[object]], Path]:
    def _write(name: str, payloads: Iterable[object]) -> Path:
        path = tmp_path / name
        lines = [json.dumps(item, ensure_ascii=False) for item in payloads]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    return _write
