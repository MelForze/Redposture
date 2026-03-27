from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.db.models import TargetHost
from redposture_core.db.repositories.common import dialect_insert
from redposture_core.db.repositories.findings import SearchRepository
from redposture_core.db.search.sqlite_fts import ensure_sqlite_fts, fts_search, fts_upsert_document
from redposture_core.db.security.crypto import ArtifactCipher, CipherResult, NoOpArtifactCipher
from redposture_core.db.session import session_scope
from redposture_core.db.types import ArtifactRole, EvidenceType, ExecutionStatus, ExportFormat, SourceType


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return self._rows


class _SessionStub:
    def __init__(self, dialect_name: str | None, rows=None) -> None:
        self._bind = None if dialect_name is None else SimpleNamespace(dialect=SimpleNamespace(name=dialect_name))
        self.rows = rows or []
        self.calls: list[tuple[object, object | None]] = []

    def get_bind(self):
        return self._bind

    def execute(self, stmt, params=None):
        self.calls.append((stmt, params))
        return _Result(self.rows)


def test_db_types_expose_expected_enum_values() -> None:
    assert SourceType.COLLECT.value == "collect"
    assert ExecutionStatus.SUCCESS.value == "success"
    assert ArtifactRole.RAW_PAYLOAD.value == "raw_payload"
    assert EvidenceType.OBSERVATION.value == "observation"
    assert ExportFormat.JSON.value == "json"


def test_artifact_cipher_contract_and_noop_roundtrip() -> None:
    cipher = ArtifactCipher()
    with pytest.raises(NotImplementedError):
        cipher.encrypt(b"payload")
    with pytest.raises(NotImplementedError):
        cipher.decrypt(b"payload")

    noop = NoOpArtifactCipher()
    encrypted = noop.encrypt(b"payload")
    assert encrypted == CipherResult(payload=b"payload", content_encoding=None)
    assert noop.decrypt(encrypted.payload) == b"payload"


def test_dialect_insert_supports_sqlite_and_rejects_other_bindings() -> None:
    sqlite_session = _SessionStub("sqlite")
    stmt = dialect_insert(sqlite_session, TargetHost)
    assert "INSERT" in str(stmt)

    postgres_session = _SessionStub("postgresql")
    stmt = dialect_insert(postgres_session, TargetHost)
    assert "INSERT" in str(stmt)

    with pytest.raises(RuntimeError, match="session is not bound"):
        dialect_insert(_SessionStub(None), TargetHost)

    with pytest.raises(RuntimeError, match="unsupported upsert dialect"):
        dialect_insert(_SessionStub("mysql"), TargetHost)


def test_sqlite_fts_helpers_are_safe_for_non_sqlite_and_use_fallback_search() -> None:
    session = _SessionStub("postgresql", rows=[{"entity_type": "finding", "entity_id": "1", "title": "Grafana"}])

    ensure_sqlite_fts(session)
    fts_upsert_document(
        session,
        workspace_id=1,
        entity_type="finding",
        entity_id="1",
        title="Grafana",
        body="datasource leak",
        tags_text="grafana high",
    )
    rows = fts_search(session, workspace_id=1, query="Grafana", limit=5)

    assert rows == [{"entity_type": "finding", "entity_id": "1", "title": "Grafana"}]
    assert len(session.calls) == 1


def test_sqlite_fts_helpers_ignore_unbound_session() -> None:
    session = _SessionStub(None)
    ensure_sqlite_fts(session)
    fts_upsert_document(
        session,
        workspace_id=1,
        entity_type="finding",
        entity_id="1",
        title="Grafana",
        body="datasource leak",
        tags_text="grafana high",
    )
    assert fts_search(session, workspace_id=1, query="Grafana") == []
    assert session.calls == []


def test_sqlite_fts_search_falls_back_to_like_for_literal_queries(db_service) -> None:
    with session_scope(db_service.session_factory) as session:
        SearchRepository(session).upsert_document(
            workspace_id=1,
            entity_type="finding",
            entity_id="1",
            title="Kafka exporter finding",
            body="sample=Kfka-M0nitor-2026",
            tags_text="exporters high",
        )
        rows = fts_search(session, workspace_id=1, query="Kfka-M0nitor-2026")

    assert len(rows) == 1
    assert rows[0]["entity_id"] == "1"
