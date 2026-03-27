from __future__ import annotations

from sqlalchemy import text

from redposture_core.db.repositories import FindingRepository, SearchRepository
from redposture_core.db.search.sqlite_fts import ensure_sqlite_fts
from redposture_core.db.session import session_scope


def test_ensure_sqlite_fts_creates_virtual_table(session_factory, workspace_id: int) -> None:
    with session_scope(session_factory) as session:
        ensure_sqlite_fts(session)
        names = {
            row[0] for row in session.execute(text("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"))
        }
        assert "search_documents_fts" in names


def test_search_repository_returns_workspace_scoped_results(session_factory, workspace_id: int) -> None:
    with session_scope(session_factory) as session:
        finding = FindingRepository(session).upsert(
            workspace_id=workspace_id,
            title="Grafana anonymous access",
            description="datasource leak",
            finding_type="anonymous_access",
            protocol="grafana",
            module_name="grafana",
            severity="high",
            confidence="high",
            status="open",
            dedup_key="grafana-search-1",
            fingerprint="grafana-search-1",
        )
        repo = SearchRepository(session)
        repo.upsert_document(
            workspace_id=workspace_id,
            entity_type="finding",
            entity_id=str(finding.id),
            title="Grafana anonymous access",
            body="datasource leak",
            tags_text="grafana high",
        )
        other_workspace_id = workspace_id + 1
        other_finding = FindingRepository(session).upsert(
            workspace_id=other_workspace_id,
            title="Other workspace",
            description="different",
            finding_type="inventory",
            protocol="grafana",
            module_name="grafana",
            severity="low",
            confidence="medium",
            status="open",
            dedup_key="other-search-1",
            fingerprint="other-search-1",
        )
        repo.upsert_document(
            workspace_id=other_workspace_id,
            entity_type="finding",
            entity_id=str(other_finding.id),
            title="Other workspace",
            body="different",
            tags_text="other",
        )
        rows = repo.search(workspace_id=workspace_id, query="Grafana")
        assert len(rows) == 1
        assert rows[0]["entity_id"] == "1"
