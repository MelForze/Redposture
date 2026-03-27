"""SQLite FTS5 support for search_documents."""

from __future__ import annotations

from sqlalchemy import String, cast, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from ..models.core import SearchDocument


def ensure_sqlite_fts(session: Session) -> None:
    bind = session.get_bind()
    if bind is None or bind.dialect.name != "sqlite":
        return
    session.execute(
        text(
            "CREATE VIRTUAL TABLE IF NOT EXISTS search_documents_fts USING fts5("
            "workspace_id UNINDEXED, entity_type UNINDEXED, entity_id UNINDEXED, title, body, tags_text)"
        )
    )


def fts_upsert_document(
    session: Session,
    *,
    workspace_id: int,
    entity_type: str,
    entity_id: str,
    title: str | None,
    body: str | None,
    tags_text: str | None,
) -> None:
    ensure_sqlite_fts(session)
    bind = session.get_bind()
    if bind is None or bind.dialect.name != "sqlite":
        return
    session.execute(
        text(
            "DELETE FROM search_documents_fts WHERE workspace_id = :workspace_id AND entity_type = :entity_type AND entity_id = :entity_id"
        ),
        {"workspace_id": str(workspace_id), "entity_type": entity_type, "entity_id": entity_id},
    )
    session.execute(
        text(
            "INSERT INTO search_documents_fts(workspace_id, entity_type, entity_id, title, body, tags_text) "
            "VALUES (:workspace_id, :entity_type, :entity_id, :title, :body, :tags_text)"
        ),
        {
            "workspace_id": str(workspace_id),
            "entity_type": entity_type,
            "entity_id": entity_id,
            "title": title or "",
            "body": body or "",
            "tags_text": tags_text or "",
        },
    )


def fts_search(session: Session, *, workspace_id: int, query: str, limit: int = 50) -> list[dict[str, str]]:
    ensure_sqlite_fts(session)
    bind = session.get_bind()
    if bind is None:
        return []
    if bind.dialect.name != "sqlite":
        return _like_search(session, workspace_id=workspace_id, query=query, limit=limit)
    try:
        rows = session.execute(
            text(
                "SELECT workspace_id, entity_type, entity_id, title, body, tags_text "
                "FROM search_documents_fts WHERE search_documents_fts MATCH :query AND workspace_id = :workspace_id LIMIT :limit"
            ),
            {"query": query, "workspace_id": str(workspace_id), "limit": int(limit)},
        ).mappings()
        return [dict(row) for row in rows]
    except OperationalError:
        return _like_search(session, workspace_id=workspace_id, query=query, limit=limit)


def _like_search(session: Session, *, workspace_id: int, query: str, limit: int) -> list[dict[str, str]]:
    like_query = f"%{query}%"
    rows = session.execute(
        select(
            cast(SearchDocument.workspace_id, String).label("workspace_id"),
            SearchDocument.entity_type,
            SearchDocument.entity_id,
            SearchDocument.title,
            SearchDocument.body,
            SearchDocument.tags_text,
        )
        .where(
            SearchDocument.workspace_id == workspace_id,
            (SearchDocument.title.ilike(like_query))
            | (SearchDocument.body.ilike(like_query))
            | (SearchDocument.tags_text.ilike(like_query)),
        )
        .limit(limit)
    ).mappings()
    return [dict(row) for row in rows]
