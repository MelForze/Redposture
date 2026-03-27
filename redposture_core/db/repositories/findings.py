"""Finding and search repositories."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..dto.query import FindingFilter
from ..models.core import Artifact, Finding, SearchDocument, Tag, finding_tags
from ..search.sqlite_fts import fts_search, fts_upsert_document
from ..util import parse_datetime, utcnow
from .common import dialect_insert


class FindingRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def upsert(self, **values: object) -> Finding:
        workspace_id = int(values["workspace_id"])
        fingerprint = str(values["fingerprint"])
        now = utcnow()
        stmt = dialect_insert(self.session, Finding).values(
            **values,
            first_seen_at=values.get("first_seen_at") or now,
            last_seen_at=values.get("last_seen_at") or now,
            created_at=now,
            updated_at=now,
            is_archived=False,
            archived_at=None,
            deleted_at=None,
        )
        update_values = {
            key: value
            for key, value in values.items()
            if key not in {"id", "workspace_id", "fingerprint", "first_seen_at", "created_at", "updated_at"}
        }
        update_values.update(
            {
                "last_seen_at": now,
                "updated_at": now,
                "is_archived": False,
                "archived_at": None,
                "deleted_at": None,
            }
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[Finding.workspace_id, Finding.fingerprint],
            set_=update_values,
        )
        self.session.execute(stmt)
        finding = self.session.scalar(
            select(Finding)
            .where(Finding.workspace_id == workspace_id, Finding.fingerprint == fingerprint)
            .execution_options(populate_existing=True)
        )
        if finding is None:
            raise RuntimeError("finding upsert failed")
        return finding

    def list(self, *, workspace_id: int, filters: FindingFilter | None = None) -> list[Finding]:
        stmt = (
            select(Finding)
            .options(
                selectinload(Finding.target_host),
                selectinload(Finding.endpoint),
                selectinload(Finding.protocol_service),
            )
            .where(Finding.workspace_id == workspace_id, Finding.deleted_at.is_(None))
        )
        if filters is not None:
            if filters.module_name:
                stmt = stmt.where(Finding.module_name == filters.module_name)
            if filters.protocol:
                stmt = stmt.where(Finding.protocol == filters.protocol)
            if filters.severity:
                stmt = stmt.where(Finding.severity == filters.severity)
            if filters.status:
                stmt = stmt.where(Finding.status == filters.status)
            if filters.tag:
                stmt = stmt.join(finding_tags, finding_tags.c.finding_id == Finding.id).join(
                    Tag, Tag.id == finding_tags.c.tag_id
                )
                stmt = stmt.where(Tag.name == filters.tag, Tag.workspace_id == workspace_id)
            if filters.date_from:
                date_from = parse_datetime(filters.date_from)
                if date_from is not None:
                    stmt = stmt.where(Finding.last_seen_at >= date_from)
            if filters.date_to:
                date_to = parse_datetime(filters.date_to)
                if date_to is not None:
                    stmt = stmt.where(Finding.last_seen_at <= date_to)
        return list(self.session.scalars(stmt.order_by(Finding.last_seen_at.desc())))


class SearchRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def upsert_document(
        self,
        *,
        workspace_id: int,
        entity_type: str,
        entity_id: str,
        title: str | None,
        body: str | None,
        tags_text: str | None,
    ) -> SearchDocument:
        now = utcnow()
        stmt = dialect_insert(self.session, SearchDocument).values(
            workspace_id=workspace_id,
            entity_type=entity_type,
            entity_id=entity_id,
            title=title,
            body=body,
            tags_text=tags_text,
            updated_at=now,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[SearchDocument.workspace_id, SearchDocument.entity_type, SearchDocument.entity_id],
            set_={"title": title, "body": body, "tags_text": tags_text, "updated_at": now},
        )
        self.session.execute(stmt)
        fts_upsert_document(
            self.session,
            workspace_id=workspace_id,
            entity_type=entity_type,
            entity_id=entity_id,
            title=title,
            body=body,
            tags_text=tags_text,
        )
        document = self.session.scalar(
            select(SearchDocument)
            .where(
                SearchDocument.workspace_id == workspace_id,
                SearchDocument.entity_type == entity_type,
                SearchDocument.entity_id == entity_id,
            )
            .execution_options(populate_existing=True)
        )
        if document is None:
            raise RuntimeError("search document upsert failed")
        return document

    def search(self, *, workspace_id: int, query: str) -> list[dict[str, str]]:
        rows = fts_search(self.session, workspace_id=workspace_id, query=query)
        return [row for row in rows if self._entity_is_live(workspace_id=workspace_id, row=row)]

    def _entity_is_live(self, *, workspace_id: int, row: dict[str, str]) -> bool:
        entity_type = str(row.get("entity_type") or "")
        entity_id = str(row.get("entity_id") or "")
        try:
            numeric_entity_id = int(entity_id)
        except ValueError:
            numeric_entity_id = -1
        if entity_type == "finding":
            return (
                self.session.scalar(
                    select(Finding.id).where(
                        Finding.workspace_id == workspace_id,
                        Finding.id == numeric_entity_id,
                        Finding.deleted_at.is_(None),
                    )
                )
                is not None
            )
        if entity_type == "artifact":
            return (
                self.session.scalar(
                    select(Artifact.id).where(
                        Artifact.workspace_id == workspace_id,
                        Artifact.id == numeric_entity_id,
                        Artifact.deleted_at.is_(None),
                    )
                )
                is not None
            )
        return (
            self.session.scalar(
                select(SearchDocument.id).where(
                    SearchDocument.workspace_id == workspace_id,
                    SearchDocument.entity_type == entity_type,
                    SearchDocument.entity_id == entity_id,
                )
            )
            is not None
        )
