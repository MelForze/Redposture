"""Workspace and app-state repositories."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.core import AppMetadata, AppState, Workspace
from .common import dialect_insert

_ACTIVE_WORKSPACE_KEY = "active_workspace_slug"


class WorkspaceRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(
        self, *, slug: str, display_name: str, client_name: str | None, environment_name: str | None
    ) -> Workspace:
        workspace = Workspace(
            slug=slug,
            display_name=display_name,
            client_name=client_name,
            environment_name=environment_name,
        )
        self.session.add(workspace)
        self.session.flush()
        return workspace

    def list(self) -> list[Workspace]:
        return list(
            self.session.scalars(select(Workspace).where(Workspace.deleted_at.is_(None)).order_by(Workspace.slug))
        )

    def get_by_slug(self, slug: str) -> Workspace | None:
        return self.session.scalar(select(Workspace).where(Workspace.slug == slug, Workspace.deleted_at.is_(None)))


class AppStateRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_active_workspace_slug(self) -> str | None:
        row = self.session.get(AppState, _ACTIVE_WORKSPACE_KEY)
        if row is None:
            return None
        return str(row.value or "").strip() or None

    def set_active_workspace_slug(self, slug: str) -> None:
        stmt = dialect_insert(self.session, AppState).values(key=_ACTIVE_WORKSPACE_KEY, value=slug)
        stmt = stmt.on_conflict_do_update(index_elements=[AppState.key], set_={"value": slug})
        self.session.execute(stmt)


class AppMetadataRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get(self, key: str) -> str | None:
        row = self.session.get(AppMetadata, key)
        if row is None:
            return None
        return str(row.value)

    def set(self, key: str, value: str) -> None:
        stmt = dialect_insert(self.session, AppMetadata).values(key=key, value=value)
        stmt = stmt.on_conflict_do_update(index_elements=[AppMetadata.key], set_={"value": value})
        self.session.execute(stmt)
