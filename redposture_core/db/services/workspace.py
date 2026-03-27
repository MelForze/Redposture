"""Workspace service."""

from __future__ import annotations

from sqlalchemy.orm import sessionmaker

from ..dto.query import WorkspaceView
from ..repositories import AppStateRepository, WorkspaceRepository
from ..session import session_scope

DEFAULT_WORKSPACE_SLUG = "default"
DEFAULT_WORKSPACE_DISPLAY_NAME = "Default"


class WorkspaceService:
    def __init__(self, session_factory: sessionmaker) -> None:
        self.session_factory = session_factory

    def create(
        self, *, slug: str, display_name: str, client_name: str | None = None, environment_name: str | None = None
    ) -> WorkspaceView:
        with session_scope(self.session_factory) as session:
            repo = WorkspaceRepository(session)
            workspace = repo.create(
                slug=slug,
                display_name=display_name,
                client_name=client_name,
                environment_name=environment_name,
            )
            return WorkspaceView.model_validate(workspace)

    def list(self) -> list[WorkspaceView]:
        with session_scope(self.session_factory, read_only=True) as session:
            repo = WorkspaceRepository(session)
            return [WorkspaceView.model_validate(item) for item in repo.list()]

    def use(self, slug: str) -> WorkspaceView:
        with session_scope(self.session_factory) as session:
            repo = WorkspaceRepository(session)
            workspace = repo.get_by_slug(slug)
            if workspace is None:
                raise ValueError(f"workspace not found: {slug}")
            AppStateRepository(session).set_active_workspace_slug(slug)
            return WorkspaceView.model_validate(workspace)

    def ensure_default(self) -> WorkspaceView:
        with session_scope(self.session_factory) as session:
            repo = WorkspaceRepository(session)
            workspace = repo.get_by_slug(DEFAULT_WORKSPACE_SLUG)
            if workspace is None:
                workspace = repo.create(
                    slug=DEFAULT_WORKSPACE_SLUG,
                    display_name=DEFAULT_WORKSPACE_DISPLAY_NAME,
                    client_name=None,
                    environment_name=None,
                )
            AppStateRepository(session).set_active_workspace_slug(str(workspace.slug))
            return WorkspaceView.model_validate(workspace)

    def resolve_workspace_slug(self, explicit_slug: str | None = None) -> str:
        if explicit_slug:
            return explicit_slug
        with session_scope(self.session_factory, read_only=True) as session:
            repo = WorkspaceRepository(session)
            slug = AppStateRepository(session).get_active_workspace_slug()
            if slug and repo.get_by_slug(slug) is not None:
                return slug
            default_workspace = repo.get_by_slug(DEFAULT_WORKSPACE_SLUG)
            if default_workspace is not None:
                return str(default_workspace.slug)
            workspaces = repo.list()
            if len(workspaces) == 1:
                return str(workspaces[0].slug)
        if not self.list():
            return self.ensure_default().slug
        raise ValueError(
            "multiple workspaces exist; implicit workspace selection is disabled without an active or default workspace"
        )

    def resolve_workspace_id(self, slug: str | None = None) -> tuple[int, str]:
        resolved_slug = self.resolve_workspace_slug(slug)
        with session_scope(self.session_factory, read_only=True) as session:
            workspace = WorkspaceRepository(session).get_by_slug(resolved_slug)
            if workspace is None:
                raise ValueError(f"workspace not found: {resolved_slug}")
            return int(workspace.id), str(workspace.slug)
