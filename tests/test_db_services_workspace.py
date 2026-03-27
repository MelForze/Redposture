from __future__ import annotations

import pytest

from redposture_core.db.services import WorkspaceService
from redposture_core.db.services.workspace import DEFAULT_WORKSPACE_SLUG


def test_workspace_service_create_list_and_use(session_factory) -> None:
    service = WorkspaceService(session_factory)

    created = service.create(slug="acme", display_name="Acme", client_name="Client", environment_name="Prod")
    assert created.slug == "acme"

    listed = service.list()
    assert [item.slug for item in listed] == ["acme"]

    active = service.use("acme")
    assert active.slug == "acme"
    assert service.resolve_workspace_slug() == "acme"
    assert service.resolve_workspace_id() == (created.id, "acme")


def test_workspace_service_auto_resolves_default_or_existing_workspace(session_factory) -> None:
    service = WorkspaceService(session_factory)

    default_workspace = service.ensure_default()
    assert default_workspace.slug == DEFAULT_WORKSPACE_SLUG
    assert service.resolve_workspace_slug() == DEFAULT_WORKSPACE_SLUG
    assert service.resolve_workspace_id()[1] == DEFAULT_WORKSPACE_SLUG

    with pytest.raises(ValueError, match="workspace not found"):
        service.use("missing")

    with pytest.raises(ValueError, match="workspace not found"):
        service.resolve_workspace_id("missing")


def test_workspace_service_rejects_ambiguous_implicit_resolution(session_factory) -> None:
    service = WorkspaceService(session_factory)

    service.create(slug="acme", display_name="Acme")
    service.create(slug="prod", display_name="Prod")

    with pytest.raises(ValueError, match="multiple workspaces exist"):
        service.resolve_workspace_slug()
