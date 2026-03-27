"""DB hardening for search/workspace/service constraints."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0002_db_hardening"
down_revision = "0001_redposture_db_init"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name in {"sqlite", "postgresql"}:
        op.execute(sa.text("DROP TABLE IF EXISTS workspace_tags"))
        op.execute(
            sa.text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_protocol_service_workspace_null_endpoint "
                "ON protocol_services (workspace_id, protocol, service_name) "
                "WHERE endpoint_id IS NULL"
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name in {"sqlite", "postgresql"}:
        op.execute(sa.text("DROP INDEX IF EXISTS uq_protocol_service_workspace_null_endpoint"))
        op.execute(
            sa.text(
                "CREATE TABLE IF NOT EXISTS workspace_tags ("
                "workspace_id INTEGER NOT NULL, "
                "tag_id INTEGER NOT NULL, "
                "PRIMARY KEY (workspace_id, tag_id), "
                "FOREIGN KEY(workspace_id) REFERENCES workspaces (id) ON DELETE CASCADE, "
                "FOREIGN KEY(tag_id) REFERENCES tags (id) ON DELETE CASCADE"
                ")"
            )
        )
