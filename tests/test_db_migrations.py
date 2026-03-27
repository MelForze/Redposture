from __future__ import annotations

from sqlalchemy import inspect

from redposture_core.db.repositories import AppMetadataRepository
from redposture_core.db.services import DatabaseService, MigrationService
from redposture_core.db.session import session_scope


def test_migration_service_upgrade_head_is_idempotent(db_url: str) -> None:
    migration = MigrationService(db_url)
    migration.upgrade_head()
    migration.upgrade_head()

    db = DatabaseService(db_url)
    try:
        with db.engine.connect() as connection:
            inspector = inspect(connection)
            table_names = set(inspector.get_table_names())
            assert {
                "workspaces",
                "module_runs",
                "run_observations",
                "findings",
                "grafana_datasources",
                "search_documents",
            } <= table_names
            assert "workspace_tags" not in table_names
            assert inspector.get_indexes("findings")
            assert any(
                index["name"] == "uq_protocol_service_workspace_null_endpoint"
                for index in inspector.get_indexes("protocol_services")
            )
    finally:
        db.close()


def test_database_init_bootstraps_schema_metadata(db_url: str) -> None:
    db = DatabaseService(db_url)
    try:
        db.init_database()

        with session_scope(db.session_factory) as session:
            assert AppMetadataRepository(session).get("schema_semver") == "1.0.0"
    finally:
        db.close()
