"""Initial RedPosture DB schema."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0001_redposture_db_init"
down_revision = None
branch_labels = None
depends_on = None


_TABLE_APP_METADATA = [
    sa.Column("key", sa.String(length=128), primary_key=True, nullable=False),
    sa.Column("value", sa.Text(), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_APP_STATE = [
    sa.Column("key", sa.String(length=128), primary_key=True, nullable=False),
    sa.Column("value", sa.Text(), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_WORKSPACES = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("slug", sa.String(length=128), nullable=False, unique=True),
    sa.Column("display_name", sa.String(length=255), nullable=False),
    sa.Column("client_name", sa.String(length=255)),
    sa.Column("environment_name", sa.String(length=255)),
    sa.Column("description", sa.Text()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("is_archived", sa.Boolean(), nullable=False),
    sa.Column("archived_at", sa.DateTime(timezone=True)),
    sa.Column("deleted_at", sa.DateTime(timezone=True)),
]

_TABLE_EXPORT_JOBS = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column("export_kind", sa.String(length=64), nullable=False),
    sa.Column("output_format", sa.String(length=32), nullable=False),
    sa.Column("status", sa.String(length=32), nullable=False),
    sa.Column("output_path", sa.Text()),
    sa.Column("stats_json", sa.JSON()),
    sa.Column("error_text", sa.Text()),
    sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("finished_at", sa.DateTime(timezone=True)),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("is_archived", sa.Boolean(), nullable=False),
    sa.Column("archived_at", sa.DateTime(timezone=True)),
    sa.Column("deleted_at", sa.DateTime(timezone=True)),
]

_TABLE_IMPORT_JOBS = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column("module_name", sa.String(length=64), nullable=False),
    sa.Column("source_format", sa.String(length=32), nullable=False),
    sa.Column("status", sa.String(length=32), nullable=False),
    sa.Column("input_path", sa.Text()),
    sa.Column("stats_json", sa.JSON()),
    sa.Column("error_text", sa.Text()),
    sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("finished_at", sa.DateTime(timezone=True)),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("is_archived", sa.Boolean(), nullable=False),
    sa.Column("archived_at", sa.DateTime(timezone=True)),
    sa.Column("deleted_at", sa.DateTime(timezone=True)),
]

_TABLE_SEARCH_DOCUMENTS = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column("entity_type", sa.String(length=64), nullable=False),
    sa.Column("entity_id", sa.String(length=64), nullable=False),
    sa.Column("title", sa.Text()),
    sa.Column("body", sa.Text()),
    sa.Column("tags_text", sa.Text()),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("workspace_id", "entity_type", "entity_id", name="uq_search_documents_entity"),
]

_TABLE_SECRET_REFS = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column("secret_kind", sa.String(length=128), nullable=False),
    sa.Column("redacted_value", sa.Text(), nullable=False),
    sa.Column("fingerprint", sa.String(length=128), nullable=False),
    sa.Column("source_hint", sa.Text()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("workspace_id", "fingerprint", name="uq_secret_refs_workspace_fingerprint"),
]

_TABLE_TAGS = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column("name", sa.String(length=128), nullable=False),
    sa.Column("color", sa.String(length=32)),
    sa.Column("description", sa.Text()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("workspace_id", "name", name="uq_tags_workspace_name"),
]

_TABLE_WORKSPACE_TAGS = [
    sa.Column(
        "workspace_id",
        sa.Integer(),
        sa.ForeignKey("workspaces.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    ),
    sa.Column(
        "tag_id",
        sa.Integer(),
        sa.ForeignKey("tags.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    ),
]

_TABLE_TARGET_HOSTS = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column("canonical_key", sa.String(length=512), nullable=False),
    sa.Column("hostname", sa.String(length=255)),
    sa.Column("fqdn", sa.String(length=255)),
    sa.Column("ip_address", sa.String(length=64)),
    sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("is_archived", sa.Boolean(), nullable=False),
    sa.Column("archived_at", sa.DateTime(timezone=True)),
    sa.Column("deleted_at", sa.DateTime(timezone=True)),
    sa.UniqueConstraint("workspace_id", "canonical_key", name="uq_target_host_workspace_canonical"),
]

_TABLE_HOST_TAGS = [
    sa.Column(
        "host_id", sa.Integer(), sa.ForeignKey("target_hosts.id", ondelete="CASCADE"), primary_key=True, nullable=False
    ),
    sa.Column("tag_id", sa.Integer(), sa.ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True, nullable=False),
]

_TABLE_MODULE_RUNS = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column("import_job_id", sa.Integer(), sa.ForeignKey("import_jobs.id", ondelete="SET NULL")),
    sa.Column("module_name", sa.String(length=64), nullable=False),
    sa.Column("protocol", sa.String(length=64), nullable=False),
    sa.Column("source_type", sa.String(length=32), nullable=False),
    sa.Column("target_scope", sa.Text()),
    sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("finished_at", sa.DateTime(timezone=True)),
    sa.Column("execution_status", sa.String(length=32), nullable=False),
    sa.Column("tool_version", sa.String(length=64)),
    sa.Column("commandline_args_snapshot_json", sa.JSON()),
    sa.Column("runner_hostname", sa.String(length=255)),
    sa.Column("operator_name", sa.String(length=255)),
    sa.Column("dedup_key", sa.String(length=128)),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("is_archived", sa.Boolean(), nullable=False),
    sa.Column("archived_at", sa.DateTime(timezone=True)),
    sa.Column("deleted_at", sa.DateTime(timezone=True)),
]

_TABLE_NETWORK_ENDPOINTS = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column("target_host_id", sa.Integer(), sa.ForeignKey("target_hosts.id", ondelete="SET NULL")),
    sa.Column("canonical_key", sa.String(length=1024), nullable=False),
    sa.Column("scheme", sa.String(length=32)),
    sa.Column("host", sa.String(length=255)),
    sa.Column("ip", sa.String(length=64)),
    sa.Column("port", sa.Integer()),
    sa.Column("path", sa.String(length=1024)),
    sa.Column("netloc", sa.String(length=512)),
    sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("is_archived", sa.Boolean(), nullable=False),
    sa.Column("archived_at", sa.DateTime(timezone=True)),
    sa.Column("deleted_at", sa.DateTime(timezone=True)),
    sa.UniqueConstraint("workspace_id", "canonical_key", name="uq_endpoint_workspace_canonical"),
]

_TABLE_ENDPOINT_TAGS = [
    sa.Column(
        "endpoint_id",
        sa.Integer(),
        sa.ForeignKey("network_endpoints.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    ),
    sa.Column("tag_id", sa.Integer(), sa.ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True, nullable=False),
]

_TABLE_PROTOCOL_SERVICES = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("network_endpoints.id", ondelete="SET NULL")),
    sa.Column("protocol", sa.String(length=64), nullable=False),
    sa.Column("service_name", sa.String(length=128), nullable=False),
    sa.Column("auth_required", sa.Boolean()),
    sa.Column("status", sa.String(length=64)),
    sa.Column("version", sa.String(length=128)),
    sa.Column("extra_summary_json", sa.JSON()),
    sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("is_archived", sa.Boolean(), nullable=False),
    sa.Column("archived_at", sa.DateTime(timezone=True)),
    sa.Column("deleted_at", sa.DateTime(timezone=True)),
    sa.UniqueConstraint(
        "workspace_id", "protocol", "endpoint_id", "service_name", name="uq_protocol_service_workspace_endpoint"
    ),
]

_TABLE_RUN_TAGS = [
    sa.Column(
        "module_run_id",
        sa.Integer(),
        sa.ForeignKey("module_runs.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    ),
    sa.Column("tag_id", sa.Integer(), sa.ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True, nullable=False),
]

_TABLE_RUN_OBSERVATIONS = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column("module_run_id", sa.Integer(), sa.ForeignKey("module_runs.id", ondelete="CASCADE"), nullable=False),
    sa.Column("target_host_id", sa.Integer(), sa.ForeignKey("target_hosts.id", ondelete="SET NULL")),
    sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("network_endpoints.id", ondelete="SET NULL")),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("target_text", sa.Text()),
    sa.Column("module_name", sa.String(length=64), nullable=False),
    sa.Column("protocol", sa.String(length=64), nullable=False),
    sa.Column("normalized_status", sa.String(length=64), nullable=False),
    sa.Column("severity", sa.String(length=32)),
    sa.Column("confidence", sa.String(length=32)),
    sa.Column("fingerprint", sa.String(length=128), nullable=False),
    sa.Column("source_type", sa.String(length=32), nullable=False),
    sa.Column("raw_json_result_sanitized", sa.JSON()),
    sa.Column("normalized_result_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("is_archived", sa.Boolean(), nullable=False),
    sa.Column("archived_at", sa.DateTime(timezone=True)),
    sa.Column("deleted_at", sa.DateTime(timezone=True)),
    sa.UniqueConstraint("workspace_id", "fingerprint", name="uq_run_observations_workspace_fingerprint"),
]

_TABLE_CLICKHOUSE_DATABASES = [
    sa.Column("database_name", sa.String(length=255), nullable=False),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_CLICKHOUSE_TABLES = [
    sa.Column("database_name", sa.String(length=255)),
    sa.Column("table_name", sa.String(length=255), nullable=False),
    sa.Column("columns_json", sa.JSON()),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_CONSUL_KV_ENTRIES = [
    sa.Column("key_path", sa.Text(), nullable=False),
    sa.Column("value_redacted", sa.Text()),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_CONSUL_SERVICES = [
    sa.Column("service_name", sa.String(length=255), nullable=False),
    sa.Column("service_id", sa.String(length=255)),
    sa.Column("node_name", sa.String(length=255)),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_ETCD_KEYS_METADATA = [
    sa.Column("key_path", sa.Text(), nullable=False),
    sa.Column("value_redacted", sa.Text()),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_EXPORTER_EVENTS = [
    sa.Column("exporter_name", sa.String(length=128), nullable=False),
    sa.Column("event_kind", sa.String(length=128), nullable=False),
    sa.Column("message", sa.Text()),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_EXPORTER_TARGETS = [
    sa.Column("exporter_name", sa.String(length=128), nullable=False),
    sa.Column("target", sa.Text(), nullable=False),
    sa.Column("status", sa.String(length=64)),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_FINDINGS = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column("module_run_id", sa.Integer(), sa.ForeignKey("module_runs.id", ondelete="SET NULL")),
    sa.Column("run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="SET NULL")),
    sa.Column("target_host_id", sa.Integer(), sa.ForeignKey("target_hosts.id", ondelete="SET NULL")),
    sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("network_endpoints.id", ondelete="SET NULL")),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("title", sa.String(length=255), nullable=False),
    sa.Column("description", sa.Text()),
    sa.Column("finding_type", sa.String(length=128), nullable=False),
    sa.Column("protocol", sa.String(length=64), nullable=False),
    sa.Column("module_name", sa.String(length=64), nullable=False),
    sa.Column("severity", sa.String(length=32)),
    sa.Column("confidence", sa.String(length=32)),
    sa.Column("status", sa.String(length=64), nullable=False),
    sa.Column("dedup_key", sa.String(length=128)),
    sa.Column("fingerprint", sa.String(length=128), nullable=False),
    sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("is_archived", sa.Boolean(), nullable=False),
    sa.Column("archived_at", sa.DateTime(timezone=True)),
    sa.Column("deleted_at", sa.DateTime(timezone=True)),
    sa.UniqueConstraint("workspace_id", "fingerprint", name="uq_findings_workspace_fingerprint"),
]

_TABLE_GITLAB_PROJECTS = [
    sa.Column("project_path", sa.String(length=255), nullable=False),
    sa.Column("visibility", sa.String(length=64)),
    sa.Column("web_url", sa.Text()),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_GITLAB_TOKENS_POLICY = [
    sa.Column("policy_name", sa.String(length=255), nullable=False),
    sa.Column("value_text", sa.Text()),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_GRAFANA_DASHBOARDS = [
    sa.Column("uid", sa.String(length=128)),
    sa.Column("title", sa.String(length=255), nullable=False),
    sa.Column("dashboard_url", sa.Text()),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_GRAFANA_DATASOURCES = [
    sa.Column("name", sa.String(length=255), nullable=False),
    sa.Column("datasource_type", sa.String(length=128)),
    sa.Column("url", sa.Text()),
    sa.Column("access_mode", sa.String(length=64)),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_KAFKA_TOPICS = [
    sa.Column("topic_name", sa.String(length=255), nullable=False),
    sa.Column("partitions", sa.Integer()),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_KUBE_RESOURCES = [
    sa.Column("kind", sa.String(length=64), nullable=False),
    sa.Column("namespace", sa.String(length=255)),
    sa.Column("name", sa.String(length=255), nullable=False),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_POSTGRES_DATABASES = [
    sa.Column("database_name", sa.String(length=255), nullable=False),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_POSTGRES_TABLES = [
    sa.Column("database_name", sa.String(length=255)),
    sa.Column("schema_name", sa.String(length=255)),
    sa.Column("table_name", sa.String(length=255), nullable=False),
    sa.Column("columns_json", sa.JSON()),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_PROXMOX_NODES = [
    sa.Column("node_name", sa.String(length=255), nullable=False),
    sa.Column("status", sa.String(length=64)),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_PROXMOX_OBJECTS = [
    sa.Column("object_type", sa.String(length=64), nullable=False),
    sa.Column("object_id", sa.String(length=255), nullable=False),
    sa.Column("title", sa.String(length=255)),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_PROXMOX_USERS = [
    sa.Column("user_id", sa.String(length=255), nullable=False),
    sa.Column("enabled", sa.String(length=32)),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_QDRANT_COLLECTIONS = [
    sa.Column("collection_name", sa.String(length=255), nullable=False),
    sa.Column("vectors_count", sa.Integer()),
    sa.Column("status", sa.String(length=64)),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_REDIS_CONFIG_ENTRIES = [
    sa.Column("config_key", sa.String(length=255), nullable=False),
    sa.Column("value_redacted", sa.Text()),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_REGISTRY_MANIFESTS = [
    sa.Column("repository_name", sa.String(length=255), nullable=False),
    sa.Column("tag", sa.String(length=255)),
    sa.Column("digest", sa.String(length=255)),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_REGISTRY_REPOSITORIES = [
    sa.Column("name", sa.String(length=255), nullable=False),
    sa.Column("anonymous_access", sa.Boolean()),
    sa.Column("tag_count", sa.Integer()),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("workspace_id", "run_observation_id", "name", name="uq_registry_repo_name"),
]

_TABLE_ZOOKEEPER_ZNODES = [
    sa.Column("znode_path", sa.Text(), nullable=False),
    sa.Column("value_redacted", sa.Text()),
    sa.Column("children_count", sa.Integer()),
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column(
        "run_observation_id", sa.Integer(), sa.ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    ),
    sa.Column("protocol_service_id", sa.Integer(), sa.ForeignKey("protocol_services.id", ondelete="SET NULL")),
    sa.Column("details_json", sa.JSON()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
]

_TABLE_ARTIFACTS = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column("module_run_id", sa.Integer(), sa.ForeignKey("module_runs.id", ondelete="SET NULL")),
    sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="SET NULL")),
    sa.Column("artifact_role", sa.String(length=64), nullable=False),
    sa.Column("mime_type", sa.String(length=128)),
    sa.Column("content_encoding", sa.String(length=64)),
    sa.Column("sha256", sa.String(length=128), nullable=False),
    sa.Column("size_bytes", sa.BigInteger(), nullable=False),
    sa.Column("sanitized_preview_text", sa.Text()),
    sa.Column("content_blob", sa.LargeBinary(), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True)),
    sa.Column("purge_after", sa.DateTime(timezone=True)),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("is_archived", sa.Boolean(), nullable=False),
    sa.Column("archived_at", sa.DateTime(timezone=True)),
    sa.Column("deleted_at", sa.DateTime(timezone=True)),
]

_TABLE_FINDING_TAGS = [
    sa.Column(
        "finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True, nullable=False
    ),
    sa.Column("tag_id", sa.Integer(), sa.ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True, nullable=False),
]

_TABLE_EVIDENCE = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column("module_run_id", sa.Integer(), sa.ForeignKey("module_runs.id", ondelete="CASCADE"), nullable=False),
    sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="SET NULL")),
    sa.Column("artifact_id", sa.Integer(), sa.ForeignKey("artifacts.id", ondelete="SET NULL")),
    sa.Column("evidence_type", sa.String(length=64), nullable=False),
    sa.Column("title", sa.String(length=255), nullable=False),
    sa.Column("description", sa.Text()),
    sa.Column("preview_text", sa.Text()),
    sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("retention_class", sa.String(length=64)),
    sa.Column("expires_at", sa.DateTime(timezone=True)),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("is_archived", sa.Boolean(), nullable=False),
    sa.Column("archived_at", sa.DateTime(timezone=True)),
    sa.Column("deleted_at", sa.DateTime(timezone=True)),
]

_TABLE_NOTES = [
    sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
    sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
    sa.Column("target_host_id", sa.Integer(), sa.ForeignKey("target_hosts.id", ondelete="CASCADE")),
    sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("network_endpoints.id", ondelete="CASCADE")),
    sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="CASCADE")),
    sa.Column("module_run_id", sa.Integer(), sa.ForeignKey("module_runs.id", ondelete="CASCADE")),
    sa.Column("artifact_id", sa.Integer(), sa.ForeignKey("artifacts.id", ondelete="CASCADE")),
    sa.Column("title", sa.String(length=255)),
    sa.Column("body", sa.Text(), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("is_archived", sa.Boolean(), nullable=False),
    sa.Column("archived_at", sa.DateTime(timezone=True)),
    sa.Column("deleted_at", sa.DateTime(timezone=True)),
    sa.CheckConstraint(
        "CASE WHEN target_host_id IS NOT NULL THEN 1 ELSE 0 END + CASE WHEN endpoint_id IS NOT NULL THEN 1 ELSE 0 END + CASE WHEN finding_id IS NOT NULL THEN 1 ELSE 0 END + CASE WHEN module_run_id IS NOT NULL THEN 1 ELSE 0 END + CASE WHEN artifact_id IS NOT NULL THEN 1 ELSE 0 END = 1",
        name="ck_notes_single_parent",
    ),
]


def upgrade() -> None:
    op.create_table("app_metadata", *_TABLE_APP_METADATA)
    op.create_table("app_state", *_TABLE_APP_STATE)
    op.create_table("workspaces", *_TABLE_WORKSPACES)
    op.create_table("export_jobs", *_TABLE_EXPORT_JOBS)
    op.create_table("import_jobs", *_TABLE_IMPORT_JOBS)
    op.create_table("search_documents", *_TABLE_SEARCH_DOCUMENTS)
    op.create_table("secret_refs", *_TABLE_SECRET_REFS)
    op.create_table("tags", *_TABLE_TAGS)
    op.create_table("workspace_tags", *_TABLE_WORKSPACE_TAGS)
    op.create_table("target_hosts", *_TABLE_TARGET_HOSTS)
    op.create_table("host_tags", *_TABLE_HOST_TAGS)
    op.create_table("module_runs", *_TABLE_MODULE_RUNS)
    op.create_table("network_endpoints", *_TABLE_NETWORK_ENDPOINTS)
    op.create_table("endpoint_tags", *_TABLE_ENDPOINT_TAGS)
    op.create_table("protocol_services", *_TABLE_PROTOCOL_SERVICES)
    op.create_table("run_tags", *_TABLE_RUN_TAGS)
    op.create_table("run_observations", *_TABLE_RUN_OBSERVATIONS)
    op.create_table("clickhouse_databases", *_TABLE_CLICKHOUSE_DATABASES)
    op.create_table("clickhouse_tables", *_TABLE_CLICKHOUSE_TABLES)
    op.create_table("consul_kv_entries", *_TABLE_CONSUL_KV_ENTRIES)
    op.create_table("consul_services", *_TABLE_CONSUL_SERVICES)
    op.create_table("etcd_keys_metadata", *_TABLE_ETCD_KEYS_METADATA)
    op.create_table("exporter_events", *_TABLE_EXPORTER_EVENTS)
    op.create_table("exporter_targets", *_TABLE_EXPORTER_TARGETS)
    op.create_table("findings", *_TABLE_FINDINGS)
    op.create_table("gitlab_projects", *_TABLE_GITLAB_PROJECTS)
    op.create_table("gitlab_tokens_policy", *_TABLE_GITLAB_TOKENS_POLICY)
    op.create_table("grafana_dashboards", *_TABLE_GRAFANA_DASHBOARDS)
    op.create_table("grafana_datasources", *_TABLE_GRAFANA_DATASOURCES)
    op.create_table("kafka_topics", *_TABLE_KAFKA_TOPICS)
    op.create_table("kube_resources", *_TABLE_KUBE_RESOURCES)
    op.create_table("postgres_databases", *_TABLE_POSTGRES_DATABASES)
    op.create_table("postgres_tables", *_TABLE_POSTGRES_TABLES)
    op.create_table("proxmox_nodes", *_TABLE_PROXMOX_NODES)
    op.create_table("proxmox_objects", *_TABLE_PROXMOX_OBJECTS)
    op.create_table("proxmox_users", *_TABLE_PROXMOX_USERS)
    op.create_table("qdrant_collections", *_TABLE_QDRANT_COLLECTIONS)
    op.create_table("redis_config_entries", *_TABLE_REDIS_CONFIG_ENTRIES)
    op.create_table("registry_manifests", *_TABLE_REGISTRY_MANIFESTS)
    op.create_table("registry_repositories", *_TABLE_REGISTRY_REPOSITORIES)
    op.create_table("zookeeper_znodes", *_TABLE_ZOOKEEPER_ZNODES)
    op.create_table("artifacts", *_TABLE_ARTIFACTS)
    op.create_table("finding_tags", *_TABLE_FINDING_TAGS)
    op.create_table("evidence", *_TABLE_EVIDENCE)
    op.create_table("notes", *_TABLE_NOTES)
    op.create_index("ix_export_jobs_workspace_status", "export_jobs", ["workspace_id", "status"], unique=False)
    op.create_index("ix_import_jobs_workspace_status", "import_jobs", ["workspace_id", "status"], unique=False)
    op.create_index(
        "ix_search_documents_workspace_entity", "search_documents", ["workspace_id", "entity_type"], unique=False
    )
    op.create_index(
        "ix_target_hosts_workspace_last_seen", "target_hosts", ["workspace_id", "last_seen_at"], unique=False
    )
    op.create_index("ix_module_runs_workspace_module", "module_runs", ["workspace_id", "module_name"], unique=False)
    op.create_index("ix_module_runs_workspace_protocol", "module_runs", ["workspace_id", "protocol"], unique=False)
    op.create_index(
        "ix_module_runs_workspace_status", "module_runs", ["workspace_id", "execution_status"], unique=False
    )
    op.create_index("ix_network_endpoints_workspace_port", "network_endpoints", ["workspace_id", "port"], unique=False)
    op.create_index(
        "ix_protocol_services_workspace_protocol", "protocol_services", ["workspace_id", "protocol"], unique=False
    )
    op.create_index(
        "ix_run_observations_workspace_module", "run_observations", ["workspace_id", "module_name"], unique=False
    )
    op.create_index(
        "ix_run_observations_workspace_protocol", "run_observations", ["workspace_id", "protocol"], unique=False
    )
    op.create_index("ix_findings_workspace_last_seen", "findings", ["workspace_id", "last_seen_at"], unique=False)
    op.create_index("ix_findings_workspace_module", "findings", ["workspace_id", "module_name"], unique=False)
    op.create_index("ix_findings_workspace_protocol", "findings", ["workspace_id", "protocol"], unique=False)
    op.create_index("ix_findings_workspace_severity", "findings", ["workspace_id", "severity"], unique=False)
    op.create_index("ix_findings_workspace_status", "findings", ["workspace_id", "status"], unique=False)
    op.create_index("ix_artifacts_workspace_role", "artifacts", ["workspace_id", "artifact_role"], unique=False)
    op.create_index("ix_evidence_workspace_collected", "evidence", ["workspace_id", "collected_at"], unique=False)
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute(
            sa.text(
                "CREATE VIRTUAL TABLE IF NOT EXISTS search_documents_fts USING fts5(workspace_id UNINDEXED, entity_type UNINDEXED, entity_id UNINDEXED, title, body, tags_text)"
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute(sa.text("DROP TABLE IF EXISTS search_documents_fts"))
    op.drop_table("notes")
    op.drop_table("evidence")
    op.drop_table("finding_tags")
    op.drop_table("artifacts")
    op.drop_table("zookeeper_znodes")
    op.drop_table("registry_repositories")
    op.drop_table("registry_manifests")
    op.drop_table("redis_config_entries")
    op.drop_table("qdrant_collections")
    op.drop_table("proxmox_users")
    op.drop_table("proxmox_objects")
    op.drop_table("proxmox_nodes")
    op.drop_table("postgres_tables")
    op.drop_table("postgres_databases")
    op.drop_table("kube_resources")
    op.drop_table("kafka_topics")
    op.drop_table("grafana_datasources")
    op.drop_table("grafana_dashboards")
    op.drop_table("gitlab_tokens_policy")
    op.drop_table("gitlab_projects")
    op.drop_table("findings")
    op.drop_table("exporter_targets")
    op.drop_table("exporter_events")
    op.drop_table("etcd_keys_metadata")
    op.drop_table("consul_services")
    op.drop_table("consul_kv_entries")
    op.drop_table("clickhouse_tables")
    op.drop_table("clickhouse_databases")
    op.drop_table("run_observations")
    op.drop_table("run_tags")
    op.drop_table("protocol_services")
    op.drop_table("endpoint_tags")
    op.drop_table("network_endpoints")
    op.drop_table("module_runs")
    op.drop_table("host_tags")
    op.drop_table("target_hosts")
    op.drop_table("workspace_tags")
    op.drop_table("tags")
    op.drop_table("secret_refs")
    op.drop_table("search_documents")
    op.drop_table("import_jobs")
    op.drop_table("export_jobs")
    op.drop_table("workspaces")
    op.drop_table("app_state")
    op.drop_table("app_metadata")
