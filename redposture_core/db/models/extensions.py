"""Protocol-specific extension tables."""

from __future__ import annotations

from sqlalchemy import JSON, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin


class _WorkspaceObservationMixin(TimestampMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False)
    run_observation_id: Mapped[int] = mapped_column(
        ForeignKey("run_observations.id", ondelete="CASCADE"), nullable=False
    )
    protocol_service_id: Mapped[int | None] = mapped_column(
        ForeignKey("protocol_services.id", ondelete="SET NULL"), nullable=True
    )
    details_json: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)


class ExporterTarget(_WorkspaceObservationMixin, Base):
    __tablename__ = "exporter_targets"
    exporter_name: Mapped[str] = mapped_column(String(128), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)


class ExporterEvent(_WorkspaceObservationMixin, Base):
    __tablename__ = "exporter_events"
    exporter_name: Mapped[str] = mapped_column(String(128), nullable=False)
    event_kind: Mapped[str] = mapped_column(String(128), nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)


class RegistryRepository(_WorkspaceObservationMixin, Base):
    __tablename__ = "registry_repositories"
    __table_args__ = (UniqueConstraint("workspace_id", "run_observation_id", "name", name="uq_registry_repo_name"),)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    anonymous_access: Mapped[bool | None] = mapped_column(nullable=True)
    tag_count: Mapped[int | None] = mapped_column(Integer, nullable=True)


class RegistryManifest(_WorkspaceObservationMixin, Base):
    __tablename__ = "registry_manifests"
    repository_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tag: Mapped[str | None] = mapped_column(String(255), nullable=True)
    digest: Mapped[str | None] = mapped_column(String(255), nullable=True)


class GrafanaDatasource(_WorkspaceObservationMixin, Base):
    __tablename__ = "grafana_datasources"
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    datasource_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    access_mode: Mapped[str | None] = mapped_column(String(64), nullable=True)


class GrafanaDashboard(_WorkspaceObservationMixin, Base):
    __tablename__ = "grafana_dashboards"
    uid: Mapped[str | None] = mapped_column(String(128), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    dashboard_url: Mapped[str | None] = mapped_column(Text, nullable=True)


class ProxmoxNode(_WorkspaceObservationMixin, Base):
    __tablename__ = "proxmox_nodes"
    node_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)


class ProxmoxObject(_WorkspaceObservationMixin, Base):
    __tablename__ = "proxmox_objects"
    object_type: Mapped[str] = mapped_column(String(64), nullable=False)
    object_id: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ProxmoxUser(_WorkspaceObservationMixin, Base):
    __tablename__ = "proxmox_users"
    user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[str | None] = mapped_column(String(32), nullable=True)


class GitLabProject(_WorkspaceObservationMixin, Base):
    __tablename__ = "gitlab_projects"
    project_path: Mapped[str] = mapped_column(String(255), nullable=False)
    visibility: Mapped[str | None] = mapped_column(String(64), nullable=True)
    web_url: Mapped[str | None] = mapped_column(Text, nullable=True)


class GitLabTokenPolicy(_WorkspaceObservationMixin, Base):
    __tablename__ = "gitlab_tokens_policy"
    policy_name: Mapped[str] = mapped_column(String(255), nullable=False)
    value_text: Mapped[str | None] = mapped_column(Text, nullable=True)


class ConsulServiceAsset(_WorkspaceObservationMixin, Base):
    __tablename__ = "consul_services"
    service_name: Mapped[str] = mapped_column(String(255), nullable=False)
    service_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    node_name: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ConsulKvEntry(_WorkspaceObservationMixin, Base):
    __tablename__ = "consul_kv_entries"
    key_path: Mapped[str] = mapped_column(Text, nullable=False)
    value_redacted: Mapped[str | None] = mapped_column(Text, nullable=True)


class KubeResource(_WorkspaceObservationMixin, Base):
    __tablename__ = "kube_resources"
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    namespace: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)


class PostgresDatabaseAsset(_WorkspaceObservationMixin, Base):
    __tablename__ = "postgres_databases"
    database_name: Mapped[str] = mapped_column(String(255), nullable=False)


class PostgresTableAsset(_WorkspaceObservationMixin, Base):
    __tablename__ = "postgres_tables"
    database_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    schema_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    table_name: Mapped[str] = mapped_column(String(255), nullable=False)
    columns_json: Mapped[list | None] = mapped_column(JSON, nullable=True)


class ClickHouseDatabaseAsset(_WorkspaceObservationMixin, Base):
    __tablename__ = "clickhouse_databases"
    database_name: Mapped[str] = mapped_column(String(255), nullable=False)


class ClickHouseTableAsset(_WorkspaceObservationMixin, Base):
    __tablename__ = "clickhouse_tables"
    database_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    table_name: Mapped[str] = mapped_column(String(255), nullable=False)
    columns_json: Mapped[list | None] = mapped_column(JSON, nullable=True)


class RedisConfigEntry(_WorkspaceObservationMixin, Base):
    __tablename__ = "redis_config_entries"
    config_key: Mapped[str] = mapped_column(String(255), nullable=False)
    value_redacted: Mapped[str | None] = mapped_column(Text, nullable=True)


class EtcdKeyMetadata(_WorkspaceObservationMixin, Base):
    __tablename__ = "etcd_keys_metadata"
    key_path: Mapped[str] = mapped_column(Text, nullable=False)
    value_redacted: Mapped[str | None] = mapped_column(Text, nullable=True)


class QdrantCollection(_WorkspaceObservationMixin, Base):
    __tablename__ = "qdrant_collections"
    collection_name: Mapped[str] = mapped_column(String(255), nullable=False)
    vectors_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)


class KafkaTopic(_WorkspaceObservationMixin, Base):
    __tablename__ = "kafka_topics"
    topic_name: Mapped[str] = mapped_column(String(255), nullable=False)
    partitions: Mapped[int | None] = mapped_column(Integer, nullable=True)


class ZooKeeperZnode(_WorkspaceObservationMixin, Base):
    __tablename__ = "zookeeper_znodes"
    znode_path: Mapped[str] = mapped_column(Text, nullable=False)
    value_redacted: Mapped[str | None] = mapped_column(Text, nullable=True)
    children_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
