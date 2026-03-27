"""Protocol extension repositories."""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..models import extensions as ext_models

_EXTENSION_MODEL_MAP = {
    "exporter_targets": ext_models.ExporterTarget,
    "exporter_events": ext_models.ExporterEvent,
    "registry_repositories": ext_models.RegistryRepository,
    "registry_manifests": ext_models.RegistryManifest,
    "grafana_datasources": ext_models.GrafanaDatasource,
    "grafana_dashboards": ext_models.GrafanaDashboard,
    "proxmox_nodes": ext_models.ProxmoxNode,
    "proxmox_objects": ext_models.ProxmoxObject,
    "proxmox_users": ext_models.ProxmoxUser,
    "gitlab_projects": ext_models.GitLabProject,
    "gitlab_tokens_policy": ext_models.GitLabTokenPolicy,
    "consul_services": ext_models.ConsulServiceAsset,
    "consul_kv_entries": ext_models.ConsulKvEntry,
    "kube_resources": ext_models.KubeResource,
    "postgres_databases": ext_models.PostgresDatabaseAsset,
    "postgres_tables": ext_models.PostgresTableAsset,
    "clickhouse_databases": ext_models.ClickHouseDatabaseAsset,
    "clickhouse_tables": ext_models.ClickHouseTableAsset,
    "redis_config_entries": ext_models.RedisConfigEntry,
    "etcd_keys_metadata": ext_models.EtcdKeyMetadata,
    "qdrant_collections": ext_models.QdrantCollection,
    "kafka_topics": ext_models.KafkaTopic,
    "zookeeper_znodes": ext_models.ZooKeeperZnode,
}


class ExtensionRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, *, table_name: str, values: dict[str, object]) -> object:
        model = _EXTENSION_MODEL_MAP[table_name]
        row = model(**values)
        self.session.add(row)
        return row
