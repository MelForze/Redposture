from __future__ import annotations

from pathlib import Path

from redposture_core.clients.kafka import _KAFKA_DEFAULT_CREDENTIALS
from redposture_core.modules.clickhouse.actions import _build_credential_candidates as clickhouse_credentials
from redposture_core.modules.elastic.actions import _ELASTIC_DEFAULT_CREDENTIALS
from redposture_core.modules.etcd.actions import _ETCD_DEFAULT_CREDS
from redposture_core.modules.grafana.actions import _build_credential_candidates as grafana_credentials
from redposture_core.modules.grpc.actions import _DEFAULT_BASIC_CREDENTIALS, _DEFAULT_BEARER_TOKENS
from redposture_core.modules.keeper.stage import _DEFAULT_CREDENTIALS as _KEEPER_DEFAULT_CREDENTIALS
from redposture_core.modules.mongodb.actions import _MONGODB_DEFAULT_CREDS
from redposture_core.modules.oracle.actions import _ORACLE_DEFAULT_CREDS
from redposture_core.modules.postgres.actions import _POSTGRES_DEFAULT_CREDENTIALS
from redposture_core.modules.proxmox.actions import _PROXMOX_DEFAULT_CREDENTIALS
from redposture_core.modules.redis.actions import _REDIS_DEFAULT_CREDENTIALS
from redposture_core.modules.zookeeper.stage import _DEFAULT_CREDENTIALS as _ZOOKEEPER_DEFAULT_CREDENTIALS


def test_readme_default_credentials_table_matches_runtime_catalogs() -> None:
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")
    table_heading = "## Default credentials checked by `--defcreds`"
    examples_heading = "## Module Examples"
    assert readme.index(table_heading) < readme.index(examples_heading)
    table = readme.split(table_heading, 1)[1].split(examples_heading, 1)[0]

    catalogs = {
        "Grafana": [(username, password) for username, password, _source in grafana_credentials(None, None, True)],
        "Proxmox": list(_PROXMOX_DEFAULT_CREDENTIALS),
        "Postgres": list(_POSTGRES_DEFAULT_CREDENTIALS),
        "MongoDB": list(_MONGODB_DEFAULT_CREDS),
        "Oracle": list(_ORACLE_DEFAULT_CREDS),
        "ClickHouse": [
            (username, password) for username, password, _source in clickhouse_credentials(None, None, True)
        ],
        "Redis": list(_REDIS_DEFAULT_CREDENTIALS),
        "etcd": list(_ETCD_DEFAULT_CREDS),
        "Elastic/OpenSearch": list(_ELASTIC_DEFAULT_CREDENTIALS),
        "gRPC": list(_DEFAULT_BASIC_CREDENTIALS),
        "Kafka": list(_KAFKA_DEFAULT_CREDENTIALS),
        "ZooKeeper": list(_ZOOKEEPER_DEFAULT_CREDENTIALS),
        "Keeper": list(_KEEPER_DEFAULT_CREDENTIALS),
    }

    for module, pairs in catalogs.items():
        row = next(line for line in table.splitlines() if line.startswith(f"| {module} |"))
        for username, password in pairs:
            rendered_password = password if password else "<empty>"
            assert f"`{username}:{rendered_password}`" in row

    grpc_row = next(line for line in table.splitlines() if line.startswith("| gRPC |"))
    for token in _DEFAULT_BEARER_TOKENS:
        assert f"`{token}`" in grpc_row


def test_readme_documents_out_target_alias_and_inputs() -> None:
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")
    assert "-ot, --out-target" in readme
    assert "--out-target exclusions.txt" in readme
    assert "removes matching hosts before ports are expanded" in readme
