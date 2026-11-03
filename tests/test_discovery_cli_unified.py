"""All secret-discovery modules expose one shared time budget contract."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.airflow import policy as airflow_policy
from redposture_core.modules.clickhouse import policy as clickhouse_policy
from redposture_core.modules.elastic import policy as elastic_policy
from redposture_core.modules.minio import policy as minio_policy
from redposture_core.modules.proxmox import policy as proxmox_policy

_DISCOVERY_COMMANDS = (
    "airflow",
    "clickhouse",
    "consul",
    "docker-registry",
    "elastic",
    "etcd",
    "gitlab",
    "harbor",
    "jenkins",
    "jupyter",
    "kafka",
    "keeper",
    "kubeapi",
    "minio",
    "mongodb",
    "nexus",
    "nomad",
    "oracle",
    "portainer",
    "postgres",
    "proxmox",
    "qdrant",
    "redis",
    "spark",
    "vault",
    "yarn",
    "zookeeper",
)

_POLICIES = {
    "airflow": airflow_policy,
    "minio": minio_policy,
    "elastic": elastic_policy,
    "clickhouse": clickhouse_policy,
    "proxmox": proxmox_policy,
}


@pytest.mark.parametrize("module", _DISCOVERY_COMMANDS)
def test_discover_max_bytes_is_not_a_cli_flag(module: str) -> None:
    defaults = parse_args([module, "-t", "127.0.0.1"])
    assert not hasattr(defaults, "discover_max_bytes")
    with pytest.raises(SystemExit) as exc:
        parse_args([module, "-t", "127.0.0.1", "--discover-max-bytes", "4096"])
    assert exc.value.code == 2


@pytest.mark.parametrize("module", _DISCOVERY_COMMANDS)
def test_discovery_defaults_and_overrides(module: str) -> None:
    defaults = parse_args([module, "-t", "127.0.0.1"])
    assert defaults.discover is False
    assert defaults.discover_time == 900.0
    chosen = parse_args([module, "-t", "127.0.0.1", "--discover", "--discover-time", "12.5"])
    assert (chosen.discover, chosen.discover_time) == (True, 12.5)
    errors: list[str] = []
    if module in _POLICIES:
        assert _POLICIES[module].validate_args(chosen, SimpleNamespace(error=errors.append)) is None, errors


@pytest.mark.parametrize("component", ["airflow", "clickhouse", "elastic", "minio", "storage", "token_api"])
@pytest.mark.parametrize("started", [0.0, 124.1, 1024.0, 1_000_000.125])
def test_discovery_engine_defaults_after_removing_cli_byte_limit(component: str, started: float) -> None:
    from redposture_core.discovery_options import DEFAULT_DISCOVER_MAX_BYTES, UNLIMITED_DISCOVER_BYTES

    limits: tuple[float | None, int | None]
    expected_time = 900.0
    if component == "airflow":
        from redposture_core.modules.airflow.discover import DiscoverConfig as AirflowConfig

        airflow = AirflowConfig()
        limits = (airflow.max_seconds, airflow.max_bytes)
    elif component == "clickhouse":
        from redposture_core.modules.clickhouse.discover import DiscoverConfig as ClickHouseConfig

        clickhouse = ClickHouseConfig()
        limits = (clickhouse.max_seconds, clickhouse.max_total_bytes)
    elif component == "elastic":
        from redposture_core.modules.elastic.discover import DiscoverOptions

        elastic = DiscoverOptions()
        limits = (elastic.max_seconds, elastic.max_source_bytes)
    elif component == "minio":
        from redposture_core.modules.minio.discover import Budget

        minio = Budget()
        limits = (minio.time_budget, minio.max_total_bytes)
    else:
        from redposture_core.modules.token_api import ReadBudget
        from redposture_core.storage_discovery import DiscoveryCollector

        args = SimpleNamespace(discover_time=None, discover_max_bytes=None)
        # Compare the absolute deadline. Subtracting the start again can lose
        # precision for legitimate monotonic clock values such as 124.1.
        expected_time = started + 900.0
        if component == "storage":
            storage = DiscoveryCollector("gitlab", SimpleNamespace(args=args, discovery_started_at=started), {})
            limits = (storage.deadline, storage.remaining)
        else:
            token_api = ReadBudget(args, started_at=started)
            limits = (token_api.deadline, token_api.remaining)
    expected_bytes = {
        "airflow": UNLIMITED_DISCOVER_BYTES,
        "clickhouse": None,
        "elastic": None,
        "minio": DEFAULT_DISCOVER_MAX_BYTES,  # One active network portion, not cumulative bytes.
        "storage": UNLIMITED_DISCOVER_BYTES,
        "token_api": UNLIMITED_DISCOVER_BYTES,
    }
    assert limits == (expected_time, expected_bytes[component])


@pytest.mark.parametrize("module", list(_POLICIES))
@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--discover-time", "nan"),
        ("--discover-time", "inf"),
        ("--discover-time", "0"),
    ],
)
def test_invalid_discovery_budgets_are_rejected(module: str, flag: str, value: str) -> None:
    args = parse_args([module, "-t", "127.0.0.1", "--discover", flag, value])
    errors: list[str] = []
    assert _POLICIES[module].validate_args(args, SimpleNamespace(error=errors.append)) == 2
    assert flag in errors[0]


@pytest.mark.parametrize(
    ("module", "obsolete"),
    [
        ("airflow", "--discover-max-logs"),
        ("airflow", "--discover-max-dags"),
        ("minio", "--max-objects"),
        ("minio", "--max-object-size"),
        ("clickhouse", "--discover-chunk-rows"),
        ("clickhouse", "--discover-max-threads"),
        ("clickhouse", "--max-query-bytes"),
        ("clickhouse", "--max-query-time"),
        ("clickhouse", "--max-memory"),
        ("clickhouse", "--exclude-db"),
        ("proxmox", "--discover-creds"),
    ],
)
def test_obsolete_discovery_flags_are_removed(module: str, obsolete: str) -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args([module, "-t", "127.0.0.1", obsolete, "1"])
    assert exc.value.code == 2
