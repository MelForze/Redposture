"""The five secret-discovery modules expose one shared budget contract."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.airflow import policy as airflow_policy
from redposture_core.modules.clickhouse import policy as clickhouse_policy
from redposture_core.modules.elastic import policy as elastic_policy
from redposture_core.modules.minio import policy as minio_policy
from redposture_core.modules.proxmox import policy as proxmox_policy

_POLICIES = {
    "airflow": airflow_policy,
    "minio": minio_policy,
    "elastic": elastic_policy,
    "clickhouse": clickhouse_policy,
    "proxmox": proxmox_policy,
}


@pytest.mark.parametrize(
    ("module", "default_time", "default_bytes"),
    [
        ("airflow", None, 50 * 1024 * 1024),
        ("minio", None, 50 * 1024 * 1024),
        ("elastic", 300.0, 50 * 1024 * 1024),
        ("clickhouse", None, 50 * 1024 * 1024),
        ("proxmox", None, 50 * 1024 * 1024),
    ],
)
def test_discovery_defaults_and_overrides(module: str, default_time: float | None, default_bytes: int | None) -> None:
    defaults = parse_args([module, "-t", "127.0.0.1"])
    assert defaults.discover is False
    assert (defaults.discover_time, defaults.discover_max_bytes) == (default_time, default_bytes)
    chosen = parse_args(
        [module, "-t", "127.0.0.1", "--discover", "--discover-time", "12.5", "--discover-max-bytes", "4096"]
    )
    assert (chosen.discover, chosen.discover_time, chosen.discover_max_bytes) == (True, 12.5, 4096)
    errors: list[str] = []
    assert _POLICIES[module].validate_args(chosen, SimpleNamespace(error=errors.append)) is None, errors


@pytest.mark.parametrize("module", list(_POLICIES))
@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--discover-time", "nan"),
        ("--discover-time", "inf"),
        ("--discover-time", "0"),
        ("--discover-max-bytes", "0"),
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
