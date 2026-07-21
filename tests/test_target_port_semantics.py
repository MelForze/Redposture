from __future__ import annotations

import importlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.stage_runtime import AuditCommandPlan

_AUDIT_MODULES = (
    "registry",
    "grafana",
    "proxmox",
    "gitlab",
    "consul",
    "kubeapi",
    "postgres",
    "mongodb",
    "docker",
    "oracle",
    "clickhouse",
    "redis",
    "etcd",
    "qdrant",
    "elastic",
    "grpc",
    "kafka",
    "zookeeper",
    "keeper",
)


def _plan_builder(module_name: str) -> Callable[[Any], AuditCommandPlan]:
    stage_module = importlib.import_module(f"redposture_core.stage_{module_name}")
    return getattr(stage_module, f"build_{module_name}_plan")


def _target_pairs(plan: AuditCommandPlan) -> set[tuple[str, int]]:
    return {(host, port) for _idx, host, port, _spec in plan.iter_target_specs()}


@pytest.mark.parametrize("module_name", _AUDIT_MODULES)
def test_audit_module_target_file_ports_override_implicit_defaults(
    module_name: str,
    tmp_path: Path,
) -> None:
    targets_file = tmp_path / f"{module_name}-targets.txt"
    targets_file.write_text(
        "10.38.15.200:8085\n10.245.98.175:8001\n",
        encoding="utf-8",
    )

    args = parse_args([module_name, "-t", str(targets_file)])
    plan = _plan_builder(module_name)(args)

    assert _target_pairs(plan) == {
        ("10.38.15.200", 8085),
        ("10.245.98.175", 8001),
    }
    assert plan.target_count == 2


@pytest.mark.parametrize("module_name", _AUDIT_MODULES)
def test_audit_module_explicit_cli_port_is_added_to_target_file_ports(
    module_name: str,
    tmp_path: Path,
) -> None:
    targets_file = tmp_path / f"{module_name}-targets.txt"
    targets_file.write_text(
        "10.38.15.200:8085\n10.245.98.175:8001\n",
        encoding="utf-8",
    )

    args = parse_args([module_name, "-t", str(targets_file), "--port", "65000"])
    plan = _plan_builder(module_name)(args)
    pairs = [(host, port) for _idx, host, port, _spec in plan.iter_target_specs()]

    assert set(pairs) == {
        ("10.38.15.200", 8085),
        ("10.38.15.200", 65000),
        ("10.245.98.175", 8001),
        ("10.245.98.175", 65000),
    }
    assert len(pairs) == len(set(pairs)) == 4
    assert plan.target_count == 4
