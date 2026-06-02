from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.stage_runtime import AuditCommandResult

RUN_CASES = {
    "redis": ["redis", "-t", "127.0.0.1"],
    "postgres": ["postgres", "-t", "127.0.0.1"],
    "kafka": ["kafka", "-t", "127.0.0.1"],
    "elastic": ["elastic", "-t", "127.0.0.1"],
    "grafana": ["grafana", "-t", "127.0.0.1"],
    "gitlab": ["gitlab", "-t", "127.0.0.1"],
    "consul": ["consul", "-t", "127.0.0.1"],
    "qdrant": ["qdrant", "-t", "127.0.0.1"],
    "kubeapi": ["kubeapi", "-t", "127.0.0.1"],
    "registry": ["registry", "-t", "127.0.0.1"],
    "proxmox": ["proxmox", "-t", "127.0.0.1", "--insecure", "--defcreds"],
    "etcd": ["etcd", "-t", "127.0.0.1"],
    "mongodb": ["mongodb", "-t", "127.0.0.1"],
    "docker": ["docker", "-t", "127.0.0.1"],
    "oracle": ["oracle", "-t", "127.0.0.1"],
    "grpc": ["grpc", "-t", "127.0.0.1"],
    "clickhouse": ["clickhouse", "-t", "127.0.0.1"],
    "zookeeper": ["zookeeper", "-t", "127.0.0.1"],
}


@pytest.mark.parametrize("module_name", sorted(RUN_CASES))
def test_package_stage_run_functions_cover_runner_plan_path(monkeypatch, module_name: str) -> None:  # type: ignore[no-untyped-def]
    stage = importlib.import_module(f"redposture_core.modules.{module_name}.stage")
    calls: list[object] = []

    def fake_run_plan(self, plan):  # type: ignore[no-untyped-def]
        calls.append(plan)
        return AuditCommandResult(records=[], detected_count=0, emitted_lines=0, typed_records=[])

    monkeypatch.setattr("redposture_core.stage_runtime.AuditCommandRunner.run_plan", fake_run_plan)
    args = parse_args(RUN_CASES[module_name])
    args._progress_owner = None
    rc = getattr(stage, f"run_{module_name}_stage")(args, SimpleNamespace(log=lambda *_a, **_k: None))

    assert rc == 0
    assert calls, module_name
