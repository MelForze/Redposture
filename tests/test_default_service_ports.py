from __future__ import annotations

import importlib

import pytest

from redposture_core.cli_args import parse_args


@pytest.mark.parametrize(
    ("module", "expected_ports"),
    [
        ("registry", (5000, 15000, 25000)),
        ("postgres", (5432, 6432, 15432, 16432, 25432, 26432)),
        ("clickhouse", (9000, 19000, 29000)),
        ("etcd", (2379, 12379, 22379)),
        ("proxmox", (8006, 18006, 28006)),
        ("grafana", (3000, 13000, 23000)),
        ("consul", (8500, 8501, 18500, 18501, 28500, 28501)),
        ("qdrant", (6333, 16333, 26333)),
        ("kubeapi", (6443, 16443, 26443)),
        ("zookeeper", (2181, 12181, 22181)),
        ("keeper", (9181, 19181, 29181)),
    ],
)
def test_bare_target_uses_complete_module_default_port_set(
    module: str,
    expected_ports: tuple[int, ...],
) -> None:
    args = parse_args([module, "-t", "127.0.0.1"])
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    plan = getattr(stage, f"build_{module}_plan")(args)

    assert args.port is None
    assert plan.ports == expected_ports


def test_clickhouse_auto_includes_every_plaintext_native_and_http_default_port() -> None:
    args = parse_args(["clickhouse", "-t", "127.0.0.1", "--protocol", "auto"])

    from redposture_core.modules.clickhouse.stage import build_clickhouse_plan

    assert build_clickhouse_plan(args).ports == (9000, 19000, 29000, 8123, 18123)
