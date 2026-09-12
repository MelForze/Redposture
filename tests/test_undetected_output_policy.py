from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.docker.stage import build_docker_spec
from redposture_core.modules.grafana.stage import build_grafana_spec
from redposture_core.modules.kafka.stage import build_kafka_spec
from redposture_core.modules.proxmox.stage import build_proxmox_spec
from redposture_core.stage_runtime import ModuleAuditSpec


@pytest.mark.parametrize(
    ("module", "build_spec"),
    [
        ("grafana", build_grafana_spec),
        ("proxmox", build_proxmox_spec),
        ("docker", build_docker_spec),
        ("kafka", build_kafka_spec),
    ],
)
def test_noisy_service_modules_inherit_findings_only_text_policy(
    module: str,
    build_spec: Callable[[Any], ModuleAuditSpec],
) -> None:
    args = parse_args([module, "-t", "127.0.0.1"])

    assert build_spec(args).suppress_undetected_records_in_text is True
