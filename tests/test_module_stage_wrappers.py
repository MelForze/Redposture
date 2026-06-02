from __future__ import annotations

import importlib
from types import SimpleNamespace

from redposture_core.stage_runtime import AuditCommandResult

MODULES = {
    "redis": ("REDIS", 6379),
    "postgres": ("POSTGRES", 5432),
    "kafka": ("KAFKA", 9092),
    "elastic": ("ELASTIC", 9200),
    "grafana": ("GRAFANA", 3000),
    "gitlab": ("GITLAB", 80),
    "consul": ("CONSUL", 8500),
    "qdrant": ("QDRANT", 6333),
    "kubeapi": ("KUBEAPI", 6443),
    "registry": ("REGISTRY", 5000),
    "proxmox": ("PROXMOX", 8006),
    "etcd": ("ETCD", 2379),
    "mongodb": ("MONGODB", 27017),
    "docker": ("DOCKER", 2375),
    "oracle": ("ORACLE", 1521),
    "grpc": ("GRPC", 50051),
    "clickhouse": ("CLICKHOUSE", 9000),
    "zookeeper": ("ZOOKEEPER", 2181),
}


def test_module_stage_wrappers_route_to_audit_command_runner(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    for module_name, (label, default_port) in MODULES.items():
        stage = importlib.import_module(f"redposture_core.modules.{module_name}.stage")
        calls: list[tuple[str, int, object]] = []

        def fake_run_plan(self, plan, calls=calls):  # type: ignore[no-untyped-def]
            calls.append((self.spec.label, self.spec.default_port, plan))
            return AuditCommandResult(records=[], detected_count=0, emitted_lines=0, typed_records=[])

        monkeypatch.setattr("redposture_core.stage_runtime.AuditCommandRunner.run_plan", fake_run_plan)
        args = SimpleNamespace(targets="127.0.0.1", hosts=None, hosts_file=None, output_format="txt", workers=1)
        if module_name == "proxmox":
            args.pve_api_token = "root@pam!audit=token"
        logger = object()

        assert getattr(stage, f"run_{module_name}_stage")(args, logger) == 0
        assert len(calls) == 1
        assert calls[0][0] == label
        assert calls[0][1] == default_port
