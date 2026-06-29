from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.module_registry import AUDIT_MODULE_NAMES
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


def test_run_cases_cover_every_registered_audit_module() -> None:
    assert set(RUN_CASES) == set(AUDIT_MODULE_NAMES)


@pytest.mark.parametrize(
    ("module_name", "argv", "expected_error"),
    [
        (
            "registry",
            ["registry", "-t", "127.0.0.1", "--token", "token", "-u", "admin", "-p", "admin", "--docker"],
            "use either --token or --username/--password",
        ),
        ("consul", ["consul", "-t", "127.0.0.1", "--key", "redposture/kafka/sasl_password"], "--key requires --dump"),
        (
            "qdrant",
            ["qdrant", "-t", "127.0.0.1", "--ssrf-target", "http://127.0.0.1:19115/probe"],
            "--ssrf-target requires --collection",
        ),
        ("postgres", ["postgres", "-t", "127.0.0.1", "--show-columns"], "--show-columns requires --table"),
        (
            "mongodb",
            ["mongodb", "-t", "127.0.0.1", "--collection", "demo", "--document", "1", "--query", '{"role":"admin"}'],
            "--document cannot be combined with --query",
        ),
        (
            "oracle",
            ["oracle", "-t", "127.0.0.1", "--service", "FREEPDB1", "--sid", "FREE"],
            "--service cannot be combined with --sid",
        ),
        ("docker", ["docker", "-t", "127.0.0.1", "--container", "web"], "--container and --exec-cmd"),
        (
            "clickhouse",
            ["clickhouse", "-t", "127.0.0.1", "--os-shell", "--sql-shell"],
            "--os-shell cannot be combined with --sql-shell",
        ),
        ("kafka", ["kafka", "-t", "127.0.0.1", "--max-messages", "0"], "--max-messages must be > 0"),
        ("zookeeper", ["zookeeper", "-t", "127.0.0.1", "-u", "zkuser"], "--username and --password"),
        ("proxmox", ["proxmox", "-t", "127.0.0.1"], "--pveapitoken, -u/-p, or --defcreds is required"),
    ],
)
def test_package_stage_policy_negative_cases_do_not_run_plan(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    module_name: str,
    argv: list[str],
    expected_error: str,
) -> None:
    stage = importlib.import_module(f"redposture_core.modules.{module_name}.stage")

    def fail_run_plan(self, plan):
        _ = (self, plan)
        pytest.fail("invalid CLI/policy combination reached AuditCommandRunner.run_plan")

    monkeypatch.setattr("redposture_core.stage_runtime.AuditCommandRunner.run_plan", fail_run_plan)
    args = parse_args(argv)
    rc = getattr(stage, f"run_{module_name}_stage")(args, SimpleNamespace(log=lambda *_a, **_k: None))

    assert rc == 2
    assert expected_error in capsys.readouterr().err


@pytest.mark.parametrize("module_name", sorted(RUN_CASES))
def test_package_stage_run_functions_cover_runner_plan_path(monkeypatch, module_name: str) -> None:
    stage = importlib.import_module(f"redposture_core.modules.{module_name}.stage")
    calls: list[object] = []

    def fake_run_plan(self, plan):
        calls.append(plan)
        return AuditCommandResult(records=[], detected_count=0, emitted_lines=0, typed_records=[])

    monkeypatch.setattr("redposture_core.stage_runtime.AuditCommandRunner.run_plan", fake_run_plan)
    args = parse_args(RUN_CASES[module_name])
    args._progress_owner = None
    rc = getattr(stage, f"run_{module_name}_stage")(args, SimpleNamespace(log=lambda *_a, **_k: None))

    assert rc == 0
    assert calls, module_name


def test_grpc_stage_debug_openapi_and_output_error_branches(monkeypatch, tmp_path) -> None:
    stage = importlib.import_module("redposture_core.modules.grpc.stage")
    descriptor_b64 = "CgxoZWFsdGgucHJvdG8="
    calls: list[object] = []

    def fake_run_plan(self, plan):
        calls.append(plan)
        return AuditCommandResult(
            records=[{"descriptor_protos_b64": [descriptor_b64]}],
            detected_count=1,
            emitted_lines=0,
            typed_records=[],
        )

    written: list[tuple[str, list[bytes]]] = []
    monkeypatch.setattr("redposture_core.stage_runtime.AuditCommandRunner.run_plan", fake_run_plan)
    monkeypatch.setattr(stage.actions, "_write_openapi_document", lambda path, data: written.append((path, data)) or 1)
    args = parse_args(["grpc", "-t", "127.0.0.1", "--debug", "--openapi", str(tmp_path / "openapi.json")])
    rc = stage.run_grpc_stage(args, SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 0
    assert calls
    assert written and written[0][0].endswith("openapi.json")

    def boom_run_plan(self, plan):
        _ = (self, plan)
        raise OSError("disk full")

    monkeypatch.setattr("redposture_core.stage_runtime.AuditCommandRunner.run_plan", boom_run_plan)
    args = parse_args(["grpc", "-t", "127.0.0.1"])
    assert stage.run_grpc_stage(args, SimpleNamespace(log=lambda *_a, **_k: None)) == 2


def test_mongodb_and_qdrant_stage_error_and_listener_branches(monkeypatch) -> None:
    mongodb_stage = importlib.import_module("redposture_core.modules.mongodb.stage")
    qdrant_stage = importlib.import_module("redposture_core.modules.qdrant.stage")

    normalized: list[object] = []

    def fake_run_plan(self, plan):
        normalized.append((self.args, plan))
        return AuditCommandResult(records=[], detected_count=0, emitted_lines=0, typed_records=[])

    monkeypatch.setattr("redposture_core.stage_runtime.AuditCommandRunner.run_plan", fake_run_plan)
    args = parse_args(
        [
            "mongodb",
            "-t",
            "127.0.0.1",
            "--database",
            "redposture",
            "--collection",
            "redposture.demo",
            "--document",
            "1",
            "--projection",
            '{"username":1}',
            "--debug",
        ]
    )
    assert mongodb_stage.run_mongodb_stage(args, SimpleNamespace(log=lambda *_a, **_k: None)) == 0
    assert args.query_filter == {"_id": 1}
    assert args.projection == {"username": 1}
    assert normalized

    def boom_run_plan(self, plan):
        _ = (self, plan)
        raise OSError("write failed")

    monkeypatch.setattr("redposture_core.stage_runtime.AuditCommandRunner.run_plan", boom_run_plan)
    assert mongodb_stage.run_mongodb_stage(parse_args(["mongodb", "-t", "127.0.0.1"]), SimpleNamespace()) == 2

    monkeypatch.setattr("redposture_core.stage_runtime.AuditCommandRunner.run_plan", fake_run_plan)
    listener = {"started": True, "port": 19090}
    monkeypatch.setattr(qdrant_stage.actions, "_start_qdrant_ssrf_capture_listener", lambda _port: listener)
    monkeypatch.setattr(qdrant_stage.actions, "_qdrant_ssrf_capture_hits", lambda _listener: [{"path": "/hit"}])
    stopped: list[object] = []
    monkeypatch.setattr(qdrant_stage.actions, "_stop_qdrant_ssrf_capture_listener", stopped.append)
    args = parse_args(
        [
            "qdrant",
            "-t",
            "127.0.0.1",
            "--collection",
            "demo",
            "--ssrf-target",
            "127.0.0.1",
            "--listen",
            "--ssrf-port",
            "19090",
        ]
    )
    assert qdrant_stage.run_qdrant_stage(args, SimpleNamespace(log=lambda *_a, **_k: None)) == 0
    assert stopped == [listener]

    monkeypatch.setattr(
        qdrant_stage.actions, "_start_qdrant_ssrf_capture_listener", lambda _port: {"started": False, "error": "busy"}
    )
    args = parse_args(
        [
            "qdrant",
            "-t",
            "127.0.0.1",
            "--collection",
            "demo",
            "--ssrf-target",
            "127.0.0.1",
            "--listen",
            "--ssrf-port",
            "19091",
        ]
    )
    assert qdrant_stage.run_qdrant_stage(args, SimpleNamespace(log=lambda *_a, **_k: None)) == 0
