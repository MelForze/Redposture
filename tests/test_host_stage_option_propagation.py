from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.clickhouse import actions as clickhouse_actions
from redposture_core.modules.clickhouse import stage as clickhouse_stage
from redposture_core.modules.consul import actions as consul_actions
from redposture_core.modules.consul import stage as consul_stage
from redposture_core.modules.elastic import actions as elastic_actions
from redposture_core.modules.elastic import stage as elastic_stage
from redposture_core.modules.gitlab import actions as gitlab_actions
from redposture_core.modules.gitlab import stage as gitlab_stage
from redposture_core.modules.grafana import actions as grafana_actions
from redposture_core.modules.grafana import stage as grafana_stage
from redposture_core.modules.grpc import actions as grpc_actions
from redposture_core.modules.grpc import stage as grpc_stage
from redposture_core.modules.kubeapi import actions as kubeapi_actions
from redposture_core.modules.kubeapi import stage as kubeapi_stage
from redposture_core.modules.proxmox import actions as proxmox_actions
from redposture_core.modules.proxmox import stage as proxmox_stage


class _CapturingHostStage:
    def __init__(self, original: Any, module: str) -> None:
        self.__signature__ = inspect.signature(original)
        self.module = module
        self.calls: list[dict[str, Any]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        bound = self.__signature__.bind(*args, **kwargs)
        bound.apply_defaults()
        call = dict(bound.arguments)
        self.calls.append(call)
        return {
            "host": call["host"],
            "port": call["port"],
            f"is_{self.module}": True,
            "status": "open_no_auth",
            "auth_required": False,
        }


def _run_with_capture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    module: str,
    actions_module: Any,
    run_stage: Any,
    argv: list[str],
    configure_args: Callable[[Any], None] | None = None,
) -> tuple[list[dict[str, Any]], Any]:
    capture = _CapturingHostStage(actions_module.host_stage, module)
    monkeypatch.setattr(actions_module, "host_stage", capture)
    output_path = tmp_path / f"{module}.jsonl"
    args = parse_args([*argv, "--format", "json", "--output", str(output_path)])
    if configure_args is not None:
        configure_args(args)
    rc = run_stage(args, logger=SimpleNamespace(log=lambda *_args, **_kwargs: None))
    assert rc == 0
    assert output_path.exists()
    return capture.calls, args


def _deep_calls(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [call for call in calls if call["run_deep_checks"] is True]


def test_clickhouse_real_stage_propagates_actions_and_http_defaults(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(clickhouse_actions, "_load_clickhouse_connect_module", lambda: object())
    calls, args = _run_with_capture(
        monkeypatch,
        tmp_path,
        module="clickhouse",
        actions_module=clickhouse_actions,
        run_stage=clickhouse_stage.run_clickhouse_stage,
        argv=[
            "clickhouse",
            "-t",
            "127.0.0.1",
            "--http",
            "--database",
            "analytics",
            "--show-databases",
            "2",
            "--show-tables",
            "3",
            "--table",
            "analytics.events,analytics.users",
            "--table",
            "ANALYTICS.events",
            "--show-columns",
            "4",
            "--column",
            "id,Name",
            "--column",
            "name",
            "--dump",
            "5",
            "--execute",
            " id ",
        ],
    )

    assert clickhouse_stage.build_clickhouse_plan(args).ports == (8123, 18123)
    assert {call["port"] for call in calls} == {8123, 18123}
    assert _deep_calls(calls)
    for call in calls:
        assert call["protocol"] == "http"
        assert call["database"] == "analytics"
        assert call["show_databases"] is True
        assert call["show_databases_limit"] == 2
        assert call["show_tables"] is True
        assert call["show_tables_limit"] == 3
        assert call["show_columns"] is True
        assert call["show_columns_limit"] == 4
        assert call["table_targets"] == ["analytics.events", "analytics.users"]
        assert call["table_columns"] == ["id", "Name"]
        assert call["dump_table_rows"] is True
        assert call["dump_row_limit"] == 5
        assert call["execute_command"] == "id"
        assert call["sql_command"] is None
        assert call["port_protocols"] is None


def test_clickhouse_http_preserves_an_explicit_port() -> None:
    args = parse_args(["clickhouse", "-t", "127.0.0.1", "--http", "--port", "9000"])
    assert clickhouse_stage.build_clickhouse_plan(args).ports == (9000,)


def test_gitlab_real_stage_propagates_project_filters_and_clone_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    clone_dir = tmp_path / "clones"
    calls, _args = _run_with_capture(
        monkeypatch,
        tmp_path,
        module="gitlab",
        actions_module=gitlab_actions,
        run_stage=gitlab_stage.run_gitlab_stage,
        argv=[
            "gitlab",
            "-t",
            "https://127.0.0.1:8443",
            "--project",
            "group/app,42",
            "--project",
            "GROUP/app",
            "--clone",
            "--clone-dir",
            str(clone_dir),
        ],
    )

    assert _deep_calls(calls)
    for call in calls:
        assert call["use_https"] is True
        assert call["project_filters"] == ["group/app", "42"]
        assert call["clone"] is True
        assert call["clone_dir"] == str(clone_dir.resolve())


def test_kubeapi_real_stage_propagates_selectors_exec_and_transport(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls, _args = _run_with_capture(
        monkeypatch,
        tmp_path,
        module="kubeapi",
        actions_module=kubeapi_actions,
        run_stage=kubeapi_stage.run_kubeapi_stage,
        argv=[
            "kubeapi",
            "-t",
            "http://127.0.0.1:8080",
            "--no-https",
            "--insecure",
            "--ca-file",
            "cluster-ca.pem",
            "--namespaces",
            "--pods",
            "--secrets",
            "--namespace",
            "default,prod",
            "--namespace",
            "DEFAULT",
            "--pod",
            "prod/api",
            "--exec-command",
            " id ",
        ],
    )

    assert _deep_calls(calls)
    for call in calls:
        assert call["use_https"] is False
        assert call["insecure"] is True
        assert call["ca_file"] == "cluster-ca.pem"
        assert call["show_namespaces"] is True
        assert call["show_pods"] is True
        assert call["show_secrets"] is True
        assert call["namespace_filters"] == ["default", "prod"]
        assert call["exec_pod"] == "prod/api"
        assert call["exec_command"] == "id"


def test_kubeapi_auth_valid_record_reaches_data_actions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    original = kubeapi_actions.host_stage
    signature = inspect.signature(original)
    calls: list[dict[str, Any]] = []

    def _host_stage(*args: Any, **kwargs: Any) -> dict[str, Any]:
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        call = dict(bound.arguments)
        calls.append(call)
        base = {
            "host": call["host"],
            "port": call["port"],
            "is_kubeapi": True,
            "auth_required": True,
        }
        if call["token"] is None:
            return {**base, "status": "auth_required"}
        if not call["run_deep_checks"]:
            return {**base, "status": "auth_valid", "auth_valid": True}
        return {
            **base,
            "status": "auth_valid",
            "auth_valid": True,
            "namespaces": [{"name": "default"}],
            "pods": [{"namespace": "default", "name": "api"}],
        }

    signature_holder: Any = _host_stage
    signature_holder.__signature__ = signature
    monkeypatch.setattr(kubeapi_actions, "host_stage", _host_stage)
    output_path = tmp_path / "kubeapi-auth-valid.jsonl"
    args = parse_args(
        [
            "kubeapi",
            "-t",
            "127.0.0.1",
            "--port",
            "16443",
            "--token",
            "auditor-token",
            "--namespaces",
            "--pods",
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
    )

    rc = kubeapi_stage.run_kubeapi_stage(
        args,
        logger=SimpleNamespace(log=lambda *_args, **_kwargs: None),
    )

    assert rc == 0
    assert any(call["run_deep_checks"] is True for call in calls)
    records = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    assert records[0]["namespaces"] == [{"name": "default"}]
    assert records[0]["pods"] == [{"namespace": "default", "name": "api"}]


def test_grpc_real_stage_parses_metadata_request_and_descriptors_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    descriptor_loads: list[tuple[Any, Any, Any]] = []

    def _load_descriptors(proto: Any, proto_path: Any, protoset: Any) -> list[bytes]:
        descriptor_loads.append((proto, proto_path, protoset))
        return [b"descriptor"]

    monkeypatch.setattr(grpc_actions, "_load_explicit_descriptor_bytes", _load_descriptors)
    calls, _args = _run_with_capture(
        monkeypatch,
        tmp_path,
        module="grpc",
        actions_module=grpc_actions,
        run_stage=grpc_stage.run_grpc_stage,
        argv=[
            "grpc",
            "-t",
            "https://127.0.0.1:50051",
            "--invoke",
            "/lab.Service/Call",
            "--data",
            '{"message":"hello"}',
            "--meta",
            "x-lab=one",
            "--meta",
            "x-trace=two",
            "--proto",
            "service.proto",
            "--proto-path",
            "proto",
            "--protoset",
            "service.protoset",
        ],
    )

    assert descriptor_loads == [(["service.proto"], ["proto"], ["service.protoset"])]
    assert _deep_calls(calls)
    for call in calls:
        assert call["preferred_scheme"] == "https"
        assert call["schema_descriptor_bytes"] == [b"descriptor"]
        assert call["invoke_path"] == "/lab.Service/Call"
        assert call["invoke_request_json"] == {"message": "hello"}
        assert call["metadata"] == [("x-lab", "one"), ("x-trace", "two")]


@pytest.mark.parametrize(
    ("extra_args", "expected_fragment"),
    [
        (["--meta", "missing-separator"], "--meta must use key=value"),
        (["--invoke", "/lab.Service/Call", "--data", "[]"], "--data must decode to a JSON object"),
    ],
)
def test_grpc_invalid_inputs_fail_before_host_stage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    extra_args: list[str],
    expected_fragment: str,
) -> None:
    capture = _CapturingHostStage(grpc_actions.host_stage, "grpc")
    monkeypatch.setattr(grpc_actions, "host_stage", capture)
    output_path = tmp_path / "grpc-invalid.jsonl"
    args = parse_args(["grpc", "-t", "127.0.0.1", *extra_args, "--format", "json", "--output", str(output_path)])

    rc = grpc_stage.run_grpc_stage(args, logger=SimpleNamespace(log=lambda *_args, **_kwargs: None))

    assert rc == 2
    assert capture.calls == []
    assert expected_fragment in capsys.readouterr().err


def test_grpc_invalid_protoset_fails_before_host_stage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = _CapturingHostStage(grpc_actions.host_stage, "grpc")
    monkeypatch.setattr(grpc_actions, "host_stage", capture)
    protoset = tmp_path / "broken.protoset"
    protoset.write_text("this is not a protobuf descriptor set", encoding="utf-8")
    args = parse_args(
        [
            "grpc",
            "-t",
            "127.0.0.1",
            "--protoset",
            str(protoset),
            "--format",
            "json",
            "--output",
            str(tmp_path / "grpc-invalid-protoset.jsonl"),
        ]
    )

    rc = grpc_stage.run_grpc_stage(args, logger=SimpleNamespace(log=lambda *_args, **_kwargs: None))

    assert rc == 2
    assert capture.calls == []
    assert "invalid protoset" in capsys.readouterr().err


def test_consul_real_stage_propagates_ssrf_dump_selectors_and_revshell(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls, _args = _run_with_capture(
        monkeypatch,
        tmp_path,
        module="consul",
        actions_module=consul_actions,
        run_stage=consul_stage.run_consul_stage,
        argv=[
            "consul",
            "-t",
            "https://127.0.0.1:8501",
            "--ssrf-target",
            "127.0.0.1",
            "--ssrf-port",
            "8080",
            "--ssrf-path",
            "/health?full=1",
            "--dump",
            "7",
            "--agent",
            "agent-1",
            "--check-id",
            "id:check-1",
            "--revshell",
            "--payload",
            "id",
        ],
    )

    assert _deep_calls(calls)
    for call in calls:
        assert call["preferred_scheme"] == "https"
        assert call["do_ssrf"] is True
        assert call["ssrf_urls"] == ["http://127.0.0.1:8080/health?full=1"]
        assert call["dump_requested"] is True
        assert call["dump_limit"] == 7
        assert call["dump_all_requested"] is False
        assert call["show_services"] is False
        assert call["show_agents"] is True
        assert call["show_checks"] is True
        assert call["show_nodes"] is False
        assert call["agent_dump_name"] == "agent-1"
        assert call["check_dump_id"] == "check-1"
        assert call["revshell_enabled"] is True
        assert call["revshell_payload"] == "id"
        assert call["revshell_check_id"] == "check-1"


def test_consul_dump_without_selectors_enables_all_categories() -> None:
    args = parse_args(["consul", "-t", "127.0.0.1", "--dump"])
    console = SimpleNamespace(warn=lambda _message: None)
    consul_stage._normalize_consul_command_args(args, console)
    options = consul_stage._build_consul_host_stage_options(args)

    assert options["dump_all_requested"] is True
    assert options["show_services"] is True
    assert options["show_agents"] is True
    assert options["show_checks"] is True
    assert options["show_nodes"] is True


def test_grafana_real_stage_propagates_datasource_and_ssrf_actions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls, _args = _run_with_capture(
        monkeypatch,
        tmp_path,
        module="grafana",
        actions_module=grafana_actions,
        run_stage=grafana_stage.run_grafana_stage,
        argv=[
            "grafana",
            "-t",
            "http://127.0.0.1:3000",
            "--show-datasources",
            "--ssrf-target",
            "127.0.0.1,localhost",
            "--ssrf-port",
            "9090",
            "--ssrf-path",
            "/-/ready",
        ],
    )

    assert _deep_calls(calls)
    for call in calls:
        assert call["show_datasources"] is True
        assert call["check_urls"] == [
            "http://127.0.0.1:9090/-/ready",
            "http://localhost:9090/-/ready",
        ]


@pytest.mark.parametrize(
    ("target", "expected_fragment"),
    [
        ("http://", "no valid SSRF targets/ports after parsing"),
        ("http://localhost:bad", "failed to parse Grafana SSRF targets/ports"),
    ],
)
def test_grafana_invalid_ssrf_target_fails_before_host_stage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    target: str,
    expected_fragment: str,
) -> None:
    capture = _CapturingHostStage(grafana_actions.host_stage, "grafana")
    monkeypatch.setattr(grafana_actions, "host_stage", capture)
    args = parse_args(
        [
            "grafana",
            "-t",
            "127.0.0.1",
            "--ssrf-target",
            target,
            "--format",
            "json",
            "--output",
            str(tmp_path / "grafana-invalid.jsonl"),
        ]
    )

    rc = grafana_stage.run_grafana_stage(args, logger=SimpleNamespace(log=lambda *_args, **_kwargs: None))

    assert rc == 2
    assert capture.calls == []
    assert expected_fragment in capsys.readouterr().err


def test_elastic_real_stage_propagates_all_action_flags_and_url_scheme(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls, _args = _run_with_capture(
        monkeypatch,
        tmp_path,
        module="elastic",
        actions_module=elastic_actions,
        run_stage=elastic_stage.run_elastic_stage,
        argv=[
            "elastic",
            "-t",
            "https://127.0.0.1:9200",
            "--ca-file",
            "elastic-ca.pem",
            "--endpoints",
            "--plugins",
            "--cluster",
            "--user",
            "--discover",
        ],
    )

    assert _deep_calls(calls)
    for call in calls:
        assert call["preferred_scheme"] == "https"
        assert call["ca_file"] == "elastic-ca.pem"
        assert call["show_endpoints"] is True
        assert call["show_plugins"] is True
        assert call["show_cluster"] is True
        assert call["show_users"] is True
        assert call["discover"] is True


def test_proxmox_real_stage_propagates_actions_and_url_scheme_priority(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def on_status_ready(_record: Any) -> None:
        return None

    def on_discovered_url(_url: str) -> None:
        return None

    def on_credential_finding(_finding: Any) -> None:
        return None

    def _configure_callbacks(args: Any) -> None:
        args.on_status_ready = on_status_ready
        args.on_discovered_url = on_discovered_url
        args.on_credential_finding = on_credential_finding

    calls, _args = _run_with_capture(
        monkeypatch,
        tmp_path,
        module="proxmox",
        actions_module=proxmox_actions,
        run_stage=proxmox_stage.run_proxmox_stage,
        argv=[
            "proxmox",
            "-t",
            "http://127.0.0.1:8006",
            "--pveapitoken",
            "root@pam!audit=secret",
            "--https",
            "--insecure",
            "--discover-creds",
            "--nodes",
            "--users",
            "--add-user",
            "auditor@pve",
        ],
        configure_args=_configure_callbacks,
    )

    deep_calls = _deep_calls(calls)
    assert len(deep_calls) == 1
    for call in calls:
        assert call["use_https"] is False
        assert call["insecure"] is True
    detect_calls = [call for call in calls if call["run_deep_checks"] is False]
    assert len(detect_calls) == 1
    assert detect_calls[0]["discover_creds"] is False
    assert detect_calls[0]["show_nodes"] is False
    assert detect_calls[0]["show_users"] is False
    assert detect_calls[0]["add_user"] is None
    assert detect_calls[0]["on_status_ready"] is None
    assert detect_calls[0]["on_discovered_url"] is None
    assert detect_calls[0]["on_credential_finding"] is None
    for call in deep_calls:
        assert call["discover_creds"] is True
        assert call["show_nodes"] is True
        assert call["show_users"] is True
        assert call["add_user"] == "auditor@pve"
        assert call["on_status_ready"] is on_status_ready
        assert call["on_discovered_url"] is on_discovered_url
        assert call["on_credential_finding"] is on_credential_finding


def test_proxmox_rejects_non_callable_callbacks_before_host_stage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = _CapturingHostStage(proxmox_actions.host_stage, "proxmox")
    monkeypatch.setattr(proxmox_actions, "host_stage", capture)
    args = parse_args(
        [
            "proxmox",
            "-t",
            "127.0.0.1",
            "--pveapitoken",
            "root@pam!audit=secret",
            "--format",
            "json",
            "--output",
            str(tmp_path / "proxmox-invalid-callback.jsonl"),
        ]
    )
    args.on_status_ready = "not-callable"

    rc = proxmox_stage.run_proxmox_stage(args, logger=SimpleNamespace(log=lambda *_args, **_kwargs: None))

    assert rc == 2
    assert capture.calls == []
    assert "on_status_ready must be callable" in capsys.readouterr().err
