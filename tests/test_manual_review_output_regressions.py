"""Regressions from the manually reviewed, real audit output gallery."""

from __future__ import annotations

import importlib
import json
import re
from typing import Any

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.console import Console
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.modules.consul import actions as consul
from redposture_core.modules.docker import actions as docker
from redposture_core.modules.kafka import actions as kafka
from redposture_core.modules.oracle import actions as oracle
from redposture_core.modules.proxmox import actions as proxmox
from redposture_core.stage_runtime import LineOutputSink, _build_colored_emit

ANSI = re.compile(r"\x1b\[[0-9;]*m")


class RecordingConsole:
    def __init__(self) -> None:
        self.paint_calls: list[tuple[str, str]] = []
        self.lines: list[str] = []

    def _paint(self, text: str, color: str, stream: Any) -> str:
        self.paint_calls.append((text, color))
        return text

    def plain(self, text: str) -> None:
        self.lines.append(text)


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
@pytest.mark.parametrize("padding", [0, 8, 15])
def test_real_module_console_columns_are_independent_of_legacy_padding(module, padding, capsys, tmp_path) -> None:
    args = parse_args([module, "-t", "127.0.0.1", "--no-color"])
    package = module.replace("-", "_")
    stage = importlib.import_module(f"redposture_core.modules.{package}.stage")
    spec = getattr(stage, f"build_{package}_spec")(args)
    prefix = f"{spec.label:<{padding}}\t127.0.0.1\t1234\t"
    lines = [f"{prefix} [*] service", f"{prefix} detail"]
    output = tmp_path / "report.txt"
    sink = LineOutputSink(str(output), _build_colored_emit(Console(no_color=True), spec.colorize))
    try:
        sink.emit_many(lines)
    finally:
        sink.close()
    rendered = capsys.readouterr().out.splitlines()
    assert len(rendered) == 2
    assert all(line.expandtabs(8).index("127.0.0.1") == 16 for line in rendered)
    assert all(line.count("\t") == 3 and "\x1b" not in line for line in rendered)
    stored = output.read_text().splitlines()
    assert all(line.split("\t")[0] == spec.label for line in stored)
    assert all(len(line.split("\t")) == 4 for line in stored)
    assert [line.split("\t", 1)[1] for line in rendered] == [line.split("\t", 1)[1] for line in stored]


@pytest.mark.parametrize("line", ['{"module":"docker"}', "No confirmed services found", ""])
def test_console_alignment_does_not_touch_structured_or_run_output(line, capsys) -> None:
    _build_colored_emit(Console(no_color=True), None)(line)
    assert capsys.readouterr().out == line + "\n"


@pytest.mark.parametrize("transport,boolean,color", [("tls", "True", "bright_green"), ("plaintext", "False", "red")])
def test_kafka_detection_uses_consistent_boolean_spelling_and_colors(transport, boolean, color) -> None:
    line = kafka._format_detect_record(
        {"host": "127.0.0.1", "port": 9092, "is_kafka": True, "auth_required": True, "transport_mode": transport},
        "txt",
    )
    assert f"(tls:{boolean})" in line
    console = RecordingConsole()
    assert kafka._render_colored_kafka_line(console, line)
    assert (f"tls:{boolean}", color) in console.paint_calls


def test_docker_plaintext_detection_is_yellow() -> None:
    line = docker._format_detect_record(
        {"host": "127.0.0.1", "port": 2375, "is_docker": True, "auth_required": False, "transport_mode": "plaintext"},
        "txt",
    )
    console = RecordingConsole()
    assert docker._render_colored_docker_line(console, line)
    assert ("transport:plaintext", "yellow") in console.paint_calls


def test_oracle_auth_required_is_only_in_detection_and_json_is_unchanged() -> None:
    record = {"host": "127.0.0.1", "port": 1521, "is_oracle": True, "status": "auth_required", "auth_required": True}
    assert "auth required:True" in oracle._format_detect_record(record, "txt")
    assert oracle._format_record(record, "txt") == ""
    assert json.loads(oracle._format_record(record, "json")) == record
    failed = {**record, "status": "invalid_credentials", "provided_username": "test", "provided_password": "bad"}
    assert "[-] invalid_credentials test:bad" in oracle._format_record(failed, "txt")
    assert "[!] connection failed" in oracle._format_record({**record, "status": "fail"}, "txt")


@pytest.mark.parametrize("count,color", [(0, "bright_green"), (1, "red"), (20, "red")])
def test_oracle_listener_counters_are_colored(count, color) -> None:
    line = f"ORACLE\t127.0.0.1\t1521\t [*] Listener Targets (available:{count} total:{count})"
    console = RecordingConsole()
    assert oracle._render_colored_oracle_line(console, line)
    for field in ("available", "total"):
        assert (f"{field}:{count}", color) in console.paint_calls


@pytest.mark.parametrize("payload", ["node=pve01 status=online", "user=root@pam enabled=True"])
def test_proxmox_markerless_details_keep_blue_module_label(payload) -> None:
    line = f"PROXMOX\t127.0.0.1\t8006\t {payload}"
    console = RecordingConsole()
    assert proxmox._render_colored_proxmox_line(console, line)
    assert ("PROXMOX", "blue") in console.paint_calls
    assert console.lines == [line]
    assert not proxmox._render_colored_proxmox_line(console, line.replace("PROXMOX", "OTHER", 1))


@pytest.mark.parametrize("rce", [True, False])
def test_consul_auth_summary_drops_pwned_without_losing_scopes_or_risk_evidence(rce) -> None:
    record = {"auth_mode": "token", "auth_valid": True, "rce": rce, "auth_scopes": {"kv": {"ok": True, "count": 2}}}
    summary = consul._auth_summary_line(record)
    assert summary and summary.startswith("[+] token auth")
    assert "Pwned!" not in summary
    assert "(kv:2)" in summary
    assert record["rce"] is rce


def test_colored_console_alignment_matches_plain_console(monkeypatch, capsys) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    emit = _build_colored_emit(Console(no_color=False), docker._render_colored_docker_line)
    emit("DOCKER\t127.0.0.1\t2375\t [*] Docker Engine API (transport:plaintext)")
    line = capsys.readouterr().out.rstrip("\n")
    assert "\x1b" in line
    assert ANSI.sub("", line).expandtabs(8).index("127.0.0.1") == 16


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_every_module_keeps_blue_label_on_markerless_details(module) -> None:
    args = parse_args([module, "-t", "127.0.0.1"])
    package = module.replace("-", "_")
    stage = importlib.import_module(f"redposture_core.modules.{package}.stage")
    spec = getattr(stage, f"build_{package}_spec")(args)
    console = RecordingConsole()
    _build_colored_emit(console, spec.colorize)(f"{spec.label}\t127.0.0.1\t1234\t <no data>")
    assert (spec.label, "blue") in console.paint_calls


RESOURCE_COUNTERS = [
    ("docker", "containers"),
    ("docker", "images"),
    ("docker", "networks"),
    ("docker", "volumes"),
    ("mongodb", "DBs"),
    ("mongodb", "collections"),
    ("mongodb", "documents"),
    ("oracle", "PDBs"),
    ("oracle", "Users"),
    ("oracle", "Tables"),
    ("kafka", "topics"),
    ("kafka", "partitions"),
    ("redis", "keys"),
    ("etcd", "keys"),
    ("postgres", "DBs"),
    ("clickhouse", "DBs"),
    ("qdrant", "collections"),
    ("grafana", "datasources"),
    ("gitlab", "projects"),
    ("docker-registry", "images"),
    ("zookeeper", "znodes"),
    ("keeper", "znodes"),
    ("minio", "buckets"),
    ("minio", "objects"),
    ("consul", "kv"),
    ("consul", "services"),
    ("consul", "agent"),
    ("kubeapi", "namespaces"),
    ("kubeapi", "pods"),
    ("kubeapi", "secrets"),
    ("rabbitmq", "Count"),
    ("grpc", "services"),
    ("grpc", "methods"),
    ("docker", "count"),
    ("consul", "count"),
    ("zookeeper", "Count"),
    ("keeper", "Count"),
    ("qdrant", "count"),
    ("minio", "Count"),
    ("clickhouse", "occurrences"),
    ("clickhouse", "tables"),
    ("grpc", "descriptors"),
    ("grpc", "checks"),
    ("docker-registry", "layers"),
    ("nexus", "components"),
    ("docker-registry", "tags"),
]


@pytest.mark.parametrize("module,field", RESOURCE_COUNTERS)
@pytest.mark.parametrize(
    "value,colors", [("0", {"green", "bright_green"}), ("2", {"red", "true_red"}), ("unknown", {"orange"})]
)
def test_resource_counter_colors_are_consistent_across_modules(module, field, value, colors) -> None:
    args = parse_args([module, "-t", "127.0.0.1"])
    package = module.replace("-", "_")
    stage = importlib.import_module(f"redposture_core.modules.{package}.stage")
    spec = getattr(stage, f"build_{package}_spec")(args)
    console = RecordingConsole()
    _build_colored_emit(console, spec.colorize)(f"{spec.label}\t127.0.0.1\t1234\t [*] Inventory ({field}:{value})")
    assert any(text == f"{field}:{value}" and color in colors for text, color in console.paint_calls)


DETAIL_COUNTERS = [
    ("mongodb", "documents"),
    ("postgres", "Rows"),
    ("kubeapi", "containers"),
    ("kubeapi", "keys"),
    ("rabbitmq", "messages"),
    ("rabbitmq", "consumers"),
    ("rabbitmq", "messages_ready"),
    ("rabbitmq", "messages_unacknowledged"),
    ("nexus", "components"),
    ("docker-registry", "tags"),
    ("docker-registry", "layers"),
]


@pytest.mark.parametrize("module,field", DETAIL_COUNTERS)
@pytest.mark.parametrize(
    "value,colors", [("0", {"green", "bright_green"}), ("2", {"red", "true_red"}), ("unknown", {"orange"})]
)
def test_resource_counters_in_details_are_colored(module, field, value, colors) -> None:
    args = parse_args([module, "-t", "127.0.0.1"])
    package = module.replace("-", "_")
    stage = importlib.import_module(f"redposture_core.modules.{package}.stage")
    spec = getattr(stage, f"build_{package}_spec")(args)
    console = RecordingConsole()
    _build_colored_emit(console, spec.colorize)(f"{spec.label}\t127.0.0.1\t1234\t collection ({field}:{value})")
    assert any(text == f"{field}:{value}" and color in colors for text, color in console.paint_calls)


@pytest.mark.parametrize(
    "module", ["redis", "grafana", "docker-registry", "kafka", "etcd", "postgres", "clickhouse", "mongodb", "docker"]
)
def test_runtime_does_not_repeat_bare_auth_requirement_but_keeps_failed_attempts(module) -> None:
    from redposture_core.audit_models import AuditRecord
    from redposture_core.stage_runtime import AuditCommandRunner, build_render_plan

    args = parse_args([module, "-t", "127.0.0.1"])
    package = module.replace("-", "_")
    stage = importlib.import_module(f"redposture_core.modules.{package}.stage")
    spec = getattr(stage, f"build_{package}_spec")(args)
    runner = AuditCommandRunner(args=args, spec=spec)
    plan = build_render_plan(spec.render_module) if spec.render_module is not None else None
    payload = {
        "host": "127.0.0.1",
        "port": spec.default_port,
        "is_registry" if module == "docker-registry" else f"is_{module}": True,
        "auth_required": True,
        "status": "auth_required",
    }
    record = AuditRecord.from_mapping(payload, module=module, service=module)
    lines = runner._render_record(record, plan, "txt", False)
    assert any("auth required:True" in line for line in lines)
    assert not any(line.split("\t", 3)[-1].strip() == "[-] authentication required" for line in lines)
    payload.update(
        {
            "provided_credentials": True,
            "provided_username": "bad",
            "effective_username": "bad",
            "provided_password": "bad",
        }
    )
    if module == "grafana":
        payload["attempted_credentials_count"] = 1
    lines = runner._render_record(AuditRecord.from_mapping(payload, module=module, service=module), plan, "txt", False)
    if module not in {"etcd", "clickhouse", "docker"}:
        assert any("bad:bad" in line or "credentials invalid" in line for line in lines)
