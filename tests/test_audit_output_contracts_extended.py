"""Cross-module output contracts exercised through every real audit spec."""

from __future__ import annotations

import importlib
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.rendering import normalize_report_line_for_storage
from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    ModuleAuditSpec,
    build_render_plan,
)

_DISCOVERY_MODULES = ("airflow", "minio", "elastic", "clickhouse", "proxmox")


class _RecordingConsole:
    def __init__(self) -> None:
        self.paint_calls: list[tuple[str, str]] = []
        self.lines: list[str] = []

    def _paint(self, text: str, color: str, _stream: object = None) -> str:
        self.paint_calls.append((text, color))
        return text

    def plain(self, text: str, color: str | None = None) -> None:
        if color is not None:
            self.paint_calls.append((text, color))
        self.lines.append(text)

    def render_tagged_payload_line(self, line: str, tag: str, payload_color: str | None = None) -> bool:
        if not line.startswith(tag):
            return False
        self.paint_calls.append((line, payload_color or "white"))
        self.lines.append(line)
        return True


def _build_real_spec(module: str, *extra: str) -> ModuleAuditSpec:
    args = parse_args([module, "-t", "127.0.0.1", *extra])
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    return getattr(stage, f"build_{module}_spec")(args)


def _detected_payload(module: str, spec: ModuleAuditSpec) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "host": "2001:db8::7",
        "port": spec.default_port,
        "module": module,
        "service": module,
        "status": "open_no_auth",
        "auth_required": False,
        "timestamp": "2026-09-24T00:00:00Z",
    }
    payload.update(
        {
            "redis": {"is_redis": True},
            "registry": {"is_registry": True},
            "postgres": {"is_postgres": True},
            "clickhouse": {"is_clickhouse": True, "protocol": "native"},
            "etcd": {"is_etcd": True, "api_versions": "v3", "server_version": "3.5.0"},
            "proxmox": {"is_proxmox": True},
            "grafana": {"is_grafana": True, "server_version": "11.0.0"},
            "gitlab": {"is_gitlab": True, "status": "detected", "login_page": True, "version": "17.0.0"},
            "consul": {"is_consul": True, "anonymous_scopes": {}, "version": "1.22.0"},
            "qdrant": {"is_qdrant": True, "version": "1.9.0", "anonymous_access": True},
            "kubeapi": {"is_kubeapi": True, "status": "detected", "version": "v1.30.0"},
            "minio": {"is_minio": True, "detection_status": "s3_api", "version": "RELEASE.2026-01-01"},
            "rabbitmq": {"is_rabbitmq": True, "detection_status": "confirmed", "version": "3.13.7"},
            "airflow": {
                "is_airflow": True,
                "detection_status": "confirmed",
                "dags_allowed": False,
                "version": "2.11.1",
            },
            "kafka": {"is_kafka": True},
            "zookeeper": {
                "is_zookeeper": True,
                "is_keeper": False,
                "version": "3.9.2",
                "transport": "plaintext",
            },
            "keeper": {
                "is_zookeeper": True,
                "is_keeper": True,
                "version": "24.3.1",
                "transport": "plaintext",
            },
            "elastic": {
                "is_elastic": True,
                "status": "detected",
                "vendor": "opensearch",
                "server_version": "2.19.1",
                "scheme": "https",
            },
            "grpc": {
                "is_grpc": True,
                "status": "detected",
                "transport_mode": "tls",
                "protocol_flavor": "grpc",
                "reflection_enabled": True,
            },
            "mongodb": {"is_mongodb": True, "server_version": "7.0.14"},
            "docker": {
                "is_docker": True,
                "transport_mode": "https",
                "server_version": "27.0.0",
                "api_version": "1.47",
            },
            "oracle": {
                "is_oracle": True,
                "transport_mode": "tcp",
                "connect_service": "FREEPDB1",
                "server_version": "23.0.0",
            },
        }[module]
    )
    return payload


def _service_lines(spec: ModuleAuditSpec, payload: dict[str, Any]) -> list[str]:
    record = AuditRecord.from_mapping(payload, module=spec.module, service=spec.module)
    if spec.render_module is not None:
        plan = build_render_plan(spec.render_module)
        formatter = plan.detect or plan.summary
        assert formatter is not None, spec.module
        value = formatter(record.to_dict(), "txt")
        return [str(value)] if value else []
    assert spec.render is not None, spec.module
    return [line for line in spec.render(record) if " [*] " in line]


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_real_audit_spec_renders_one_tsv_service_line(module: str) -> None:
    spec = _build_real_spec(module)
    lines = _service_lines(spec, _detected_payload(module, spec))

    assert len(lines) == 1, (module, lines)
    fields = lines[0].split("\t", 3)
    assert len(fields) == 4, (module, lines[0])
    assert fields[0].strip() == spec.label
    assert fields[1] == "2001:db8::7"
    assert fields[2] == str(spec.default_port)
    assert fields[3].startswith(" [*] ")


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_real_audit_specs_enable_findings_only_text_and_explicit_colorizer(module: str) -> None:
    spec = _build_real_spec(module)

    assert spec.suppress_undetected_records_in_text is True
    assert callable(spec.colorize)


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
@pytest.mark.parametrize(
    ("marker", "expected_color"),
    [("[*]", "cyan"), ("[+]", "bright_green"), ("[-]", "red"), ("[!]", "red")],
)
def test_every_real_colorizer_preserves_marker_contract(module: str, marker: str, expected_color: str) -> None:
    spec = _build_real_spec(module)
    console = _RecordingConsole()
    line = f"{spec.label}\t127.0.0.1\t{spec.default_port}\t {marker} contract payload"

    assert spec.colorize is not None
    assert spec.colorize(console, line) is True
    assert any(text == marker and color == expected_color for text, color in console.paint_calls), (
        module,
        console.paint_calls,
    )


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_every_real_colorizer_rejects_foreign_module_lines(module: str) -> None:
    spec = _build_real_spec(module)
    console = _RecordingConsole()

    assert spec.colorize is not None
    assert spec.colorize(console, "FOREIGN\t127.0.0.1\t1\t [*] payload") is False
    assert console.lines == []


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_every_real_colorizer_keeps_cve_heading_white_and_finding_orange(module: str) -> None:
    spec = _build_real_spec(module)
    heading_console = _RecordingConsole()
    finding_console = _RecordingConsole()
    heading = "CVE's Enumeration"
    finding = "CVE-2026-99999 potentially affected (CRITICAL 9.9) QA command execution"

    assert spec.colorize is not None
    assert spec.colorize(
        heading_console,
        f"{spec.label}\t127.0.0.1\t{spec.default_port}\t [*] {heading}",
    )
    assert any(heading in text and color == "white" for text, color in heading_console.paint_calls)
    assert spec.colorize(
        finding_console,
        f"{spec.label}\t127.0.0.1\t{spec.default_port}\t [!] {finding}",
    )
    assert any(finding in text and color == "orange" for text, color in finding_console.paint_calls)


@pytest.mark.parametrize("module", _DISCOVERY_MODULES)
def test_discovery_modules_share_white_heading_and_orange_finding(module: str) -> None:
    spec = _build_real_spec(module)
    heading_console = _RecordingConsole()
    finding_console = _RecordingConsole()
    finding = 'Pass Value="qa-secret\\nwith-tab\\t" Place="qa/π"'

    assert spec.colorize is not None
    assert spec.colorize(
        heading_console,
        f"{spec.label}\t127.0.0.1\t{spec.default_port}\t [*] Discover Secrets",
    )
    assert any("Discover Secrets" in text and color == "white" for text, color in heading_console.paint_calls)
    assert spec.colorize(
        finding_console,
        f"{spec.label}\t127.0.0.1\t{spec.default_port}\t [!] {finding}",
    )
    assert any(finding in text and color == "orange" for text, color in finding_console.paint_calls)


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
@pytest.mark.parametrize(
    "payload",
    (
        "",
        "Unknown Ω " + "x" * 4096,
        "Access Denied (count:unknown partial)",
        'Value=\\"quoted\\" Place=\\"line\\\\nfeed\\"',
    ),
)
def test_real_colorizers_survive_empty_unicode_and_long_malformed_payloads(module: str, payload: str) -> None:
    spec = _build_real_spec(module)
    console = _RecordingConsole()

    assert spec.colorize is not None
    assert (
        spec.colorize(
            console,
            f"{spec.label}\t127.0.0.1\t{spec.default_port}\t [!] {payload}",
        )
        is True
    )


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_real_renderers_keep_terminal_and_output_file_order_identical(module: str, tmp_path: Path) -> None:
    real_spec = _build_real_spec(module)
    payload = _detected_payload(module, real_spec)
    record = AuditRecord.from_mapping(payload, module=module, service=module)
    output_path = tmp_path / f"{module}.txt"
    emitted: list[str] = []

    test_spec = replace(
        real_spec,
        host_stage=None,
        host_stage_options=None,
        detect=lambda _ctx: record,
        auth=None,
        capabilities=None,
        data=None,
        lifecycle_state_factory=None,
        lifecycle_state_close=None,
        deep_gate=lambda _record: (False, "render-only contract"),
        is_detected=lambda _record: True,
    )
    args = SimpleNamespace(debug=False, enum_cve=False, discover=False, no_color=True)
    AuditCommandRunner(args=args, spec=test_spec, emit_line=emitted.append).run_plan(
        AuditCommandPlan(
            targets_by_port={real_spec.default_port: ("2001:db8::7",)},
            workers=1,
            output_format="txt",
            output_path=str(output_path),
        )
    )

    stored = output_path.read_text(encoding="utf-8").splitlines()
    assert stored == [normalize_report_line_for_storage(line) for line in emitted]
    assert stored
    assert all(line.split("\t", 1)[0] == real_spec.label for line in stored)
    assert "\x1b[" not in "\n".join(stored)
    expected_service = normalize_report_line_for_storage(_service_lines(real_spec, payload)[0])
    assert stored.count(expected_service) == 1, (module, stored)
