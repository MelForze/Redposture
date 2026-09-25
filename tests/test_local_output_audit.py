"""Opt-in output audit.

These assertions describe the desired operator-facing contract. They are kept
outside the default suite because product defects found here are reported, not
fixed, by the output-audit task.
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.stage_runtime import LineOutputSink, ModuleAuditSpec, build_render_plan

pytestmark = pytest.mark.local_output_audit

_DISCOVERY_MODULES = ("airflow", "minio", "elastic", "clickhouse", "proxmox")
_CAPABILITY_COLOR_CASES = (
    ("elastic", "(Indices:7)", "red"),
    ("elastic", "(Documents:Read)", "red"),
    ("elastic", "(Users:Access Denied)", "bright_green"),
    ("elastic", "(Cluster:Unknown)", "orange"),
    ("airflow", "(Dags:7)", "red"),
    ("airflow", "(Keys:Access Denied)", "bright_green"),
    ("airflow", "(Connections:Unknown)", "orange"),
    ("postgres", "(read:True)", "red"),
    ("postgres", "(superuser:False)", "bright_green"),
    ("postgres", "(execute:unknown)", "orange"),
    ("clickhouse", "(read:True)", "red"),
    ("clickhouse", "(admin:False)", "bright_green"),
    ("clickhouse", "(execute:unknown)", "orange"),
    ("redis", "(keys:7)", "red"),
    ("redis", "(keys:0)", "bright_green"),
    ("redis", "(keys:unknown)", "orange"),
    ("consul", "(kv:7)", "red"),
    ("consul", "(services:7)", "red"),
    ("consul", "(agent:7)", "red"),
    ("consul", "(kv:0)", "bright_green"),
    ("kubeapi", "(secrets:7)", "red"),
    ("kubeapi", "(pods:7)", "red"),
    ("kubeapi", "(namespaces:7)", "red"),
    ("kubeapi", "(secrets:0)", "bright_green"),
    ("rabbitmq", "(admin:True)", "red"),
    ("rabbitmq", "(admin:False)", "bright_green"),
    ("rabbitmq", "(Count:7)", "red"),
    ("rabbitmq", "(Count:0)", "bright_green"),
    ("registry", "(images:7)", "red"),
    ("registry", "(images:0)", "bright_green"),
)


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


def _spec(module: str) -> ModuleAuditSpec:
    args = parse_args([module, "-t", "127.0.0.1"])
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    return getattr(stage, f"build_{module}_spec")(args)


def _contains_color(console: _RecordingConsole, text: str, color: str) -> bool:
    accepted = {"red", "true_red"} if color == "red" else {color}
    return any(text in painted and painted_color in accepted for painted, painted_color in console.paint_calls)


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_stored_tsv_module_tag_has_no_padding(module: str, tmp_path) -> None:
    """A TSV tag is data, so alignment spaces must be added only by the console."""

    spec = _spec(module)
    assert spec.render_module is not None or spec.render is not None
    if spec.render_module is None:
        pytest.skip("stateful renderer is covered by its module acceptance test")
    plan = build_render_plan(spec.render_module)
    formatter = plan.detect or plan.summary
    assert formatter is not None
    payload: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": spec.default_port,
        "status": "detected",
        "auth_required": True,
        f"is_{module}": True,
        "is_zookeeper": module in {"zookeeper", "keeper"},
        "is_keeper": module == "keeper",
        "detection_status": "confirmed",
        "api_versions": "v3",
        "anonymous_scopes": {},
        "dags_allowed": False,
        "transport_mode": "tls",
        "protocol_flavor": "grpc",
        "reflection_enabled": True,
    }
    line = str(formatter(payload, "txt"))
    assert line
    output_path = tmp_path / f"{module}.txt"
    emitted: list[str] = []
    sink = LineOutputSink(str(output_path), emitted.append)
    sink.emit_many([line])
    sink.close()

    stored_line = output_path.read_text(encoding="utf-8").rstrip("\n")
    assert stored_line.split("\t", 1)[0] == spec.label
    # Terminal rendering retains each module's established display alignment.
    assert emitted == [line]


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_cve_heading_is_white_for_every_real_colorizer(module: str) -> None:
    spec = _spec(module)
    console = _RecordingConsole()
    heading = "CVE's Enumeration"

    assert spec.colorize is not None
    assert spec.colorize(
        console,
        f"{spec.label}\t127.0.0.1\t{spec.default_port}\t [*] {heading}",
    )
    assert _contains_color(console, heading, "white")
    assert not any(heading in text and color != "white" for text, color in console.paint_calls)


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_cve_finding_description_is_orange_for_every_real_colorizer(module: str) -> None:
    spec = _spec(module)
    console = _RecordingConsole()
    finding = "CVE-2024-99999 potentially affected (CRITICAL 9.9) QA command execution"

    assert spec.colorize is not None
    assert spec.colorize(
        console,
        f"{spec.label}\t127.0.0.1\t{spec.default_port}\t [!] {finding}",
    )
    assert _contains_color(console, finding, "orange")


@pytest.mark.parametrize("module", _DISCOVERY_MODULES)
def test_discovery_heading_is_white_and_finding_is_orange(module: str) -> None:
    spec = _spec(module)
    heading_console = _RecordingConsole()
    finding_console = _RecordingConsole()
    finding = 'Pass Value="qa-secret" Place="qa/place"'

    assert spec.colorize is not None
    assert spec.colorize(
        heading_console,
        f"{spec.label}\t127.0.0.1\t{spec.default_port}\t [*] Discover Secrets",
    )
    assert _contains_color(heading_console, "Discover Secrets", "white")
    assert spec.colorize(
        finding_console,
        f"{spec.label}\t127.0.0.1\t{spec.default_port}\t [!] {finding}",
    )
    assert _contains_color(finding_console, finding, "orange")


@pytest.mark.parametrize(("module", "token", "expected_color"), _CAPABILITY_COLOR_CASES)
def test_capability_semantics_use_common_exposure_colors(module: str, token: str, expected_color: str) -> None:
    spec = _spec(module)
    console = _RecordingConsole()

    assert spec.colorize is not None
    assert spec.colorize(
        console,
        f"{spec.label}\t127.0.0.1\t{spec.default_port}\t [+] qa:qa {token}",
    )
    # Shared span rendering deliberately keeps the surrounding parentheses
    # white, so assert the semantic payload rather than the wrappers.
    assert _contains_color(console, token[1:-1], expected_color)
