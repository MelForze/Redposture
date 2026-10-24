"""Backend and UI pairs share the accepted/rejected credential palette."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import TextIO

import pytest

from redposture_core import web_panels
from redposture_core.console import Console
from redposture_core.stage_runtime import AuditCommandRunner, LineOutputSink, ModuleAuditSpec
from tests.test_credential_color_contract import _assert_color


class _ColorConsole(Console):
    def _use_color(self, stream: TextIO) -> bool:
        return not self._no_color


def _runner(module: str, *, no_color: bool = False) -> AuditCommandRunner:
    renderer = importlib.import_module(f"redposture_core.modules.{module}.render")
    console = _ColorConsole(no_color=no_color)
    return AuditCommandRunner(
        args=SimpleNamespace(debug=False),
        spec=ModuleAuditSpec(
            module=module,
            label=module.upper(),
            default_port=9200,
            colorize=getattr(renderer, f"_render_colored_{module}_line"),
        ),
        console=console,
    )


@pytest.mark.parametrize(
    "module", ["docker", "portainer", "mongodb", "elastic", "redis", "postgres", "kubeapi", "minio"]
)
@pytest.mark.parametrize("credential", ["logstash:logstash", "user:password with spaces", "user:"])
def test_accepted_backend_pairs_are_red_with_ui_routing_enabled(module, credential, capsys):
    runner = _runner(module)
    runner.emit_line(f"{module.upper()}\t127.0.0.1\t9200\t [+] {credential}")
    text = capsys.readouterr().out
    _assert_color(text, credential, "1;38;5;196")
    assert "\x1b[1;92m[+]\x1b[0m" in text


@pytest.mark.parametrize("module,credential", [("elastic", "apikey auth"), ("kubeapi", "token auth")])
def test_backend_token_auth_uses_confirmed_access_color(module, credential, capsys):
    runner = _runner(module)
    runner.emit_line(f"{module.upper()}\t127.0.0.1\t9200\t [+] {credential}")
    assert f"\x1b[1;38;5;196m{credential}" in capsys.readouterr().out


def test_opensearch_denials_and_access_use_independent_colors(capsys):
    runner = _runner("elastic")
    runner.emit_line(
        "ELASTIC\t10.173.132.245\t9200\t [+] logstash:logstash"
        " (Indices:Access Denied) (Documents:Access Denied)"
        " (Cluster:Allowed) (Nodes:3) (Users:Access Denied)"
    )
    text = capsys.readouterr().out
    _assert_color(text, "logstash:logstash", "1;38;5;196")
    for resource in ("Indices", "Documents", "Users"):
        assert f"\x1b[1;92m{resource}:Access Denied\x1b[0m" in text
    for resource in ("Cluster:Allowed", "Nodes:3"):
        assert f"\x1b[1;38;5;196m{resource}\x1b[0m" in text


@pytest.mark.parametrize("module", ["portainer", "mongodb", "elastic", "redis", "postgres", "kubeapi", "minio"])
@pytest.mark.parametrize("marker", ["[+]", "[-]"])
def test_ui_pairs_follow_the_verdict_with_neutral_ui_suffix_and_no_color(module, marker, capsys):
    line = f"{module.upper()}\t127.0.0.1\t9001\t {marker} user:secret (UI)"
    _runner(module).emit_line(line)
    text = capsys.readouterr().out
    _assert_color(text, "user:secret", "1;38;5;196" if marker == "[+]" else "1;97")
    _assert_color(text, "(UI)", "1;97")
    if marker == "[+]":
        assert "\x1b[1;92m[+]\x1b[0m" in text
    _runner(module, no_color=True).emit_line(line)
    plain = capsys.readouterr().out
    assert "user:secret (UI)" in plain
    assert "\x1b" not in plain


@pytest.mark.parametrize("module", ["portainer", "mongodb", "elastic", "redis", "postgres", "kubeapi", "minio"])
def test_ui_detection_version_is_white_with_ui_suffix(module, capsys):
    record = {
        "host": "127.0.0.1",
        "port": 5601,
        "ui_product": "opensearch_dashboards",
        "ui": {"version": "2.14.0", "auth_required": True},
    }
    line = web_panels.render_panel(record, module.upper())[0]
    assert line.endswith("(version:2.14.0) (UI)")
    _runner(module).emit_line(line)
    text = capsys.readouterr().out
    _assert_color(text, "(version:2.14.0)", "1;97")
    _assert_color(text, "(UI)", "1;97")
    assert "\x1b[1;92mauth required:True\x1b[0m" in text


def test_ui_colorizer_declines_backend_credentials_without_emitting(capsys):
    assert not web_panels.colorize_panel_line(
        Console(), "ELASTIC\t127.0.0.1\t9200\t [+] logstash:logstash (Nodes:3)", "ELASTIC"
    )
    assert not capsys.readouterr().out


@pytest.mark.parametrize("vendor", ["kafbat", "provectus", "akhq", "redpanda_console"])
def test_kafka_ui_version_and_pairs_share_standard_palette(vendor, capsys):
    from redposture_core.modules.kafka import render

    record = {
        "host": "127.0.0.1",
        "port": 8080,
        "is_kafka_ui": True,
        "ui_vendor": vendor,
        "auth_required": True,
        "version": "1.4.2",
        "status": "valid_credentials",
        "provided_username": "user",
        "provided_password": "secret",
    }
    console = _ColorConsole()
    detection = render._format_detect_record(record, "txt")
    pair = render._format_record(record, "txt")
    assert detection.endswith("(UI)") and pair.endswith("user:secret (UI)")
    render._render_colored_kafka_line(console, detection)
    text = capsys.readouterr().out
    assert "\x1b[1;97m) (version:1.4.2) (UI)\x1b[0m" in text
    render._render_colored_kafka_line(console, pair)
    text = capsys.readouterr().out
    _assert_color(text, "user:secret", "1;38;5;196")
    _assert_color(text, "(UI)", "1;97")


@pytest.mark.parametrize("module", ["portainer", "mongodb", "elastic", "redis", "postgres", "kubeapi", "minio"])
def test_saved_reports_and_no_color_preserve_plain_backend_payload(module, tmp_path: Path, capsys):
    line = f"{module.upper()}\t127.0.0.1\t9200\t [+] user:secret (Nodes:3)"
    text_path = tmp_path / "result.txt"
    sink = LineOutputSink(str(text_path), _runner(module).emit_line)
    try:
        sink.emit_many([line])
    finally:
        sink.close()
    assert "\x1b" in capsys.readouterr().out
    assert text_path.read_text() == line + "\n"
    _runner(module, no_color=True).emit_line(line)
    assert "\x1b" not in capsys.readouterr().out
    payload = {"module": module, "credential_state": "valid", "username": "user", "password": "secret"}
    json_path = tmp_path / "result.json"
    sink = LineOutputSink(str(json_path), _runner(module).emit_line)
    try:
        sink.emit_many([json.dumps(payload)])
    finally:
        sink.close()
    assert "\x1b" not in capsys.readouterr().out
    assert json.loads(json_path.read_text()) == payload
