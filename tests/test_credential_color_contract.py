"""One credential-pair palette through every registered audit renderer."""

from __future__ import annotations

import json
import re
from typing import TextIO

import pytest

from redposture_core.console import Console
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.rendering import BooleanColorRule, render_colored_marker_line, render_module_marker_line
from redposture_core.stage_runtime import AuditCommandRunner, LineOutputSink
from redposture_core.stage_spray import Candidate, SpraySink
from tests.test_audit_output_contracts_extended import _build_real_spec

_SGR = re.compile(r"\x1b\[([0-9;]*)m")


class _ColorConsole(Console):
    def _use_color(self, stream: TextIO) -> bool:
        return not self._no_color


def _assert_color(output: str, fragment: str, expected: str) -> None:
    plain = ""
    colors: list[str] = []
    current = ""
    cursor = 0
    for match in _SGR.finditer(output):
        chunk = output[cursor : match.start()]
        plain += chunk
        colors.extend([current] * len(chunk))
        current = "" if match[1] in {"", "0"} else match[1]
        cursor = match.end()
    plain += output[cursor:]
    colors.extend([current] * len(output[cursor:]))
    start = plain.index(fragment)
    assert set(colors[start : start + len(fragment)]) == {expected}, output


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_all_module_renderers_color_only_the_pair_by_its_verdict(module, capsys):
    spec = _build_real_spec(module)
    assert spec.colorize is not None
    console = _ColorConsole()
    for pair in ("user:secret", "user:", ":secret", "user:pass with spaces", "юзер:p(a)ss:word"):
        for suffix in ("", " (UI)"):
            for marker, marker_color, pair_color in (("[+]", "1;92", "1;38;5;196"), ("[-]", "1;38;5;196", "1;97")):
                assert spec.colorize(console, f"{spec.label}\tqa\t1234\t {marker} {pair}{suffix}")
                output = capsys.readouterr().out
                _assert_color(output, marker, marker_color)
                _assert_color(output, pair, pair_color)
                if suffix:
                    _assert_color(output, "(UI)", "1;97")


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_all_module_no_color_and_saved_txt_json_remain_plain(module, tmp_path, capsys):
    spec = _build_real_spec(module)
    runner = AuditCommandRunner(args=object(), spec=spec, console=_ColorConsole(no_color=True))
    txt = tmp_path / "out.txt"
    line = f"{spec.label}\tqa\t1234\t [+] user:secret (UI)"
    sink = LineOutputSink(str(txt), runner.emit_line)
    try:
        sink.emit_many([line])
    finally:
        sink.close()
    assert txt.read_text() == line + "\n"
    assert "\x1b" not in capsys.readouterr().out
    payload = {"module": module, "username": "user", "password": "secret", "status": "valid_credentials"}
    path = tmp_path / "out.json"
    sink = LineOutputSink(str(path), runner.emit_line)
    try:
        sink.emit_many([json.dumps(payload)])
    finally:
        sink.close()
    assert json.loads(path.read_text()) == payload
    assert "\x1b" not in path.read_text() + capsys.readouterr().out


@pytest.mark.parametrize("marker,color", [("[+]", "1;38;5;196"), ("[-]", "1;97")])
def test_pair_verdict_overrides_local_broad_spans_without_recoloring_metadata(marker, color, capsys):
    payload = "user:password (admin:True) (UI)"
    render_module_marker_line(
        _ColorConsole(),
        f"DEMO\tqa\t80\t {marker} {payload}",
        tag="DEMO",
        spans=[(0, len(payload), "orange")],
    )
    output = capsys.readouterr().out
    _assert_color(output, "user:password", color)
    _assert_color(output, "admin:True", "1;38;5;208")


def test_successful_pair_uses_same_red_as_postgres_superuser_true(capsys):
    assert render_colored_marker_line(
        _ColorConsole(),
        "POSTGRES\tqa\t5432\t [+] user:secret (superuser:True)",
        tag="POSTGRES",
        booleans=(BooleanColorRule("superuser"),),
    )
    output = capsys.readouterr().out
    _assert_color(output, "user:secret", "1;38;5;196")
    _assert_color(output, "superuser:True", "1;38;5;196")


@pytest.mark.parametrize(
    "module,payload",
    [
        ("jupyter", "Token accepted"),
        ("nomad", "Token accepted"),
        ("vault", "Vault token accepted (policies:1)"),
        ("keycloak", "Bearer token accepted"),
        ("portainer", "Token accepted (UI)"),
        ("nexus", "token auth"),
    ],
)
def test_successful_token_uses_same_red_as_credential_pair(module, payload, capsys):
    spec = _build_real_spec(module)
    assert spec.colorize is not None
    assert spec.colorize(_ColorConsole(), f"{spec.label}\tqa\t1234\t [+] {payload}")
    output = capsys.readouterr().out
    _assert_color(output, "[+]", "1;92")
    token_label = payload.removesuffix(" (UI)").split(" (", 1)[0]
    _assert_color(output, token_label, "1;38;5;196")
    if payload.endswith(" (UI)"):
        _assert_color(output, "(UI)", "1;97")


@pytest.mark.parametrize("payload", ["https://qa/path", '{"name":"value"}', "Command Execution (mode:groovy)"])
def test_inventory_and_execution_rows_are_not_credential_pairs(payload, capsys):
    render_module_marker_line(_ColorConsole(), f"DEMO\tqa\t80\t [+] {payload}", tag="DEMO")
    _assert_color(capsys.readouterr().out, payload, "1;97")


@pytest.mark.parametrize("pair", ["user:password (ordinary words)", "user:password (ordinary words) (UI)"])
def test_parentheses_in_a_password_do_not_end_the_credential_span(pair, capsys):
    render_module_marker_line(_ColorConsole(), f"DEMO\tqa\t80\t [+] {pair}", tag="DEMO")
    _assert_color(capsys.readouterr().out, "user:password (ordinary words)", "1;38;5;196")


@pytest.mark.parametrize("status", ["valid", "invalid", "inconclusive"])
def test_spray_uses_the_same_pair_palette_with_capability_details(status, tmp_path, capsys):
    path = tmp_path / "spray.txt"
    sink = SpraySink(str(path), "txt", [Candidate("pair", "user", "secret")], _ColorConsole())
    try:
        sink.emit("elastic", "qa", 9200, 0, status, "product verifier", "(Nodes:3) (Users:Access Denied)")
    finally:
        sink.close()
    output = capsys.readouterr().out
    _assert_color(output, "[+]" if status == "valid" else "[-]", "1;92" if status == "valid" else "1;38;5;196")
    _assert_color(output, "user:secret", "1;38;5;196" if status == "valid" else "1;97")
    if status == "valid":
        _assert_color(output, "Nodes:3", "1;38;5;196")
        _assert_color(output, "Users:Access Denied", "1;92")
    assert "\x1b" not in path.read_text()
