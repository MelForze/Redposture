"""Proxmox output follows the Airflow palette without changing saved reports."""

from __future__ import annotations

import json

from redposture_core.console import Console
from redposture_core.modules.proxmox.actions import _render_colored_proxmox_line
from redposture_core.modules.proxmox.render import _format_vms_detail_records
from redposture_core.stage_runtime import LineOutputSink
from tests.test_credential_color_contract import _assert_color, _ColorConsole


def test_proxmox_token_and_auth_status_use_airflow_palette(capsys):
    for payload, fragment, color in (
        ("[+] token accepted (read:true)", "token accepted", "1;38;5;196"),
        ("[*] Proxmox API (auth required:True)", "auth required:True", "1;92"),
        ("[*] Proxmox API (auth required:False)", "auth required:False", "1;38;5;196"),
        ("[*] Proxmox API (auth required:unknown)", "auth required:unknown", "1;38;5;208"),
    ):
        assert _render_colored_proxmox_line(_ColorConsole(), f"PROXMOX\tqa\t8006\t {payload}")
        _assert_color(capsys.readouterr().out, fragment, color)


def test_proxmox_discovered_urls_and_vms_color_values_but_not_headings(capsys):
    for payload, value in (
        ("[*] https://qa:8006/api2/json/nodes/pve", "https://qa:8006/api2/json/nodes/pve"),
        ("[*] VM=101 Name=billing-api (execute:True) (type:qemu) (node:pve) (status:running)", "Name=billing-api"),
    ):
        assert _render_colored_proxmox_line(_ColorConsole(), f"PROXMOX\tqa\t8006\t {payload}")
        output = capsys.readouterr().out
        _assert_color(output, value, "1;38;5;208")
        if "execute:True" in payload:
            _assert_color(output, "execute:True", "1;38;5;196")
            _assert_color(output, "node:pve", "1;38;5;208")
            _assert_color(output, "status:running", "1;38;5;208")
    assert _render_colored_proxmox_line(_ColorConsole(), "PROXMOX\tqa\t8006\t [*] VMs Enumeration (Count:2)")
    output = capsys.readouterr().out
    _assert_color(output, "VMs Enumeration", "1;97")
    _assert_color(output, "Count:2", "1;38;5;196")


def test_proxmox_palette_is_console_only(tmp_path, capsys):
    record = {
        "host": "qa",
        "port": 8006,
        "show_vms": True,
        "vms": [{"vmid": 101, "name": "billing-api", "execute": True, "type": "qemu", "node": "pve"}],
    }
    line = _format_vms_detail_records(record, "txt")[1]
    assert "\x1b" not in line
    assert _render_colored_proxmox_line(Console(no_color=True), line)
    assert "\x1b" not in capsys.readouterr().out
    for name, saved_line in (("out.txt", line), ("out.json", json.dumps(record, ensure_ascii=False))):
        path = tmp_path / name
        sink = LineOutputSink(str(path), lambda value: _render_colored_proxmox_line(_ColorConsole(), value))
        sink.emit_many([saved_line])
        sink.close()
        assert "\x1b" not in path.read_text()
    assert json.loads((tmp_path / "out.json").read_text()) == record
