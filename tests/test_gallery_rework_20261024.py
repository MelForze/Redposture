"""User-visible regressions from the five pending gallery remarks."""

from __future__ import annotations

import importlib
from dataclasses import replace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.stage_runtime import AuditCommandRunner
from tests.test_credential_color_contract import _assert_color, _ColorConsole
from tests.test_token_audit_modules import context


@pytest.mark.parametrize("module", ["kafka", "portainer", "nexus"])
def test_execute_does_not_append_product_labels_to_heading_command_or_stdout(module):
    path = "registry.product_render" if module == "nexus" else module + ".render"
    render = importlib.import_module("redposture_core.modules." + path)
    record = {
        "host": "qa",
        "port": 80,
        "module": module,
        "execution": {
            "command": 'echo "literal (UI)"',
            "executed": True,
            "exit_code": 0,
            "stdout": "literal (UI)\nlast line",
            "stderr": "",
            "status": "complete",
        },
    }
    lines = render._format_execution_records(record, "txt")
    assert [line.split("\t", 3)[3] for line in lines] == [
        " [*] Execute Command",
        ' command=echo "literal (UI)"',
        " literal (UI)",
        " last line",
    ]
    assert render._format_execution_records(record, "json") == []
    assert "\x1b" not in "\n".join(lines)


def test_portainer_credentials_drop_ui_suffix_but_keep_standard_colors(capsys):
    from redposture_core.modules.portainer import render

    record = {
        "host": "qa",
        "port": 9443,
        "status": "valid_credentials",
        "credential_state": "valid",
        "provided_username": "admin",
        "provided_password": "secret",
    }
    line = render._format_record(record, "txt")
    assert line.endswith(" [+] admin:secret")
    assert render.colorize(_ColorConsole(), line)
    output = capsys.readouterr().out
    _assert_color(output, "[+]", "1;92")
    _assert_color(output, "admin:secret", "1;38;5;196")


@pytest.mark.parametrize("show_contents,discover", [(False, True), (True, True), (True, False)])
def test_jupyter_discover_reads_notebooks_without_implicitly_printing_inventory(show_contents, discover):
    from redposture_core.modules.jupyter import actions, render

    root = {
        "name": "",
        "path": "",
        "type": "directory",
        "content": [{"name": "qa.ipynb", "path": "qa.ipynb", "type": "notebook"}],
    }
    notebook = {
        "name": "qa.ipynb",
        "path": "qa.ipynb",
        "type": "notebook",
        "content": {"cells": [{"cell_type": "code", "source": ['password = "qa-secret"']}]},
    }
    ctx = context(
        {"/api/contents?content=1": (200, root), "/api/contents/qa.ipynb?content=1": (200, notebook)},
        show_contents=show_contents,
        discover=discover,
    )
    result = actions.data_record(
        ctx, {"host": "qa", "port": 8888, "api_endpoint": "http://qa:8888", "status": "open_no_auth"}
    )
    if discover:
        assert result["notebook_contents"][0]["notebook"]["cells"][0]["source"] == ['password = "qa-secret"']
    assert (
        any("Contents Enumeration" in line for line in render._format_inventory_records(result, "txt")) is show_contents
    )
    assert bool(result.get("contents"))


@pytest.mark.parametrize(
    "access,want,color", [("allowed", "True", "1;38;5;196"), ("denied", "False", "1;92"), ("unverified", None, None)]
)
def test_nomad_detection_reports_only_verified_job_registration(access, want, color, capsys):
    from redposture_core.modules.nomad import render

    record = {
        "host": "qa",
        "port": 4646,
        "is_nomad": True,
        "acl_enabled": False,
        "auth_required": False,
        "version": "1.10.1",
        "submit_probe": {"access": access},
    }
    line = render._format_detect_record(record, "txt")
    if want is None:
        assert "Job registration allowed:" not in line
    else:
        assert f"(ACL enabled:False) (Job registration allowed:{want})" in line
        assert line.endswith("(version:1.10.1)")
        render._render_colored_nomad_line(_ColorConsole(), line)
        _assert_color(capsys.readouterr().out, f"Job registration allowed:{want}", color)


def test_nomad_probe_prints_one_final_detection_with_registration_result():
    from redposture_core.modules.nomad import actions
    from redposture_core.modules.nomad.stage import build_nomad_plan, build_nomad_spec

    ctx = context(
        {
            "/v1/agent/self": (200, {"config": {"Version": "1.10.1", "ACL": {"Enabled": False}}, "stats": {}}),
            "/v1/status/leader": (200, "qa:4647"),
            "/v1/jobs?namespace=default": (200, []),
        },
        probe_submit=True,
    )
    payload = actions.detect_record(ctx)
    args = parse_args(["nomad", "-t", "127.0.0.1", "--probe-submit", "--no-color"])
    spec = replace(
        build_nomad_spec(args),
        lifecycle_state_factory=None,
        lifecycle_state_close=None,
        detect=lambda _: AuditRecord.from_mapping(payload, module="nomad"),
        auth=None,
        data=lambda _, rec: AuditRecord.from_mapping(
            {**rec.to_dict(), "submit_probe": {"access": "allowed"}}, module="nomad"
        ),
    )
    lines = []
    AuditCommandRunner(args=args, spec=spec, emit_line=lines.append).run_plan(build_nomad_plan(args))
    detections = [line for line in lines if "HashiCorp Nomad" in line]
    assert len(detections) == 1
    assert "(Job registration allowed:True)" in detections[0]
    assert "\x1b" not in "\n".join(lines)
