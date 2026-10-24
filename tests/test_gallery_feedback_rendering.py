"""Regressions reproduced from the real output-gallery review."""

from __future__ import annotations

import importlib
import json
from dataclasses import replace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.modules.jupyter import render as jupyter_render
from redposture_core.modules.nomad import render as nomad_render
from redposture_core.modules.portainer import render as portainer
from redposture_core.modules.portainer.stage import build_portainer_plan, build_portainer_spec
from redposture_core.modules.registry import product_render
from redposture_core.modules.spark import render as spark_render
from redposture_core.modules.vault import render as vault_render
from redposture_core.modules.yarn import render as yarn_render
from redposture_core.stage_runtime import AuditCommandRunner
from tests.test_credential_color_contract import _assert_color, _ColorConsole
from tests.test_portainer_render_contract import record as portainer_record
from tests.test_token_audit_modules import context


def test_sealed_vault_omits_unverifiable_auth_required():
    line = vault_render._format_detect_record(
        {
            "host": "qa",
            "port": 8200,
            "is_vault": True,
            "auth_required": None,
            "initialized": False,
            "sealed": True,
            "standby": True,
            "version": "1.21.0",
        },
        "txt",
    )
    assert "HashiCorp Vault" in line and "(initialized:False)" in line
    assert "auth required:unknown" not in line


def test_nomad_detection_omits_unknown_acl_and_version():
    line = nomad_render._format_detect_record(
        {
            "host": "qa",
            "port": 4646,
            "is_nomad": True,
            "auth_required": True,
            "acl_enabled": None,
            "version": None,
        },
        "txt",
    )
    assert "HashiCorp Nomad (auth required:True)" in line
    assert "ACL enabled:" not in line and "version:" not in line


def test_spark_rce_potential_is_on_detection_line_not_duplicate_detail():
    record = {
        "host": "qa",
        "port": 6066,
        "is_spark": True,
        "auth_required": False,
        "version": "3.5.6",
        "surface": "submission_rest",
        "rce_potential": True,
        "submit_probe": {"parser_reachable": True, "access": "unverified"},
    }
    assert "(RCE:Possible)" in spark_render._format_detect_record(record, "txt")
    lines = spark_render._format_inventory_records(record, "txt")
    assert len(lines) == 1 and "Submission Probe" in lines[0]
    assert all("RCE:potential" not in line for line in lines)


def test_yarn_zero_metrics_are_observations_not_safe_denials(capsys):
    line = 'YARN\tqa\t8088\t [+] Metric "appsSubmitted"=0'
    assert yarn_render._render_colored_yarn_line(_ColorConsole(), line)
    output = capsys.readouterr().out
    _assert_color(output, 'Metric "appsSubmitted"=0', "1;38;5;208")


def test_jupyter_accepted_token_uses_credential_red(capsys):
    assert jupyter_render._render_colored_jupyter_line(_ColorConsole(), "JUPYTER\tqa\t8888\t [+] Token accepted")
    output = capsys.readouterr().out
    _assert_color(output, "[+]", "1;92")
    _assert_color(output, "Token accepted", "1;38;5;196")


def test_nexus_redacted_json_credentials_do_not_look_empty():
    line = product_render._format_record(
        {
            "module": "nexus",
            "host": "qa",
            "port": 8081,
            "status": "valid_credentials",
            "provided_credentials": True,
            "provided_username": "admin",
        },
        "txt",
    )
    assert line.endswith("[+] admin:<redacted>")
    empty = product_render._format_record(
        {
            "module": "nexus",
            "host": "qa",
            "port": 8081,
            "status": "valid_credentials",
            "provided_credentials": True,
            "provided_username": "admin",
            "provided_password": "",
        },
        "txt",
    )
    assert empty.endswith("[+] admin:<empty>")
    username_only = product_render._format_record(
        {"module": "nexus", "host": "qa", "port": 8081, "status": "auth_required", "provided_username": "admin"},
        "txt",
    )
    assert "<redacted>" not in username_only


@pytest.mark.parametrize(
    "module,label",
    [
        ("vault", "Vault token rejected"),
        ("nomad", "Token rejected"),
        ("jupyter", "Token rejected"),
        ("keycloak", "Bearer token rejected"),
    ],
)
def test_rejected_token_label_is_white_with_a_red_minus(module, label, capsys):
    render = importlib.import_module(f"redposture_core.modules.{module}.render")
    assert getattr(render, f"_render_colored_{module}_line")(
        _ColorConsole(), f"{module.upper()}\tqa\t8200\t [-] {label}"
    )
    output = capsys.readouterr().out
    _assert_color(output, "[-]", "1;38;5;196")
    _assert_color(output, label, "1;97")


@pytest.mark.parametrize("state", ["ok", "nonzero", "unverified", "timeout", "partial", "cleanup"])
def test_portainer_direct_runner_emits_execution_result_after_auth_and_inventory(state, capsys):
    payload = portainer_record()
    verified = state not in {"unverified", "timeout"}
    payload["execution"] = {
        "command": "id",
        "mode": "portainer_container_exec",
        "executed": verified,
        "exit_code": 7 if state == "nonzero" else 0 if verified else None,
        "stdout": "uid=1000(qa)\nqa" if verified else "partial-before-timeout" if state == "timeout" else "",
        "stderr": "qa-stderr" if state == "nonzero" else "",
        "status": "partial" if state == "partial" else "timeout" if state == "timeout" else "complete",
        "error": "deadline exceeded" if state == "timeout" else "no command proof" if state == "unverified" else None,
        "cleanup": "failed" if state == "cleanup" else "complete",
        "cleanup_error": "qa-cleanup-error",
    }
    args = parse_args(["portainer", "-t", "https://qa:9443", "--execute", "id"])
    runner = AuditCommandRunner(args=args, spec=build_portainer_spec(args), console=_ColorConsole())
    record = AuditRecord.from_mapping(payload, module="portainer", service="portainer")
    lines = runner._render_record(record, None, "txt", False)
    assert sum("Execute Command" in line for line in lines) == 1
    auth = next(i for i, line in enumerate(lines) if "admin:secret" in line)
    inventory = next(i for i, line in enumerate(lines) if "Containers Enumeration" in line)
    execution = next(i for i, line in enumerate(lines) if "Execute Command" in line)
    assert auth < inventory < execution
    assert all(not line.endswith(" (UI)") for line in lines[execution:])
    text = "\n".join(lines)
    if verified:
        assert "command=id" in text
        assert "uid=1000(qa)" in text and "\t qa" in text
    else:
        assert f"<error:{payload['execution']['error']}>" in text
    if state == "nonzero":
        assert "qa-stderr" in text and "<error:command exited with status 7>" in text
    if state == "timeout":
        assert "partial-before-timeout" in text
    if state == "partial":
        assert "<error:output incomplete>" in text
    if state == "cleanup":
        assert "<error:cleanup failed: qa-cleanup-error>" in text
    assert "Execute Command" not in portainer._format_record(payload, "txt")
    assert not any("Execute Command" in line for line in portainer._format_inventory_records(payload, "txt"))
    args_json = parse_args(["portainer", "-t", "https://qa:9443", "-f", "json"])
    spec_json = replace(
        build_portainer_spec(args_json),
        detect=lambda ctx: record,
        auth=lambda ctx, prior: prior,
        data=lambda ctx, prior: prior,
        lifecycle_state_factory=None,
    )
    rendered_json = []
    AuditCommandRunner(args=args_json, spec=spec_json, emit_line=rendered_json.append).run_plan(
        build_portainer_plan(args_json)
    )
    assert (
        next(json.loads(line) for line in rendered_json if "execution" in json.loads(line))["execution"]
        == payload["execution"]
    )
    assert "\x1b" not in text + "\n".join(rendered_json)
    for line in lines:
        runner.emit_line(line)
    output = capsys.readouterr().out
    _assert_color(output, "admin:secret", "1;38;5;196")


@pytest.mark.parametrize("show_jobs,discover", [(False, False), (True, False), (False, True), (True, True)])
def test_nomad_only_shows_job_inventory_with_explicit_flag(show_jobs, discover):
    from redposture_core.modules.nomad import actions, render

    ctx = context(
        {
            "/v1/jobs?namespace=default": (200, [{"ID": "qa-job"}]),
            "/v1/job/qa-job?namespace=default": (200, {"ID": "qa-job", "Env": {"password": "qa-secret"}}),
        },
        show_jobs=show_jobs,
        discover=discover,
    )
    result = actions.data_record(
        ctx, {"host": "qa", "port": 4646, "api_endpoint": "http://qa:4646", "status": "open_no_auth", "is_nomad": True}
    )
    lines = render._format_inventory_records(result, "txt")
    assert any("Jobs Enumeration" in line for line in lines) is show_jobs
    assert bool(ctx.lifecycle_state.http.calls) is (show_jobs or discover)
    if discover:
        assert result["job_specs"][0]["spec"]["Env"]["password"] == "qa-secret"
