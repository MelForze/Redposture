"""Execution TXT follows the PostgreSQL example across gallery modules."""

from __future__ import annotations

import pytest

from redposture_core.modules.execution_api import render as render_execution
from redposture_core.modules.jenkins import render as jenkins_render
from redposture_core.modules.spark import render as spark_render
from redposture_core.modules.token_render import inventory as token_inventory
from redposture_core.modules.yarn import render as yarn_render


@pytest.mark.parametrize(
    "module",
    ["kafka", "consul", "jenkins", "nomad", "spark", "yarn", "portainer", "jupyter", "nexus"],
)
def test_gallery_execution_uses_postgres_heading_command_and_unlabelled_output(module: str) -> None:
    record = {
        "host": "qa",
        "port": 80,
        "execution": {
            "command": "id && whoami",
            "mode": "test",
            "executed": True,
            "exit_code": 0,
            "stdout": "uid=1000(qa)\nqa\n",
            "stderr": "",
            "status": "complete",
            "cleanup": "complete",
        },
    }
    assert render_execution(module, record) == [
        f"{module.upper()}\tqa\t80\t [*] Execute Command",
        f"{module.upper()}\tqa\t80\t command=id && whoami",
        f"{module.upper()}\tqa\t80\t uid=1000(qa)",
        f"{module.upper()}\tqa\t80\t qa",
    ]


def test_execution_failures_use_postgres_error_line_without_old_status_rows() -> None:
    base = {"host": "qa", "port": 80}
    failed = render_execution(
        "spark",
        {
            **base,
            "execution": {
                "command": "exit 7",
                "executed": True,
                "exit_code": 7,
                "stdout": "out",
                "stderr": "err",
                "status": "complete",
            },
        },
    )
    assert failed[0].endswith(" [*] Execute Command")
    assert failed[1].endswith(" command=exit 7")
    assert failed[2].endswith(" out")
    assert failed[3].endswith(" err")
    assert failed[4].endswith(" <error:command exited with status 7>")
    assert not any("Command Execution" in line or "stdout:" in line or "stderr:" in line for line in failed)
    unverified = render_execution(
        "spark", {**base, "execution": {"command": "id", "executed": False, "error": "access denied"}}
    )
    assert unverified[-1].endswith(" <error:access denied>")


def test_jenkins_uses_verified_identity_when_redacted_json_omits_credential_results() -> None:
    record = {
        "host": "qa",
        "port": 8080,
        "credential_state": "valid",
        "authenticated_identity": "admin",
        "credential_password": "admin",
        "credential_jobs_access": "allowed",
        "credential_jobs_count": 2,
    }
    assert "[+] admin:admin (Jobs:2)" in jenkins_render._format_record(record, "txt")


def test_confirmed_spark_execution_does_not_end_with_rce_potential() -> None:
    record = {"host": "qa", "port": 6066, "rce_potential": True, "execute_verified": True}
    assert not any("RCE:potential" in line for line in spark_render._format_inventory_records(record, "txt"))


@pytest.mark.parametrize("renderer", [spark_render._format_inventory_records, yarn_render._format_inventory_records])
def test_explicit_cluster_enumeration_does_not_emit_rce_potential(renderer) -> None:
    record = {"host": "qa", "port": 80, "rce_potential": True, "inventory_requested": ["apps"], "apps": []}
    assert not any("RCE:potential" in line for line in renderer(record, "txt"))


@pytest.mark.parametrize("module,resource", [("nomad", "jobs"), ("jupyter", "contents")])
def test_token_inventory_omits_rce_potential_during_explicit_enumeration(module: str, resource: str) -> None:
    record = {
        "host": "qa",
        "port": 80,
        "rce_potential": True,
        "rce_surfaces": ["kernel"],
        "inventory_requested": [resource],
        resource: [],
        resource + "_access": "allowed",
    }
    assert not any("RCE:potential" in line for line in token_inventory(module, record, "txt"))
    render = __import__(f"redposture_core.modules.{module}.render", fromlist=["_format_detect_record"])
    assert "(RCE:Possible)" in render._format_detect_record({**record, f"is_{module}": True}, "txt")
