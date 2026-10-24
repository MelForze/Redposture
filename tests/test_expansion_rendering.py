"""Jenkins' low-covered renderer branches retain operation and color semantics."""

from __future__ import annotations

from typing import Any

import pytest

from redposture_core.console import Console
from redposture_core.modules.jenkins import render


@pytest.mark.parametrize("field", ["jobs", "builds", "plugins", "nodes", "queue", "artifacts"])
@pytest.mark.parametrize("access,expected", [("denied", "Access Denied"), ("unknown", "Unknown"), (None, None)])
def test_requested_but_unavailable_inventory_never_looks_like_an_empty_list(
    field: str, access: str | None, expected: str | None
) -> None:
    record = {"host": "qa", "port": 8080, field + "_requested": True, field + "_access": access, field: None}
    lines = render._format_inventory_records(record, "txt")
    if expected is None:
        assert lines == []
    else:
        assert len(lines) == 1 and f"(access:{expected})" in lines[0]
        assert ":0)" not in lines[0]
    assert render._format_inventory_records(record, "json") == []


def test_nodes_and_artifacts_keep_unknown_counts_distinct_from_zero() -> None:
    record = {
        "host": "qa",
        "port": 8080,
        "nodes_requested": True,
        "artifacts_requested": True,
        "nodes": [None, {"name": "agent", "offline": None, "executors": None, "busy": None}],
        "artifacts": [None, {"name": "report.txt", "job": "build", "build": 1, "size_bytes": None}],
    }
    lines = render._format_inventory_records(record, "txt")
    assert len(lines) == 4
    assert "(online:Unknown) (executors:Unknown) (busy:Unknown)" in lines[1]
    assert "(size_bytes:Unknown)" in lines[3]


@pytest.mark.parametrize("field", ["job_discovery", "builds", "artifacts"])
def test_partial_inventory_carries_reason_instead_of_silently_completing(field: str) -> None:
    record: dict[str, Any] = {"host": "qa", "port": 8080, field + "_partial": True}
    lines = render._format_inventory_records(record, "txt")
    assert len(lines) == 1 and "(status:partial)" in lines[0] and "incomplete" in lines[0]
    record["discovery_errors" if field == "job_discovery" else field + "_errors"] = ["HTTP 503"]
    assert "HTTP 503" in render._format_inventory_records(record, "txt")[0]


@pytest.mark.parametrize(
    "access,count,expected", [("allowed", 0, "0"), ("allowed", None, "Unknown"), ("denied", 3, "Access Denied")]
)
def test_selected_token_credential_summary_keeps_capability_state(
    access: str, count: int | None, expected: str
) -> None:
    record = {
        "credential_state": "valid",
        "credential_results": [{"username": "qa"}],
        "credential_password": "API token",
        "credential_jobs_access": access,
        "credential_jobs_count": count,
    }
    assert f"[+] qa (API token) (Jobs:{expected})" in render._format_record(record, "txt")
    assert render._format_record(record, "json") == ""


def test_attempt_rendering_handles_token_failure_and_skips_only_selected_success() -> None:
    record = {
        "credential_results": [{"username": "chosen"}],
        "credential_password": "secret",
        "attempted_credentials": [
            None,
            {
                "username": "token-user",
                "password": "never-print",
                "source": "api_token",
                "status": "invalid_credentials",
            },
            {"username": "chosen", "password": "secret", "status": "valid_credentials"},
            {"username": "other", "password": "pass", "status": "valid_credentials"},
            {"username": "pending", "password": "pass", "status": "auth_required"},
        ],
    }
    lines = render._format_credential_attempts_records(record, "txt")
    assert len(lines) == 2
    assert "[-] token-user (API token)" in lines[0] and "never-print" not in lines[0]
    assert "[+] other:pass" in lines[1]
    assert render._format_credential_attempts_records(record, "json") == []
    assert (
        render._format_credential_attempts_records({"credential_state": "invalid", "credential_results": []}, "txt")
        == []
    )


@pytest.mark.parametrize("access,color", [("Access Denied", "\x1b[1;92m"), ("Unknown", "\x1b[1;38;5;208m")])
def test_access_state_color_and_plain_saved_line_are_independent(
    access: str, color: str, capsys: pytest.CaptureFixture[str]
) -> None:
    line = f"JENKINS\tqa\t8080\t [*] Jobs Enumeration (access:{access})"
    assert render._render_colored_jenkins_line(Console(no_color=False), line)
    colored = capsys.readouterr().out
    assert f"{color}access:{access}\x1b[0m" in colored
    assert render._render_colored_jenkins_line(Console(no_color=True), line)
    plain = capsys.readouterr().out
    assert f"(access:{access})" in plain and "\x1b" not in plain


def test_renderer_ignores_foreign_module_and_keeps_untagged_detail() -> None:
    assert not render._render_colored_jenkins_line(Console(no_color=True), "REDIS\tqa\t6379\t [*] foreign")
    assert render._render_colored_jenkins_line(Console(no_color=True), "JENKINS\tqa\t8080\t raw detail")
