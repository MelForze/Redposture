"""EXEC23 Consul: one remote command, lossless separators, truthful output caps."""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest

from redposture_core.modules.consul import execution


@pytest.mark.parametrize("text", ["tail", "tail\n", "tail\n\n", "tail\r\n", "\n\n"])
def test_consul_proof_removes_only_the_wrapper_separator(text: str) -> None:
    assert execution._proof(text + "\nRP_TEST:7\n", "RP_TEST") == (text, 7)


def test_consul_periodic_checks_reuse_result_without_reexecuting(tmp_path) -> None:
    counter = tmp_path / "executions"
    guard = tmp_path / "guard"
    command = f"printf x >> {shlex.quote(str(counter))}; printf 'tail\\n\\n'; exit 7"
    script = execution._wrapper(command, "RP_TEST", max_bytes=64, guard_dir=str(guard))

    runs = [subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=3) for _ in range(4)]

    assert counter.read_text() == "x"
    assert {run.returncode for run in runs} == {7}
    assert {run.stdout for run in runs} == {"tail\n\n\nRP_TEST:7:0\n"}
    assert all(not child.is_dir() for child in guard.iterdir()), "capture work directories must be cleaned"


def test_consul_concurrent_periodic_check_cannot_start_second_command(tmp_path) -> None:
    counter = tmp_path / "executions"
    script = execution._wrapper(
        f"printf x >> {shlex.quote(str(counter))}; sleep 0.2; printf done",
        "RP_TEST",
        max_bytes=64,
        guard_dir=str(tmp_path / "guard"),
    )
    first = subprocess.Popen(["/bin/sh", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        second = subprocess.run(["/bin/sh", "-c", script], capture_output=True, timeout=3)
        stdout, _ = first.communicate(timeout=3)
    finally:
        if first.poll() is None:
            first.kill()
            first.wait()
    assert counter.read_text() == "x"
    assert b"RP_TEST:0:0" in stdout + second.stdout


def test_consul_remote_capture_bounds_large_output_without_losing_completion(tmp_path) -> None:
    command = f"{shlex.quote(sys.executable)} -c 'import sys; sys.stdout.write(\"X\" * 262144)'"
    script = execution._wrapper(command, "RP_TEST", max_bytes=64, guard_dir=str(tmp_path / "guard"))
    run = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=3)
    assert run.returncode == 0
    assert execution._proof(run.stdout, "RP_TEST") == ("X" * 64, 0)
    assert run.stdout.endswith("\nRP_TEST:0:1\n")
    assert len(run.stdout.encode()) < 256


def _collect(
    monkeypatch,
    *,
    product_truncation: bool,
    proof: bool = True,
    poll_status: int = 200,
    text: str = "tail",
    capture_truncated: bool = False,
):
    registered = []

    def register(*args, **_kwargs):
        registered.append(args[4])
        return 200, None, None

    monkeypatch.setattr(execution.actions, "_consul_put_json", register)
    monkeypatch.setattr(execution.actions, "_consul_put_no_body", Mock(return_value=(204, None)))
    monkeypatch.setattr(execution, "time", NS(monotonic=Mock(side_effect=[0.0, 0.0, 1000.0]), sleep=lambda _: None))

    def checks(*_a, **_kw):
        marker = re.search(r"RP_EXEC_END_[0-9a-f]+", registered[0]["Args"][2]).group()
        value = text + (f"\n{marker}:0:{int(capture_truncated)}\n" if proof else "")
        if product_truncation:
            value = "Captured 4096 of 262184 bytes\n...\n" + value
        return poll_status, {registered[0]["ID"]: {"Output": value, "Status": "passing"}}, None

    monkeypatch.setattr(execution.actions, "_consul_get_checks", checks)
    ctx = NS(args=NS(execute="printf tail", execute_timeout=1.0, execute_max_bytes=1048576))
    state = NS(host="consul.test", port=8500, scheme="http", insecure=False, auth_headers=None, execution=None)
    result = execution.collect(
        ctx, {"is_consul": True, "status": "open_no_auth", "detection_status": "confirmed", "rce": True}, state
    )
    return result, registered[0]


def test_consul_registration_reserves_server_output_for_capture_and_proof(monkeypatch) -> None:
    result, check = _collect(monkeypatch, product_truncation=False)
    assert result["execution"]["status"] == "complete"
    assert check.get("OutputMaxSize", 4096) > 1048576


@pytest.mark.parametrize("proof", [True, False])
def test_consul_server_truncation_is_partial_and_never_user_stdout(monkeypatch, proof: bool) -> None:
    result, _ = _collect(monkeypatch, product_truncation=True, proof=proof)
    output = result["execution"]
    assert output["status"] == "partial"
    assert output["truncated"] is True
    assert output["stdout"] == "tail"
    assert output["executed"] is proof
    assert result["execute_verified"] is proof


def test_consul_denied_poll_payload_cannot_prove_execution(monkeypatch) -> None:
    result, _ = _collect(monkeypatch, product_truncation=False, poll_status=403)
    assert result["execute_verified"] is False
    assert result["execution"]["exit_code"] is None
    assert "403" in result["execution"]["error"]


def test_consul_remote_truncation_proof_marks_result_partial(monkeypatch) -> None:
    result, _ = _collect(monkeypatch, product_truncation=False, capture_truncated=True)
    assert result["execute_verified"] is True
    assert result["execution"]["status"] == "partial"
    assert result["execution"]["truncated"] is True


def test_consul_command_stream_and_saved_json_have_no_ansi(monkeypatch) -> None:
    result, _ = _collect(monkeypatch, product_truncation=False, text="\x1b[31mtail\x1b[0m")
    assert result["execution"]["stdout"] == "tail"
    assert "\\u001b" not in json.dumps(result)
