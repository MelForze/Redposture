"""EXEC23 Portainer: the deadline belongs to the remote command process group."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
import time

from redposture_core.modules.portainer import execution


def _run(command: str, *, timeout: float = 1.0, cap: int = 1024, env=None):
    script = execution._wrapper(command, "RP_TEST:", timeout, cap)
    run = subprocess.run(["/bin/sh", "-c", script], capture_output=True, timeout=5, env=env)
    return execution._proof(run.stdout, "RP_TEST:")


def test_portainer_remote_wrapper_preserves_real_exit_and_both_streams() -> None:
    proof = _run("printf 'out\\n\\n'; printf 'err\\n' >&2; exit 7")
    assert proof["exit_code"] == 7
    assert proof["stdout"] == "out\n\n"
    assert proof["stderr"] == "err\n"
    assert proof["timed_out"] is False
    assert proof["truncated"] is False


def test_portainer_deadline_kills_background_command_tree_before_late_write(tmp_path) -> None:
    marker = tmp_path / "late"
    proof = _run(f"(sleep 0.7; printf LATE > {shlex.quote(str(marker))}) & wait", timeout=0.15)
    assert proof["timed_out"] is True
    time.sleep(0.8)
    assert not marker.exists()


def test_portainer_remote_output_is_bounded_without_losing_exit_evidence() -> None:
    command = f'{shlex.quote(sys.executable)} -c \'import sys; sys.stdout.write("X" * 262144); sys.stderr.write("Y" * 262144); sys.exit(9)\''
    proof = _run(command, cap=64)
    assert proof["exit_code"] == 9
    assert proof["stdout"] == "X" * 64
    assert proof["stderr"] == "Y" * 64
    assert proof["truncated"] is True
    assert proof["timed_out"] is False


def test_portainer_missing_remote_runtime_is_explicit_and_does_not_execute(tmp_path) -> None:
    marker = tmp_path / "sent"
    proof = _run(f"printf SENT > {shlex.quote(str(marker))}", env={**os.environ, "PATH": str(tmp_path)})
    assert proof["unsupported"] is True
    assert "Python" in proof["error"]
    assert not marker.exists()
