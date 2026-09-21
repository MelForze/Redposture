"""Process-level signal handling across every audit lifecycle stage."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


_SCRIPT = r"""
import json
import sys
import time
from dataclasses import replace
from pathlib import Path

from redposture_core import cli
from redposture_core.audit_models import AuditRecord
from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    ModuleAuditSpec,
)

stage = sys.argv[1]
output = Path(sys.argv[2])
checkpoint = Path(sys.argv[3])


def wait(name):
    if stage == name:
        if name == "data":
            checkpoint.write_text(json.dumps({"status": "running", "stage": name}) + "\n", encoding="utf-8")
        print(f"STAGE:{name}", flush=True)
        time.sleep(30)


def detect(ctx):
    wait("detect")
    return AuditRecord(host=ctx.host, port=ctx.port, module="qa", service="qa", status="detected")


def auth(ctx, record):
    wait("auth")
    return replace(record, status="valid_credentials")


def capabilities(ctx, record):
    wait("capabilities")
    return record


def data(ctx, record):
    wait("data")
    return record


def run(_args, _logger):
    spec = ModuleAuditSpec(
        module="qa",
        label="QA",
        default_port=1,
        detect=detect,
        auth=auth,
        capabilities=capabilities,
        data=data,
        is_detected=lambda _record: True,
        render=lambda record: [f"QA {record.host} {record.port} {record.status}"],
    )
    plan = AuditCommandPlan(
        targets_by_port={1: ("target",)},
        credential_runs=(AuditCredentialRun(username="qa", password="qa", source="provided"),),
        workers=1,
        output_path=str(output),
    )
    AuditCommandRunner(args=_args, spec=spec, emit_line=print).run_plan(plan)
    return 0


cli._run_command = run
raise SystemExit(cli.main(["redis", "-t", "127.0.0.1"]))
"""


def _wait_for_stage(process: subprocess.Popen[str], stage: str) -> str:
    assert process.stdout is not None
    deadline = time.monotonic() + 5
    output = ""
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        output += line
        if f"STAGE:{stage}" in line:
            return output
        if process.poll() is not None:
            break
    pytest.fail(f"stage {stage} did not start; output={output!r}")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process signals")
@pytest.mark.parametrize("stage", ["detect", "auth", "capabilities", "data"])
@pytest.mark.parametrize(("sent_signal", "expected_code"), [(signal.SIGINT, 130), (signal.SIGTERM, 143)])
def test_signals_unwind_every_lifecycle_stage_without_corrupting_files(
    tmp_path: Path,
    stage: str,
    sent_signal: signal.Signals,
    expected_code: int,
) -> None:
    output = tmp_path / "result.txt"
    checkpoint = tmp_path / "checkpoint.json"
    process = subprocess.Popen(
        [sys.executable, "-c", _SCRIPT, stage, str(output), str(checkpoint)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "NO_COLOR": "1"},
    )
    prefix = _wait_for_stage(process, stage)
    started = time.monotonic()
    process.send_signal(sent_signal)
    stdout, stderr = process.communicate(timeout=5)

    assert process.returncode == expected_code
    assert time.monotonic() - started < 3
    assert "Traceback" not in prefix + stdout + stderr
    assert output.read_text(encoding="utf-8") == ""
    if checkpoint.exists():
        assert json.loads(checkpoint.read_text(encoding="utf-8"))["stage"] == "data"
    if sent_signal == signal.SIGINT:
        assert "interrupted by user" in stderr
    else:
        assert "terminated by signal" in stderr
