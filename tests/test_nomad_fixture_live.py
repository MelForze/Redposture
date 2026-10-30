"""Cold starts of the genuine Nomad execution fixture, one client at a time."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from scripts.qa_owned_volumes import guarded_command
from scripts.wait_nomad_ready import wait_ready

pytestmark = pytest.mark.skipif(os.environ.get("REDPOSTURE_REAL_QA") != "1", reason="serial real Nomad execution QA")
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("cycle", range(3))
def test_cold_start_ready_execute_and_cleanup(tmp_path: Path, cycle: int) -> None:
    project = "rp-nomad-cold-" + uuid.uuid4().hex[:10]
    fixture = ROOT / "tests/fixtures/token_apis"

    def run(command: list[str], *, check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        with (tmp_path / "commands.log").open("a") as log:
            log.write(
                subprocess.list2cmdline(command)
                + "\n"
                + result.stdout
                + result.stderr
                + f"\nexit={result.returncode}\n"
            )
        if check:
            assert result.returncode == 0, result.stderr
        return result

    base = [
        "docker",
        "compose",
        "-p",
        project,
        "-f",
        str(fixture / "docker-compose.yml"),
        "-f",
        str(fixture / "nomad-execute-root.yml"),
        "--profile",
        "nomad-execute",
    ]
    config = json.loads(run([*base, "config", "--format", "json"]).stdout)
    service = config["services"]["nomad-execute"]
    service["profiles"] = []
    service["ports"] = [{"target": 4646, "published": "0", "host_ip": "127.0.0.1"}]
    resolved = tmp_path / "compose.json"
    resolved.write_text(json.dumps({"services": {"nomad-execute": service}}))
    compose = ["docker", "compose", "-p", project, "-f", str(resolved)]
    try:
        run(guarded_command([*compose, "up", "-d", "--pull", "never"], tmp_path))
        address = run([*compose, "port", "nomad-execute", "4646"]).stdout.strip()
        target = "http://" + address
        wait_ready(target, 150)
        for name, command, code, stdout in [
            ("success", "id; printf cold-start-ok", 0, "cold-start-ok"),
            ("failure", "printf stdout; printf stderr >&2; exit 7", 7, "stdout"),
        ]:
            output = tmp_path / (name + ".json")
            result = run(
                [
                    sys.executable,
                    str(ROOT / "redposture.py"),
                    "nomad",
                    "-t",
                    target,
                    "--execute",
                    command,
                    "--execute-timeout",
                    "45",
                    "--timeout",
                    "5",
                    "--no-color",
                    "-f",
                    "json",
                    "-o",
                    str(output),
                ],
                timeout=90,
            )
            raw = output.read_text()
            value = json.loads(raw)
            record = value[0] if isinstance(value, list) else value
            execution = record["execution"]
            assert execution["executed"] is True and execution["exit_code"] == code, execution
            assert stdout in execution["stdout"], execution
            assert not execution.get("cleanup_error"), execution
            assert "\x1b" not in raw + result.stdout
        import urllib.request

        with urllib.request.urlopen(target + "/v1/jobs", timeout=5) as response:
            assert not json.load(response), "temporary command jobs leaked"
    finally:
        run([*compose, "logs", "--no-color"], check=False)
        run(guarded_command([*compose, "down", "--volumes", "--remove-orphans"], tmp_path))
