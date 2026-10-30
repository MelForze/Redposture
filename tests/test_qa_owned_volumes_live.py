"""Small sequential real Docker controls; opt in explicitly."""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest

from scripts.qa_owned_volumes import guarded_command

pytestmark = pytest.mark.skipif(os.environ.get("REDPOSTURE_REAL_QA") != "1", reason="serial Docker ownership QA")


@pytest.mark.parametrize("failed_seed", [False, True])
def test_compose_cleanup_preserves_external_volume_after_normal_or_failed_seed(
    tmp_path: Path, failed_seed: bool
) -> None:
    project = "rp-volumes-" + uuid.uuid4().hex[:12]
    original = project + "-original"

    def run(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, capture_output=True, text=True, timeout=45, check=True)

    before = set(run(["docker", "volume", "ls", "-q"]).stdout.split())
    run(["docker", "volume", "create", original])
    fixture = tmp_path / "compose.json"
    fixture.write_text(
        json.dumps(
            {
                "services": {
                    "test": {
                        "image": "alpine:3.20",
                        "command": ["sleep", "300"],
                        "cpus": 0.25,
                        "mem_limit": "32m",
                        "volumes": ["/anonymous", "owned:/owned", "original:/original"],
                    }
                },
                "volumes": {"owned": {}, "original": {"external": True, "name": original}},
            }
        )
    )
    compose = ["docker", "compose", "-p", project, "-f", str(fixture)]
    try:
        run(guarded_command([*compose, "up", "-d", "--pull", "never"], tmp_path))
        if failed_seed:
            result = subprocess.run(
                [*compose, "exec", "-T", "test", "sh", "-c", "exit 23"], capture_output=True, timeout=15
            )
            assert result.returncode == 23
    finally:
        run(guarded_command([*compose, "down", "--volumes"], tmp_path))
    after = set(run(["docker", "volume", "ls", "-q"]).stdout.split())
    try:
        assert after == before | {original}
        ledger = json.loads(next((tmp_path / "volumes").glob("*.json")).read_text())
        assert ledger["containers"] and len(ledger["volumes"]) == 2
        assert original not in ledger["volumes"] and not ledger["cleanup_errors"]
    finally:
        run(["docker", "volume", "rm", original])


def test_interrupted_startup_preserves_mount_evidence_for_emergency_cleanup(tmp_path: Path) -> None:
    import time

    project = "rp-volume-interrupt-" + uuid.uuid4().hex[:10]
    fixture = tmp_path / "compose.json"
    fixture.write_text(
        json.dumps(
            {
                "services": {
                    "test": {
                        "image": "alpine:3.20",
                        "command": ["sleep", "300"],
                        "cpus": 0.25,
                        "mem_limit": "32m",
                        "volumes": ["/anonymous"],
                        "healthcheck": {"test": ["CMD", "false"], "interval": "2s", "retries": 40},
                    }
                }
            }
        )
    )
    compose = ["docker", "compose", "-p", project, "-f", str(fixture)]
    before = set(
        subprocess.run(
            ["docker", "volume", "ls", "-q"], capture_output=True, text=True, check=True, timeout=15
        ).stdout.split()
    )
    child = subprocess.Popen(
        guarded_command([*compose, "up", "-d", "--pull", "never", "--wait", "--wait-timeout", "90"], tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 20
        while not subprocess.run(
            [*compose, "ps", "-q", "test"], capture_output=True, text=True, timeout=10
        ).stdout.strip():
            assert time.monotonic() < deadline
            time.sleep(0.1)
        child.terminate()
        child.communicate(timeout=20)
        assert child.returncode != 0
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
        subprocess.run(
            guarded_command([*compose, "down", "--volumes"], tmp_path),
            check=True,
            capture_output=True,
            text=True,
            timeout=45,
        )
    after = set(
        subprocess.run(
            ["docker", "volume", "ls", "-q"], capture_output=True, text=True, check=True, timeout=15
        ).stdout.split()
    )
    assert after == before
    ledger = json.loads(next((tmp_path / "volumes").glob("*.json")).read_text())
    assert ledger["volumes"] and not ledger["cleanup_errors"]
