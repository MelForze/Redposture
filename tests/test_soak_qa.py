from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.local_output_audit

ROOT = Path(__file__).resolve().parents[1]


def test_short_soak_processes_repeated_large_plans_without_resource_leaks() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/run_soak_qa.py",
            "--targets",
            "10000",
            "--workers",
            "128",
            "--duration",
            "0",
            "--rounds",
            "2",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout.strip())
    assert report["processed"] == 20_000
    assert report["rounds"] == 2
    assert report["threads_after"] <= report["threads_before"]
