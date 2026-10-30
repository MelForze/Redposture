"""The optional long QA section must finish or report a bounded failure."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_qa_with_timeout.py"


def test_qa_timeout_runner_preserves_success_and_output() -> None:
    result = subprocess.run(
        [sys.executable, str(RUNNER), "2", "--", sys.executable, "-c", "print('done')"],
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 0
    assert result.stdout == "done\n"


def test_qa_timeout_runner_stops_and_reports_overlong_child() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "0.2",
            "--",
            sys.executable,
            "-c",
            "import time; print('started', flush=True); time.sleep(10)",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 124
    assert result.stdout == "started\n"
    assert "timed out after 0.2 seconds" in result.stderr
