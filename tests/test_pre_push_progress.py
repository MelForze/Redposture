from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_pre_push_streams_matrix_progress_and_keeps_complete_log(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_git = fake_bin / "git"
    fake_git.write_text(
        '#!/bin/sh\ncase "$1" in rev-parse) echo abc123;; status) echo " M example.py";; diff) exit 0;; esac\n',
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    fake_bash = fake_bin / "bash"
    fake_bash.write_text(
        '#!/bin/sh\necho "== prepare python3.12 =="\necho "== lint (python3.12) =="\n'
        'echo "All checks passed!"\necho "== tests python3.12 =="\n'
        'echo "................ [  9%]"\necho "Required test coverage of 85.0% reached."\n'
        'echo "Full log detail that should stay out of the concise progress view"\n',
        encoding="utf-8",
    )
    fake_bash.chmod(0o755)
    report_dir = tmp_path / "report"
    env = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}")

    result = subprocess.run(
        ["/bin/bash", str(ROOT / "scripts/check_before_push.sh"), "--out", str(report_dir)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "[1/2] diff-check" in result.stdout
    assert "[2/2] ci-matrix" in result.stdout
    assert "== tests python3.12 ==" in result.stdout
    assert "[  9%]" in result.stdout
    assert "Full log detail" not in result.stdout
    assert "Full log detail" in (report_dir / "ci-matrix.log").read_text(encoding="utf-8")
    assert "| ci-matrix | 0 |" in (report_dir / "report.md").read_text(encoding="utf-8")


def test_pre_push_preserves_failing_matrix_exit_and_reports_log(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_git = fake_bin / "git"
    fake_git.write_text(
        '#!/bin/sh\ncase "$1" in rev-parse) echo abc123;; status) exit 0;; diff) exit 0;; esac\n',
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    fake_bash = fake_bin / "bash"
    fake_bash.write_text(
        '#!/bin/sh\necho "== tests python3.13 =="\necho "FAILED test_example"\nexit 7\n', encoding="utf-8"
    )
    fake_bash.chmod(0o755)
    report_dir = tmp_path / "report"
    env = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}")

    result = subprocess.run(
        ["/bin/bash", str(ROOT / "scripts/check_before_push.sh"), "--out", str(report_dir)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 7
    assert "== tests python3.13 ==" in result.stdout
    assert "[failed] ci-matrix (exit 7" in result.stderr
    assert "FAILED test_example" in result.stderr
    assert "| ci-matrix | 7 |" in (report_dir / "report.md").read_text(encoding="utf-8")
