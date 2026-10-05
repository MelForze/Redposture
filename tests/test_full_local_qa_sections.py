from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_full_local_qa.sh"


def _run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_full_qa_lists_and_plans_independent_sections(tmp_path: Path) -> None:
    listed = _run("--list")
    assert listed.returncode == 0
    assert "hypothesis" in listed.stdout
    assert "docker-matrix" in listed.stdout

    destination = tmp_path / "plan-only"
    planned = _run(str(destination), "--section", "hypothesis,pytest", "--section", "pytest", "--plan")
    assert planned.returncode == 0
    assert planned.stdout.splitlines()[-2:] == ["section: hypothesis", "section: pytest"]
    assert not destination.exists()

    invalid = _run(str(destination), "--section", "not-a-section")
    assert invalid.returncode == 2
    assert "unknown QA section" in invalid.stderr
    assert not destination.exists()


def test_selected_qa_sections_write_independent_logs_without_docker(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_python = fake_bin / "python"
    fake_python.write_text('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$QA_FAKE_LOG"\n', encoding="utf-8")
    fake_python.chmod(0o755)
    fake_docker = fake_bin / "docker"
    fake_docker.write_text("#!/bin/sh\necho unexpected-docker >&2\nexit 99\n", encoding="utf-8")
    fake_docker.chmod(0o755)
    invocation_log = tmp_path / "invocations.txt"
    env = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}", PYTHON_BIN=str(fake_python))
    env["QA_FAKE_LOG"] = str(invocation_log)
    destination = tmp_path / "artifacts"

    first = _run(str(destination), "--section", "pytest", env=env)
    assert first.returncode == 0, first.stderr
    second = _run(str(destination), "--section", "cli-fuzz", env=env)
    assert second.returncode == 0, second.stderr
    assert invocation_log.read_text(encoding="utf-8").count("-m pytest") == 2
    summary = (destination / "sections" / "summary.tsv").read_text(encoding="utf-8")
    assert "pytest\tpassed\t0\t" in summary
    assert "cli-fuzz\tpassed\t0\t" in summary
    assert (destination / "sections" / "pytest.log").is_file()
    assert (destination / "sections" / "cli-fuzz.log").is_file()

    duplicate = _run(str(destination), "--section", "pytest", env=env)
    assert duplicate.returncode == 2
    assert "already has a log" in duplicate.stderr
