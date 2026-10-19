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
    assert "optional-real" in listed.stdout

    default = _run(str(tmp_path / "default-plan"), "--plan")
    assert default.returncode == 0
    assert "section: optional-real" not in default.stdout

    isolated = _run(str(tmp_path / "isolated-plan"), "--section", "optional-real", "--plan")
    assert isolated.returncode == 0
    assert isolated.stdout.splitlines()[-1] == "section: optional-real"

    mixed = _run(str(tmp_path / "mixed-plan"), "--section", "pytest,optional-real", "--plan")
    assert mixed.returncode == 2
    assert "must run by itself" in mixed.stderr

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


def test_full_qa_rejects_reused_late_section_before_running_earlier_sections(tmp_path: Path) -> None:
    destination = tmp_path / "artifacts"
    section_dir = destination / "sections"
    section_dir.mkdir(parents=True)
    old_log = section_dir / "docker-matrix.log"
    old_log.write_text("previous Docker run\n", encoding="utf-8")
    fake_python = tmp_path / "python"
    fake_python.write_text('#!/bin/sh\nprintf "called\\n" >> "$QA_FAKE_LOG"\n', encoding="utf-8")
    fake_python.chmod(0o755)
    invocation_log = tmp_path / "invocations.txt"
    env = dict(os.environ, PYTHON_BIN=str(fake_python), QA_FAKE_LOG=str(invocation_log))

    result = _run(str(destination), "--section", "fixtures,docker-matrix", env=env)

    assert result.returncode == 2
    assert "already has a log" in result.stderr
    assert "docker-matrix.log" in result.stderr
    assert not invocation_log.exists()
    assert not (section_dir / "fixtures.log").exists()
    assert old_log.read_text(encoding="utf-8") == "previous Docker run\n"


def test_full_qa_collects_failures_and_runs_later_sections(tmp_path: Path) -> None:
    fake_python = tmp_path / "python"
    fake_python.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$QA_FAKE_LOG"\n'
        'case "$*" in *lab/services/coverage.py*|*run_mutation_smoke.py*) exit 7;; esac\n',
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    invocation_log = tmp_path / "invocations.txt"
    env = dict(os.environ, PYTHON_BIN=str(fake_python), QA_FAKE_LOG=str(invocation_log))
    destination = tmp_path / "artifacts"

    result = _run(str(destination), "--section", "fixtures,pytest,mutation,cli-fuzz", env=env)

    assert result.returncode == 1
    assert "failed sections: fixtures mutation" in result.stderr
    summary = (destination / "sections" / "summary.tsv").read_text(encoding="utf-8")
    assert [line.split("\t")[:3] for line in summary.splitlines()[1:]] == [
        ["fixtures", "failed", "7"],
        ["pytest", "passed", "0"],
        ["mutation", "failed", "7"],
        ["cli-fuzz", "passed", "0"],
    ]
    assert invocation_log.read_text(encoding="utf-8").count("-m pytest") == 2
    report = (destination / "report.md").read_text(encoding="utf-8")
    assert "Failed sections: fixtures mutation" in report
    assert "[log](sections/cli-fuzz.log)" in report


def test_docker_preflight_failure_is_recorded_without_blocking_pytest(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_docker = fake_bin / "docker"
    fake_docker.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
    fake_docker.chmod(0o755)
    fake_python = fake_bin / "python"
    fake_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_python.chmod(0o755)
    env = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}", PYTHON_BIN=str(fake_python))
    destination = tmp_path / "artifacts"

    result = _run(str(destination), "--section", "docker-matrix,pytest", env=env)

    assert result.returncode == 1
    summary = (destination / "sections" / "summary.tsv").read_text(encoding="utf-8")
    assert "docker-matrix\tfailed\t2\t" in summary
    assert "pytest\tpassed\t0\t" in summary
    assert "Docker Compose is unavailable" in (destination / "sections" / "docker-matrix.log").read_text()
