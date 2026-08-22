from __future__ import annotations

import re
from pathlib import Path

import tomlkit
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
LOCK_FILES = (
    "requirements/ci-py310.txt",
    "requirements/ci-py311.txt",
    "requirements/ci-py312.txt",
    "requirements/ci-py313.txt",
    "requirements/release-py312.txt",
)
PINNED_REQUIREMENT = re.compile(r"^[A-Za-z0-9_.-]+==[^\s]+$")


def test_ci_lock_files_contain_only_exact_versions() -> None:
    project = tomlkit.parse((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    runtime_dependencies = {canonicalize_name(Requirement(str(value)).name) for value in project["dependencies"]}

    for relative_path in LOCK_FILES:
        path = ROOT / relative_path
        lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        assert lines, relative_path
        assert all(PINNED_REQUIREMENT.fullmatch(line) for line in lines), relative_path
        assert "pip==26.2.1" in lines
        locked_names = {canonicalize_name(line.partition("==")[0]) for line in lines}
        assert runtime_dependencies <= locked_names, relative_path

    for relative_path in LOCK_FILES[:4]:
        lines = (ROOT / relative_path).read_text(encoding="utf-8").splitlines()
        assert "pytest-socket==0.8.1" in lines
        assert "editables==0.5" in lines
        assert any(line.startswith("hatchling==") for line in lines)
        assert any(line.startswith("tox==") for line in lines)


def test_local_tox_and_github_ci_delegate_to_shared_runner() -> None:
    local_ci = (ROOT / "scripts/check_ci_matrix.sh").read_text(encoding="utf-8")
    tox = (ROOT / "tox.ini").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "scripts/run_ci_job.sh lint" in local_ci
    assert "scripts/run_ci_job.sh test" in local_ci
    assert "bash scripts/run_ci_job.sh lint" in tox
    assert "bash scripts/run_ci_job.sh test" in tox
    assert "bash scripts/run_ci_job.sh lint" in workflow
    assert "bash scripts/run_ci_job.sh test" in workflow


def test_github_actions_and_runner_are_pinned() -> None:
    checkout = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
    setup_python = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0"

    for relative_path in (".github/workflows/ci.yml", ".github/workflows/release-smoke.yml"):
        workflow = (ROOT / relative_path).read_text(encoding="utf-8")
        assert checkout in workflow
        assert setup_python in workflow
        assert "runs-on: ubuntu-24.04" in workflow
        assert "contents: read" in workflow
        assert "cache-dependency-path:" in workflow

    release_workflow = (ROOT / ".github/workflows/release-smoke.yml").read_text(encoding="utf-8")
    assert "python -m build --no-isolation" in release_workflow
    assert "PIP_CONSTRAINT:" in release_workflow


def test_pytest_network_isolation_is_global() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert '"pytest-socket==0.8.1"' in pyproject
    assert "--disable-socket" in pyproject
    assert "--allow-hosts=127.0.0.1,::1,localhost" in pyproject
    assert "--allow-unix-socket" in pyproject
