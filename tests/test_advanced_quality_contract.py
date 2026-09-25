from __future__ import annotations

from pathlib import Path

import tomlkit
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]


def _project_minima() -> dict[str, str]:
    project = tomlkit.parse((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    result: dict[str, str] = {}
    for raw in project["dependencies"]:
        requirement = Requirement(str(raw))
        lower = next(spec.version for spec in requirement.specifier if spec.operator == ">=")
        result[canonicalize_name(requirement.name)] = lower
    return result


def test_minimum_dependency_profile_tracks_declared_project_floor() -> None:
    script = (ROOT / "scripts" / "run_dependency_compat.sh").read_text(encoding="utf-8")
    for name, version in _project_minima().items():
        assert f"'{name}=={version}'" in script
    assert '"${PYTHON_BIN}" -m pip check' in script
    assert '"${PYTHON_BIN}" -m pytest -q' in script
    assert '--upgrade-strategy eager "${ROOT_DIR}[dev,kafka-codecs]"' in script


def test_dependency_profiles_are_scheduled_and_manually_runnable() -> None:
    workflow = (ROOT / ".github" / "workflows" / "dependency-compat.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "schedule:" in workflow
    assert "profile: [min, max]" in workflow
    assert 'scripts/run_dependency_compat.sh "${{ matrix.profile }}"' in workflow


def test_nightly_quality_runs_only_fast_cli_fuzz_and_free_threaded_contracts() -> None:
    workflow = (ROOT / ".github" / "workflows" / "advanced-quality.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "schedule:" in workflow
    assert "bash scripts/run_cli_param_fuzz.sh" in workflow
    assert 'python-version: "3.13t"' in workflow
    assert 'Py_GIL_DISABLED") == 1' in workflow
    assert "scripts/run_mutation_smoke.py" not in workflow
    assert "tests/test_concurrency_stress.py" not in workflow


def test_advanced_workflows_pin_third_party_actions_and_do_not_run_full_docker_matrix() -> None:
    checkout = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    setup_python = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
    for name in ("dependency-compat.yml", "advanced-quality.yml"):
        workflow = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        assert checkout in workflow
        assert setup_python in workflow
        assert "run_full_local_qa.sh" not in workflow

    all_workflows = "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / ".github" / "workflows").glob("*.yml")
    )
    assert "run_mutation_smoke.py" not in all_workflows
    assert "local_output_audit" not in all_workflows
