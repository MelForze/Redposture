from __future__ import annotations

import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

from redposture_core.module_registry import (
    COMMAND_DOCKER,
    COMMAND_EXPORTERS,
    COMMAND_ORACLE,
    COMMAND_POSTGRES,
    COMMAND_SPECS_BY_NAME,
    EXPORTERS_ACTION_SPECS_BY_NAME,
    CommandSpec,
    command_names_for_error,
    resolve_command_runner,
)


def test_module_registry_contains_core_commands_and_exporter_actions() -> None:
    assert COMMAND_POSTGRES in COMMAND_SPECS_BY_NAME
    assert COMMAND_DOCKER in COMMAND_SPECS_BY_NAME
    assert COMMAND_ORACLE in COMMAND_SPECS_BY_NAME
    assert set(EXPORTERS_ACTION_SPECS_BY_NAME) == {"scan", "collect", "trigger"}


def test_module_registry_specs_have_parser_and_runner_contract() -> None:
    for name, spec in COMMAND_SPECS_BY_NAME.items():
        assert spec.name == name
        assert spec.runner_attr.startswith("run_")
        assert callable(spec.configure_parser)


def test_command_error_list_is_registry_backed() -> None:
    text = command_names_for_error()
    assert COMMAND_EXPORTERS in text
    assert COMMAND_POSTGRES in text
    assert "--selfcert" in text


def test_module_registry_resolves_stage_runner_lazily() -> None:
    runner = resolve_command_runner(COMMAND_SPECS_BY_NAME[COMMAND_POSTGRES])
    assert runner.__name__ == "run_postgres_stage"


def test_all_registered_module_package_runners_resolve() -> None:
    for spec in COMMAND_SPECS_BY_NAME.values():
        runner = resolve_command_runner(spec)
        assert callable(runner)
        assert runner.__name__ == spec.runner_attr


def test_registered_module_runner_packages_have_stage_files() -> None:
    for spec in COMMAND_SPECS_BY_NAME.values():
        module_name = spec.runner_module or f"redposture_core.modules.{spec.name}.stage"
        if not module_name.startswith("redposture_core.modules."):
            continue
        module_spec = importlib.util.find_spec(module_name)
        assert module_spec is not None, module_name
        assert module_spec.origin is not None, module_name
        assert module_spec.origin.endswith("/stage.py"), module_spec.origin

    docker_spec = importlib.util.find_spec("redposture_core.modules.docker.stage")
    assert docker_spec is not None
    assert docker_spec.origin is not None
    assert docker_spec.origin.endswith("/redposture_core/modules/docker/stage.py")


def _hatch_build_ignores_vcs(root: Path) -> bool:
    in_hatch_build_table = False
    for raw_line in (root / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            in_hatch_build_table = line == "[tool.hatch.build]"
            continue
        if in_hatch_build_table and line == "ignore-vcs = true":
            return True
    return False


def test_registered_module_stage_files_are_not_vcs_ignored() -> None:
    root = Path.cwd().resolve()
    if _hatch_build_ignores_vcs(root):
        return
    if shutil.which("git") is None:
        pytest.skip("git is required for VCS-ignore packaging guard")
    if not (root / ".git").exists():
        pytest.skip("VCS-ignore packaging guard requires a git checkout")

    stage_paths: list[str] = []
    for spec in COMMAND_SPECS_BY_NAME.values():
        module_name = spec.runner_module or f"redposture_core.modules.{spec.name}.stage"
        if not module_name.startswith("redposture_core.modules."):
            continue
        module_spec = importlib.util.find_spec(module_name)
        assert module_spec is not None, module_name
        assert module_spec.origin is not None, module_name
        stage_paths.append(str(Path(module_spec.origin).resolve().relative_to(root)))

    result = subprocess.run(
        ["git", "check-ignore", "--no-index", *stage_paths],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1, f"registered module stage files are VCS-ignored:\n{result.stdout}"


def test_local_lab_tree_is_unconditionally_vcs_ignored() -> None:
    rules = [
        line.split("#", 1)[0].strip() for line in (Path.cwd() / ".gitignore").read_text(encoding="utf-8").splitlines()
    ]

    assert "lab/" in rules
    assert not any(rule == "!lab" or rule.startswith("!lab/") for rule in rules)


def test_module_registry_reports_bad_runner_specs() -> None:
    missing_module = CommandSpec(
        name="missing",
        help="missing",
        runner_attr="run_missing_stage",
        configure_parser=lambda *_args: None,
    )
    with pytest.raises(LookupError, match="no runner module registered"):
        resolve_command_runner(missing_module)

    missing_runner = CommandSpec(
        name=COMMAND_POSTGRES,
        help="postgres",
        runner_attr="not_a_runner",
        configure_parser=lambda *_args: None,
    )
    with pytest.raises(LookupError, match="not_a_runner"):
        resolve_command_runner(missing_runner)


def test_module_registry_wraps_import_error_as_lookup_error() -> None:
    broken_import = CommandSpec(
        name="broken",
        help="broken",
        runner_attr="run_broken",
        configure_parser=lambda *_args: None,
        runner_module="redposture_core.modules.nonexistent_module_xyz",
    )
    with pytest.raises(LookupError, match="cannot import module"):
        resolve_command_runner(broken_import)
