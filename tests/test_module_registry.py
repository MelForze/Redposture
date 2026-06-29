from __future__ import annotations

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
