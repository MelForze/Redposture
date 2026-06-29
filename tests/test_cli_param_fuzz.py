from __future__ import annotations

import argparse
import importlib
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest

pytestmark = pytest.mark.cli_param_fuzz

if os.environ.get("REDPOSTURE_CLI_PARAM_FUZZ") != "1":
    pytest.skip("set REDPOSTURE_CLI_PARAM_FUZZ=1 to run the large CLI parameter fuzz suite", allow_module_level=True)

# Imports below the skip on purpose: the large parameter-fuzz surface is only
# loaded when the env-gate opts in (importing the full CLI parser eagerly
# pulls in every module). ruff's E402 is silenced for the same reason.
from redposture_core.cli_args import build_parser, parse_args  # noqa: E402
from redposture_core.logger import AttemptLogger  # noqa: E402
from redposture_core.module_registry import AUDIT_MODULE_NAMES  # noqa: E402
from redposture_core.stage_runtime import build_basic_audit_plan  # noqa: E402


@dataclass(frozen=True)
class CliSurface:
    name: str
    argv_prefix: tuple[str, ...]
    parser: argparse.ArgumentParser


@dataclass(frozen=True)
class ArgparseFuzzCase:
    case_id: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class PolicyCase:
    case_id: str
    module: str
    argv: tuple[str, ...]
    expected_error: str


@dataclass(frozen=True)
class StageCase:
    case_id: str
    stage: str
    argv: tuple[str, ...]
    expected_error: str


@dataclass(frozen=True)
class PlanPortCase:
    case_id: str
    module: str
    argv: tuple[str, ...]


class _ConsoleRecorder:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(str(message))


def _subparser_actions(parser: argparse.ArgumentParser) -> list[argparse._SubParsersAction[Any]]:
    return [action for action in parser._actions if isinstance(action, argparse._SubParsersAction)]


def _iter_cli_surfaces() -> Iterator[CliSurface]:
    parser = build_parser()
    root_actions = _subparser_actions(parser)
    assert len(root_actions) == 1
    root_action = root_actions[0]
    for command, command_parser in sorted(root_action.choices.items()):
        child_actions = _subparser_actions(command_parser)
        if child_actions:
            assert len(child_actions) == 1
            for child, child_parser in sorted(child_actions[0].choices.items()):
                yield CliSurface(
                    name=f"{command}_{child}",
                    argv_prefix=(str(command), str(child)),
                    parser=child_parser,
                )
            continue
        yield CliSurface(name=str(command), argv_prefix=(str(command),), parser=command_parser)


_SURFACES = tuple(_iter_cli_surfaces())
_AUDIT_SURFACES_BY_MODULE = {surface.argv_prefix[0]: surface for surface in _SURFACES if len(surface.argv_prefix) == 1}


def _surface_actions(surface: CliSurface) -> tuple[argparse.Action, ...]:
    return tuple(action for action in surface.parser._actions if not isinstance(action, argparse._HelpAction))


def _option_strings(action: argparse.Action) -> tuple[str, ...]:
    return tuple(option for option in action.option_strings if option not in {"-h", "--help"})


def _id_fragment(value: object) -> str:
    text = re.sub(r"[^A-Za-z0-9_]+", "_", str(value).strip("-") or "empty")
    return text.strip("_") or "empty"


def _type_name(action: argparse.Action) -> str:
    action_type = getattr(action, "type", None)
    if action_type is None:
        return ""
    return str(getattr(action_type, "__name__", action_type.__class__.__name__))


def _action_requires_operand(action: argparse.Action) -> bool:
    if isinstance(
        action,
        (
            argparse._StoreTrueAction,
            argparse._StoreFalseAction,
            argparse._HelpAction,
            argparse.BooleanOptionalAction,
        ),
    ):
        return False
    nargs = getattr(action, "nargs", None)
    if nargs is None:
        return True
    if nargs == "+":
        return True
    return isinstance(nargs, int) and nargs > 0


def _is_boolean_like(action: argparse.Action) -> bool:
    return isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction, argparse.BooleanOptionalAction))


def _invalid_values_for_action(action: argparse.Action) -> tuple[str, ...]:
    name = _type_name(action)
    if name == "_port":
        return ("0", "65536", "-1", "abc", "1.5")
    if name in {"_positive_int", "positive_int"}:
        return ("0", "-1", "abc", "1.5")
    if name in {"_non_negative_int", "non_negative_int"}:
        return ("-1", "abc", "1.5")
    if name == "_positive_float":
        return ("0", "-0.1", "abc", "nan", "inf")
    if name == "int":
        return ("abc", "1.5")
    if name == "float":
        return ("abc",)
    return ()


def _build_argparse_fuzz_cases() -> tuple[ArgparseFuzzCase, ...]:
    cases: list[ArgparseFuzzCase] = []
    for surface in _SURFACES:
        cases.append(
            ArgparseFuzzCase(
                case_id=f"{surface.name}__unknown_flag",
                argv=(*surface.argv_prefix, f"--redposture-fuzz-unknown-{surface.name}"),
            )
        )
        for action in _surface_actions(surface):
            options = _option_strings(action)
            if not options:
                continue
            if _action_requires_operand(action):
                for option in options:
                    cases.append(
                        ArgparseFuzzCase(
                            case_id=f"{surface.name}__{_id_fragment(option)}__missing_value",
                            argv=(*surface.argv_prefix, option),
                        )
                    )
            if getattr(action, "choices", None):
                invalid_choice = "redposture-invalid-choice"
                if invalid_choice in set(str(item) for item in action.choices or ()):
                    invalid_choice = "redposture-invalid-choice-alt"
                for option in options:
                    cases.append(
                        ArgparseFuzzCase(
                            case_id=f"{surface.name}__{_id_fragment(option)}__invalid_choice",
                            argv=(*surface.argv_prefix, option, invalid_choice),
                        )
                    )
            for invalid_value in _invalid_values_for_action(action):
                for option in options:
                    if option == "--port" and invalid_value not in {"0", "65536"}:
                        continue
                    cases.append(
                        ArgparseFuzzCase(
                            case_id=(
                                f"{surface.name}__{_id_fragment(option)}__"
                                f"invalid_{_id_fragment(_type_name(action))}_{_id_fragment(invalid_value)}"
                            ),
                            argv=(*surface.argv_prefix, option, invalid_value),
                        )
                    )
            if _is_boolean_like(action):
                for option in options:
                    cases.append(
                        ArgparseFuzzCase(
                            case_id=f"{surface.name}__{_id_fragment(option)}__boolean_extra_value",
                            argv=(*surface.argv_prefix, option, "unexpected"),
                        )
                    )

    deduped: list[ArgparseFuzzCase] = []
    seen: set[tuple[str, ...]] = set()
    for case in cases:
        if case.argv in seen:
            continue
        seen.add(case.argv)
        deduped.append(case)
    return tuple(deduped)


_ARGPARSE_FUZZ_CASES = _build_argparse_fuzz_cases()


def _module_supports_dest(module: str, dest: str) -> bool:
    surface = _AUDIT_SURFACES_BY_MODULE[module]
    return any(action.dest == dest for action in _surface_actions(surface))


def _preferred_option_for_dest(module: str, dest: str) -> str:
    surface = _AUDIT_SURFACES_BY_MODULE[module]
    for action in _surface_actions(surface):
        if action.dest != dest:
            continue
        options = _option_strings(action)
        long_options = tuple(option for option in options if option.startswith("--") and not option.startswith("--no-"))
        return (long_options or options)[0]
    raise AssertionError(f"{module} does not expose dest={dest!r}")


def _module_argv(module: str, *extra: str, targets: str | None = "127.0.0.1") -> tuple[str, ...]:
    argv: list[str] = [module]
    if targets is not None:
        argv.extend(["-t", targets])
    if module == "proxmox":
        argv.extend(["--pveapitoken", "audit@pve!redposture=token"])
    argv.extend(extra)
    return tuple(argv)


_USERNAME_MODULES = tuple(
    module
    for module in AUDIT_MODULE_NAMES
    if module in _AUDIT_SURFACES_BY_MODULE and _module_supports_dest(module, "username")
)
_PASSWORD_MODULES = tuple(
    module
    for module in AUDIT_MODULE_NAMES
    if module in _AUDIT_SURFACES_BY_MODULE and _module_supports_dest(module, "password")
)
_PURE_HTTP_MODULES = ("registry", "grafana", "etcd", "qdrant")
_SPECIFIC_USERNAME_PASSWORD_MESSAGE_MODULES = {"grafana", "postgres", "mongodb", "oracle", "clickhouse"}


def _common_policy_cases() -> Iterator[PolicyCase]:
    for module in AUDIT_MODULE_NAMES:
        yield PolicyCase(
            case_id=f"{module}__missing_targets",
            module=module,
            argv=_module_argv(module, targets=None),
            expected_error=f"{module} requires -t/--targets",
        )

    for module in _USERNAME_MODULES:
        yield PolicyCase(
            case_id=f"{module}__empty_username",
            module=module,
            argv=_module_argv(
                module,
                _preferred_option_for_dest(module, "username"),
                "",
                _preferred_option_for_dest(module, "password"),
                "pw",
            ),
            expected_error="--username must not be empty",
        )
        expected = (
            "--password is required when --username is set"
            if module in _SPECIFIC_USERNAME_PASSWORD_MESSAGE_MODULES
            else "--username and --password must be set together"
        )
        yield PolicyCase(
            case_id=f"{module}__username_without_password",
            module=module,
            argv=_module_argv(module, _preferred_option_for_dest(module, "username"), "user"),
            expected_error=expected,
        )

    for module in _PASSWORD_MODULES:
        if module == "redis":
            continue
        yield PolicyCase(
            case_id=f"{module}__password_without_username",
            module=module,
            argv=_module_argv(module, _preferred_option_for_dest(module, "password"), "pw"),
            expected_error="--username and --password must be set together",
        )

    for module in _PURE_HTTP_MODULES:
        yield PolicyCase(
            case_id=f"{module}__https_target_rejected",
            module=module,
            argv=_module_argv(module, targets="https://127.0.0.1"),
            expected_error="accepts only http:// URL targets",
        )


def _policy_case(module: str, expected_error: str, *extra: str, targets: str | None = "127.0.0.1") -> PolicyCase:
    return PolicyCase(
        case_id=f"{module}__{'_'.join(_id_fragment(item) for item in extra[:3])}",
        module=module,
        argv=_module_argv(module, *extra, targets=targets),
        expected_error=expected_error,
    )


def _curated_policy_cases() -> tuple[PolicyCase, ...]:
    cases = [
        _policy_case("registry", "use either --token or --username/--password", "--token", "tok", "-u", "u", "-p", "p"),
        _policy_case("registry", "--show-tags requires --repository", "--docker", "--show-tags"),
        _policy_case("registry", "--tag requires --repository", "--docker", "--tag", "latest"),
        _policy_case(
            "registry", "--metadata requires --repository and --tag", "--docker", "--repository", "repo", "--metadata"
        ),
        _policy_case("registry", "--assets requires --nexus", "--assets"),
        _policy_case("registry", "--download requires --image", "--docker", "--download"),
        _policy_case("consul", "--key requires --dump", "--key", "redposture/kafka/sasl_password"),
        _policy_case("consul", "--service requires --dump", "--service", "svc-redposture-api"),
        _policy_case("consul", "--agent requires --dump", "--agent", "redposture-lab-consul"),
        _policy_case("consul", "--node requires --dump", "--node", "redposture-lab-consul"),
        _policy_case("consul", "--ssrf-port/--ssrf-path require --ssrf-target", "--ssrf-port", "19100"),
        _policy_case("consul", "failed to parse --ssrf-port", "--ssrf-target", "127.0.0.1", "--ssrf-port", "bad"),
        _policy_case("consul", "--delete requires --revshell or --check-id", "--delete"),
        _policy_case("consul", "--listen requires --revshell", "--listen"),
        _policy_case("consul", "--lhost is required when --revshell is set", "--revshell"),
        _policy_case(
            "consul",
            "--lhost must be a plain IPv4/DNS hostname",
            "--revshell",
            "--lhost",
            "http://bad",
            "--lport",
            "4444",
        ),
        _policy_case("consul", "--listen requires --lport", "--revshell", "--listen", "--lhost", "127.0.0.1"),
        _policy_case("consul", "--check-id id:<value> requires a non-empty check id", "--check-id", "id:"),
        _policy_case("consul", "--check-id requires --revshell, --delete, or --dump", "--check-id", "id:redposture"),
        _policy_case("qdrant", "--listen requires --ssrf-target", "--collection", "demo_vectors", "--listen"),
        _policy_case("qdrant", "--ssrf-target requires --collection", "--ssrf-target", "http://127.0.0.1:19115/probe"),
        _policy_case(
            "qdrant",
            "failed to parse SSRF targets/ports",
            "--collection",
            "demo_vectors",
            "--ssrf-target",
            "127.0.0.1",
            "--ssrf-port",
            "bad",
        ),
        _policy_case("postgres", "--show-columns requires --table", "--show-columns"),
        _policy_case("postgres", "--column requires --table", "--column", "username"),
        _policy_case(
            "postgres", "--execute cannot be combined with --sql-cmd", "--execute", "id", "--sql-cmd", "select 1"
        ),
        _policy_case(
            "postgres", "--execute cannot be combined with --os-read", "--execute", "id", "--os-read", "/etc/hostname"
        ),
        _policy_case(
            "postgres",
            "--os-read cannot be combined with --sql-cmd",
            "--os-read",
            "/etc/hostname",
            "--sql-cmd",
            "select 1",
        ),
        _policy_case("postgres", "--os-shell cannot be combined with --sql-shell", "--os-shell", "--sql-shell"),
        _policy_case(
            "postgres", "--os-shell cannot be combined with --os-read", "--os-shell", "--os-read", "/etc/hostname"
        ),
        _policy_case(
            "postgres", "--sql-shell cannot be combined with --os-read", "--sql-shell", "--os-read", "/etc/hostname"
        ),
        _policy_case("clickhouse", "--show-columns requires --table", "--show-columns"),
        _policy_case("clickhouse", "--column requires --table", "--column", "username"),
        _policy_case(
            "clickhouse", "--execute cannot be combined with --sql-cmd", "--execute", "id", "--sql-cmd", "select 1"
        ),
        _policy_case("clickhouse", "--os-shell cannot be combined with --sql-shell", "--os-shell", "--sql-shell"),
        _policy_case(
            "clickhouse", "--os-shell cannot be combined with --sql-cmd", "--os-shell", "--sql-cmd", "select 1"
        ),
        _policy_case("clickhouse", "--os-shell cannot be combined with --execute", "--os-shell", "--execute", "id"),
        _policy_case("clickhouse", "--sql-shell cannot be combined with --execute", "--sql-shell", "--execute", "id"),
        _policy_case(
            "clickhouse", "--sql-shell cannot be combined with --sql-cmd", "--sql-shell", "--sql-cmd", "select 1"
        ),
        _policy_case("clickhouse", "--sql-shell cannot be used with -o/--output", "--sql-shell", "-o", "out.txt"),
        _policy_case("clickhouse", "--sql-shell requires --format txt", "--sql-shell", "-f", "json"),
        _policy_case(
            "mongodb", "--query must be valid JSON object", "--collection", "demo_accounts", "--query", "{bad"
        ),
        _policy_case("mongodb", "--query requires --collection", "--query", '{"role":"admin"}'),
        _policy_case("mongodb", "--document requires --collection", "--document", "1"),
        _policy_case(
            "mongodb",
            "--document cannot be combined with --query",
            "--collection",
            "demo_accounts",
            "--document",
            "1",
            "--query",
            '{"role":"admin"}',
        ),
        _policy_case(
            "mongodb", "--projection must be valid JSON object", "--collection", "demo_accounts", "--projection", "{bad"
        ),
        _policy_case("mongodb", "--nosql-cmd must be valid JSON object", "--nosql-cmd", "{bad"),
        _policy_case(
            "mongodb",
            "--nosql-cmd cannot be combined with --nosql-shell",
            "--nosql-cmd",
            '{"dbStats":1}',
            "--nosql-shell",
        ),
        _policy_case("oracle", "--service cannot be combined with --sid", "--service", "FREEPDB1", "--sid", "FREE"),
        _policy_case(
            "oracle",
            "--query must be a read-only SELECT statement",
            "--service",
            "FREEPDB1",
            "--query",
            "delete from accounts",
        ),
        _policy_case(
            "oracle",
            "--os-write must use local:remote or remote:local syntax",
            "--service",
            "FREEPDB1",
            "--os-write",
            "/tmp/file",
        ),
        _policy_case(
            "oracle",
            "--download must use local:remote or remote:local syntax",
            "--service",
            "FREEPDB1",
            "--download",
            "wallet.txt",
        ),
        _policy_case("docker", "--container and --exec-cmd must be used together", "--container", "redposture-web"),
        _policy_case("docker", "--container and --exec-cmd must be used together", "--exec-cmd", "id"),
        _policy_case("docker", "--tls-cert and --tls-key must be used together", "--tls-cert", "client.crt"),
        _policy_case("docker", "--tls-cert and --tls-key must be used together", "--tls-key", "client.key"),
        _policy_case("kafka", "--dump count cannot conflict with --max-messages", "--dump", "3", "--max-messages", "4"),
        _policy_case("kafka", "--max-messages must be > 0", "--max-messages", "0"),
        _policy_case("kafka", "--max-messages must be > 0", "--max-messages", "-1"),
    ]
    return tuple(cases)


_POLICY_CASES = (*tuple(_common_policy_cases()), *_curated_policy_cases())


def _stage_case(stage: str, expected_error: str, *argv: str) -> StageCase:
    return StageCase(
        case_id=f"{stage}__{'_'.join(_id_fragment(item) for item in argv[:4])}",
        stage=stage,
        argv=tuple(argv),
        expected_error=expected_error,
    )


_STAGE_CASES = (
    _stage_case("scan", "scan requires -t/--targets", "exporters", "scan", "-p", "9100"),
    _stage_case("scan", "failed to parse --ports", "exporters", "scan", "-t", "127.0.0.1", "-p", "bad"),
    _stage_case(
        "scan", "accepts only http:// URL targets", "exporters", "scan", "-t", "https://127.0.0.1:19100/metrics"
    ),
    _stage_case("collect", "collect requires -t/--targets", "exporters", "collect"),
    _stage_case("collect", "failed to parse --ports", "exporters", "collect", "-t", "127.0.0.1", "-p", "bad"),
    _stage_case(
        "collect",
        "accepts only http:// URL targets",
        "exporters",
        "collect",
        "-t",
        "https://127.0.0.1:19100/debug/vars",
    ),
    _stage_case(
        "trigger",
        "--listen-seconds must be >= 0",
        "exporters",
        "trigger",
        "-t",
        "127.0.0.1",
        "--callback-ip",
        "127.0.0.1",
        "--with-listen",
        "--listen-seconds",
        "-1",
    ),
    _stage_case(
        "trigger",
        "--check-credentials requires --with-listen",
        "exporters",
        "trigger",
        "-t",
        "127.0.0.1",
        "--callback-ip",
        "127.0.0.1",
        "--no-with-listen",
        "--check-credentials",
    ),
    _stage_case(
        "trigger",
        "--format json with --with-listen requires --output",
        "exporters",
        "trigger",
        "-t",
        "127.0.0.1",
        "--callback-ip",
        "127.0.0.1",
        "--with-listen",
        "--format",
        "json",
    ),
    _stage_case(
        "trigger",
        "failed to parse --ports",
        "exporters",
        "trigger",
        "-t",
        "127.0.0.1",
        "--callback-ip",
        "127.0.0.1",
        "-p",
        "bad",
    ),
    _stage_case(
        "trigger",
        "trigger requires -t/--targets",
        "exporters",
        "trigger",
        "--callback-ip",
        "127.0.0.1",
        "--no-with-listen",
    ),
    _stage_case(
        "trigger",
        "accepts only http:// URL targets",
        "exporters",
        "trigger",
        "-t",
        "https://127.0.0.1:19121/scrape",
        "--callback-ip",
        "127.0.0.1",
        "--no-with-listen",
    ),
    _stage_case(
        "trigger",
        "--callback-ip must be a valid IP address",
        "exporters",
        "trigger",
        "-t",
        "127.0.0.1",
        "--callback-ip",
        "999.999.999.999",
        "--no-with-listen",
    ),
    _stage_case(
        "trigger",
        "trigger requires --callback-ip and/or --callback-dns",
        "exporters",
        "trigger",
        "-t",
        "127.0.0.1",
        "--no-with-listen",
    ),
)


def _build_plan_port_cases() -> tuple[PlanPortCase, ...]:
    cases: list[PlanPortCase] = []
    bad_specs = (
        ("--ports", "bad"),
        ("--ports", "0"),
        ("--ports", "65536"),
        ("--port", "bad"),
        ("--port", "-1"),
        ("--port", "1.5"),
        ("--port", "1-bad"),
    )
    for module in AUDIT_MODULE_NAMES:
        for flag, value in bad_specs:
            cases.append(
                PlanPortCase(
                    case_id=f"{module}__{_id_fragment(flag)}__{_id_fragment(value)}",
                    module=module,
                    argv=_module_argv(module, flag, value),
                )
            )
    return tuple(cases)


_PLAN_PORT_CASES = _build_plan_port_cases()


def _assert_no_traceback(text: str) -> None:
    assert "Traceback (most recent call last)" not in text
    assert "Traceback" not in text


def _run_policy_case(case: PolicyCase) -> tuple[int | None, str]:
    args = parse_args(list(case.argv))
    console = _ConsoleRecorder()
    policy = importlib.import_module(f"redposture_core.modules.{case.module}.policy")
    rc = policy.validate_args(args, console)
    return rc, "\n".join(console.errors)


def _run_stage_case(case: StageCase) -> int:
    args = parse_args(list(case.argv))
    if case.stage == "scan":
        from redposture_core.stage_scan import run_scan_stage

        return int(run_scan_stage(args))

    logger = AttemptLogger()
    try:
        if case.stage == "collect":
            from redposture_core.stage_collect import run_collect_stage

            return int(run_collect_stage(args, logger))
        if case.stage == "trigger":
            from redposture_core.stage_trigger import run_trigger_stage

            return int(run_trigger_stage(args, logger))
    finally:
        logger.close()
    raise AssertionError(f"unknown stage: {case.stage}")


def test_cli_param_fuzz_case_generation_is_large_and_current() -> None:
    surface_names = {surface.name for surface in _SURFACES}
    assert {"exporters_scan", "exporters_collect", "exporters_trigger"}.issubset(surface_names)
    assert set(AUDIT_MODULE_NAMES).issubset(surface_names)
    assert len(_ARGPARSE_FUZZ_CASES) >= 1_400
    assert len(_POLICY_CASES) >= 100
    assert len(_PLAN_PORT_CASES) >= len(AUDIT_MODULE_NAMES) * 5
    assert len(_ARGPARSE_FUZZ_CASES) + len(_POLICY_CASES) + len(_STAGE_CASES) + len(_PLAN_PORT_CASES) >= 1_500


@pytest.mark.parametrize("case", _ARGPARSE_FUZZ_CASES, ids=lambda case: case.case_id)
def test_argparse_rejects_generated_negative_parameter_cases(
    case: ArgparseFuzzCase, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(list(case.argv))

    assert exc.value.code == 2
    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert output.strip()
    assert "usage:" in output or "error:" in output
    _assert_no_traceback(output)


@pytest.mark.parametrize("case", _POLICY_CASES, ids=lambda case: case.case_id)
def test_module_policies_reject_semantic_parameter_conflicts(case: PolicyCase) -> None:
    rc, output = _run_policy_case(case)

    assert rc == 2
    assert case.expected_error in output
    _assert_no_traceback(output)


@pytest.mark.parametrize("case", _STAGE_CASES, ids=lambda case: case.case_id)
def test_exporter_stages_reject_early_parameter_conflicts(case: StageCase, capsys: pytest.CaptureFixture[str]) -> None:
    rc = _run_stage_case(case)

    captured = capsys.readouterr()
    output = f"{captured.out}\n{captured.err}"
    assert rc == 2
    assert case.expected_error in output
    _assert_no_traceback(output)


@pytest.mark.parametrize("case", _PLAN_PORT_CASES, ids=lambda case: case.case_id)
def test_basic_audit_plan_rejects_malformed_multi_port_specs(case: PlanPortCase) -> None:
    args = parse_args(list(case.argv))
    default_port = int(getattr(args, "port", 1) or 1)

    with pytest.raises(ValueError, match="failed to parse --port"):
        build_basic_audit_plan(args, default_port=default_port)
