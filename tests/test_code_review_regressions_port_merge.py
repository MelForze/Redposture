"""Regression tests for the --port / --ports merge and the Kafka SASL_SSL
default-port extension.

Historical shape:
  - `--port <int>`      → args.port: int
  - `--ports <spec>`    → args.ports: str  (list/range/file)

New shape (single canonical flag):
  - `--port <int>`      → args.port: int, args.ports: None
  - `--port <spec>`     → normalizer splits into `--port <first_int> --ports <spec>`;
                          downstream `build_basic_audit_plan` merges them.
  - `--ports <spec>`    → still accepted (hidden alias, backward compat) for old scripts.

Every regression check below pins one of those contracts so a future refactor of
`_normalize_multi_port_port_flag` or `_port_spec` can't silently regress the UX.
"""

from __future__ import annotations

import argparse
from types import SimpleNamespace

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.stage_runtime import build_basic_audit_plan

# ---------------------------------------------------------------------------
# --port accepts the same list/range/file syntax that --ports used to require
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("module", "default_first_port"),
    [
        ("redis", 6379),
        ("etcd", 2379),
        ("mongodb", 27017),
        ("postgres", 5432),
        ("kafka", 9092),
        ("registry", 5000),
        ("zookeeper", 2181),
    ],
)
def test_port_flag_accepts_list_syntax_and_normalizes_to_hidden_ports(
    module: str,
    default_first_port: int,
) -> None:
    """`--port a,b,c` — the head becomes args.port; the full spec goes to args.ports."""
    argv = [module, "-t", "10.0.0.1", "--port", f"{default_first_port},{default_first_port + 1}"]
    args = parse_args(argv)
    assert args.command == module
    assert args.port == default_first_port
    assert args.ports == f"{default_first_port},{default_first_port + 1}"


@pytest.mark.parametrize(
    ("module", "range_spec", "head_port"),
    [
        ("redis", "6379-6381", 6379),
        ("etcd", "2379-2381", 2379),
        ("kafka", "9092-9095", 9092),
    ],
)
def test_port_flag_accepts_range_syntax_and_normalizes_to_hidden_ports(
    module: str,
    range_spec: str,
    head_port: int,
) -> None:
    args = parse_args([module, "-t", "10.0.0.1", "--port", range_spec])
    assert args.port == head_port
    assert args.ports == range_spec


def test_port_flag_accepts_ports_file_and_normalizes_to_hidden_ports(tmp_path) -> None:
    ports_file = tmp_path / "ports.txt"
    ports_file.write_text("6379\n6380\n", encoding="utf-8")
    args = parse_args(["redis", "-t", "10.0.0.1", "--port", str(ports_file)])
    # A file path can't be parsed as an int head; the whole value gets pushed
    # to args.ports and args.port stays None.
    assert args.port is None
    assert args.ports == str(ports_file)


def test_port_flag_single_int_still_maps_to_int_port_field() -> None:
    """Single-int form must stay backward-compatible: args.port is an int, not a str."""
    args = parse_args(["redis", "-t", "10.0.0.1", "--port", "6379"])
    assert args.port == 6379
    assert isinstance(args.port, int)
    assert args.ports is None


def test_port_flag_out_of_range_int_is_rejected() -> None:
    """The `_port_spec` type-check must still enforce 1..65535 for single-int form."""
    with pytest.raises(SystemExit) as exc:
        parse_args(["redis", "-t", "10.0.0.1", "--port", "70000"])
    assert exc.value.code == 2


def test_ports_alias_still_accepted_for_backward_compat() -> None:
    """`--ports <spec>` (the legacy flag) must keep working for existing scripts."""
    args = parse_args(["kafka", "-t", "10.0.0.1", "--ports", "9092,9093"])
    assert args.command == "kafka"
    assert args.ports == "9092,9093"


def test_ports_flag_is_hidden_from_help_for_all_port_modules() -> None:
    """The --help surface must show only `--port` — the deprecated alias must
    stay suppressed so users don't see two ways to do the same thing."""
    from redposture_core.cli_args import build_parser

    parser = build_parser()
    for module in ("redis", "etcd", "mongodb", "postgres", "kafka", "registry", "zookeeper"):
        # argparse doesn't expose subparser help directly; format and grep.
        subparsers_action = next(
            (a for a in parser._actions if isinstance(a, argparse._SubParsersAction)),
            None,
        )
        assert subparsers_action is not None
        subparser = subparsers_action.choices[module]
        help_text = subparser.format_help()
        assert "--port" in help_text, f"{module}: --port must remain visible"
        # `--ports` is a substring of `--port`; anchor on the flag name with
        # a following space / equals / newline to avoid the false positive.
        lines_mentioning_ports = [line for line in help_text.splitlines() if "--ports " in line or "--ports=" in line]
        assert not lines_mentioning_ports, (
            f"{module}: --ports must be hidden from --help (found lines: {lines_mentioning_ports!r})"
        )


# ---------------------------------------------------------------------------
# build_basic_audit_plan merges args.port (spec) with args.ports
# ---------------------------------------------------------------------------


def test_build_basic_audit_plan_merges_port_spec_with_ports_alias() -> None:
    """If a legacy caller sets both args.port (spec) and args.ports (spec),
    the plan must include ports from BOTH — never silently dropping one."""
    ns = SimpleNamespace(
        port="6379,6380",
        ports="6381",
        targets="10.0.0.1",
        hosts=None,
        hosts_file=None,
        username=None,
        password=None,
        defcreds=False,
        max_workers=1,
        timeout=1.0,
        retries=0,
        output=None,
        output_format="txt",
        log=None,
        debug=False,
        stream=False,
    )
    plan = build_basic_audit_plan(ns, default_port=6379, default_ports=(6379, 16379))
    assert 6379 in plan.ports
    assert 6380 in plan.ports
    assert 6381 in plan.ports


def test_build_basic_audit_plan_int_port_takes_precedence_over_defaults() -> None:
    """Single-int --port must beat the module's default port set (unchanged behavior)."""
    ns = SimpleNamespace(
        port=6380,
        ports=None,
        targets="10.0.0.1",
        hosts=None,
        hosts_file=None,
        username=None,
        password=None,
        defcreds=False,
        max_workers=1,
        timeout=1.0,
        retries=0,
        output=None,
        output_format="txt",
        log=None,
        debug=False,
        stream=False,
    )
    plan = build_basic_audit_plan(ns, default_port=6379, default_ports=(6379, 16379))
    assert list(plan.ports) == [6380]


# ---------------------------------------------------------------------------
# Kafka default ports now include 9093 (SASL_SSL)
# ---------------------------------------------------------------------------


def test_kafka_default_ports_include_sasl_ssl_listener_9093() -> None:
    """9093 = well-known SASL_SSL listener. Users often only expose 9093
    externally; the default scan must find it without extra flags."""
    from redposture_core.modules.kafka.stage import _DEFAULT_PORTS

    assert _DEFAULT_PORTS is not None
    assert 9092 in _DEFAULT_PORTS  # SASL_PLAINTEXT baseline
    assert 9093 in _DEFAULT_PORTS  # SASL_SSL — new
    assert 19092 in _DEFAULT_PORTS  # docker-compose commonly maps to 19092


def test_kafka_default_ports_are_used_when_no_port_flag_given() -> None:
    """Plan-level check: no `--port` at all → scan all defaults incl. 9093."""
    ns = SimpleNamespace(
        port=None,
        ports=None,
        targets="10.0.0.1",
        hosts=None,
        hosts_file=None,
        username=None,
        password=None,
        defcreds=False,
        max_workers=1,
        timeout=1.0,
        retries=0,
        output=None,
        output_format="txt",
        log=None,
        debug=False,
        stream=False,
    )
    plan = build_basic_audit_plan(ns, default_port=9092, default_ports=(9092, 9093, 19092))
    assert set(plan.ports) == {9092, 9093, 19092}


def test_kafka_help_advertises_9093_sasl_ssl_default() -> None:
    """`redposture kafka -h` output must mention 9093 in the default-port
    guidance so operators know they don't need to add it manually."""
    from redposture_core.cli_args import build_parser

    parser = build_parser()
    subparsers_action = next(
        (a for a in parser._actions if isinstance(a, argparse._SubParsersAction)),
        None,
    )
    assert subparsers_action is not None
    help_text = subparsers_action.choices["kafka"].format_help()
    assert "9093" in help_text
    assert "SASL_SSL" in help_text
