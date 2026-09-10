"""Negative CLI parsing and policy-validation scenarios for the Airflow module.

Covers argument rejection (bad format, transport/token flags that must not exist)
and the `policy.validate_args` contract for every combination of `--port`,
`-u/--username` and `-p/--password`, plus the real stage entrypoint refusing an
invalid combination before any network work.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.airflow import policy
from redposture_core.modules.airflow import stage as airflow_stage


class _Console:
    def __init__(self):
        self.errors: list[str] = []

    def error(self, message):
        self.errors.append(message)


def _args(*, port=None, username=None, password=None):
    return SimpleNamespace(port=port, username=username, password=password)


# --- policy: --port -------------------------------------------------------


@pytest.mark.parametrize("port", [0, -1, -100])
def test_policy_rejects_nonpositive_port(port):
    console = _Console()
    assert policy.validate_args(_args(port=port), console) == 2
    assert "--port must be > 0" in console.errors[0]


def test_policy_allows_missing_port():
    assert policy.validate_args(_args(port=None), _Console()) is None


def test_policy_allows_positive_port():
    assert policy.validate_args(_args(port=8080), _Console()) is None


def test_policy_ignores_string_port_spec():
    # A list/range/file spec arrives as a str; the >0 check only applies to a
    # single int and must not choke on the spec form.
    assert policy.validate_args(_args(port="8080,8081"), _Console()) is None


# --- policy: -p requires -u ----------------------------------------------


def test_policy_password_requires_username():
    console = _Console()
    assert policy.validate_args(_args(password="pw"), console) == 2
    assert "-u/--username is missing" in console.errors[0]


def test_policy_empty_username_counts_as_missing():
    console = _Console()
    assert policy.validate_args(_args(password="pw", username=""), console) == 2


def test_policy_password_with_username_ok():
    assert policy.validate_args(_args(password="pw", username="airflow"), _Console()) is None


def test_policy_empty_password_with_username_ok():
    # An empty password is a real (if unusual) value; only a missing username is fatal.
    assert policy.validate_args(_args(password="", username="airflow"), _Console()) is None


def test_policy_username_requires_password():
    console = _Console()
    assert policy.validate_args(_args(username="airflow"), console) == 2
    assert "-p/--password is missing" in console.errors[0]


def test_policy_combined_port_and_credential_errors_report_port_first():
    console = _Console()
    assert policy.validate_args(_args(port=0, password="pw"), console) == 2
    assert "--port must be > 0" in console.errors[0]


# --- CLI parsing ----------------------------------------------------------


def test_cli_defcreds_defaults_false():
    assert parse_args(["airflow", "-t", "127.0.0.1"]).defcreds is False


def test_cli_rejects_unknown_format():
    with pytest.raises(SystemExit):
        parse_args(["airflow", "-t", "127.0.0.1", "-f", "yaml"])


def test_cli_username_without_password_parses():
    args = parse_args(["airflow", "-t", "127.0.0.1", "-u", "airflow"])
    assert args.username == "airflow" and args.password is None


def test_cli_multi_ports_alias_parsed():
    args = parse_args(["airflow", "-t", "127.0.0.1", "--ports", "8080,8081"])
    assert args.ports == "8080,8081"


@pytest.mark.parametrize("flag", ["--https", "--insecure", "--ca-file", "--session-token", "--token"])
def test_cli_rejects_transport_and_token_flags(flag):
    with pytest.raises(SystemExit):
        parse_args(["airflow", "-t", "127.0.0.1", flag, "x"])


# --- real stage refuses bad combos before any network work ----------------


def test_stage_rejects_password_without_username(capsys):
    args = parse_args(["airflow", "-t", "127.0.0.1", "-p", "pw"])
    rc = airflow_stage.run_airflow_stage(args, SimpleNamespace(log=lambda *a, **k: None))
    assert rc == 2
    assert "-u/--username is missing" in capsys.readouterr().err
