from __future__ import annotations

import pytest

from redposture_core.cli_args import parse_args
from redposture_core.modules.airflow.stage import build_airflow_plan


def test_airflow_default_ports():
    plan = build_airflow_plan(parse_args(["airflow", "-t", "127.0.0.1"]))
    assert plan.ports == (8080, 8081, 18080, 28080, 8443)


def test_airflow_creds_and_defcreds_parse():
    args = parse_args(["airflow", "-t", "127.0.0.1", "-u", "airflow", "-p", "airflow", "--defcreds"])
    assert args.username == "airflow" and args.password == "airflow" and args.defcreds is True


def test_airflow_output_format_and_file():
    args = parse_args(["airflow", "-t", "127.0.0.1", "-f", "json", "-o", "out.json"])
    assert args.output_format == "json" and args.output == "out.json"
    assert parse_args(["airflow", "-t", "127.0.0.1"]).output_format == "txt"


def test_airflow_show_keys_accepts_optional_limit():
    assert parse_args(["airflow", "-t", "127.0.0.1", "--show-keys"]).show_keys is True
    assert parse_args(["airflow", "-t", "127.0.0.1", "--show-keys", "7"]).show_keys == 7


def test_airflow_show_connections_accepts_optional_limit():
    assert parse_args(["airflow", "-t", "127.0.0.1", "--show-connections"]).show_connections is True
    assert parse_args(["airflow", "-t", "127.0.0.1", "--show-connections", "7"]).show_connections == 7


@pytest.mark.parametrize("flag", ["--https", "--insecure", "--session-token"])
def test_airflow_has_no_transport_or_token_flags(flag):
    with pytest.raises(SystemExit):
        parse_args(["airflow", "-t", "127.0.0.1", flag, "x"])
