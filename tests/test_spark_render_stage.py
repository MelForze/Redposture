"""Spark parser/lifecycle and Airflow-compatible output semantics."""

from __future__ import annotations

import argparse
import importlib
import json
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.console import Console


def load(name):
    try:
        return importlib.import_module("redposture_core.modules.spark." + name)
    except ModuleNotFoundError:
        pytest.fail("Spark lifecycle/rendering has not been implemented")


def parse(argv):
    from redposture_core import cli_args as shared

    try:
        from redposture_core.cli_modules.spark import configure_spark_parser
    except ModuleNotFoundError:
        pytest.fail("Spark CLI parser has not been implemented")
    parser = argparse.ArgumentParser()
    configure_spark_parser(
        parser,
        add_output_flags=shared._add_output_flags,
        add_log_flag=shared._add_log_flag,
        add_scan_host_flags=shared._add_scan_host_flags,
        add_multi_ports_flag=shared._add_multi_ports_flag,
        add_save_flag=shared._add_save_flag,
        port_type=shared._port_spec,
    )
    return parser.parse_args(argv)


def test_parser_default_audit_is_read_only_and_has_no_password_options():
    args = parse(["-t", "master", "--show-workers", "--show-apps"])
    assert args.probe_submit is False
    assert args.show_workers and args.show_apps
    assert not hasattr(args, "username") and not hasattr(args, "password")


def test_parser_exposes_only_explicit_non_executing_submit_probe():
    args = parse(["-t", "master", "--probe-submit", "--tls-ca", "ca.pem", "--discover-max-bytes", "1000"])
    assert args.probe_submit and args.tls_ca == "ca.pem" and args.discover_max_bytes == 1000


def test_plan_scans_ui_and_rest_ports_with_no_credential_attempts():
    args = parse(["-t", "master"])
    plan = load("stage").build_spark_plan(args)
    assert plan.ports == (8080, 6066)
    assert plan.credential_runs == ()


def test_plan_keeps_explicit_target_port_and_prefix():
    args = parse(["-t", "https://master:9443/proxy"])
    plan = load("stage").build_spark_plan(args)
    assert plan.target_plan is not None
    assert plan.credential_runs == ()
    assert [(host, port) for _idx, host, port, _target in plan.iter_target_specs()] == [("master", 9443)]


@pytest.mark.parametrize(
    "values",
    [{"tls_cert": "client.pem"}, {"tls_key": "client.key"}, {"discover_time": float("nan")}, {"discover_max_bytes": 0}],
)
def test_invalid_tls_pairs_and_discovery_budgets_fail_before_connect(values):
    errors = []
    assert load("policy").validate_args(SimpleNamespace(**values), SimpleNamespace(error=errors.append)) == 2
    assert errors


class RecordingConsole:
    def __init__(self):
        self.paints: list[tuple[str, str]] = []

    def _paint(self, text: str, color: str, stream: Any) -> str:
        self.paints.append((text, color))
        return text

    def plain(self, _text):
        pass


def test_detect_coloring_matches_airflow_access_and_version_semantics():
    render = load("render")
    record = {
        "host": "master",
        "port": 6066,
        "is_spark": True,
        "auth_required": False,
        "version": "3.5.1",
        "surface": "submission_rest",
    }
    line = render._format_detect_record(record, "txt")
    console = RecordingConsole()
    assert render._render_colored_spark_line(console, line)
    assert any("auth required:False" in text and color == "true_red" for text, color in console.paints)
    assert any("version:3.5.1" in text and color == "white" for text, color in console.paints)
    assert any("Apache Spark" in text and color == "white" for text, color in console.paints)
    assert render._format_detect_record(record, "json") == ""


@pytest.mark.parametrize("count,color", [(0, "bright_green"), (1, "true_red")])
def test_inventory_heading_is_white_counts_are_findings_and_values_are_orange(count, color):
    render = load("render")
    record = {
        "host": "master",
        "port": 8080,
        "inventory_requested": ["workers"],
        "workers_access": "allowed",
        "workers": [{"id": "worker-qa"}] * count,
    }
    lines = render._format_inventory_records(record, "txt")
    console = RecordingConsole()
    for line in lines:
        assert render._render_colored_spark_line(console, line)
    assert any("Workers Enumeration" in text and paint == "white" for text, paint in console.paints)
    assert any(f"workers:{count}" in text and paint == color for text, paint in console.paints)
    assert any("access:allowed" in text and paint == "true_red" for text, paint in console.paints)
    if count:
        assert any("worker-qa" in text and paint == "orange" for text, paint in console.paints)


@pytest.mark.parametrize(
    "state,color",
    [("denied", "bright_green"), ("unknown", "orange"), ("unavailable", "orange"), ("rate_limited", "orange")],
)
def test_inventory_denial_and_unknown_states_have_distinct_color(state, color):
    render = load("render")
    lines = render._format_inventory_records({"inventory_requested": ["apps"], "apps_access": state}, "txt")
    console = RecordingConsole()
    assert render._render_colored_spark_line(console, lines[0])
    assert any("access:" + state in text and paint == color for text, paint in console.paints)


def test_probe_parser_reachability_never_renders_submit_allowed():
    render = load("render")
    record = {
        "submit_probe": {"access": "unverified", "parser_reachable": True, "execution": False},
        "rce_potential": True,
    }
    lines = render._format_inventory_records(record, "txt")
    assert any("parser reachable:True" in line for line in lines)
    assert all("access:allowed" not in line for line in lines)
    console = RecordingConsole()
    render._render_colored_spark_line(
        console,
        render._format_detect_record({"is_spark": True, "rce_potential": True}, "txt"),
    )
    for line in lines:
        render._render_colored_spark_line(console, line)
    assert any("RCE:Possible" in text and color == "true_red" for text, color in console.paints)
    assert any("parser reachable:True" in text and color == "true_red" for text, color in console.paints)
    assert any("access:unverified" in text and color == "orange" for text, color in console.paints)


def test_no_color_console_and_all_raw_rendered_outputs_contain_no_ansi(monkeypatch, capsys):
    monkeypatch.setenv("FORCE_COLOR", "1")
    render = load("render")
    record = {
        "host": "master",
        "port": 8080,
        "is_spark": True,
        "auth_required": False,
        "inventory_requested": ["apps"],
        "apps_access": "allowed",
        "apps": [{"name": "contains\x1b[31msecret"}],
    }
    lines = [render._format_detect_record(record, "txt"), *render._format_inventory_records(record, "txt")]
    console = Console(no_color=True)
    for line in lines:
        render._render_colored_spark_line(console, line)
    assert "\x1b" not in capsys.readouterr().out
    assert all("\x1b" not in line for line in lines)
    assert "\x1b" not in json.dumps(record)
    assert render._format_inventory_records(record, "json") == []
