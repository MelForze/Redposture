"""Large-plan scheduling and preflight contracts."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace

from hypothesis import given, settings
from hypothesis import strategies as st

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.console import Console
from redposture_core.modules.airflow.stage import build_airflow_plan
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, ModuleAuditSpec
from redposture_core.targeting import stream_scan_target_specs


def test_slow_target_does_not_block_the_next_target_window() -> None:
    first_started = threading.Event()
    third_started = threading.Event()
    release_first = threading.Event()
    results: list[int] = []
    lines: list[str] = []

    def detect(ctx: object) -> AuditRecord:
        if ctx.host == "first":
            first_started.set()
            release_first.wait(timeout=3)
        if ctx.host == "third":
            third_started.set()
        return AuditRecord(host=str(ctx.host), port=1, module="probe", service="probe", status="detected")

    def run() -> None:
        result = AuditCommandRunner(
            args=SimpleNamespace(debug=False),
            spec=ModuleAuditSpec(
                module="probe",
                label="PROBE",
                default_port=1,
                detect=detect,
                is_detected=lambda _record: True,
                render=lambda record: [record.host],
            ),
            emit_line=lines.append,
        ).run_plan(
            AuditCommandPlan(
                targets_by_port={1: ("first", "second", "third")},
                workers=2,
                target_window_size=2,
            )
        )
        results.append(result.record_count)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert first_started.wait(timeout=2)
        assert third_started.wait(timeout=2), "next window waited for the slow first target"
    finally:
        release_first.set()
        thread.join(timeout=4)
    assert not thread.is_alive()
    assert results == [3]
    assert sorted(lines) == ["first", "second", "third"]


def test_large_plan_counts_hosts_and_ports_without_expanding_ranges() -> None:
    target_plan = stream_scan_target_specs("10.0.0.1-10.0.0.3,10.0.0.2:8443,http://example.test:9000")
    plan = AuditCommandPlan(target_plan=target_plan, ports=(8080, 8443), workers=2)

    assert plan.unique_host_count == 4
    assert plan.target_counts_by_port() == {8080: 3, 8443: 3, 9000: 1}
    assert sum(plan.target_counts_by_port().values()) == plan.target_count == 7


def test_additive_port_matrix_counts_each_host_port_once() -> None:
    target_plan = stream_scan_target_specs("10.0.0.1,10.0.0.1:8443,10.0.0.1:9000")
    target_plan = target_plan.with_additional_ports_for_bare_explicit_targets()
    plan = AuditCommandPlan(target_plan=target_plan, ports=(8080, 8443), workers=2)

    actual: dict[int, int] = {}
    for _index, _host, port, _spec in plan.iter_target_specs():
        actual[port] = actual.get(port, 0) + 1
    assert plan.unique_host_count == 1
    assert plan.target_counts_by_port() == actual
    assert sum(actual.values()) == plan.target_count


def test_preflight_keeps_large_cidr_as_an_interval() -> None:
    target_plan = stream_scan_target_specs("10.0.0.0/8")
    plan = AuditCommandPlan(target_plan=target_plan, ports=(8080, 8443), workers=128)

    assert plan.unique_host_count == target_plan.target_count
    assert plan.target_counts_by_port() == {
        8080: target_plan.target_count,
        8443: target_plan.target_count,
    }
    assert plan.target_count == target_plan.target_count * 2


def test_http_url_without_explicit_port_uses_scheme_port_in_preflight() -> None:
    args = parse_args(["airflow", "-t", "http://example.test/airflow"])
    plan = build_airflow_plan(args)

    assert plan.unique_host_count == 1
    assert plan.target_count == 1
    assert plan.target_counts_by_port() == {80: 1}


@settings(max_examples=250, deadline=None)
@given(
    st.lists(
        st.sampled_from(
            (
                "10.0.0.1",
                "10.0.0.2",
                "10.0.0.1:8443",
                "10.0.0.1:9000",
                "10.0.0.1-10.0.0.3",
                "http://10.0.0.2:8080/app",
                "https://example.test:443/app",
                "https://example.test:8443/other",
            )
        ),
        min_size=1,
        max_size=10,
    ),
    st.booleans(),
)
def test_preflight_counts_match_executed_endpoint_stream(targets: list[str], additive: bool) -> None:
    target_plan = stream_scan_target_specs(",".join(targets))
    if additive:
        target_plan = target_plan.with_additional_ports_for_bare_explicit_targets()
    plan = AuditCommandPlan(target_plan=target_plan, ports=(8080, 8443), workers=2)
    actual: dict[int, int] = {}
    hosts: set[str] = set()
    for _index, host, port, _spec in plan.iter_target_specs():
        hosts.add(host)
        actual[port] = actual.get(port, 0) + 1
    assert plan.target_counts_by_port() == actual
    assert plan.unique_host_count == len(hosts)
    assert sum(actual.values()) == plan.target_count


def test_scan_plan_is_hidden_without_debug(tmp_path: Path, capsys) -> None:
    path = tmp_path / "result.txt"

    def detect(ctx: object) -> AuditRecord:
        return AuditRecord(host=str(ctx.host), port=1, module="probe", service="probe", status="detected")

    runner = AuditCommandRunner(
        args=SimpleNamespace(debug=False),
        spec=ModuleAuditSpec(
            module="probe",
            label="PROBE",
            default_port=1,
            detect=detect,
            is_detected=lambda _record: True,
            render=lambda record: [f"PROBE\t{record.host}\t{record.port}\t[*] detected"],
        ),
        emit_line=lambda line: print(line),
        console=Console(no_color=True),
    )
    runner.run_plan(AuditCommandPlan(targets_by_port={1: ("one", "two")}, workers=2, output_path=str(path)))

    output = capsys.readouterr().out.splitlines()
    assert len(output) == 2
    assert all(line.startswith("PROBE") for line in output)
    assert not any("Scan plan" in line or "Ports:" in line for line in output)
    saved = path.read_text(encoding="utf-8")
    assert "Scan plan" not in saved
    assert "\x1b" not in saved
    assert len(saved.splitlines()) == 2


def test_json_scan_plan_stays_on_stderr_only_in_debug(capsys) -> None:
    def detect(ctx: object) -> AuditRecord:
        return AuditRecord(host=str(ctx.host), port=1, module="probe", service="probe", status="detected")

    runner = AuditCommandRunner(
        args=SimpleNamespace(debug=True),
        spec=ModuleAuditSpec(module="probe", label="PROBE", default_port=1, detect=detect, is_detected=lambda _: True),
        emit_line=lambda line: print(line),
        console=Console(debug=True, no_color=True),
    )
    runner.run_plan(AuditCommandPlan(targets_by_port={1: ("one", "two")}, workers=1, output_format="json"))

    captured = capsys.readouterr()
    assert "Scan plan" in captured.err
    assert "Ports:" in captured.err
    assert "Scan plan" not in captured.out
    assert json.loads(captured.out.splitlines()[0])["host"] == "one"
