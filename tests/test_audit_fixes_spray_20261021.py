"""Audit regressions: durable pacing, bounded replay and exporter scheduling."""

from __future__ import annotations

import json
import threading
import tracemalloc
from argparse import Namespace
from types import SimpleNamespace

import pytest

from redposture_core import stage_scan, stage_spray
from redposture_core.cli_args import parse_args
from redposture_core.console import Console
from redposture_core.exporters import collect, discover
from redposture_core.targeting import ScanTargetSpec


@pytest.mark.parametrize("flag", ["--timeout", "--origin-rate", "--account-interval"])
@pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
def test_spray_rejects_nonfinite_cli_floats(flag, value):
    with pytest.raises(SystemExit):
        parse_args(["spray", "-t", "localhost", "--modules", "airflow", "-u", "a", "-p", "b", f"{flag}={value}"])


def test_resumed_gate_keeps_remaining_cooldown_and_origin_stop(tmp_path, monkeypatch):
    clock = [1000.0, 100.0]
    monkeypatch.setattr(stage_spray.time, "time", lambda: clock[0])
    monkeypatch.setattr(stage_spray.time, "monotonic", lambda: clock[1])
    path = str(tmp_path / "spray.sqlite")
    journal = stage_spray.AttemptJournal(path, "same", False)
    gate = stage_spray.RateGate(2, 60, journal=journal)
    assert gate.claim("https://a:443", "alice") == 0
    gate.stop("https://b:443", "429")
    journal.close()
    clock[:] = [1010.0, 500.0]
    resumed = stage_spray.AttemptJournal(path, "same", True)
    try:
        gate = stage_spray.RateGate(2, 60, journal=resumed)
        assert gate.reserve("https://a:443", "alice") == (True, 50.0)
        assert gate.claim("https://a:443", "alice") == 50.0
        assert gate.claim("https://a:443", "bob") == 0.0
        assert gate.reserve("https://b:443", "bob") == (False, "429")
    finally:
        resumed.close()


def test_journal_replay_memory_is_bounded_by_page(tmp_path):
    journal = stage_spray.AttemptJournal(str(tmp_path / "spray.sqlite"), "same", False)
    journal.db.executemany(
        "INSERT INTO results VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ((str(i), "airflow", f"h{i % 2}", 8080, i, "invalid", "x" * 2048, "") for i in range(12000)),
    )
    journal.db.commit()
    tracemalloc.start()
    try:
        count = sum(1 for _ in journal.rows())
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
        journal.close()
    assert count == 12000
    assert peak < 3 * 1024 * 1024


def test_collect_json_does_not_retain_emitted_bodies():
    peak_at_emit = []

    def task(host, exporter, port, endpoint, timeout, retries):
        record = dict(
            host=host,
            exporter=exporter,
            port=port,
            endpoint=endpoint,
            url=f"http://{host}:{port}{endpoint}",
            status=200,
            ok=True,
            error=None,
            body=host + "x" * (256 * 1024),
            timestamp="now",
            truncated=False,
        )
        return record, True

    def emitted(line):
        if json.loads(line).get("ok"):
            peak_at_emit.append(tracemalloc.get_traced_memory()[0])

    tracemalloc.start()
    try:
        assert collect.collect_exporter_debug_data(
            None,
            [f"h{i}" for i in range(24)],
            1,
            None,
            "json",
            emitted,
            workers=1,
            collect_exporters=[dict(name="node", port=9100)],
            collect_debug_endpoints=["/metrics"],
            adaptive_collect=False,
            collect_task_fn=task,
            max_inflight_requests=1,
        ) == (24, 24)
    finally:
        tracemalloc.stop()
    assert peak_at_emit[-1] - peak_at_emit[0] < 2 * 1024 * 1024


def test_large_scan_feeds_next_window_while_first_endpoint_is_slow(monkeypatch, tmp_path):
    release = threading.Event()
    passed_window = threading.Event()
    first_started = threading.Event()
    results = []

    def task(host, port, exporters, timeout, retries, **kwargs):
        number = int(host[1:])
        if number == 0:
            first_started.set()
            assert release.wait(15)
        if number == 4096:
            passed_window.set()
        return dict(
            timestamp="now",
            host=host,
            port=port,
            detected=False,
            exporter="unknown",
            method="none",
            status=404,
            error=None,
            url=f"http://{host}:{port}/metrics",
        ), None

    monkeypatch.setattr(discover, "scan_presence_port_task", task)
    from redposture_core.targeting import stream_scan_target_specs

    targets = tmp_path / "targets.txt"
    targets.write_text("".join(f"h{i}\n" for i in range(65537)))
    plan = stream_scan_target_specs(str(targets))
    output = tmp_path / "scan.jsonl"
    args = Namespace(timeout=1, output=str(output), output_format="json", debug=False, workers=8, retries=0)
    thread = threading.Thread(
        target=lambda: results.append(
            stage_scan._run_large_scan_stage(
                args,
                None,
                Console(no_color=True),
                target_plan=plan,
                custom_ports=[9100],
                profiles={"discovery_exporters": [dict(name="node", port=9100)]},
                emit_line=None,
                stream_to_stdout=False,
                tls_context=None,
            )
        )
    )
    thread.start()
    try:
        assert first_started.wait(5)
        assert passed_window.wait(5), "4096-window barrier left seven workers idle behind endpoint h0"
    finally:
        release.set()
        thread.join(30)
    assert not thread.is_alive()
    assert results == [0]
    lines = output.read_text().splitlines()
    assert len(lines) == 65538
    summary = json.loads(lines[-1])
    assert summary["checks"] == 65537
    assert sum(json.loads(line).get("type") == "summary" for line in lines) == 1
    assert "\x1b" not in output.read_text()


def test_legacy_resume_starts_conservative_cooldown_and_restores_stop(tmp_path, monkeypatch):
    import sqlite3

    path = str(tmp_path / "legacy.sqlite")
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO meta VALUES ('fingerprint', 'same')")
    journal = stage_spray.AttemptJournal(path, "same", True)
    journal.put("a0", "airflow", "a", 8080, 0, "invalid", "rejected")
    journal.put("b0", "airflow", "b", 8080, 0, "rate_limited", "429")
    monkeypatch.setattr(stage_spray.time, "time", lambda: 1000.0)
    monkeypatch.setattr(stage_spray.time, "monotonic", lambda: 100.0)
    candidates = (stage_spray.Candidate("pair", "alice", "secret"),)
    try:
        gate = stage_spray.RateGate(2, 60, journal=journal)
        gate.restore_legacy("tcp://a:8080", journal.target_rows("airflow", "a", 8080), candidates)
        gate.restore_legacy("tcp://b:8080", journal.target_rows("airflow", "b", 8080), candidates)
        assert gate.claim("tcp://a:8080", "alice") == 60.0
        assert gate.reserve("tcp://b:8080", "alice") == (False, "429")
    finally:
        journal.close()
    journal = stage_spray.AttemptJournal(path, "same", True)
    try:
        gate = stage_spray.RateGate(2, 60, journal=journal)
        assert gate.claim("tcp://a:8080", "alice") == 60.0
        assert gate.reserve("tcp://b:8080", "alice") == (False, "429")
    finally:
        journal.close()


def test_completed_replay_is_not_duplicated_if_job_finish_was_interrupted(tmp_path, capsys):
    journal = stage_spray.AttemptJournal(str(tmp_path / "replay.sqlite"), "same", False)
    journal.put("detect", "airflow", "a", 8080, None, "confirmed", "detected")
    journal.put("attempt", "airflow", "a", 8080, 0, "invalid", "rejected")
    output = tmp_path / "spray.txt"
    sink = stage_spray.SpraySink(
        str(output), "txt", (stage_spray.Candidate("pair", "a", "b"),), Console(no_color=True), group_targets=True
    )
    try:
        for row in journal.complete_rows(1):
            sink.emit(*row)
        sink.replay_journal = journal
        sink.begin_target("airflow", "a", 8080)
        sink.end_target()
    finally:
        sink.close()
        journal.close()
    assert len(output.read_text().splitlines()) == 2


def test_large_scan_keeps_mixed_scheme_deduplication(monkeypatch, tmp_path):
    from redposture_core.targeting import stream_scan_target_specs

    targets = tmp_path / "targets.txt"
    targets.write_text("h:9100\nhttp://h:9100/a\nhttp://h:9100/b\nhttps://h:9100/a\n")
    plan = stream_scan_target_specs(str(targets))
    output = tmp_path / "mixed.jsonl"

    def task(host, port, exporters, timeout, retries, *, scheme="http"):
        return dict(
            timestamp="now",
            host=host,
            port=port,
            detected=False,
            exporter="unknown",
            method="none",
            status=404,
            error=None,
            url=f"{scheme}://{host}:{port}/metrics",
        ), None

    monkeypatch.setattr(discover, "scan_presence_port_task", task)
    args = Namespace(timeout=1, output=str(output), output_format="json", debug=False, workers=2, retries=0)
    assert (
        stage_scan._run_large_scan_stage(
            args,
            None,
            Console(no_color=True),
            target_plan=plan,
            custom_ports=[9100],
            profiles={"discovery_exporters": [dict(name="node", port=9100)]},
            emit_line=None,
            stream_to_stdout=False,
            tls_context=None,
        )
        == 0
    )
    records = [json.loads(line) for line in output.read_text().splitlines()]
    assert sorted(record["url"] for record in records[:-1]) == ["http://h:9100/metrics", "https://h:9100/metrics"]
    assert records[-1]["checks"] == 2


def test_late_claim_cannot_erase_durable_origin_stop(tmp_path):
    path = str(tmp_path / "late.sqlite")
    journal = stage_spray.AttemptJournal(path, "same", False)
    gate = stage_spray.RateGate(2, 60, journal=journal)
    gate.reserve("origin", "alice")
    gate.stop("origin", "429")
    gate.claim("origin", "alice")
    journal.close()
    journal = stage_spray.AttemptJournal(path, "same", True)
    try:
        gate = stage_spray.RateGate(2, 60, journal=journal)
        assert gate.reserve("origin", "bob") == (False, "429")
    finally:
        journal.close()


@pytest.mark.parametrize("first_status", ["auth_required", "rate_limited"])
def test_saved_result_interruption_preserves_real_target_dispatch_policy(tmp_path, monkeypatch, first_status):
    from redposture_core.audit_models import AuditRecord
    from redposture_core.stage_runtime import ModuleAuditSpec

    calls = []

    def detect(ctx):
        return AuditRecord.from_mapping(dict(host=ctx.host, port=ctx.port, status="detected", is_airflow=True))

    def auth(ctx, record):
        calls.append(ctx.credential.password)
        return AuditRecord.from_mapping(dict(host=ctx.host, port=ctx.port, status=first_status, is_airflow=True))

    spec = ModuleAuditSpec(
        module="airflow",
        label="AIRFLOW",
        default_port=8080,
        detect=detect,
        auth=auth,
        is_detected=lambda record: record.extra.get("is_airflow") is True,
    )
    monkeypatch.setattr(
        stage_spray.importlib, "import_module", lambda name: SimpleNamespace(build_airflow_spec=lambda args: spec)
    )
    clock = [1000.0, 100.0]
    monkeypatch.setattr(stage_spray.time, "time", lambda: clock[0])
    monkeypatch.setattr(stage_spray.time, "monotonic", lambda: clock[1])
    candidates = (stage_spray.Candidate("pair", "alice", "first"), stage_spray.Candidate("pair", "alice", "second"))
    path = str(tmp_path / "interrupted.sqlite")
    journal = stage_spray.AttemptJournal(path, "same", False)

    def interrupt(module, host, port, index, status, evidence, detail):
        if index == 0 and status != "started":
            raise KeyboardInterrupt

    journal.on_result = interrupt
    gate = stage_spray.RateGate(2, 60, journal=journal)
    try:
        with pytest.raises(KeyboardInterrupt):
            stage_spray._run_target(
                "airflow", Namespace(), "a", 8080, ScanTargetSpec("a"), candidates, journal, gate, None
            )
    finally:
        journal.close()
    assert calls == ["first"]
    clock[:] = [1005.0, 500.0]
    journal = stage_spray.AttemptJournal(path, "same", True)
    gate = stage_spray.RateGate(2, 60, journal=journal)
    token = stage_spray._COOPERATIVE_SPRAY.set(True)
    operation = stage_spray._run_target(
        "airflow", Namespace(), "a", 8080, ScanTargetSpec("a"), candidates, journal, gate, None
    )
    try:
        if first_status == "auth_required":
            assert next(operation) == 55.0
        else:
            with pytest.raises(StopIteration):
                next(operation)
            assert list(journal.rows())[-1][4] == "rate_limited"
        assert calls == ["first"]
    finally:
        operation.close()
        stage_spray._COOPERATIVE_SPRAY.reset(token)
        journal.close()


def test_sql_grouped_replay_preserves_first_target_and_attempt_order(tmp_path):
    journal = stage_spray.AttemptJournal(str(tmp_path / "order.sqlite"), "same", False)
    for i, (host, candidate, status) in enumerate(
        [
            ("a", None, "confirmed"),
            ("b", None, "confirmed"),
            ("a", 0, "invalid"),
            ("b", 0, "invalid"),
            ("a", 1, "valid"),
            ("b", 1, "valid"),
            ("partial", None, "confirmed"),
            ("partial", 0, "invalid"),
        ]
    ):
        journal.put(str(i), "airflow", host, 8080, candidate, status, "")
    try:
        assert [(row[1], row[3], row[4]) for row in journal.complete_rows(2)] == [
            ("a", None, "confirmed"),
            ("a", 0, "invalid"),
            ("a", 1, "valid"),
            ("b", None, "confirmed"),
            ("b", 0, "invalid"),
            ("b", 1, "valid"),
        ]
    finally:
        journal.close()


def test_partial_grouped_replay_spills_to_disk_without_retaining_evidence(tmp_path, monkeypatch):
    journal = stage_spray.AttemptJournal(str(tmp_path / "partial.sqlite"), "same", False)
    journal.db.executemany(
        "INSERT INTO results VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ((str(i), "airflow", "a", 8080, i, "invalid", "x" * 2048, "") for i in range(12000)),
    )
    journal.db.commit()
    candidates = (stage_spray.Candidate("pair", "u", "p"),) * 12001
    console = Console(no_color=True)
    monkeypatch.setattr(console, "plain", lambda *args, **kwargs: None)
    output = tmp_path / "partial.txt"
    sink = stage_spray.SpraySink(str(output), "txt", candidates, console, group_targets=True)
    sink.replay_journal = journal
    tracemalloc.start()
    try:
        sink.begin_target("airflow", "a", 8080)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    try:
        sink.end_target()
    finally:
        sink.close()
        journal.close()
    assert peak < 3 * 1024 * 1024
    with output.open() as stream:
        assert sum(1 for _ in stream) == 12000
    assert "\x1b" not in output.read_text()


@pytest.mark.parametrize("second_status", ["invalid", "rate_limited"])
def test_legacy_restore_merges_accounts_and_stops_across_same_origin_targets(tmp_path, monkeypatch, second_status):
    import sqlite3

    path = str(tmp_path / "legacy-shared-origin.sqlite")
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO meta VALUES ('fingerprint', 'same')")
    journal = stage_spray.AttemptJournal(path, "same", True)
    journal.put("a", "airflow", "a", 8080, 0, "invalid", "rejected")
    journal.put("b", "grafana", "a", 8080, 1, second_status, "429" if second_status == "rate_limited" else "rejected")
    monkeypatch.setattr(stage_spray.time, "time", lambda: 1000.0)
    monkeypatch.setattr(stage_spray.time, "monotonic", lambda: 100.0)
    candidates = (stage_spray.Candidate("pair", "alice", "a"), stage_spray.Candidate("pair", "bob", "b"))
    try:
        gate = stage_spray.RateGate(2, 60, journal=journal)
        gate.restore_legacy("http://a:8080", journal.target_rows("airflow", "a", 8080), candidates)
        gate.restore_legacy("http://a:8080", journal.target_rows("grafana", "a", 8080), candidates)
        if second_status == "invalid":
            assert gate.claim("http://a:8080", "bob") == 60.0
        else:
            assert gate.reserve("http://a:8080", "bob") == (False, "429")
    finally:
        journal.close()


def test_partial_replay_excludes_results_written_after_run_started(tmp_path):
    journal = stage_spray.AttemptJournal(str(tmp_path / "snapshot.sqlite"), "same", False)
    output = tmp_path / "snapshot.txt"
    sink = stage_spray.SpraySink(
        str(output),
        "txt",
        (stage_spray.Candidate("pair", "u", "p"),) * 2,
        Console(no_color=True),
        group_targets=True,
    )
    sink.replay_journal = journal
    # Another job has already emitted this new result during the current run.
    journal.put("new-result", "airflow", "a", 8080, 0, "invalid", "rejected")
    try:
        sink.begin_target("airflow", "a", 8080)
        sink.end_target()
    finally:
        sink.close()
        journal.close()
    assert output.read_text() == ""


def test_grouped_resume_keeps_partial_rows_for_finished_blocked_job(tmp_path, monkeypatch):
    args = parse_args(
        [
            "spray",
            "-t",
            "a:8080",
            "--modules",
            "airflow,grafana",
            "-u",
            "alice",
            "-p",
            "first",
            "--checkpoint",
            str(tmp_path / "blocked.sqlite"),
            "-o",
            str(tmp_path / "blocked.txt"),
            "--resume",
            "--no-color",
        ]
    )
    candidates = (stage_spray.Candidate("pair", "alice", "first"), stage_spray.Candidate("pair", "alice", "second"))
    monkeypatch.setattr(stage_spray, "load_candidates", lambda args: candidates)
    target = ScanTargetSpec("a", explicit_port=8080, raw="a:8080")
    fingerprint = stage_spray._input_fingerprint(args, ("airflow", "grafana"), {})
    journal = stage_spray.AttemptJournal(args.checkpoint, fingerprint, False)
    journal.put("detect", "airflow", "a", 8080, None, "confirmed", "detected")
    journal.put("first", "airflow", "a", 8080, 0, "rate_limited", "429")
    journal.finish_job(stage_spray._attempt_id("airflow", target, 8080, -1))
    journal.close()
    monkeypatch.setattr(stage_spray.importlib, "import_module", lambda name: SimpleNamespace())
    monkeypatch.setattr(
        stage_spray,
        "_spray_jobs",
        lambda modules, module_args: iter(
            [
                ("airflow", Namespace(), "a", 8080, target),
            ]
        ),
    )
    assert stage_spray.run_spray_stage(args, None) == 0
    lines = (tmp_path / "blocked.txt").read_text().splitlines()
    assert len(lines) == 2
    assert "[*] Airflow" in lines[0]
    assert "[!] alice:first" in lines[1]


def test_partial_target_history_is_replayed_once_across_repeated_jobs(tmp_path):
    journal = stage_spray.AttemptJournal(str(tmp_path / "once.sqlite"), "same", False)
    journal.put("saved", "airflow", "a", 8080, 0, "invalid", "rejected")
    output = tmp_path / "once.txt"
    sink = stage_spray.SpraySink(
        str(output),
        "txt",
        (stage_spray.Candidate("pair", "u", "p"),) * 2,
        Console(no_color=True),
        group_targets=True,
    )
    sink.replay_journal = journal
    try:
        for _ in range(2):
            sink.begin_target("airflow", "a", 8080)
            sink.end_target()
    finally:
        sink.close()
        journal.close()
    assert len(output.read_text().splitlines()) == 1
