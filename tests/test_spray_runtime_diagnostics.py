"""Spray debug diagnoses the pipeline without polluting credential results."""

from __future__ import annotations

import json
import threading
from contextlib import nullcontext

import pytest

from redposture_core import stage_spray as spray
from redposture_core.cli_args import parse_args
from redposture_core.runtime_diagnostics import RuntimeDiagnostics


def run_seeded_stage(monkeypatch, tmp_path, *, debug, fmt="json", interrupt=False):
    captured = []

    def target(module, ns, host, port, destination, candidates, journal, gate, logger):
        observer = getattr(ns, "_runtime_observer", None)
        captured.append(observer)
        with observer.measure("auth") if observer else nullcontext():
            if interrupt:
                raise KeyboardInterrupt
            journal.put("detected", module, host, port, None, "confirmed", "auth required:True; version:1.0")
            journal.put("credential", module, host, port, 0, "valid", "verified", "(datasources:2)")
        return True

    monkeypatch.setattr(spray, "_run_target", target)
    output = tmp_path / f"results.{fmt}"
    argv = [
        "spray",
        "-t",
        "127.0.0.1:3000",
        "--modules",
        "grafana",
        "-u",
        "qa-user",
        "-p",
        "qa-password",
        "--workers",
        "1",
        "--no-color",
        "--format",
        fmt,
        "-o",
        str(output),
    ]
    if debug:
        argv.append("--debug")
    return lambda: spray.run_spray_stage(parse_args(argv), None), output, captured


@pytest.mark.parametrize("fmt", ["json", "txt"])
def test_debug_publishes_limits_and_actual_phases_without_entering_saved_results(monkeypatch, tmp_path, capsys, fmt):
    run, output, observed = run_seeded_stage(monkeypatch, tmp_path, debug=True, fmt=fmt)
    assert run() == 0
    terminal = capsys.readouterr()
    debug = terminal.err if fmt == "json" else terminal.out
    assert "spray worker profile: targets=1 detect_limit=0 workers=1" in debug
    assert "spray work runtime phase=auth calls=1 active=0" in debug
    assert "spray work runtime phase=finish" in debug
    assert "spray work runtime queue=deep_tasks" in debug
    assert observed[0] is not None
    saved = output.read_text()
    assert "runtime phase" not in saved and "worker profile" not in saved and "\x1b" not in saved
    if fmt == "json":
        records = [json.loads(line) for line in saved.splitlines()]
        assert [r["status"] for r in records] == ["confirmed", "valid"]
        assert records[1]["username"] == "qa-user" and records[1]["password"] == "qa-password"
        assert [json.loads(line) for line in terminal.out.splitlines()] == records


def test_disabled_debug_constructs_no_observer_or_reporter(monkeypatch, tmp_path, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("observer allocated without debug")

    monkeypatch.setattr(RuntimeDiagnostics, "__init__", forbidden)
    run, output, observed = run_seeded_stage(monkeypatch, tmp_path, debug=False)
    before = {t.ident for t in threading.enumerate()}
    assert run() == 0 and observed == [None]
    assert {t.ident for t in threading.enumerate()} == before
    terminal = capsys.readouterr()
    assert not terminal.err and "runtime" not in output.read_text()


def test_interrupt_emits_finished_diagnostic_and_stops_reporter(monkeypatch, tmp_path, capsys):
    run, _, observed = run_seeded_stage(monkeypatch, tmp_path, debug=True, interrupt=True)
    with pytest.raises(KeyboardInterrupt):
        run()
    assert observed[0] is not None
    assert observed[0].snapshot()["phases"]["auth"]["active"] == 0
    assert "spray work runtime phase=auth calls=1 active=0" in capsys.readouterr().err
    assert not any(t.name == "redposture-runtime-debug" for t in threading.enumerate())


def test_periodic_diagnostics_arrive_during_work_and_reporter_joins():
    from redposture_core.spray_diagnostics import SprayDiagnostics

    emitted = []
    arrived = threading.Event()
    before = {t.ident for t in threading.enumerate()}

    def emit(line):
        emitted.append(line)
        if "spray work runtime progress:" in line and "auth_jobs=1" in line:
            arrived.set()

    diagnostics = SprayDiagnostics(emit)
    with diagnostics.reporting(targets=1000, detect_limit=512, workers=4, interval=0.01):
        with diagnostics.work.measure("auth"):
            assert arrived.wait(2), "no diagnostic while auth was blocked"
        assert sum(t.name == "redposture-runtime-debug" for t in threading.enumerate()) == 1
    assert {t.ident for t in threading.enumerate()} == before
    assert any("spray detect runtime progress:" in line for line in emitted)
    assert any("spray work runtime phase=auth calls=1 active=0" in line for line in emitted)
    assert diagnostics.work.snapshot()["configuration"]["deep_workers"] == 4


def test_broken_diagnostic_sink_cannot_cancel_work_or_leak_reporter():
    from redposture_core.spray_diagnostics import SprayDiagnostics

    def broken(_line):
        raise OSError("diagnostic destination closed")

    diagnostics = SprayDiagnostics(broken)
    with diagnostics.reporting(targets=1, detect_limit=0, workers=1):
        with diagnostics.work.measure("auth"):
            pass
    assert diagnostics.emit_errors > 0
    assert diagnostics.work.snapshot()["phases"]["auth"]["calls"] == 1
    assert not any(t.name == "redposture-runtime-debug" for t in threading.enumerate())


def test_native_source_observes_actual_detect_slots_and_prepared_queue(monkeypatch):
    import asyncio
    import queue
    import time
    from types import SimpleNamespace

    from redposture_core import spray_async_detect
    from redposture_core.targeting import ScanTargetSpec

    async def prepare(job, logger):
        await asyncio.sleep(0.001)
        return None

    monkeypatch.setattr(spray_async_detect, "prepare_target", prepare)
    observer = RuntimeDiagnostics()
    target = ScanTargetSpec("127.0.0.1", explicit_port=3000)
    source = spray_async_detect.PreparedSource(
        [("grafana", SimpleNamespace(), target.host, 3000, target) for _ in range(40)],
        None,
        SimpleNamespace(cancelled=threading.Event()),
        SimpleNamespace(job_finished=lambda _: False),
        limit=4,
        workers=2,
        observer=observer,
    )
    got = []
    deadline = time.monotonic() + 3
    try:
        while time.monotonic() < deadline:
            try:
                got.append(next(source))
            except queue.Empty:
                time.sleep(0.001)
            except StopIteration:
                break
        assert len(got) == 40
    finally:
        source.close()
    snapshot = observer.snapshot()
    assert snapshot["configuration"] == {"detect_limit": 4, "deep_workers": 1, "max_inflight": 8}
    assert snapshot["queues"]["detect_slots"]["current"] == 0
    assert 1 <= snapshot["queues"]["detect_slots"]["peak"] <= 4
    assert snapshot["queues"]["prepared"]["current"] == 0
    assert 1 <= snapshot["queues"]["prepared"]["peak"] <= 4
    assert not source._thread.is_alive()
