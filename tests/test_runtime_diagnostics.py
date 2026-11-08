from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.runtime_diagnostics import RuntimeDiagnostics
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, ModuleAuditSpec


def test_observer_counts_concurrent_service_time_and_closes_on_error():
    clock = iter([0, 1000, 5000, 7000])
    observer = RuntimeDiagnostics(clock_ns=lambda: next(clock))
    with observer.measure("auth"):
        with pytest.raises(ValueError), observer.measure("auth"):
            raise ValueError("a target failed")
    row = observer.snapshot()["phases"]["auth"]
    assert row == {
        "calls": 2,
        "active": 0,
        "peak_active": 2,
        "total_ns": 11000,
        "max_ns": 7000,
        "p50_upper_us": 4,
        "p95_upper_us": 8,
        "p99_upper_us": 8,
    }


def test_observer_never_stores_dynamic_labels_or_unbounded_sample_lists():
    observer = RuntimeDiagnostics()
    for index in range(10000):
        observer.duration(f"secret-target-{index}", 0.001)
        observer.queue(f"host-{index}", index % 3)
        observer.configure(**{f"token-{index}": index})
    snapshot = observer.snapshot()
    assert set(snapshot["phases"]) == set(snapshot["queues"]) == {"other"}
    assert snapshot["configuration"] == {}
    assert snapshot["phases"]["other"]["calls"] == 10000
    assert snapshot["queues"]["other"] == {"current": 0, "peak": 2}
    assert all("secret" not in line and "\x1b" not in line for line in observer.debug_lines())


@pytest.mark.parametrize("seconds", [-1, float("inf"), float("nan")])
def test_invalid_measurements_are_not_silently_accepted(seconds):
    with pytest.raises(ValueError):
        RuntimeDiagnostics().duration("data", seconds)


def test_runtime_observer_is_opt_in_and_does_not_change_results():
    def detect(ctx):
        return AuditRecord(host=ctx.host, port=ctx.port, module="test", service="test", status="open_no_auth")

    async def native(ctx, http):
        await asyncio.sleep(0.001)
        return detect(ctx)

    def data(ctx, row):
        return replace(row, extra={**row.extra, "payload": "complete"})

    spec = ModuleAuditSpec(
        module="test",
        label="TEST",
        default_port=9,
        detect=detect,
        detect_async=native,
        async_detect_sync_hook=detect,
        data=data,
        render=lambda _: (),
        is_detected=lambda row: row.status == "open_no_auth",
    )
    plan = AuditCommandPlan(targets_by_port={9: tuple(str(i) for i in range(40))}, ports=(9,), workers=2)
    records = []
    for enabled in (False, True):
        args = SimpleNamespace(timeout=1, retries=0, debug=enabled)
        runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None)
        result = runner.run_plan(plan)
        records.append(sorted((r["host"], r["payload"]) for r in result.records))
        if not enabled:
            assert runner._runtime_stats is None
        else:
            snapshot = runner._runtime_stats.snapshot()
            assert snapshot["phases"]["detect_async"]["calls"] == 40
            assert snapshot["phases"]["data"]["calls"] == 40
            assert all(row["active"] == 0 for row in snapshot["phases"].values())
            assert snapshot["configuration"]["deep_workers"] == 2
    assert records[0] == records[1]


def test_scheduler_measures_bounded_queue_and_wait_without_changing_target_set():
    from redposture_core.async_detection import AsyncDetectScheduler

    observer = RuntimeDiagnostics()
    native_thread, finish_threads = set(), set()

    async def detect(index):
        native_thread.add(threading.current_thread().name)
        await asyncio.sleep(0.001)
        return index

    def finish(index, result):
        finish_threads.add(threading.current_thread().name)
        time.sleep(0.002)
        return index, result

    scheduler = AsyncDetectScheduler(detect_workers=8, deep_workers=2, max_inflight=16, observer=observer)
    rows = list(scheduler.iter_completed(range(64), detect, finish))
    assert {item for item, _ in rows} == set(range(64))
    assert len(rows) == 64 and all(value == (item, item) for item, value in rows)
    snapshot = observer.snapshot()
    assert snapshot["phases"]["queue_wait"]["calls"] == 64
    assert snapshot["phases"]["finish"]["calls"] == 64
    assert 0 < snapshot["queues"]["ready"]["peak"] <= 16
    assert snapshot["queues"]["deep_tasks"]["peak"] <= 4
    assert 0 < snapshot["queues"]["detect_slots"]["peak"] <= 8
    assert all(row["current"] == 0 for row in snapshot["queues"].values())
    assert len(native_thread) == 1 and not native_thread.intersection(finish_threads)


def test_reporter_emits_while_work_is_blocked_and_stops_on_exception():
    observer = RuntimeDiagnostics()
    observer.configure(detect_limit=64, deep_workers=2)
    emitted = threading.Event()
    lines = []

    def emit(line):
        lines.append(line)
        emitted.set()

    before = {thread.ident for thread in threading.enumerate()}
    with pytest.raises(RuntimeError), observer.reporting(emit, interval=0.005), observer.measure("data"):
        assert emitted.wait(1)
        raise RuntimeError("cancel work")
    assert any("data_jobs=1" in line and "detect_limit=64" in line for line in lines)
    assert {thread.ident for thread in threading.enumerate()} == before
    assert observer.snapshot()["phases"]["data"]["active"] == 0


def test_disabled_reporter_has_no_thread_and_diagnostic_errors_are_counted():
    observer = RuntimeDiagnostics()
    before = threading.active_count()
    with observer.reporting(None):
        assert threading.active_count() == before
    failed = threading.Event()

    def bad_emit(_line):
        failed.set()
        raise OSError("closed debug pipe")

    with observer.reporting(bad_emit, interval=0.005):
        assert failed.wait(1)
    assert observer.snapshot()["report_errors"] >= 1


def test_histogram_overflow_and_empty_active_phase_remain_honest():
    observer = RuntimeDiagnostics()
    with observer.measure("auth"):
        assert observer.snapshot()["phases"]["auth"]["p95_upper_us"] is None
    observer.duration("data", 10000)
    assert observer.snapshot()["phases"]["data"]["p99_upper_us"] == 10_000_000_000
