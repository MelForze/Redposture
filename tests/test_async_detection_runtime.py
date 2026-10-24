"""Only detect becomes async; downstream hooks and result accounting stay intact."""

from __future__ import annotations

import asyncio
import threading
from dataclasses import replace
from types import SimpleNamespace

from redposture_core.audit_models import AuditRecord
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, ModuleAuditSpec


def test_async_detect_feeds_original_sync_data_once_per_confirmed_target():
    detect_threads = []
    data_threads = []
    closed = []

    def sync_detect(ctx):
        raise AssertionError("native detect should own this path")

    async def async_detect(ctx, http):
        detect_threads.append(threading.current_thread().name)
        await asyncio.sleep(0.001)
        hit = int(ctx.host) % 4 == 0
        return AuditRecord(
            host=ctx.host,
            port=9999,
            module="probe",
            service="probe",
            status="open_no_auth" if hit else "not_service",
            extra={"is_probe": hit},
        )

    def data(ctx, record):
        data_threads.append(threading.current_thread().name)
        return replace(record, extra={**record.extra, "data_done": True})

    spec = ModuleAuditSpec(
        module="probe",
        label="PROBE",
        default_port=9999,
        detect=sync_detect,
        detect_async=async_detect,
        async_detect_sync_hook=sync_detect,
        data=data,
        lifecycle_state_factory=lambda ctx: ctx.host,
        lifecycle_state_close=closed.append,
        is_detected=lambda rec: rec.extra.get("is_probe") is True,
    )
    plan = AuditCommandPlan(
        targets_by_port={9999: tuple(str(i) for i in range(100))}, ports=(9999,), workers=4, output_format="json"
    )
    lines = []
    result = AuditCommandRunner(
        args=SimpleNamespace(timeout=1, retries=0, debug=False), spec=spec, emit_line=lines.append
    ).run_plan(plan)
    assert result.record_count == 100 and result.detected_count == 25
    assert len(data_threads) == 25 and set(detect_threads) == {"redposture-async-detect"}
    assert all(name.startswith("redposture-scheduler-") for name in data_threads)
    assert set(closed) == set(str(i) for i in range(100)) and len(closed) == 100
    assert all(bool(r.get("data_done")) == r["is_probe"] for r in result.records)
    assert len(lines) == 100 and all("\x1b" not in line for line in lines)


def test_replacing_sync_hook_does_not_leave_stale_native_detector_enabled():
    calls = []

    def original(ctx):
        raise AssertionError("old detector")

    async def stale(ctx, http):
        raise AssertionError("stale async adapter")

    def replacement(ctx):
        calls.append(ctx.host)
        return AuditRecord(host=ctx.host, port=1, module="probe", service="probe", status="not_service")

    spec = ModuleAuditSpec(
        module="probe",
        label="PROBE",
        default_port=1,
        detect=original,
        detect_async=stale,
        async_detect_sync_hook=original,
    )
    spec = replace(spec, detect=replacement)
    plan = AuditCommandPlan(
        targets_by_port={1: tuple(str(i) for i in range(40))}, ports=(1,), workers=2, output_format="json"
    )
    AuditCommandRunner(
        args=SimpleNamespace(timeout=1, retries=0, debug=False), spec=spec, emit_line=lambda _: None
    ).run_plan(plan)
    assert len(calls) == 40


def test_unsupported_native_http_restarts_legacy_detection_and_closes_both_states():
    from redposture_core.clients.async_http_detect import AsyncHttpFallback

    sync_calls = []
    states = []
    closed = []

    def state_factory(ctx):
        state = object()
        states.append(state)
        return state

    async def native(ctx, http):
        raise AsyncHttpFallback("redirect/framing/DNS")

    def legacy(ctx):
        sync_calls.append(ctx.host)
        return AuditRecord(host=ctx.host, port=1, service="probe", module="probe", status="open_no_auth")

    spec = ModuleAuditSpec(
        module="probe",
        label="PROBE",
        default_port=1,
        detect=legacy,
        detect_async=native,
        async_detect_sync_hook=legacy,
        lifecycle_state_factory=state_factory,
        lifecycle_state_close=closed.append,
        is_detected=lambda record: record.status == "open_no_auth",
    )
    result = AuditCommandRunner(
        args=SimpleNamespace(timeout=1, retries=0, debug=False), spec=spec, emit_line=lambda _: None
    ).run_plan(
        AuditCommandPlan(
            targets_by_port={1: tuple(str(i) for i in range(40))}, ports=(1,), workers=4, output_format="json"
        )
    )
    assert result.detected_count == 40 and result.record_count == 40
    assert len(sync_calls) == len(set(sync_calls)) == 40
    assert len(states) == len(closed) == 80 and set(states) == set(closed)


def test_automatic_detect_has_more_inflight_than_sync_data_workers():
    active = peak = 0
    data_active = data_peak = 0
    lock = threading.Lock()

    async def native(ctx, http):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return AuditRecord(host=ctx.host, port=1, module="probe", service="probe", status="open_no_auth")

    def legacy(ctx):
        raise AssertionError("unexpected fallback")

    def data(ctx, record):
        import time

        nonlocal data_active, data_peak
        with lock:
            data_active += 1
            data_peak = max(data_peak, data_active)
        time.sleep(0.002)
        with lock:
            data_active -= 1
        return record

    spec = ModuleAuditSpec(
        module="probe",
        label="PROBE",
        default_port=1,
        detect=legacy,
        detect_async=native,
        async_detect_sync_hook=legacy,
        data=data,
        is_detected=lambda r: True,
    )
    result = AuditCommandRunner(
        args=SimpleNamespace(timeout=1, retries=0, debug=False), spec=spec, emit_line=lambda _: None
    ).run_plan(
        AuditCommandPlan(
            targets_by_port={1: tuple(str(i) for i in range(100))}, ports=(1,), workers=2, output_format="json"
        )
    )
    assert result.detected_count == result.record_count == 100
    assert 2 < peak <= 64
    assert data_peak == 2


def test_no_native_fd_headroom_preserves_the_entire_legacy_path(monkeypatch):
    import resource

    monkeypatch.setattr(resource, "getrlimit", lambda _: (64, 64))
    calls = []

    def legacy(ctx):
        calls.append(ctx.host)
        return AuditRecord(host=ctx.host, port=1, module="probe", service="probe", status="open_no_auth")

    async def native(ctx, http):
        raise AssertionError("native connection must not be attempted without FD headroom")

    spec = ModuleAuditSpec(
        module="probe",
        label="PROBE",
        default_port=1,
        detect=legacy,
        detect_async=native,
        async_detect_sync_hook=legacy,
        is_detected=lambda r: True,
    )
    result = AuditCommandRunner(
        args=SimpleNamespace(timeout=1, retries=0, debug=False), spec=spec, emit_line=lambda _: None
    ).run_plan(
        AuditCommandPlan(
            targets_by_port={1: tuple(str(i) for i in range(40))}, ports=(1,), workers=4, output_format="json"
        )
    )
    assert result.detected_count == result.record_count == 40
    assert len(calls) == len(set(calls)) == 40


def test_negative_retained_lifecycle_close_stays_off_native_event_loop():
    import threading

    closed = []

    def sync(ctx):
        raise AssertionError("unexpected legacy detect")

    async def native(ctx, http):
        return AuditRecord(host=ctx.host, port=9999, module="probe", service="probe", status="not_service")

    def close(state):
        closed.append(threading.current_thread().name)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        raise AssertionError("blocking lifecycle cleanup ran on detection loop")

    spec = ModuleAuditSpec(
        module="probe",
        label="PROBE",
        default_port=9999,
        detect=sync,
        detect_async=native,
        async_detect_sync_hook=sync,
        lifecycle_state_factory=lambda ctx: object(),
        lifecycle_state_close=close,
        is_detected=lambda rec: False,
    )
    args = SimpleNamespace(timeout=1, retries=0, workers=2, debug=False, no_color=True)
    runner = AuditCommandRunner(args=args, spec=spec, emit_line=lambda line: None)
    plan = AuditCommandPlan(
        targets_by_port={9999: tuple(str(i) for i in range(40))}, ports=(9999,), workers=2, output_format="json"
    )
    runner.run_plan(plan)
    assert len(closed) == 40
    assert "redposture-async-detect" not in closed
