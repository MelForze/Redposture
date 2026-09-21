"""Execution-level stress contracts for primary and nested worker pools."""

from __future__ import annotations

import threading
import time

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.scheduler import SharedNestedScheduler
from redposture_core.stage_runtime import AuditCommandRunner, ModuleAuditSpec, build_basic_audit_plan


@pytest.mark.parametrize(
    ("target_range", "expected_count", "expected_workers"),
    [
        ("10.0.0.1-10.0.3.231", 999, 64),
        ("10.0.0.1-10.0.3.232", 1_000, 128),
        ("10.0.0.1-10.0.39.16", 10_000, 128),
    ],
)
def test_primary_pool_executes_full_999_1000_10000_target_boundaries(
    target_range: str,
    expected_count: int,
    expected_workers: int,
) -> None:
    args = parse_args(["redis", "-t", target_range, "--port", "6379"])
    plan = build_basic_audit_plan(args, default_port=6379)
    lock = threading.Lock()
    active = 0
    peak = 0
    completed = 0

    def detect(ctx: object) -> AuditRecord:
        nonlocal active, peak, completed
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.0005)
        with lock:
            active -= 1
            completed += 1
        return AuditRecord(
            host=str(ctx.host),
            port=int(ctx.port),
            module="stress",
            service="stress",
            status="not_stress",
        )

    result = AuditCommandRunner(
        args=args,
        spec=ModuleAuditSpec(
            module="stress",
            label="STRESS",
            default_port=6379,
            detect=detect,
            is_detected=lambda _record: False,
            record_retention_limit=0,
        ),
        emit_line=lambda _line: None,
    ).run_plan(plan)

    assert plan.target_count == expected_count
    assert plan.workers == expected_workers
    assert result.record_count == expected_count
    assert completed == expected_count
    assert 1 < peak <= expected_workers
    assert result.records == []
    assert result.record_retention_truncated is True


def test_shared_nested_pool_enforces_module_limits_under_simultaneous_load() -> None:
    scheduler = SharedNestedScheduler(max_workers=32)
    limits = {"minio": 8, "elastic": 8, "proxmox": 8, "clickhouse": 4}
    active = {name: 0 for name in limits}
    peaks = {name: 0 for name in limits}
    global_active = 0
    global_peak = 0
    start_order: list[str] = []
    outputs: dict[str, list[int]] = {}
    lock = threading.Lock()
    gate = threading.Barrier(len(limits) + 1)

    def coordinator(name: str, limit: int) -> None:
        nonlocal global_active, global_peak
        gate.wait(timeout=3)

        def work(value: int) -> int:
            nonlocal global_active, global_peak
            with lock:
                active[name] += 1
                global_active += 1
                peaks[name] = max(peaks[name], active[name])
                global_peak = max(global_peak, global_active)
                start_order.append(name)
            time.sleep(0.003)
            with lock:
                active[name] -= 1
                global_active -= 1
            return value * 2

        outputs[name] = scheduler.map_ordered(range(80), work, key=name, per_key_limit=limit)

    threads = [threading.Thread(target=coordinator, args=(name, limit), daemon=True) for name, limit in limits.items()]
    for thread in threads:
        thread.start()
    gate.wait(timeout=3)
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()
    scheduler.close()

    assert outputs == {name: [value * 2 for value in range(80)] for name in limits}
    assert all(1 <= peaks[name] <= limit for name, limit in limits.items())
    assert global_peak <= 32
    assert set(start_order[:64]) == set(limits)
    assert not any(thread.name.startswith("redposture-nested-") for thread in threading.enumerate())


def test_shared_nested_cancel_returns_without_waiting_for_blocked_worker() -> None:
    scheduler = SharedNestedScheduler(max_workers=2)
    release = threading.Event()
    started = threading.Event()

    def work(value: int) -> None:
        if value == 0:
            started.set()
            release.wait(timeout=5)
            return
        assert started.wait(timeout=2)
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        list(scheduler.iter_completed(range(100), work, key="target", per_key_limit=2))
    began = time.monotonic()
    scheduler.cancel()
    elapsed = time.monotonic() - began
    release.set()

    assert elapsed < 0.25
