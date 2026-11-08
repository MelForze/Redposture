"""Slow post-detection work must preserve bounded queues and fair root progress."""

from __future__ import annotations

import asyncio
import threading
from collections import Counter

import pytest

from redposture_core.async_detection import AsyncDetectScheduler
from redposture_core.detect_backoff import detect_backoff
from redposture_core.runtime_diagnostics import RuntimeDiagnostics
from redposture_core.scheduler import BoundedScheduler


@pytest.mark.parametrize("engine", ["sync", "async"])
@pytest.mark.parametrize("priority", [False, True])
def test_ready_leaf_priority_preserves_all_jobs_and_socket_locality(engine, priority):
    def children(item, value):
        if item[0] == "root":
            return [("plan", index) for index in range(20)]
        return [("leaf", item[1])] if item[0] == "plan" else []

    selected = (lambda item, value: item[0] == "plan") if priority else None
    if engine == "sync":
        scheduler = BoundedScheduler(max_workers=1, max_inflight=4)
        rows = list(scheduler.iter_expanding([("root", 0)], lambda item: item, children, prioritize_children=selected))
    else:

        async def detect(item):
            await asyncio.sleep(0)
            return item

        async_scheduler: AsyncDetectScheduler[tuple[str, int], tuple[str, int], tuple[str, int]] = AsyncDetectScheduler(
            detect_workers=4, deep_workers=1, max_inflight=4
        )
        rows = list(
            async_scheduler.iter_completed(
                [("root", 0)], detect, lambda item, value: value, children, prioritize_children=selected
            )
        )
    order = [item for item, _ in rows]
    expected = [("root", 0), *[(kind, index) for kind in ("plan", "leaf") for index in range(20)]]
    assert Counter(order) == Counter(expected)
    assert all(item == value for item, value in rows)
    assert (order.index(("leaf", 0)) < order.index(("plan", 19))) is priority


def test_prioritized_leaf_does_not_wait_behind_already_detected_plans():
    detected_wave = threading.Event()
    first_leaf_ready = threading.Event()
    started = []
    detected = []

    async def detect(item):
        detected.append(item)
        if len(detected) >= 32:
            detected_wave.set()
        await asyncio.sleep(0)
        if item == ("leaf", 0):
            first_leaf_ready.set()
        return item

    def finish(item, _value):
        started.append(item)
        if item == ("plan", 0):
            assert detected_wave.wait(2)
        if item == ("plan", 1):
            # Check a genuinely ready leaf, not how soon the consumer thread
            # resumes the generator to create it after the first yield.
            assert first_leaf_ready.wait(2)
        return item

    scheduler = AsyncDetectScheduler(detect_workers=32, deep_workers=1, max_inflight=64)
    rows = list(
        scheduler.iter_completed(
            [("plan", index) for index in range(50)],
            detect,
            finish,
            lambda item, value: [("leaf", item[1])] if item[0] == "plan" else [],
            prioritize_children=lambda item, value: item[0] == "plan",
        )
    )
    expected = [(kind, index) for kind in ("plan", "leaf") for index in range(50)]
    assert Counter(item for item, value in rows) == Counter(expected)
    # A bounded deep queue may already own two jobs, but the remaining ready
    # plans must not make completed origins lose their idle sockets first.
    assert started.index(("leaf", 0)) < 10


def test_slow_deep_jobs_do_not_consume_detect_slots_or_lose_bounded_results():
    observer = RuntimeDiagnostics()
    entered = threading.Event()
    release = threading.Event()
    result = []

    async def detect(index):
        await asyncio.sleep(0)
        return index

    def finish(index, detected):
        if index < 2:
            entered.set()
            assert release.wait(3)
        return detected

    scheduler = AsyncDetectScheduler(detect_workers=8, deep_workers=2, max_inflight=20, observer=observer)
    consumer = threading.Thread(target=lambda: result.extend(scheduler.iter_completed(range(100), detect, finish)))
    consumer.start()
    try:
        assert entered.wait(2)
        # Wait for backpressure to fill the bounded ready wave, rather than
        # timing a race between the coordinator and a fixed sleep.
        for _ in range(200):
            snapshot = observer.snapshot()
            if (
                snapshot["queues"].get("inflight", {}).get("current") == 20
                and snapshot["queues"].get("detect_slots", {}).get("current") == 0
            ):
                break
            threading.Event().wait(0.001)
        assert snapshot["queues"]["inflight"]["current"] == 20
        assert snapshot["queues"]["ready"]["peak"] <= 20
        assert snapshot["queues"]["deep_tasks"]["peak"] <= 4
        assert snapshot["queues"]["detect_slots"]["current"] == 0
    finally:
        release.set()
        consumer.join(4)
    assert not consumer.is_alive()
    assert Counter(item for item, _ in result) == Counter(range(100))
    assert all(item == value for item, value in result)


def test_detect_children_and_finish_children_do_not_starve_roots_or_duplicate_output():
    observer = RuntimeDiagnostics()
    observed = []

    async def detect(item):
        observed.append(item)
        await asyncio.sleep(0)
        return item

    def children(item, _result):
        return [(item[0], 2)] if item[1] == 0 else []

    def detect_children(item, _result):
        return [(item[0], 1)] if item[1] == 0 else []

    scheduler = AsyncDetectScheduler(detect_workers=4, deep_workers=2, max_inflight=12, observer=observer)
    roots = [(i, 0) for i in range(100)]
    rows = list(
        scheduler.iter_completed(roots, detect, lambda item, _value: item, children, detect_children=detect_children)
    )
    assert Counter(item for item, _value in rows) == Counter((i, depth) for i in range(100) for depth in range(3))
    assert observed.index((99, 0)) < 299
    snapshot = observer.snapshot()
    assert snapshot["queues"]["inflight"]["peak"] <= 12
    assert snapshot["queues"]["ready"]["peak"] <= 12
    assert all(row["current"] == 0 for row in snapshot["queues"].values())


def test_socket_free_backoff_is_visible_without_holding_a_detect_slot():
    observer = RuntimeDiagnostics()
    paused = threading.Event()
    result = []

    async def detect(index):
        if index == 0:
            paused.set()
            await detect_backoff(0.15)
        return index

    scheduler = AsyncDetectScheduler(detect_workers=1, deep_workers=1, max_inflight=8, observer=observer)
    consumer = threading.Thread(
        target=lambda: result.extend(scheduler.iter_completed(range(8), detect, lambda i, v: v))
    )
    consumer.start()
    try:
        assert paused.wait(2)
        # This new gauge must measure a real sleeping retry, not just infer it
        # from low socket occupancy or call the target finished prematurely.
        for _ in range(100):
            snapshot = observer.snapshot()
            if snapshot["queues"].get("backoff", {}).get("current") == 1:
                break
            threading.Event().wait(0.001)
        assert snapshot["queues"].get("backoff", {}).get("peak") == 1
    finally:
        consumer.join(3)
    assert not consumer.is_alive()
    assert Counter(i for i, _ in result) == Counter(range(8))
    snapshot = observer.snapshot()
    assert snapshot["queues"]["backoff"]["current"] == 0
    assert snapshot["phases"]["retry_wait"]["calls"] == 1


@pytest.mark.parametrize("cancelled", [False, True])
def test_cancelled_or_completed_retry_releases_diagnostic_wait_count(cancelled):
    from redposture_core.detect_backoff import DetectLease, DetectSlots

    async def run():
        observer = RuntimeDiagnostics()
        lease = DetectLease(DetectSlots(1), lambda: None, observer=observer)
        await lease.acquire()
        task = asyncio.create_task(lease.pause(10 if cancelled else 0))
        await asyncio.sleep(0)
        if cancelled:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            await task
        lease.release()
        assert observer.snapshot()["queues"]["backoff"] == {"current": 0, "peak": 1}

    asyncio.run(run())
