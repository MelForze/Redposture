"""Opt-in sync finish continuations keep native detection and children bounded."""

from __future__ import annotations

import asyncio
import threading
from collections import Counter
from concurrent.futures import Future
from contextvars import ContextVar

import pytest

from redposture_core.async_detection import AsyncDetectScheduler
from redposture_core.runtime_diagnostics import RuntimeDiagnostics


def test_paused_finish_interleaves_roots_with_inline_negatives_and_dynamic_children():
    marker = ContextVar("async-finish-job", default=None)
    order, inline = [], []

    async def detect(item):
        await asyncio.sleep(0)
        return item

    def finish(item, value):
        inline.append(item)
        return value

    def steps(item, value):
        token = marker.set(item)
        try:
            order.append((item, "begin"))
            if item == 0:
                yield 0.05
            assert marker.get() == item
            order.append((item, "end"))
            return value
        finally:
            marker.reset(token)

    scheduler = AsyncDetectScheduler(detect_workers=4, deep_workers=1, max_inflight=8)
    rows = list(
        scheduler.iter_completed(
            range(32),
            detect,
            finish,
            lambda item, value: [32] if item == 0 else [],
            inline_finish=lambda item, value: item == 31,
            finish_steps=steps,
        )
    )
    assert Counter(i for i, value in rows) == Counter(range(33))
    assert all(i == value for i, value in rows) and inline == [31]
    assert order.index((1, "end")) < order.index((0, "end"))
    assert marker.get() is None


def test_cancel_closes_idle_finish_continuation_without_waiting_for_its_delay():
    entered, closed, cancelled = threading.Event(), threading.Event(), threading.Event()
    rows = []

    async def detect(item):
        return item

    def steps(item, value):
        try:
            entered.set()
            yield 60
            return value
        finally:
            closed.set()

    scheduler = AsyncDetectScheduler(detect_workers=2, deep_workers=1, max_inflight=4)
    consumer = threading.Thread(
        target=lambda: rows.extend(
            scheduler.iter_completed(
                [1],
                detect,
                lambda i, value: value,
                cancel_event=cancelled,
                finish_steps=steps,
            )
        )
    )
    consumer.start()
    try:
        assert entered.wait(2)
        cancelled.set()
        assert closed.wait(2)
    finally:
        cancelled.set()
        consumer.join(3)
    assert not consumer.is_alive() and not rows


@pytest.mark.parametrize("cancel", [False, True])
def test_wait_diagnostics_count_parked_jobs_separately_from_busy_workers(cancel):
    observer = RuntimeDiagnostics()
    gate, closed, cancelled = Future(), threading.Event(), threading.Event()
    rows = []

    async def detect(item):
        return item

    def steps(item, value):
        try:
            yield gate
            return value
        finally:
            closed.set()

    scheduler = AsyncDetectScheduler(detect_workers=2, deep_workers=1, max_inflight=4, observer=observer)
    consumer = threading.Thread(
        target=lambda: rows.extend(
            scheduler.iter_completed(
                [1],
                detect,
                lambda item, value: value,
                finish_steps=steps,
                cancel_event=cancelled,
            )
        )
    )
    consumer.start()
    try:
        for _ in range(200):
            snapshot = observer.snapshot()
            if snapshot["queues"].get("finish_wait", {}).get("current") == 1:
                break
            closed.wait(0.005)
        assert snapshot["queues"].get("finish_wait") == {"current": 1, "peak": 1}
        assert snapshot["phases"]["finish"]["active"] == 0
        assert "finish_wait=1" in observer.progress_line()
        if cancel:
            cancelled.set()
        else:
            gate.set_result(None)
        assert closed.wait(2)
    finally:
        cancelled.set()
        consumer.join(3)
    assert not consumer.is_alive()
    assert rows == ([] if cancel else [(1, 1)])
    snapshot = observer.snapshot()
    assert snapshot["queues"]["finish_wait"] == {"current": 0, "peak": 1}
    assert snapshot["phases"]["finish_wait"]["calls"] == 1
    assert snapshot["phases"]["finish_wait"]["total_ns"] > 0
    assert not gate.cancelled(), "the scheduler must not own the caller's admission Future"


def test_bounded_parked_wave_keeps_one_free_lane_until_the_last_root_releases_it():
    observer, gate = RuntimeDiagnostics(), Future()
    marker = ContextVar("parked-wave-target", default=None)
    visits = Counter()

    async def detect(item):
        return item

    def steps(item, value):
        token = marker.set(item)
        try:
            visits[(item, "begin")] += 1
            if item < 7:
                yield gate
            if item == 999:
                gate.set_result(None)
            assert marker.get() == item
            visits[(item, "end")] += 1
            return value
        finally:
            marker.reset(token)

    scheduler = AsyncDetectScheduler(detect_workers=4, deep_workers=2, max_inflight=8, observer=observer)
    rows = list(scheduler.iter_completed(range(1000), detect, lambda item, value: value, finish_steps=steps))
    assert Counter(item for item, value in rows if item == value) == Counter(range(1000))
    assert visits == Counter((item, phase) for item in range(1000) for phase in ("begin", "end"))
    snapshot = observer.snapshot()
    assert snapshot["queues"]["inflight"]["peak"] <= 8
    assert snapshot["queues"]["finish_wait"]["peak"] == 7
    assert snapshot["phases"]["finish"]["peak_active"] <= 2
    assert all(row["current"] == 0 for row in snapshot["queues"].values())
    assert marker.get() is None
