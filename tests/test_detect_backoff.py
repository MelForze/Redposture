"""Socket-free retry pauses can use spare credits without dropping identities."""

import asyncio
import threading
import time

import pytest

from redposture_core.async_detection import AsyncDetectScheduler
from redposture_core.detect_backoff import detect_backoff


@pytest.mark.parametrize("socket_free", [True, False])
def test_backoff_replaces_waiter_only_when_socket_is_closed(socket_free):
    attempts = []
    intervals = []
    active = peak = 0
    pending = pending_peak = 0

    async def detect(item):
        nonlocal active, peak, pending, pending_peak
        pending += 1
        pending_peak = max(pending_peak, pending)
        try:
            for attempt in range(3):
                active += 1
                peak = max(peak, active)
                attempts.append((item, attempt, time.monotonic()))
                await asyncio.sleep(0.002)
                active -= 1
                if attempt < 2:
                    started = time.monotonic()
                    await detect_backoff(0.025, socket_free=socket_free)
                    intervals.append(time.monotonic() - started)
            return item
        finally:
            pending -= 1

    scheduler = AsyncDetectScheduler(detect_workers=2, deep_workers=1, max_inflight=6)
    got = list(scheduler.iter_completed(range(12), detect, lambda i, v: v))
    assert sorted(got) == [(i, i) for i in range(12)]
    assert len(attempts) == 36 and peak <= 2 and pending == active == 0
    assert all(delay >= 0.025 for delay in intervals)
    assert pending_peak <= 6
    third_start = next(t for i, a, t in attempts if i == 2 and a == 0)
    first_retry = next(t for i, a, t in attempts if i == 0 and a == 1)
    assert (third_start < first_retry) is socket_free
    assert (pending_peak > 2) is socket_free


def test_cancel_during_backoff_closes_source_and_all_sleepers():
    closed = threading.Event()
    waiting = threading.Event()
    active = set()

    def source():
        try:
            yield from range(1000)
        finally:
            closed.set()

    async def detect(item):
        active.add(item)
        try:
            if item == 0:
                return item
            if len(active) >= 4:
                waiting.set()
            await detect_backoff(30)
            return item
        finally:
            active.remove(item)

    values = AsyncDetectScheduler(detect_workers=2, deep_workers=1, max_inflight=6).iter_completed(
        source(), detect, lambda i, v: v
    )
    next(values)
    assert waiting.wait(1)
    values.close()
    assert closed.wait(1) and not active


def test_child_task_cannot_release_its_parents_active_slot():
    active = peak = 0

    async def detect(item):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.create_task(detect_backoff(0.005))
            return item
        finally:
            active -= 1

    result = list(
        AsyncDetectScheduler(detect_workers=1, deep_workers=1).iter_completed(range(12), detect, lambda i, v: v)
    )
    assert len(result) == 12 and peak == 1 and active == 0


def test_closed_socket_guard_is_passed_by_retained_interpreter(monkeypatch):
    from types import SimpleNamespace

    from redposture_core.clients import async_retained_socket as native
    from redposture_core.detection_io import DetectDelay

    calls = []

    async def pause(seconds, *, socket_free=True):
        calls.append((seconds, socket_free))

    monkeypatch.setattr(native, "detect_backoff", pause)

    def steps():
        yield DetectDelay(0.2)
        return 42

    for fd in (-1, 4):
        sock = type("Socket", (), {"fileno": lambda self, value=fd: value})()
        assert asyncio.run(native.run_native(steps(), None, {}, SimpleNamespace(sockets={sock: 1}))) == 42
    assert calls == [(0.2, True), (0.2, False)]


def test_retained_socket_prevents_backoff_admission():
    from redposture_core.detect_backoff import retain_detect_slot

    calls = []

    async def detect(item):
        calls.append(item)
        retain_detect_slot()
        await detect_backoff(0.01)
        assert calls[-1] == item
        return item

    got = list(AsyncDetectScheduler(detect_workers=1, deep_workers=1).iter_completed(range(6), detect, lambda i, v: v))
    assert got == [(i, i) for i in range(6)]


def test_retry_pause_preserves_dynamic_children_and_small_inflight():
    async def detect(item):
        await detect_backoff(0.001)
        return item

    def children(item, result):
        return [item + 100, item + 200] if item < 10 else []

    for limit in (1, 3, 12):
        got = list(
            AsyncDetectScheduler(detect_workers=4, deep_workers=2, max_inflight=limit).iter_completed(
                range(10), detect, lambda i, v: v, children=children
            )
        )
        expected = [(i, i) for i in [*range(10), *range(100, 110), *range(200, 210)]]
        assert sorted(got) == expected


@pytest.mark.parametrize("cancel_after_grant", [False, True])
def test_slot_fifo_cancellation_returns_granted_permit(cancel_after_grant):
    from redposture_core.detect_backoff import DetectSlots

    async def run():
        slots = DetectSlots(1)
        await slots.acquire()
        first = asyncio.create_task(slots.acquire())
        second = asyncio.create_task(slots.acquire())
        await asyncio.sleep(0)
        if cancel_after_grant:
            slots.release()
            first.cancel()
        else:
            first.cancel()
            slots.release()
        with pytest.raises(asyncio.CancelledError):
            await first
        await asyncio.wait_for(second, 1)
        assert slots.active == 1
        slots.release()
        assert slots.active == 0 and not slots.waiters

    asyncio.run(run())
