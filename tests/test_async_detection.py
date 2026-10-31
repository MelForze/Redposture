"""Hybrid detection must preserve every item with bounded, cancellable work."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest


@pytest.mark.parametrize(
    "targets,want", [(32, 32), (999, 64), (1000, 128), (9999, 128), (10000, 256), (100000, 512), (1000000, 1024)]
)
def test_automatic_detect_scales_input_without_scaling_sync_workers(monkeypatch, targets, want):
    import resource

    from redposture_core.async_detection import automatic_detect_concurrency

    monkeypatch.setattr(resource, "getrlimit", lambda _: (100000, 100000))
    assert automatic_detect_concurrency(targets, deep_workers=16) == want


def test_automatic_detect_reserves_descriptors_for_sync_work_and_output(monkeypatch):
    import os
    import resource

    from redposture_core.async_detection import automatic_detect_concurrency

    monkeypatch.setattr(resource, "getrlimit", lambda _: (256, 256))
    monkeypatch.setattr(os, "listdir", lambda _: [str(i) for i in range(32)])
    assert automatic_detect_concurrency(1000000, deep_workers=16) == 64
    assert automatic_detect_concurrency(1000000, deep_workers=16, max_inflight=8) == 8


def test_automatic_detect_handles_unlimited_or_unavailable_fd_limits(monkeypatch):
    import resource

    from redposture_core.async_detection import automatic_detect_concurrency

    monkeypatch.setattr(resource, "getrlimit", lambda _: (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    assert automatic_detect_concurrency(1000000, deep_workers=128) == 1024

    def unsupported(_):
        raise OSError("unavailable")

    monkeypatch.setattr(resource, "getrlimit", unsupported)
    assert automatic_detect_concurrency(-1, deep_workers=64) == 1
    assert automatic_detect_concurrency(10**20, deep_workers=64) == 1024


def test_automatic_detect_includes_eventual_idle_pool_growth_in_fd_reservation(monkeypatch):
    import os
    import resource

    from redposture_core.async_detection import automatic_detect_concurrency

    monkeypatch.setattr(resource, "getrlimit", lambda _: (768, 768))
    monkeypatch.setattr(os, "listdir", lambda _: [str(i) for i in range(32)])
    assert automatic_detect_concurrency(10000, deep_workers=16, retained_fds=512) == 64
    monkeypatch.setattr(resource, "getrlimit", lambda _: (256, 256))
    assert automatic_detect_concurrency(10000, deep_workers=16, retained_fds=512) == 0


def test_native_detect_does_not_hold_sync_workers_and_handoff_is_continuous():
    from redposture_core.async_detection import AsyncDetectScheduler

    release = threading.Event()
    first_done = threading.Event()
    detecting = []
    thread_ids = set()

    async def detect(item):
        thread_ids.add(threading.get_ident())
        detecting.append(item)
        if item == 0:
            return item
        while not release.is_set():
            await asyncio.sleep(0.002)
        return item

    def finish(item, value):
        assert not first_done.is_set() or item != 0
        if item == 0:
            first_done.set()
            assert not release.is_set()
            release.set()
        return value * 2

    got = list(AsyncDetectScheduler(detect_workers=8, deep_workers=2).iter_completed(range(100), detect, finish))
    assert first_done.is_set() and len(thread_ids) == 1
    assert dict(got) == {i: i * 2 for i in range(100)}
    assert len(detecting) == 100


def test_pipeline_backpressure_does_not_consume_unbounded_input():
    from redposture_core.async_detection import AsyncDetectScheduler

    consumed = []
    release = threading.Event()

    def source():
        for i in range(1000000):
            consumed.append(i)
            yield i

    async def detect(item):
        return item

    def finish(item, value):
        release.wait(2)
        return value

    stream = AsyncDetectScheduler(detect_workers=4, deep_workers=2).iter_completed(source(), detect, finish)
    timer = threading.Timer(0.05, release.set)
    timer.start()
    try:
        next(stream)
        assert len(consumed) <= 16
    finally:
        stream.close()
        release.set()
        timer.join()


def test_cancel_cancels_async_waits_and_finishes_loop():
    from redposture_core.async_detection import AsyncDetectScheduler

    closed = []

    async def detect(item):
        try:
            if item:
                await asyncio.sleep(60)
            return item
        finally:
            closed.append(item)

    stream = AsyncDetectScheduler(detect_workers=4, deep_workers=1).iter_completed(range(20), detect, lambda i, v: v)
    assert next(stream) == (0, 0)
    started = time.monotonic()
    stream.close()
    assert time.monotonic() - started < 1.5
    assert len(closed) >= 1
    assert not any(t.name.startswith("redposture-async-detect") for t in threading.enumerate())


def test_detect_exception_propagates_without_hanging_or_leaking_loop():
    from redposture_core.async_detection import AsyncDetectScheduler

    async def detect(item):
        if item == 2:
            raise ValueError("broken detector")
        await asyncio.sleep(0.001)
        return item

    with pytest.raises(ValueError, match="broken detector"):
        list(AsyncDetectScheduler(detect_workers=4, deep_workers=1).iter_completed(range(10), detect, lambda i, v: v))


def test_dependent_work_is_not_lost_when_roots_finish_and_has_priority():
    from redposture_core.async_detection import AsyncDetectScheduler

    prepared = []

    async def detect(item):
        prepared.append(item)
        await asyncio.sleep(0.001)
        return item

    def children(item, value):
        if item < 10:
            yield item + 100

    got = list(
        AsyncDetectScheduler(detect_workers=2, deep_workers=1).iter_completed(
            range(10), detect, lambda i, v: v, children=children
        )
    )
    assert sorted(i for i, _ in got) == list(range(10)) + list(range(100, 110))
    assert prepared.index(100) < prepared.index(9)


def test_only_explicitly_pure_negatives_may_finish_on_loop():
    from redposture_core.async_detection import AsyncDetectScheduler

    locations = {}

    async def detect(item):
        return item

    def finish(item, value):
        locations[item] = threading.current_thread().name
        return value

    result = dict(
        AsyncDetectScheduler(detect_workers=4, deep_workers=2).iter_completed(
            range(20), detect, finish, inline_finish=lambda i, v: i % 2 == 0
        )
    )
    assert result == dict(enumerate(range(20)))
    assert all(locations[i] == "redposture-async-detect" for i in range(0, 20, 2))
    assert all(locations[i].startswith("redposture-scheduler-") for i in range(1, 20, 2))


def test_static_source_does_not_poll_while_last_detection_is_pending(monkeypatch):
    """Idle detect slots must sleep without repeatedly scheduling timer callbacks."""
    from redposture_core.async_detection import AsyncDetectScheduler

    real_sleep = asyncio.sleep

    async def sleep(delay, *args, **kwargs):
        assert delay != 0.002, "idle scheduler is busy-polling"
        return await real_sleep(delay, *args, **kwargs)

    async def detect(item):
        await asyncio.sleep(0.02)
        return item

    monkeypatch.setattr(asyncio, "sleep", sleep)
    assert list(
        AsyncDetectScheduler(detect_workers=16, deep_workers=1).iter_completed([7], detect, lambda i, v: v)
    ) == [(7, 7)]


def test_cancel_after_source_exhaustion_interrupts_blocked_finish(monkeypatch):
    from redposture_core.async_detection import AsyncDetectScheduler
    from redposture_core.scheduler import _DaemonWorkerPool

    draining = threading.Event()
    original_close = _DaemonWorkerPool.close

    def close(pool):
        draining.set()
        return original_close(pool)

    monkeypatch.setattr(_DaemonWorkerPool, "close", close)
    finish_started = threading.Event()
    release_finish = threading.Event()
    cancelled = threading.Event()
    coordinator_done = threading.Event()
    source_exhausted = threading.Event()
    values = []
    errors = []

    def source():
        yield 1
        source_exhausted.set()

    async def detect(item):
        return item

    def finish(item, value):
        finish_started.set()
        release_finish.wait(3)
        return value

    def consume():
        try:
            values.extend(
                AsyncDetectScheduler(detect_workers=8, deep_workers=1).iter_completed(
                    source(),
                    detect,
                    finish,
                    cancel_event=cancelled,
                )
            )
        except BaseException as exc:
            errors.append(exc)
        finally:
            coordinator_done.set()

    thread = threading.Thread(target=consume, daemon=True)
    thread.start()
    try:
        assert source_exhausted.wait(1) and finish_started.wait(1)
        # Catch the premature pool.close window; a live watcher need not enter it.
        draining.wait(0.1)
        cancelled.set()
        assert coordinator_done.wait(1), "cancel monitoring ended before synchronous work drained"
        assert not errors and values == []
    finally:
        release_finish.set()
        thread.join(3)
