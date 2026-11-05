"""Fixed detection retains concurrency, bounded work and cancellation."""

import asyncio
import threading
import time

import pytest

from redposture_core.async_detection import AsyncDetectScheduler


def test_fixed_workers_drain_all_work_without_scaling_sync_pool():
    active = peak = 0
    threads = set()

    async def detect(item):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.008)
            return item * 3
        finally:
            active -= 1

    def finish(item, value):
        threads.add(threading.get_ident())
        return value

    got = list(AsyncDetectScheduler(detect_workers=4, deep_workers=2).iter_completed(range(220), detect, finish))
    assert sorted(got) == [(i, i * 3) for i in range(220)]
    assert peak == 4 and active == 0
    assert 1 <= len(threads) <= 2


def test_explicit_inflight_remains_a_hard_bound():
    active = peak = 0

    async def detect(item):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.003)
            return item
        finally:
            active -= 1

    got = list(
        AsyncDetectScheduler(detect_workers=8, deep_workers=1, max_inflight=3).iter_completed(
            range(60), detect, lambda i, v: v
        )
    )
    assert sorted(got) == [(i, i) for i in range(60)]
    assert peak == 3


def test_generator_close_finishes_native_tasks_and_closes_source():
    closed = threading.Event()
    active = set()

    def source():
        try:
            yield from range(1000)
        finally:
            closed.set()

    async def detect(item):
        active.add(item)
        try:
            await asyncio.sleep(0.005)
            return item
        finally:
            active.remove(item)

    values = AsyncDetectScheduler(detect_workers=2, deep_workers=1).iter_completed(source(), detect, lambda i, v: v)
    next(values)
    values.close()
    assert closed.is_set()
    assert not active


@pytest.mark.parametrize("limit", [1, 3, 12])
def test_multilevel_children_keep_every_identity_once(limit):
    async def detect(item):
        await asyncio.sleep((item % 3) * 0.0001)
        return item

    def children(item, value):
        return [item + 100, item + 200] if item < 10 else []

    got = list(
        AsyncDetectScheduler(detect_workers=4, deep_workers=2, max_inflight=limit).iter_completed(
            range(10), detect, lambda i, v: v, children=children
        )
    )
    assert sorted(got) == [(i, i) for i in [*range(10), *range(100, 110), *range(200, 210)]]


@pytest.mark.parametrize("pressure", ["cpu", "memory", "loop_lag"])
def test_pressure_does_not_resample_resources_or_change_worker_count(monkeypatch, pressure):
    import resource

    def forbidden(*args):
        pytest.fail("fixed scheduler sampled process resources")

    monkeypatch.setattr(time, "process_time", forbidden)
    monkeypatch.setattr(resource, "getrusage", forbidden)
    monkeypatch.setattr(resource, "getrlimit", forbidden)
    counts = []
    connections = []

    async def detect(item):
        loop = asyncio.get_running_loop()
        connections.append(loop.sock_connect)
        task = asyncio.current_task()
        code = task.get_coro().cr_code
        counts.append(sum(t.get_coro().cr_code is code for t in asyncio.all_tasks()))
        if item == 0:
            if pressure == "loop_lag":
                time.sleep(0.07)
            elif pressure == "cpu":
                until = time.monotonic() + 0.06
                while time.monotonic() < until:
                    pass
            else:
                data = bytearray(2_000_000)
                assert len(data) == 2_000_000
        await asyncio.sleep(0.025)
        return item

    scheduler = AsyncDetectScheduler(detect_workers=4, deep_workers=2)
    got = list(scheduler.iter_completed(range(100), detect, lambda i, v: v))
    assert sorted(got) == [(i, i) for i in range(100)]
    assert scheduler.detect_workers == 4
    assert counts and all(count == 4 for count in counts)
    assert all(connection == connections[0] for connection in connections)


def test_native_failure_is_propagated_and_remaining_tasks_are_cleaned():
    active = set()

    async def detect(item):
        active.add(item)
        try:
            await asyncio.sleep(0.005)
            if item == 0:
                raise OSError("local connection failure")
            return item
        finally:
            active.remove(item)

    with pytest.raises(OSError, match="local connection failure"):
        list(AsyncDetectScheduler(detect_workers=4, deep_workers=1).iter_completed(range(100), detect, lambda i, v: v))
    assert not active


def test_large_followup_tree_keeps_all_results_once():
    async def detect(item):
        await asyncio.sleep(0.0001)
        return item

    def children(item, value):
        return range(1000 + item * 64, 1000 + (item + 1) * 64) if item < 20 else []

    got = list(
        AsyncDetectScheduler(detect_workers=4, deep_workers=1).iter_completed(
            range(20), detect, lambda i, v: v, children=children
        )
    )
    assert len(got) == len(set(got)) == 1300


def test_fd_budget_is_sampled_at_start_only(monkeypatch):
    import resource

    from redposture_core.async_detection import automatic_detect_concurrency

    calls = []

    def startup_budget(_):
        calls.append(1)
        assert len(calls) == 1, "FD budget resampled during detection"
        return 100000, 100000

    monkeypatch.setattr(resource, "getrlimit", startup_budget)
    limit = automatic_detect_concurrency(40, deep_workers=2)

    async def detect(item):
        await asyncio.sleep(0.001)
        return item

    got = list(
        AsyncDetectScheduler(detect_workers=limit, deep_workers=2).iter_completed(range(40), detect, lambda i, v: v)
    )
    assert len(got) == 40 and len(calls) == 1 and limit == 40


def test_next_wave_can_finish_while_coordinator_writes_previous_result():
    completed = set()
    next_wave = threading.Event()

    async def detect(item):
        await asyncio.sleep(0.001)
        completed.add(item)
        if len(completed) == 32:
            next_wave.set()
        return item

    values = AsyncDetectScheduler(detect_workers=16, deep_workers=1).iter_completed(
        range(32), detect, lambda i, v: v, inline_finish=lambda *_: True
    )
    try:
        next(values)
        assert next_wave.wait(1), "coordinator backpressure prematurely pinned detect workers"
    finally:
        values.close()
