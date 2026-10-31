"""Dynamic admission must retain results, cancellation and explicit bounds."""

import asyncio
import errno
import threading

import pytest

from redposture_core.async_detection import AsyncDetectScheduler


@pytest.fixture
def healthy_capacity(monkeypatch):
    """Control host-load inputs so parallel CI cannot invalidate a growth test."""
    from redposture_core.adaptive_detection import AdaptiveDetectLimit

    original = AdaptiveDetectLimit.observe

    def observed(self, **kw):
        kw.update(cpu=0, lag=0, rss_growth=0, fd_limit=10000)
        return original(self, **kw)

    monkeypatch.setattr(AdaptiveDetectLimit, "observe", observed)


def test_adaptive_growth_drains_all_work_without_scaling_sync_pool(healthy_capacity):
    active = peak = 0
    threads = set()
    events = []

    async def detect(item):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.025)
            return item * 3
        finally:
            active -= 1

    def finish(item, value):
        threads.add(threading.get_ident())
        return value

    s = AsyncDetectScheduler(
        detect_workers=2,
        deep_workers=2,
        adaptive_max=4,
        on_limit_change=lambda limit, reason: events.append((limit, reason)),
    )
    got = list(s.iter_completed(range(220), detect, finish))
    assert sorted(got) == [(i, i * 3) for i in range(220)]
    assert 2 < peak <= 4
    assert 1 <= len(threads) <= 2
    assert any(reason == "probe" for _, reason in events)


def test_explicit_inflight_remains_a_hard_bound_under_adaptation():
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
        AsyncDetectScheduler(detect_workers=8, deep_workers=1, max_inflight=3, adaptive_max=16).iter_completed(
            range(60), detect, lambda i, v: v
        )
    )
    assert sorted(got) == [(i, i) for i in range(60)]
    assert peak <= 3


def test_monitor_reports_local_connection_pressure_without_swallowing_error(monkeypatch):
    from redposture_core.adaptive_detection import observe_connection_errors

    async def run():
        loop = asyncio.get_running_loop()
        error = OSError(errno.EADDRNOTAVAIL, "fixture")

        async def fail(*a, **kw):
            raise error

        monkeypatch.setattr(loop, "sock_connect", fail)
        seen = []
        observe_connection_errors(loop, seen.append)
        try:
            await loop.sock_connect(None, None)
        except OSError as caught:
            assert caught is error
        assert seen == [error]

    asyncio.run(run())


def test_adaptive_generator_close_finishes_native_tasks_and_closes_source():
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

    values = AsyncDetectScheduler(detect_workers=2, deep_workers=1, adaptive_max=4).iter_completed(
        source(), detect, lambda i, v: v
    )
    next(values)
    values.close()
    assert closed.is_set()
    assert not active


def test_pressure_reduction_drains_started_checks_instead_of_cancelling(monkeypatch):
    from redposture_core.adaptive_detection import DetectResources

    monkeypatch.setattr(DetectResources, "sample", lambda self, elapsed: (1.5, 0))
    completed, cancelled, changes = [], [], []

    async def detect(item):
        try:
            await asyncio.sleep(0.03)
            completed.append(item)
            return item
        except asyncio.CancelledError:
            cancelled.append(item)
            raise

    got = list(
        AsyncDetectScheduler(
            detect_workers=4, deep_workers=1, adaptive_max=8, on_limit_change=lambda n, r: changes.append((n, r))
        ).iter_completed(range(100), detect, lambda i, v: v)
    )
    assert sorted(got) == [(i, i) for i in range(100)]
    assert sorted(completed) == list(range(100)) and not cancelled
    assert (2, "cpu") in changes


@pytest.mark.parametrize("limit", [1, 3, 12])
def test_adaptive_multilevel_children_keep_every_identity_once(limit):
    async def detect(item):
        await asyncio.sleep((item % 3) * 0.0001)
        return item

    def children(item, value):
        return [item + 100, item + 200] if item < 10 else []

    got = list(
        AsyncDetectScheduler(detect_workers=4, deep_workers=2, max_inflight=limit, adaptive_max=8).iter_completed(
            range(10), detect, lambda i, v: v, children=children
        )
    )
    assert sorted(got) == [(i, i) for i in [*range(10), *range(100, 110), *range(200, 210)]]


def test_control_task_failure_is_not_silently_reported_as_success(healthy_capacity):
    async def detect(item):
        await asyncio.sleep(0.02)
        return item

    def broken_callback(limit, reason):
        raise RuntimeError("control callback failed")

    with pytest.raises(RuntimeError, match="control callback failed"):
        list(
            AsyncDetectScheduler(
                detect_workers=2, deep_workers=1, adaptive_max=4, on_limit_change=broken_callback
            ).iter_completed(range(150), detect, lambda i, v: v)
        )


def test_followups_do_not_count_as_newly_detected_targets(monkeypatch):
    from redposture_core.adaptive_detection import AdaptiveDetectLimit

    observe = AdaptiveDetectLimit.observe
    sampled = []

    def observed(self, **kw):
        sampled.append(kw["completed"])
        return observe(self, **kw)

    monkeypatch.setattr(AdaptiveDetectLimit, "observe", observed)

    async def detect(item):
        await asyncio.sleep(0.003)
        return item

    def children(item, value):
        return range(1000 + item * 64, 1000 + (item + 1) * 64) if item < 20 else []

    got = list(
        AsyncDetectScheduler(detect_workers=2, deep_workers=1, adaptive_max=4).iter_completed(
            range(20), detect, lambda i, v: v, children=children
        )
    )
    assert len(got) == len(set(got)) == 1300
    assert sampled and sum(sampled) <= 20


def test_long_detect_is_not_rejected_before_extra_admissions_can_complete(healthy_capacity):
    import time

    changes = []

    async def detect(item):
        await asyncio.sleep(0.6)
        return item

    started = time.monotonic()
    got = list(
        AsyncDetectScheduler(
            detect_workers=2,
            deep_workers=1,
            adaptive_max=4,
            on_limit_change=lambda n, r: changes.append((time.monotonic() - started, n, r)),
        ).iter_completed(range(16), detect, lambda i, v: v)
    )
    assert sorted(got) == [(i, i) for i in range(16)]
    assert any(n > 2 for _, n, _ in changes)
    assert not any(t < 2.2 and reason == "no_throughput_gain" for t, n, reason in changes)


def test_adaptive_workers_are_allocated_on_demand_not_at_the_ceiling():
    worker_counts = []

    async def detect(item):
        task = asyncio.current_task()
        code = task.get_coro().cr_code
        worker_counts.append(sum(t.get_coro().cr_code is code for t in asyncio.all_tasks()))
        await asyncio.sleep(0.001)
        return item

    got = list(
        AsyncDetectScheduler(detect_workers=2, deep_workers=1, adaptive_max=16).iter_completed(
            range(20), detect, lambda i, v: v
        )
    )
    assert sorted(got) == [(i, i) for i in range(20)]
    assert max(worker_counts) == 2
