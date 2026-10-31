"""Bounded scheduling must make progress without timer polling or stage starvation."""

import asyncio
import threading

import pytest

from redposture_core.async_detection import AsyncDetectScheduler


def test_backpressure_and_dynamic_drain_do_not_poll_timers(monkeypatch):
    original = asyncio.sleep

    async def sleep(delay, *args, **kw):
        assert delay != 0.002, "scheduler busy-polls instead of awaiting a notification"
        return await original(delay, *args, **kw)

    async def detect(item):
        await asyncio.sleep(0.003)
        return item

    def finish(item, value):
        import time

        time.sleep(0.005)
        return value

    monkeypatch.setattr(asyncio, "sleep", sleep)
    got = list(
        AsyncDetectScheduler[int, int, int](detect_workers=8, deep_workers=1, max_inflight=8).iter_completed(
            range(20), detect, finish, children=lambda i, v: [i + 100] if i < 20 else []
        )
    )
    assert sorted(i for i, _ in got) == list(range(20)) + list(range(100, 120))


def test_full_sync_queue_does_not_pin_detect_slots_before_credit_limit():
    release, negative_seen = threading.Event(), threading.Event()

    async def detect(item):
        if item == 15:
            if not release.is_set():
                negative_seen.set()
            release.set()
        return item

    def finish(item, value):
        if item < 5:
            release.wait(10)
        return value

    timer = threading.Timer(5, release.set)
    timer.start()
    try:
        got = list(
            AsyncDetectScheduler(detect_workers=2, deep_workers=1, max_inflight=16).iter_completed(
                range(16), detect, finish, inline_finish=lambda i, v: i >= 5
            )
        )
        assert negative_seen.is_set(), "detect slots were blocked behind the full sync queue"
        assert dict(got) == dict(enumerate(range(16)))
    finally:
        release.set()
        timer.cancel()
        timer.join()


def test_child_backlog_does_not_starve_roots_and_borrows_capacity_after_roots():
    release, last_root = threading.Event(), threading.Event()
    active = peak = 0
    lock = threading.Lock()
    workers_ready = threading.Barrier(2)

    async def detect(item):
        if item == 19:
            if not release.is_set():
                last_root.set()
            release.set()
        return item

    def finish(item, value):
        nonlocal active, peak
        if item >= 100:
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                workers_ready.wait(5)
                release.wait(10)
            finally:
                with lock:
                    active -= 1
        return value

    timer = threading.Timer(5, release.set)
    timer.start()
    try:
        got = list(
            AsyncDetectScheduler[int, int, int](detect_workers=4, deep_workers=2, max_inflight=16).iter_completed(
                range(20),
                detect,
                finish,
                children=lambda i, v: range(100, 120) if i == 0 else [],
                inline_finish=lambda i, v: i < 100,
            )
        )
        assert last_root.is_set(), "dependent work monopolized the root budget"
        assert sorted(i for i, _ in got) == list(range(20)) + list(range(100, 120))
        assert peak == 2
    finally:
        release.set()
        timer.cancel()
        timer.join()


def test_root_fairness_cannot_accumulate_children_for_unbounded_input():
    release = threading.Event()
    roots = []
    sampled = []

    def source():
        for i in range(1000):
            roots.append(i)
            yield i

    async def detect(item):
        return item

    def finish(item, value):
        if item >= 10000:
            release.wait(2)
        return value

    def unlock():
        sampled.append(len(roots))
        release.set()

    timer = threading.Timer(0.1, unlock)
    timer.start()
    try:
        results = list(
            AsyncDetectScheduler[int, int, int](detect_workers=4, deep_workers=1, max_inflight=8).iter_completed(
                source(),
                detect,
                finish,
                children=lambda i, v: [10000 + i * 6 + j for j in range(6)] if i < 1000 else [],
                inline_finish=lambda i, v: i < 1000,
            )
        )
        assert len(results) == 7000
        assert sampled[0] <= 32, "child backlog grew with total root count instead of the bounded pipeline"
    finally:
        release.set()
        timer.cancel()
        timer.join()


@pytest.mark.parametrize("seed", [7, 71, 710, 7101])
@pytest.mark.parametrize("limit", [1, 2, 8])
def test_seeded_multilevel_graph_has_exact_results_and_cleanup(seed, limit):
    import random

    rng = random.Random(seed)
    graph: dict[tuple[int, ...], list[tuple[int, ...]]] = {}

    def build(node, depth):
        graph[node] = [(*node, j) for j in range(rng.randrange(4))] if depth else []
        for child in graph[node]:
            build(child, depth - 1)

    roots = [(i,) for i in range(8)]
    for root in roots:
        build(root, 2)
    closed = []

    def source():
        try:
            yield from roots
        finally:
            closed.append(True)

    async def detect(item):
        if sum(item) % 2:
            await asyncio.sleep(0.0005)
        return item

    got = list(
        AsyncDetectScheduler[tuple[int, ...], tuple[int, ...], tuple[int, ...]](
            detect_workers=12, deep_workers=3, max_inflight=limit
        ).iter_completed(
            source(),
            detect,
            lambda item, value: value,
            children=lambda item, value: graph[item],
            inline_finish=lambda item, value: sum(item) % 3 == 0,
        )
    )
    assert len(got) == len(graph) and dict(got) == {node: node for node in graph}
    assert closed == [True]
    assert not any(t.name == "redposture-async-detect" for t in threading.enumerate())
