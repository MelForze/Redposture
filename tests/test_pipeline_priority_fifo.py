"""Ready children of equal priority must not overtake older ready children."""

from __future__ import annotations

import asyncio
import threading
from collections import Counter

from redposture_core.async_detection import AsyncDetectScheduler
from redposture_core.runtime_diagnostics import RuntimeDiagnostics


def test_ready_priority_is_fifo_in_detect_completion_order():
    root_wave = threading.Event()
    worker_blocked = threading.Event()
    leaves_completing = threading.Event()
    release_worker = threading.Event()
    first_leaf = asyncio.Event()
    detect_threads: set[int] = set()
    detected_roots = []
    detected_leaves = []
    started = []

    class Observer(RuntimeDiagnostics):
        def queue(self, name: str, size: int) -> None:
            super().queue(name, size)
            if name == "ready" and threading.get_ident() in detect_threads and leaves_completing.is_set():
                # The loop reports ready occupancy after inserting the second
                # leaf. Neither leaf may reach the worker pool before that.
                release_worker.set()

    observer = Observer()

    async def wait_for_full_deep_queue():
        while not worker_blocked.is_set() or observer.snapshot()["queues"].get("deep_tasks", {}).get("current") != 2:
            await asyncio.sleep(0)

    async def detect(item):
        detect_threads.add(threading.get_ident())
        if item == ("leaf", 0):
            await asyncio.wait_for(wait_for_full_deep_queue(), timeout=2)
            detected_leaves.append(item)
            first_leaf.set()
            return item
        if item == ("leaf", 1):
            await first_leaf.wait()
            detected_leaves.append(item)
            leaves_completing.set()
            return item
        detected_roots.append(item)
        if len(detected_roots) == 32:
            root_wave.set()
        await asyncio.sleep(0)
        return item

    def finish(item, value):
        started.append(item)
        if item == ("plan", 0):
            assert root_wave.wait(2)
        if item == ("plan", 2):
            # Both children become ready while this worker and its bounded
            # input queue still own normal plans. No wall-clock sleep decides
            # which child completed detection first.
            worker_blocked.set()
            assert release_worker.wait(2)
        return value

    scheduler = AsyncDetectScheduler(detect_workers=32, deep_workers=1, max_inflight=64, observer=observer)
    rows = list(
        scheduler.iter_completed(
            [("plan", i) for i in range(32)],
            detect,
            finish,
            lambda item, value: [("leaf", item[1])] if item in {("plan", 0), ("plan", 1)} else [],
            prioritize_children=lambda item, value: item[0] == "plan",
        )
    )
    assert detected_leaves == [("leaf", 0), ("leaf", 1)]
    assert Counter(item for item, value in rows) == Counter(
        [("plan", i) for i in range(32)] + [("leaf", 0), ("leaf", 1)]
    )
    assert all(item == value for item, value in rows)
    assert started.index(("leaf", 0)) < started.index(("leaf", 1))
    assert max(started.index(("leaf", i)) for i in (0, 1)) < 8


def test_priority_batches_are_fifo_and_precede_normal_work():
    from redposture_core.async_detection import _PriorityDeque

    queue = _PriorityDeque[str]()
    queue.extend(["root0", "root1"])
    queue.extend(["old0", "old1"], prioritized=True)
    queue.append("root2")
    queue.extend(["new0", "new1"], prioritized=True)
    assert len(queue) == 7
    assert [queue.popleft() for _ in range(7)] == [
        ("old0", True),
        ("old1", True),
        ("new0", True),
        ("new1", True),
        ("root0", False),
        ("root1", False),
        ("root2", False),
    ]
    assert not queue
