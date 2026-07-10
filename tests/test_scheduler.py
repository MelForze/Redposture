from __future__ import annotations

import threading
import time

from redposture_core.scheduler import BoundedScheduler


def test_bounded_scheduler_preserves_input_order() -> None:
    scheduler: BoundedScheduler[int, int] = BoundedScheduler(max_workers=3, max_inflight=2)

    def worker(value: int) -> int:
        time.sleep(0.001 * (3 - value))
        return value * 10

    assert scheduler.map_ordered([1, 2, 3], worker) == [10, 20, 30]


def test_bounded_scheduler_honors_per_key_limit() -> None:
    scheduler: BoundedScheduler[tuple[str, int], int] = BoundedScheduler(
        max_workers=4,
        max_inflight=4,
        per_key_limit=1,
    )
    active_by_key: dict[str, int] = {}
    max_active_by_key: dict[str, int] = {}
    lock = threading.Lock()

    def worker(item: tuple[str, int]) -> int:
        key, value = item
        with lock:
            active_by_key[key] = active_by_key.get(key, 0) + 1
            max_active_by_key[key] = max(max_active_by_key.get(key, 0), active_by_key[key])
        time.sleep(0.005)
        with lock:
            active_by_key[key] -= 1
        return value

    assert scheduler.map_ordered([("a", 1), ("a", 2), ("b", 3), ("b", 4)], worker, key_fn=lambda item: item[0]) == [
        1,
        2,
        3,
        4,
    ]
    assert max_active_by_key == {"a": 1, "b": 1}


def test_bounded_scheduler_iter_completed_returns_original_items() -> None:
    scheduler: BoundedScheduler[tuple[str, int], int] = BoundedScheduler(max_workers=2, max_inflight=2)

    completed = list(
        scheduler.iter_completed(
            [("first", 1), ("second", 2)],
            lambda item: item[1] * 10,
        )
    )

    assert sorted(completed) == [(("first", 1), 10), (("second", 2), 20)]


def test_bounded_scheduler_iter_completed_does_not_materialize_source() -> None:
    scheduler: BoundedScheduler[int, int] = BoundedScheduler(max_workers=2, max_inflight=2)
    consumed: list[int] = []
    both_workers_started = threading.Event()
    release_workers = threading.Event()
    worker_count = 0
    lock = threading.Lock()

    def source():
        for value in range(10):
            consumed.append(value)
            yield value

    def worker(value: int) -> int:
        nonlocal worker_count
        with lock:
            worker_count += 1
            if worker_count == 2:
                both_workers_started.set()
        release_workers.wait(timeout=2)
        return value

    iterator = scheduler.iter_completed(source(), worker)
    result: list[tuple[int, int]] = []
    thread = threading.Thread(target=lambda: result.append(next(iterator)))
    thread.start()
    assert both_workers_started.wait(timeout=1)
    assert consumed == [0, 1]

    release_workers.set()
    thread.join(timeout=1)
    assert not thread.is_alive()
    assert result and result[0][0] in {0, 1}
    iterator.close()
