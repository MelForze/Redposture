from __future__ import annotations

import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from redposture_core.scheduler import BoundedScheduler, SharedNestedScheduler


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


def test_bounded_scheduler_cancel_does_not_start_queued_work() -> None:
    scheduler: BoundedScheduler[int, int] = BoundedScheduler(max_workers=2, max_inflight=8)
    release_workers = threading.Event()
    started: list[int] = []
    lock = threading.Lock()

    def worker(value: int) -> int:
        with lock:
            started.append(value)
        if value == 0:
            return value
        release_workers.wait(timeout=2)
        return value

    iterator = scheduler.iter_completed(range(20), worker)
    assert next(iterator) == (0, 0)

    started_before_cancel = set(started)
    started_at = time.monotonic()
    iterator.close()
    assert time.monotonic() - started_at < 0.5

    release_workers.set()
    time.sleep(0.1)
    assert set(started) == started_before_cancel


def test_bounded_scheduler_sigint_does_not_wait_for_blocked_worker(tmp_path: Path) -> None:
    marker = tmp_path / "worker-started"
    script = """
import sys
import time
from pathlib import Path

from redposture_core.scheduler import BoundedScheduler

marker = Path(sys.argv[1])

def worker(_value):
    marker.write_text("started", encoding="utf-8")
    time.sleep(30)
    return 1

try:
    list(BoundedScheduler(max_workers=1, max_inflight=1).iter_completed([1], worker))
except KeyboardInterrupt:
    raise SystemExit(130)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(marker)],
        cwd=Path(__file__).resolve().parents[1],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not marker.exists():
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                raise AssertionError(f"worker process exited early rc={process.returncode}: {stdout=} {stderr=}")
            time.sleep(0.01)
        assert marker.exists(), "blocked worker did not start"

        started_at = time.monotonic()
        process.send_signal(signal.SIGINT)
        return_code = process.wait(timeout=2)
        elapsed = time.monotonic() - started_at
        assert return_code == 130
        assert elapsed < 2
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)


def test_shared_nested_scheduler_bounds_each_producer_window() -> None:
    scheduler = SharedNestedScheduler(max_workers=8)
    consumed: list[int] = []
    release = threading.Event()

    def source():
        for value in range(100):
            consumed.append(value)
            yield value

    def worker(value: int) -> int:
        release.wait(timeout=2)
        return value

    iterator = scheduler.iter_completed(source(), worker, key="target", per_key_limit=2)
    completed: list[tuple[int, int]] = []
    thread = threading.Thread(target=lambda: completed.append(next(iterator)))
    thread.start()
    deadline = time.monotonic() + 1
    while len(consumed) < 4 and time.monotonic() < deadline:
        time.sleep(0.005)
    assert consumed == [0, 1, 2, 3]

    release.set()
    thread.join(timeout=1)
    iterator.close()
    scheduler.close()
    assert completed


def test_shared_nested_scheduler_runs_dynamic_follow_up_work() -> None:
    scheduler = SharedNestedScheduler(max_workers=4)
    completed: list[int] = []

    def on_completed(item: int, result: int):
        completed.append(result)
        return (item + 1,) if item < 4 else ()

    try:
        scheduler.run_dynamic([1], lambda item: item, on_completed, key="target", per_key_limit=2)
    finally:
        scheduler.close()

    assert completed == [1, 2, 3, 4]


@pytest.mark.parametrize("worker_limit", [32, 64])
def test_shared_nested_scheduler_enforces_command_wide_peak(worker_limit: int) -> None:
    scheduler = SharedNestedScheduler(max_workers=worker_limit)
    release = threading.Event()
    full_peak = threading.Event()
    lock = threading.Lock()
    active = 0
    peak = 0

    def worker(value: int) -> int:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            if active == worker_limit:
                full_peak.set()
        release.wait(timeout=3)
        with lock:
            active -= 1
        return value

    thread = threading.Thread(target=lambda: list(scheduler.iter_completed(range(worker_limit * 2), worker)))
    thread.start()
    try:
        assert full_peak.wait(timeout=2)
        assert peak == worker_limit
    finally:
        release.set()
        thread.join(timeout=3)
        scheduler.close()
    assert not thread.is_alive()


def test_shared_nested_scheduler_does_not_starve_another_target() -> None:
    scheduler = SharedNestedScheduler(max_workers=8)
    first_release = threading.Event()
    first_started = threading.Event()
    second_started = threading.Event()
    lock = threading.Lock()
    first_active = 0

    def first_worker(value: int) -> int:
        nonlocal first_active
        with lock:
            first_active += 1
            if first_active == 2:
                first_started.set()
        first_release.wait(timeout=3)
        return value

    def second_worker(value: int) -> int:
        second_started.set()
        return value

    first_thread = threading.Thread(
        target=lambda: list(scheduler.iter_completed(range(20), first_worker, key="first", per_key_limit=2))
    )
    second_thread = threading.Thread(
        target=lambda: list(scheduler.iter_completed([1], second_worker, key="second", per_key_limit=1))
    )
    first_thread.start()
    assert first_started.wait(timeout=1)
    second_thread.start()
    try:
        assert second_started.wait(timeout=1)
    finally:
        first_release.set()
        first_thread.join(timeout=3)
        second_thread.join(timeout=3)
        scheduler.close()
    assert not first_thread.is_alive()
    assert not second_thread.is_alive()


def test_shared_nested_scheduler_cancels_queued_work_when_iterator_closes() -> None:
    scheduler = SharedNestedScheduler(max_workers=2)
    release = threading.Event()
    started: list[int] = []
    lock = threading.Lock()

    def worker(value: int) -> int:
        with lock:
            started.append(value)
        if value:
            release.wait(timeout=3)
        return value

    iterator = scheduler.iter_completed(range(20), worker, key="target", per_key_limit=2)
    assert next(iterator) == (0, 0)
    iterator.close()
    started_before_release = set(started)
    release.set()
    time.sleep(0.1)
    scheduler.close()

    assert set(started) == started_before_release
