from __future__ import annotations

import threading

import pytest

from redposture_core.exporters.postprocess import AsyncPostprocessWorker


def test_async_postprocess_worker_processes_payloads_in_order() -> None:
    seen: list[int] = []
    worker = AsyncPostprocessWorker(lambda value: seen.append(value), name="test-postprocess")

    worker.put(1)
    worker.put(2)
    worker.close()

    assert seen == [1, 2]


def test_async_postprocess_worker_propagates_worker_errors() -> None:
    def fail(_payload: object) -> None:
        raise ValueError("boom")

    worker = AsyncPostprocessWorker(fail, name="test-postprocess")
    worker.put("payload")

    with pytest.raises(ValueError, match="boom"):
        worker.close()


def test_async_postprocess_worker_rejects_put_after_close() -> None:
    worker = AsyncPostprocessWorker(lambda _payload: None, name="test-postprocess")
    worker.close()

    with pytest.raises(RuntimeError, match="already closed"):
        worker.put("late")


def test_async_postprocess_worker_close_is_idempotent() -> None:
    worker = AsyncPostprocessWorker(lambda _payload: None, name="test-postprocess")

    worker.close()
    worker.close()


def test_async_postprocess_worker_applies_backpressure_when_queue_is_full() -> None:
    handler_started = threading.Event()
    release_handler = threading.Event()
    producer_done = threading.Event()
    seen: list[int] = []

    def slow_handler(value: int) -> None:
        handler_started.set()
        release_handler.wait(timeout=2)
        seen.append(value)

    worker = AsyncPostprocessWorker(slow_handler, name="test-postprocess", max_queue_size=1)
    worker.put(1)
    assert handler_started.wait(timeout=1)
    worker.put(2)

    producer = threading.Thread(target=lambda: (worker.put(3), producer_done.set()))
    producer.start()
    assert not producer_done.wait(timeout=0.05)

    release_handler.set()
    assert producer_done.wait(timeout=1)
    producer.join(timeout=1)
    worker.close()
    assert seen == [1, 2, 3]
