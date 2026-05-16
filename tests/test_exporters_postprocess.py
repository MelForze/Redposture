from __future__ import annotations

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
