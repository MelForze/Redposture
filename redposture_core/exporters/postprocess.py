"""Async post-processing helpers for exporter scan/collect pipelines."""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from typing import Any


class AsyncPostprocessWorker:
    """Single-writer worker for file/logger/index side effects.

    Network worker threads should not block progress updates on file writes or
    structured logger/index side effects. This helper centralizes the lifecycle
    and error propagation that scanner/collect previously duplicated locally.
    """

    def __init__(self, handler: Callable[[Any], None], *, name: str = "postprocess") -> None:
        self._handler = handler
        self._queue: queue.Queue[Any] = queue.Queue()
        self._stop = object()
        self._errors: list[BaseException] = []
        self._errors_lock = threading.Lock()
        self._closed = False
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)
        self._thread.start()

    def put(self, payload: Any) -> None:
        if self._closed:
            self.raise_if_failed()
            raise RuntimeError("postprocess worker is already closed")
        self._queue.put(payload)

    def raise_if_failed(self) -> None:
        if not self._errors:
            return
        err = self._errors[0]
        if isinstance(err, Exception):
            raise err
        raise RuntimeError(str(err))

    def close(self) -> None:
        if self._closed:
            self.raise_if_failed()
            return
        self._queue.join()
        self._queue.put(self._stop)
        self._queue.join()
        self._thread.join()
        self._closed = True
        self.raise_if_failed()

    def _record_error(self, exc: BaseException) -> None:
        with self._errors_lock:
            if not self._errors:
                self._errors.append(exc)

    def _run(self) -> None:
        while True:
            payload = self._queue.get()
            try:
                if payload is self._stop:
                    return
                self._handler(payload)
            except BaseException as exc:  # pragma: no cover - defensive safety belt
                self._record_error(exc)
            finally:
                self._queue.task_done()


__all__ = ["AsyncPostprocessWorker"]
