"""Shared bounded scheduling primitives."""

from __future__ import annotations

import itertools
import queue
import threading
from collections.abc import Callable, Generator, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Generic, TypeVar, cast

T = TypeVar("T")
R = TypeVar("R")
K = TypeVar("K")

_STOP = object()
_POOL_SEQUENCE = itertools.count(1)


@dataclass(frozen=True)
class _Task(Generic[T]):
    index: int
    item: T


@dataclass(frozen=True)
class _Outcome(Generic[T, R]):
    index: int
    item: T
    value: R | None = None
    error: BaseException | None = None


class _KeyLimiter(Generic[T, K]):
    def __init__(self, key_fn: Callable[[T], K] | None, per_key_limit: int) -> None:
        self._key_fn = key_fn
        self._per_key_limit = per_key_limit
        self._semaphores: dict[K, threading.Semaphore] = {}
        self._lock = threading.Lock()

    def run(self, item: T, worker: Callable[[T], R]) -> R:
        if self._key_fn is None:
            return worker(item)
        key = self._key_fn(item)
        with self._lock:
            semaphore = self._semaphores.get(key)
            if semaphore is None:
                semaphore = threading.Semaphore(self._per_key_limit)
                self._semaphores[key] = semaphore
        with semaphore:
            return worker(item)


class _DaemonWorkerPool(Generic[T, R]):
    """A small daemon-thread pool whose cancellation path never joins active work.

    ``ThreadPoolExecutor.shutdown(wait=False)`` still leaves its workers registered
    in CPython's interpreter-exit hook, so a blocked socket operation can hold the
    CLI open after Ctrl+C. These workers are ordinary daemon threads and therefore
    cannot delay process exit. Normal completion still joins every worker.
    """

    def __init__(
        self,
        *,
        max_workers: int,
        max_inflight: int,
        worker: Callable[[T], R],
        key_fn: Callable[[T], Any] | None,
        per_key_limit: int,
    ) -> None:
        self._tasks: queue.Queue[_Task[T] | object] = queue.Queue(maxsize=max_inflight)
        self.results: queue.Queue[_Outcome[T, R]] = queue.Queue()
        self._cancelled = threading.Event()
        self._worker = worker
        self._limiter: _KeyLimiter[T, Any] = _KeyLimiter(key_fn, per_key_limit)
        pool_id = next(_POOL_SEQUENCE)
        self._threads = [
            threading.Thread(
                target=self._worker_loop,
                name=f"redposture-scheduler-{pool_id}-{index + 1}",
                daemon=True,
            )
            for index in range(max_workers)
        ]
        for thread in self._threads:
            thread.start()

    def submit(self, task: _Task[T]) -> None:
        if self._cancelled.is_set():
            raise RuntimeError("scheduler is cancelled")
        self._tasks.put(task)

    def _worker_loop(self) -> None:
        while True:
            queued = self._tasks.get()
            try:
                if queued is _STOP:
                    return
                task = cast(_Task[T], queued)
                if self._cancelled.is_set():
                    continue
                try:
                    value = self._limiter.run(task.item, self._worker)
                except BaseException as exc:  # noqa: BLE001 - transported to the caller thread
                    if not self._cancelled.is_set():
                        self.results.put(_Outcome(index=task.index, item=task.item, error=exc))
                else:
                    if not self._cancelled.is_set():
                        self.results.put(_Outcome(index=task.index, item=task.item, value=value))
            finally:
                self._tasks.task_done()

    def close(self) -> None:
        """Finish a normally drained pool and join all worker threads."""

        for _thread in self._threads:
            self._tasks.put(_STOP)
        for thread in self._threads:
            thread.join()

    def cancel(self) -> None:
        """Discard queued work and detach immediately from active daemon workers."""

        if self._cancelled.is_set():
            return
        self._cancelled.set()
        while True:
            try:
                self._tasks.get_nowait()
            except queue.Empty:
                break
            else:
                self._tasks.task_done()
        # Wake workers that are idle now. Active workers will consume a stop
        # marker after their current call returns; we deliberately do not join.
        for _thread in self._threads:
            try:
                self._tasks.put_nowait(_STOP)
            except queue.Full:  # pragma: no cover - the queue was drained above
                break


class BoundedScheduler(Generic[T, R]):
    """Bounded daemon-worker scheduler with ordered and completion-order APIs."""

    def __init__(
        self,
        *,
        max_workers: int,
        max_inflight: int | None = None,
        per_key_limit: int | None = None,
    ) -> None:
        self.max_workers = max(1, int(max_workers))
        self.max_inflight = max(self.max_workers, int(max_inflight or self.max_workers * 2))
        self.per_key_limit = max(1, int(per_key_limit or self.max_inflight))

    def _iter_outcomes(
        self,
        items: Iterable[T],
        worker: Callable[[T], R],
        *,
        key_fn: Callable[[T], K] | None = None,
    ) -> Generator[_Outcome[T, R], None, None]:
        pool: _DaemonWorkerPool[T, R] = _DaemonWorkerPool(
            max_workers=self.max_workers,
            max_inflight=self.max_inflight,
            worker=worker,
            key_fn=key_fn,
            per_key_limit=self.per_key_limit,
        )
        source = enumerate(items)
        exhausted = False
        in_flight = 0
        drained_normally = False

        def _fill() -> None:
            nonlocal exhausted, in_flight
            while not exhausted and in_flight < self.max_inflight:
                try:
                    index, item = next(source)
                except StopIteration:
                    exhausted = True
                    break
                pool.submit(_Task(index=index, item=item))
                in_flight += 1

        try:
            _fill()
            while in_flight:
                outcome = pool.results.get()
                in_flight -= 1
                if outcome.error is not None:
                    raise outcome.error
                yield outcome
                _fill()
            drained_normally = True
        finally:
            if drained_normally:
                pool.close()
            else:
                pool.cancel()

    def map_ordered(
        self,
        items: Iterable[T],
        worker: Callable[[T], R],
        *,
        key_fn: Callable[[T], K] | None = None,
    ) -> list[R]:
        results: dict[int, R] = {}
        outcomes = self._iter_outcomes(items, worker, key_fn=key_fn)
        try:
            for outcome in outcomes:
                results[outcome.index] = cast(R, outcome.value)
        finally:
            outcomes.close()
        return [results[index] for index in range(len(results))]

    def iter_completed(
        self,
        items: Iterable[T],
        worker: Callable[[T], R],
        *,
        key_fn: Callable[[T], K] | None = None,
    ) -> Iterator[tuple[T, R]]:
        """Yield completed work items while enforcing shared backpressure."""

        outcomes = self._iter_outcomes(items, worker, key_fn=key_fn)
        try:
            for outcome in outcomes:
                yield outcome.item, cast(R, outcome.value)
        finally:
            outcomes.close()


@dataclass
class _SharedTask:
    index: int
    item: Any
    worker: Callable[[Any], Any]
    completion: queue.Queue[_Outcome[Any, Any]]
    limiter: threading.Semaphore | None


class SharedNestedScheduler:
    """One daemon pool shared by every nested operation in a command."""

    def __init__(self, max_workers: int) -> None:
        self.max_workers = max(1, int(max_workers))
        self._tasks: queue.Queue[_SharedTask | object] = queue.Queue(maxsize=self.max_workers * 4)
        self._threads: list[threading.Thread] = []
        self._limiters: dict[tuple[Any, int], threading.Semaphore] = {}
        self._lock = threading.Lock()
        self._closed = False
        self._budget = threading.BoundedSemaphore(self.max_workers)

    def _ensure_started(self) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("nested scheduler is closed")
            if self._threads:
                return
            pool_id = next(_POOL_SEQUENCE)
            self._threads = [
                threading.Thread(
                    target=self._worker_loop,
                    name=f"redposture-nested-{pool_id}-{index + 1}",
                    daemon=True,
                )
                for index in range(self.max_workers)
            ]
            for thread in self._threads:
                thread.start()

    def _limiter(self, key: Any | None, per_key_limit: int | None) -> threading.Semaphore | None:
        if key is None or per_key_limit is None:
            return None
        limit = max(1, min(self.max_workers, int(per_key_limit)))
        cache_key = (key, limit)
        with self._lock:
            limiter = self._limiters.get(cache_key)
            if limiter is None:
                limiter = threading.Semaphore(limit)
                self._limiters[cache_key] = limiter
            return limiter

    def _worker_loop(self) -> None:
        while True:
            queued = self._tasks.get()
            try:
                if queued is _STOP:
                    return
                task = cast(_SharedTask, queued)
                try:
                    with self.slot():
                        if task.limiter is None:
                            value = task.worker(task.item)
                        else:
                            with task.limiter:
                                value = task.worker(task.item)
                except BaseException as exc:  # noqa: BLE001
                    task.completion.put(_Outcome(index=task.index, item=task.item, error=exc))
                else:
                    task.completion.put(_Outcome(index=task.index, item=task.item, value=value))
            finally:
                self._tasks.task_done()

    @contextmanager
    def slot(self) -> Iterator[None]:
        """Reserve one slot from the command-wide nested concurrency budget."""

        self._budget.acquire()
        try:
            yield
        finally:
            self._budget.release()

    def iter_completed(
        self,
        items: Iterable[T],
        worker: Callable[[T], R],
        *,
        key: Any | None = None,
        per_key_limit: int | None = None,
    ) -> Iterator[tuple[T, R]]:
        self._ensure_started()
        completion: queue.Queue[_Outcome[T, R]] = queue.Queue()
        count = 0
        limiter = self._limiter(key, per_key_limit)
        for index, item in enumerate(items):
            self._tasks.put(
                _SharedTask(
                    index=index,
                    item=item,
                    worker=cast(Callable[[Any], Any], worker),
                    completion=cast(queue.Queue[_Outcome[Any, Any]], completion),
                    limiter=limiter,
                )
            )
            count += 1
        for _ in range(count):
            outcome = completion.get()
            if outcome.error is not None:
                raise outcome.error
            yield outcome.item, cast(R, outcome.value)

    def map_ordered(
        self,
        items: Iterable[T],
        worker: Callable[[T], R],
        *,
        key: Any | None = None,
        per_key_limit: int | None = None,
    ) -> list[R]:
        ordered_items = list(items)
        results: dict[int, R] = {}
        indexed_items = list(enumerate(ordered_items))
        for indexed_item, value in self.iter_completed(
            indexed_items,
            lambda pair: worker(pair[1]),
            key=key,
            per_key_limit=per_key_limit,
        ):
            results[indexed_item[0]] = value
        return [results[index] for index in range(len(ordered_items))]

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            threads = list(self._threads)
        for _thread in threads:
            self._tasks.put(_STOP)
        for thread in threads:
            thread.join()
        with self._lock:
            self._threads.clear()
            self._limiters.clear()


__all__ = ["BoundedScheduler", "SharedNestedScheduler"]
