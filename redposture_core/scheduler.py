"""Shared bounded scheduling primitives."""

from __future__ import annotations

import heapq
import itertools
import queue
import threading
import time
import weakref
from collections import deque
from collections.abc import Callable, Generator, Iterable, Iterator
from concurrent.futures import Future
from contextlib import contextmanager
from contextvars import Context, copy_context
from dataclasses import dataclass
from typing import Any, Generic, TypeVar, cast

from .runtime_diagnostics import RuntimeDiagnostics

T = TypeVar("T")
R = TypeVar("R")
K = TypeVar("K")

_STOP = object()
_POOL_SEQUENCE = itertools.count(1)
_PAUSE_READY = object()
_PAUSE_SOURCE = object()
WorkPause = float | Future[Any]


def run_paused_sync(steps: Generator[WorkPause, None, R], *, sleep: Callable[[float], None] = time.sleep) -> R:
    """Compatibility driver for callers without a cooperative coordinator."""
    try:
        while True:
            try:
                pause = next(steps)
            except StopIteration as done:
                return cast(R, done.value)
            if isinstance(pause, Future):
                pause.result()
            elif pause > 0:
                sleep(pause)
    finally:
        steps.close()


class NestedSchedulerCancelled(RuntimeError):
    """A nested audit was stopped before its active work completed."""


@dataclass(frozen=True)
class _Task(Generic[T]):
    index: int
    item: T
    queued_at_ns: int | None = None


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
        observer: RuntimeDiagnostics | None = None,
    ) -> None:
        self._observer = observer
        self._tasks: queue.Queue[_Task[T] | object] = queue.Queue(maxsize=max_inflight)
        self.results: queue.SimpleQueue[_Outcome[T, R]] = queue.SimpleQueue()
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
        if self._observer is not None:
            task = _Task(task.index, task.item, time.perf_counter_ns())
        self._tasks.put(task)
        if self._observer is not None:
            self._observer.queue("deep_tasks", self._tasks.qsize())

    def _worker_loop(self) -> None:
        while True:
            queued = self._tasks.get()
            try:
                if self._observer is not None:
                    self._observer.queue("deep_tasks", self._tasks.qsize())
                if queued is _STOP:
                    return
                task = cast(_Task[T], queued)
                if self._cancelled.is_set():
                    continue
                try:
                    if self._observer is None:
                        value = self._limiter.run(task.item, self._worker)
                    else:
                        if task.queued_at_ns is not None:
                            self._observer.duration("queue_wait", (time.perf_counter_ns() - task.queued_at_ns) / 1e9)
                        with self._observer.measure("finish"):
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
        observer: RuntimeDiagnostics | None = None,
    ) -> None:
        self.observer = observer
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
            observer=self.observer,
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

    def iter_expanding(
        self,
        items: Iterable[T],
        worker: Callable[[T], R],
        children: Callable[[T, R], Iterable[T]],
        *,
        prioritize_children: Callable[[T, R], bool] | None = None,
    ) -> Iterator[tuple[T, R]]:
        """Schedule finite dependent jobs as their parent finishes, in one pool.

        Children have priority over fresh roots. Only max_inflight parents can
        contribute pending children at once; callers bound per-parent fanout.
        """
        pool: _DaemonWorkerPool[T, R] = _DaemonWorkerPool(
            max_workers=self.max_workers,
            max_inflight=self.max_inflight,
            worker=worker,
            key_fn=None,
            per_key_limit=self.max_inflight,
            observer=self.observer,
        )
        source = iter(items)
        pending: deque[T] = deque()
        exhausted = False
        inflight = 0
        sequence = itertools.count()
        complete = False
        try:
            while True:
                while inflight < self.max_inflight:
                    if pending:
                        item = pending.popleft()
                    elif not exhausted:
                        try:
                            item = next(source)
                        except StopIteration:
                            exhausted = True
                            continue
                    else:
                        break
                    pool.submit(_Task(next(sequence), item))
                    inflight += 1
                if not inflight:
                    complete = True
                    return
                outcome = pool.results.get()
                inflight -= 1
                if outcome.error is not None:
                    raise outcome.error
                value = cast(R, outcome.value)
                new_items = list(children(outcome.item, value))
                if new_items and prioritize_children is not None and prioritize_children(outcome.item, value):
                    pending.extendleft(reversed(new_items))
                else:
                    pending.extend(new_items)
                yield outcome.item, value
        finally:
            if complete:
                pool.close()
            else:
                pool.cancel()

    def iter_paused(
        self,
        items: Iterable[T],
        worker: Callable[[T], Generator[WorkPause, None, R]],
        *,
        cancelled: threading.Event | None = None,
        poll_source: bool = False,
        source_wakeup: Callable[[Callable[[], None] | None], None] | None = None,
    ) -> Iterator[tuple[T, R]]:
        """Run bounded resumable jobs; yielded delays never occupy workers.

        Contexts and generators stay attached to a job across pool threads.
        max_inflight also bounds parked lifecycle state and open connections.
        """
        states: dict[int, tuple[T, Context, Generator[WorkPause, None, R] | None]] = {}
        parked: list[tuple[float, int]] = []
        waiting: dict[int, Future[Any]] = {}
        ready: deque[int] = deque()
        pause_started: dict[int, float] = {}
        source = enumerate(items)
        exhausted = False
        running: set[int] = set()
        finished = False
        abandoned = threading.Event()

        def record_pause(index: int) -> None:
            if self.observer is not None:
                pause_started[index] = time.monotonic()
                self.observer.queue("finish_wait", len(pause_started))

        def end_pause(index: int) -> None:
            started = pause_started.pop(index, None)
            if started is not None and self.observer is not None:
                self.observer.duration("finish_wait", max(0.0, time.monotonic() - started))
                self.observer.queue("finish_wait", len(pause_started))

        def step(index: int) -> tuple[bool, Any]:
            item, context, generator = states[index]
            if generator is None:
                generator = context.run(worker, item)
                states[index] = (item, context, generator)
            try:
                if abandoned.is_set() or (cancelled is not None and cancelled.is_set()):
                    return True, None
                try:
                    return False, context.run(next, generator)
                except StopIteration as done:
                    return True, done.value
            finally:
                # Cancellation can occur during a blocking next(). If that call
                # later yields, nobody will resume it: close in its own Context.
                if abandoned.is_set() or (cancelled is not None and cancelled.is_set()):
                    context.run(generator.close)

        pool: _DaemonWorkerPool[int, tuple[bool, Any]] = _DaemonWorkerPool(
            max_workers=self.max_workers,
            max_inflight=self.max_inflight,
            worker=step,
            key_fn=None,
            per_key_limit=self.max_inflight,
            observer=self.observer,
        )

        if source_wakeup is not None:
            pool_ref = weakref.ref(pool)

            def source_ready() -> None:
                owner = pool_ref()
                if owner is not None and not abandoned.is_set():
                    owner.results.put(_Outcome(index=-1, item=-1, value=(False, _PAUSE_SOURCE)))

            source_wakeup(source_ready)
        try:
            while True:
                if cancelled is not None and cancelled.is_set():
                    return
                while len(running) < self.max_workers:
                    if ready:
                        index = ready.popleft()
                    elif parked and parked[0][0] <= time.monotonic():
                        _, index = heapq.heappop(parked)
                    elif not exhausted and len(states) < self.max_inflight:
                        try:
                            index, item = next(source)
                        except queue.Empty:
                            if not poll_source:
                                raise
                            break
                        except StopIteration:
                            exhausted = True
                            continue
                        states[index] = (item, copy_context(), None)
                    else:
                        break
                    end_pause(index)
                    running.add(index)
                    pool.submit(_Task(index=index, item=index))
                if not states and exhausted:
                    finished = True
                    return
                timeout = 0.05
                if parked:
                    timeout = min(timeout, max(0.001, parked[0][0] - time.monotonic()))
                try:
                    outcome = pool.results.get(timeout=timeout)
                except queue.Empty:
                    continue
                if outcome.value == (False, _PAUSE_SOURCE):
                    continue
                if outcome.value == (False, _PAUSE_READY):
                    if outcome.index in waiting:
                        waiting.pop(outcome.index)
                        ready.append(outcome.index)
                    continue
                running.remove(outcome.index)
                if outcome.error is not None:
                    raise outcome.error
                done, value = cast(tuple[bool, Any], outcome.value)
                if done:
                    item, _, _ = states.pop(outcome.index)
                    yield item, cast(R, value)
                elif isinstance(value, Future):
                    record_pause(outcome.index)
                    waiting[outcome.index] = value
                    pool_ref = weakref.ref(pool)

                    def awakened(_future: Future[Any], index: int = outcome.index, ref: Any = pool_ref) -> None:
                        owner = ref()
                        if owner is not None and not abandoned.is_set():
                            owner.results.put(_Outcome(index=index, item=index, value=(False, _PAUSE_READY)))

                    value.add_done_callback(awakened)
                else:
                    heapq.heappush(parked, (time.monotonic() + max(0.0, float(value)), outcome.index))
                    record_pause(outcome.index)
        finally:
            if source_wakeup is not None:
                source_wakeup(None)
            close_source = getattr(items, "close", None)
            if poll_source and callable(close_source):
                close_source()
            abandoned.set()
            if finished:
                pool.close()
            else:
                pool.cancel()
            # Close idle and just-completed continuations. An executing call
            # owns its Context and closes itself in step's finally on return.
            cleanup_error: BaseException | None = None
            for _index, (_item, context, generator) in list(states.items()):
                if generator is not None and not getattr(generator, "gi_running", False):
                    try:
                        context.run(generator.close)
                    except BaseException as exc:  # noqa: BLE001 - close every independent lifecycle
                        if isinstance(exc, RuntimeError) and "already entered" in str(exc):
                            continue
                        if cleanup_error is None:
                            cleanup_error = exc
            for index in tuple(pause_started):
                end_pause(index)
            states.clear()
            waiting.clear()
            ready.clear()
            if cleanup_error is not None:
                raise cleanup_error

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


class _PausedWorkerPool(Generic[T, R]):
    """Queue-compatible bridge to the bounded, Context-preserving step scheduler.

    Only a yielded socket-free delay is parked. Normal synchronous calls still
    use exactly max_workers daemon workers. The coordinator owns every idle
    continuation; cancellation closes it in the Context in which it was made.
    """

    def __init__(
        self,
        *,
        max_workers: int,
        max_inflight: int,
        worker: Callable[[T], Generator[WorkPause, None, R]],
        observer: RuntimeDiagnostics | None = None,
    ) -> None:
        self._tasks: queue.Queue[_Task[T]] = queue.Queue(maxsize=max_inflight)
        self.results: queue.SimpleQueue[_Outcome[T, R]] = queue.SimpleQueue()
        self._cancelled, self._closed = threading.Event(), threading.Event()
        self._source_wake: Callable[[], None] | None = None
        self._source_wake_lock = threading.Lock()
        owner = self

        def set_source_wakeup(callback: Callable[[], None] | None) -> None:
            with self._source_wake_lock:
                self._source_wake = callback

        class Source:
            def __iter__(self) -> Source:
                return self

            def __next__(self) -> _Task[T]:
                if owner._cancelled.is_set() or (owner._closed.is_set() and owner._tasks.empty()):
                    raise StopIteration
                task = owner._tasks.get_nowait()
                owner._tasks.task_done()
                return task

            def close(self) -> None:
                owner._closed.set()

        def work(task: _Task[T]) -> Generator[WorkPause, None, _Outcome[T, R]]:
            try:
                result = yield from worker(task.item)
            except GeneratorExit:
                raise
            except BaseException as exc:  # noqa: BLE001 - transport to the owning consumer
                return _Outcome(index=task.index, item=task.item, error=exc)
            return _Outcome(index=task.index, item=task.item, value=result)

        def run() -> None:
            try:
                scheduler: BoundedScheduler[_Task[T], _Outcome[T, R]] = BoundedScheduler(
                    max_workers=max_workers, max_inflight=max_inflight, observer=observer
                )
                for _task, result in scheduler.iter_paused(
                    Source(), work, cancelled=self._cancelled, poll_source=True, source_wakeup=set_source_wakeup
                ):
                    if not self._cancelled.is_set():
                        self.results.put(result)
            except BaseException as exc:  # noqa: BLE001 - also wake the consumer on a bad yielded delay
                if not self._cancelled.is_set():
                    self.results.put(_Outcome(index=-1, item=cast(T, None), error=exc))

        self._thread = threading.Thread(
            target=copy_context().run, args=(run,), name="redposture-paused-finish", daemon=True
        )
        self._thread.start()

    def submit(self, task: _Task[T]) -> None:
        if self._closed.is_set() or self._cancelled.is_set():
            raise RuntimeError("paused scheduler is closed")
        self._tasks.put(task)
        with self._source_wake_lock:
            wake = self._source_wake
        if wake is not None:
            wake()

    def close(self) -> None:
        self._closed.set()
        self._thread.join(5)
        if self._thread.is_alive():
            self.cancel()
            raise RuntimeError("paused finish coordinator did not stop")

    def cancel(self) -> None:
        self._cancelled.set()
        self._closed.set()
        while True:
            try:
                self._tasks.get_nowait()
            except queue.Empty:
                break
            else:
                self._tasks.task_done()
        if threading.current_thread() is not self._thread:
            self._thread.join(0.1)


@dataclass
class _SharedTask:
    index: int
    item: Any
    worker: Callable[[Any], Any]
    completion: queue.Queue[_Outcome[Any, Any]]
    limiter: threading.Semaphore | None
    cancelled: threading.Event
    context: Context


class SharedNestedScheduler:
    """One daemon pool shared by every nested operation in a command."""

    def __init__(self, max_workers: int) -> None:
        self.max_workers = max(1, int(max_workers))
        self._tasks: queue.Queue[_SharedTask | object] = queue.Queue(maxsize=self.max_workers * 4)
        self._threads: list[threading.Thread] = []
        self._limiters: dict[tuple[Any, int], threading.Semaphore] = {}
        self._lock = threading.Lock()
        self._closed = False
        self._cancelled = threading.Event()
        self._completions: set[queue.Queue[_Outcome[Any, Any]]] = set()
        self._budget = threading.BoundedSemaphore(self.max_workers)

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def _register_completion(self, completion: queue.Queue[_Outcome[Any, Any]]) -> None:
        with self._lock:
            if self._closed:
                raise NestedSchedulerCancelled("nested scheduler is cancelled")
            self._completions.add(completion)

    def _unregister_completion(self, completion: queue.Queue[_Outcome[Any, Any]]) -> None:
        with self._lock:
            self._completions.discard(completion)

    def _submit(self, task: _SharedTask) -> None:
        while not self._cancelled.is_set():
            try:
                self._tasks.put(task, timeout=0.1)
                return
            except queue.Full:
                continue
        raise NestedSchedulerCancelled("nested scheduler is cancelled")

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
                if self._cancelled.is_set() or task.cancelled.is_set():
                    continue
                try:
                    with self.slot():
                        if self._cancelled.is_set() or task.cancelled.is_set():
                            continue
                        if task.limiter is None:
                            value = task.context.run(task.worker, task.item)
                        else:
                            with task.limiter:
                                if self._cancelled.is_set() or task.cancelled.is_set():
                                    continue
                                value = task.context.run(task.worker, task.item)
                except BaseException as exc:  # noqa: BLE001
                    if not self._cancelled.is_set() and not task.cancelled.is_set():
                        task.completion.put(_Outcome(index=task.index, item=task.item, error=exc))
                else:
                    if not self._cancelled.is_set() and not task.cancelled.is_set():
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
        self._register_completion(cast(queue.Queue[_Outcome[Any, Any]], completion))
        limiter = self._limiter(key, per_key_limit)
        cancelled = threading.Event()
        source = enumerate(items)
        exhausted = False
        in_flight = 0
        effective_limit = self.max_workers if per_key_limit is None else min(self.max_workers, int(per_key_limit))
        # Do not queue more work for a keyed target than its concurrency limit.
        # Extra tasks would occupy pool threads while waiting on the key's
        # semaphore, starving discovery on other targets.
        local_window = max(1, effective_limit) if limiter is not None else self.max_workers * 2

        def _fill() -> None:
            nonlocal exhausted, in_flight
            while not exhausted and in_flight < local_window:
                try:
                    index, item = next(source)
                except StopIteration:
                    exhausted = True
                    break
                self._submit(
                    _SharedTask(
                        index=index,
                        item=item,
                        worker=cast(Callable[[Any], Any], worker),
                        completion=cast(queue.Queue[_Outcome[Any, Any]], completion),
                        limiter=limiter,
                        cancelled=cancelled,
                        context=copy_context(),
                    )
                )
                in_flight += 1

        try:
            _fill()
            while in_flight:
                outcome = completion.get()
                in_flight -= 1
                if self._cancelled.is_set():
                    raise NestedSchedulerCancelled("nested scheduler is cancelled")
                if outcome.error is not None:
                    raise outcome.error
                yield outcome.item, cast(R, outcome.value)
                _fill()
        finally:
            # Queued work from an abandoned iterator is skipped by the shared
            # workers. Active calls remain daemonized and cannot hold CLI exit.
            cancelled.set()
            self._unregister_completion(cast(queue.Queue[_Outcome[Any, Any]], completion))

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

    def run_dynamic(
        self,
        items: Iterable[T],
        worker: Callable[[T], R],
        on_completed: Callable[[T, R], Iterable[T] | None],
        *,
        key: Any | None = None,
        per_key_limit: int | None = None,
    ) -> None:
        """Run bounded work whose completed items may enqueue follow-up work.

        ``on_completed`` always runs in the caller thread. This keeps shared
        budgets, checkpoints, and result aggregation deterministic while the
        expensive operation runs in the nested pool.
        """

        self._ensure_started()
        completion: queue.Queue[_Outcome[T, R]] = queue.Queue()
        self._register_completion(cast(queue.Queue[_Outcome[Any, Any]], completion))
        limiter = self._limiter(key, per_key_limit)
        cancelled = threading.Event()
        source = iter(items)
        follow_up: deque[T] = deque()
        source_exhausted = False
        in_flight = 0
        sequence = itertools.count()
        effective_limit = self.max_workers if per_key_limit is None else min(self.max_workers, int(per_key_limit))
        # As in iter_completed, avoid parking pool threads on one target's
        # per-key semaphore while another target has runnable work.
        local_window = max(1, effective_limit) if limiter is not None else self.max_workers * 2

        def _next_item() -> T:
            nonlocal source_exhausted
            if not source_exhausted:
                try:
                    return next(source)
                except StopIteration:
                    source_exhausted = True
            if follow_up:
                return follow_up.popleft()
            raise StopIteration

        def _fill() -> None:
            nonlocal in_flight
            while in_flight < local_window:
                try:
                    item = _next_item()
                except StopIteration:
                    break
                self._submit(
                    _SharedTask(
                        index=next(sequence),
                        item=item,
                        worker=cast(Callable[[Any], Any], worker),
                        completion=cast(queue.Queue[_Outcome[Any, Any]], completion),
                        limiter=limiter,
                        cancelled=cancelled,
                        context=copy_context(),
                    )
                )
                in_flight += 1

        try:
            _fill()
            while in_flight:
                outcome = completion.get()
                in_flight -= 1
                if self._cancelled.is_set():
                    raise NestedSchedulerCancelled("nested scheduler is cancelled")
                if outcome.error is not None:
                    raise outcome.error
                generated = on_completed(outcome.item, cast(R, outcome.value))
                if generated is not None:
                    follow_up.extend(generated)
                _fill()
        finally:
            cancelled.set()
            self._unregister_completion(cast(queue.Queue[_Outcome[Any, Any]], completion))

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

    def cancel(self) -> None:
        """Stop accepting work and detach from active daemon workers immediately."""

        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._cancelled.set()
            threads = list(self._threads)
            completions = list(self._completions)
        for completion in completions:
            completion.put(
                _Outcome(index=-1, item=None, error=NestedSchedulerCancelled("nested scheduler is cancelled"))
            )
        while True:
            try:
                queued = self._tasks.get_nowait()
            except queue.Empty:
                break
            else:
                if isinstance(queued, _SharedTask):
                    queued.cancelled.set()
                self._tasks.task_done()
        for _thread in threads:
            try:
                self._tasks.put_nowait(_STOP)
            except queue.Full:  # pragma: no cover - the queue was drained above
                break
        with self._lock:
            self._limiters.clear()


__all__ = ["BoundedScheduler", "NestedSchedulerCancelled", "SharedNestedScheduler"]
