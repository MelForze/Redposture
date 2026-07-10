"""Shared bounded scheduling primitives."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import Any, Generic, TypeVar

T = TypeVar("T")
R = TypeVar("R")
K = TypeVar("K")


def _cancel_pending_futures(executor: ThreadPoolExecutor, pending: dict[Future[Any], Any]) -> None:
    """Best-effort cancel + non-waiting shutdown used by Ctrl+C paths.

    Python's default `with ThreadPoolExecutor` calls `shutdown(wait=True)` on
    exit, which parks the CLI until every in-flight socket op times out. We
    cancel futures that never started and detach without waiting so operator
    Ctrl+C surfaces immediately.
    """
    for future in list(pending.keys()):
        future.cancel()
    try:
        executor.shutdown(wait=False, cancel_futures=True)
    except TypeError:
        # Python < 3.9 lacked cancel_futures — fall back to the two-arg form.
        executor.shutdown(wait=False)


class BoundedScheduler(Generic[T, R]):
    """Small ThreadPool wrapper with max-inflight and optional per-key limits."""

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

    def map_ordered(
        self,
        items: Iterable[T],
        worker: Callable[[T], R],
        *,
        key_fn: Callable[[T], K] | None = None,
    ) -> list[R]:
        results: dict[int, R] = {}
        semaphores: dict[K, threading.Semaphore] = {}

        def _run(item: T) -> R:
            if key_fn is None:
                return worker(item)
            key = key_fn(item)
            semaphore = semaphores.setdefault(key, threading.Semaphore(self.per_key_limit))
            with semaphore:
                return worker(item)

        executor = ThreadPoolExecutor(max_workers=self.max_workers)
        pending: dict[Future[R], int] = {}
        try:
            iterator = enumerate(items)
            exhausted = False
            submitted = 0
            while not exhausted or pending:
                while not exhausted and len(pending) < self.max_inflight:
                    try:
                        idx, item = next(iterator)
                    except StopIteration:
                        exhausted = True
                        break
                    pending[executor.submit(_run, item)] = idx
                    submitted += 1
                if not pending:
                    continue
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    idx = pending.pop(future)
                    results[idx] = future.result()
        except (KeyboardInterrupt, SystemExit):
            # C3 fix: default ThreadPoolExecutor.__exit__ calls shutdown(wait=True),
            # so Ctrl+C freezes the CLI until every in-flight socket times out.
            _cancel_pending_futures(executor, pending)
            raise
        except BaseException:
            # E1 fix: any worker-side exception (TypeError, KeyError, custom
            # exceptions from broken render helpers, etc.) previously escaped
            # without shutting the executor down — the remaining worker threads
            # kept running against subsequent hosts. Cancel + non-waiting
            # shutdown here so the leak point is closed.
            _cancel_pending_futures(executor, pending)
            raise
        else:
            executor.shutdown(wait=True)
        return [results[idx] for idx in range(submitted)]

    def iter_completed(
        self,
        items: Iterable[T],
        worker: Callable[[T], R],
        *,
        key_fn: Callable[[T], K] | None = None,
    ) -> Iterator[tuple[T, R]]:
        """Yield completed work items while enforcing shared backpressure.

        Results are yielded as tasks complete. The original item is returned
        with each result so callers that need stable ordered output can buffer
        by their own item key.
        """

        semaphores: dict[K, threading.Semaphore] = {}

        def _run(item: T) -> R:
            if key_fn is None:
                return worker(item)
            key = key_fn(item)
            semaphore = semaphores.setdefault(key, threading.Semaphore(self.per_key_limit))
            with semaphore:
                return worker(item)

        executor = ThreadPoolExecutor(max_workers=self.max_workers)
        pending: dict[Future[R], T] = {}
        drained_normally = False
        try:
            iterator = iter(items)
            exhausted = False
            while not exhausted or pending:
                while not exhausted and len(pending) < self.max_inflight:
                    try:
                        item = next(iterator)
                    except StopIteration:
                        exhausted = True
                        break
                    pending[executor.submit(_run, item)] = item
                if not pending:
                    continue
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    item = pending.pop(future)
                    yield item, future.result()
            drained_normally = True
        finally:
            # E1 fix: generators can be closed early (GeneratorExit when the
            # consumer breaks out of the loop) OR raise any exception from
            # `future.result()`. In every non-normal exit we cancel pending
            # futures and shut the executor down without waiting so we don't
            # leak worker threads that keep hammering sockets in the background.
            if drained_normally:
                executor.shutdown(wait=True)
            else:
                _cancel_pending_futures(executor, pending)


__all__ = ["BoundedScheduler"]
