"""Shared bounded scheduling primitives."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import Generic, TypeVar

T = TypeVar("T")
R = TypeVar("R")
K = TypeVar("K")


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
        indexed = list(enumerate(items))
        results: dict[int, R] = {}
        semaphores: dict[K, threading.Semaphore] = {}

        def _run(item: T) -> R:
            if key_fn is None:
                return worker(item)
            key = key_fn(item)
            semaphore = semaphores.setdefault(key, threading.Semaphore(self.per_key_limit))
            with semaphore:
                return worker(item)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            pending: dict[Future[R], int] = {}
            cursor = 0
            while cursor < len(indexed) or pending:
                while cursor < len(indexed) and len(pending) < self.max_inflight:
                    idx, item = indexed[cursor]
                    pending[executor.submit(_run, item)] = idx
                    cursor += 1
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    idx = pending.pop(future)
                    results[idx] = future.result()

        return [results[idx] for idx, _item in indexed]

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

        indexed = list(enumerate(items))
        semaphores: dict[K, threading.Semaphore] = {}

        def _run(item: T) -> R:
            if key_fn is None:
                return worker(item)
            key = key_fn(item)
            semaphore = semaphores.setdefault(key, threading.Semaphore(self.per_key_limit))
            with semaphore:
                return worker(item)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            pending: dict[Future[R], tuple[int, T]] = {}
            cursor = 0
            while cursor < len(indexed) or pending:
                while cursor < len(indexed) and len(pending) < self.max_inflight:
                    _idx, item = indexed[cursor]
                    pending[executor.submit(_run, item)] = (_idx, item)
                    cursor += 1
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    _idx, item = pending.pop(future)
                    yield item, future.result()


__all__ = ["BoundedScheduler"]
