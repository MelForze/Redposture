"""Bounded native-async detection followed by the existing synchronous work.

Only the first callback runs on the event loop. Blocking post-detection work
runs in the same cancellable daemon pool used by the synchronous scheduler.
"""

from __future__ import annotations

import asyncio
import threading
from collections import deque
from collections.abc import Awaitable, Callable, Iterable, Iterator
from contextvars import copy_context
from typing import Any, Generic, TypeVar, cast

from .scheduler import _DaemonWorkerPool, _Outcome, _Task

T = TypeVar("T")
D = TypeVar("D")
R = TypeVar("R")
_FINISHED = object()


def automatic_detect_concurrency(
    target_count: int, *, deep_workers: int, max_inflight: int | None = None, retained_fds: int = 0
) -> int:
    """Scale native I/O independently, keeping room for existing sync work.

    Counts are expanded endpoints, not input lines. Never materialize the
    target source here. Reserve two FDs per native slot and sync worker, plus
    headroom for open files/stdio and eventual shared pool retention. Return
    zero to retain the legacy path when no native FD budget remains.
    Platforms without resource keep the bounded size profile.
    """
    count = max(1, int(target_count))
    requested = 64
    for threshold, limit in ((1000, 128), (10000, 256), (100000, 512), (1000000, 1024)):
        if count >= threshold:
            requested = limit
    requested = min(count, requested)
    if max_inflight is not None:
        requested = min(requested, max(1, int(max_inflight)))
    from .adaptive_detection import fd_detect_budget

    budget = fd_detect_budget(deep_workers, retained_fds)
    if budget is not None:
        requested = min(requested, budget)
    return max(0, requested)


def adaptive_detect_ceiling(
    target_count: int,
    *,
    initial: int,
    deep_workers: int,
    max_inflight: int | None = None,
    retained_fds: int = 0,
) -> int:
    from .adaptive_detection import fd_detect_budget

    ceiling = min(max(1, target_count), max(1, initial) * 2, 2048)
    if max_inflight is not None:
        ceiling = min(ceiling, max(1, max_inflight))
    budget = fd_detect_budget(deep_workers, retained_fds)
    return max(0, min(ceiling, budget)) if budget is not None else ceiling


class AsyncDetectScheduler(Generic[T, D, R]):
    def __init__(
        self,
        *,
        detect_workers: int,
        deep_workers: int,
        max_inflight: int | None = None,
        adaptive_max: int | None = None,
        retained_fds: int = 0,
        on_limit_change: Callable[[int, str], None] | None = None,
    ) -> None:
        self.detect_workers = max(1, int(detect_workers))
        self.deep_workers = max(1, int(deep_workers))
        self.adaptive_max = max(1, int(adaptive_max)) if adaptive_max is not None else None
        self.retained_fds = max(0, retained_fds)
        self.on_limit_change = on_limit_change
        self.max_inflight = (
            max(1, int(max_inflight))
            if max_inflight is not None
            else max(self.detect_workers, self.adaptive_max or 0) + self.deep_workers * 2
        )

    def iter_completed(
        self,
        items: Iterable[T],
        detect: Callable[[T], Awaitable[D]],
        finish: Callable[[T, D], R],
        children: Callable[[T, R], Iterable[T]] | None = None,
        inline_finish: Callable[[T, D], bool] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> Iterator[tuple[T, R]]:
        source = iter(items)

        notices_lock = threading.Lock()
        notice_queued = False
        released_credits = 0
        wake_source = False
        capacity_blocked = threading.Event()

        def apply_notices() -> None:
            nonlocal notice_queued, released_credits, wake_source
            with notices_lock:
                count, notify_source = released_credits, wake_source
                released_credits = 0
                wake_source = False
                notice_queued = False
            for _ in range(count):
                credits.release()
            changed.set()
            if notify_source:
                work_available.set()

        def wake_loop(*, release: bool = False, source_ready: bool = False) -> None:
            nonlocal notice_queued, released_credits, wake_source
            with notices_lock:
                released_credits += int(release)
                wake_source = wake_source or source_ready
                if notice_queued:
                    return
                notice_queued = True
            if loop_ref:
                try:
                    loop_ref[0].call_soon_threadsafe(apply_notices)
                except RuntimeError:
                    pass  # Cancelled workers may finish after loop close.

        def finish_worker(pair: tuple[T, D]) -> R:
            if capacity_blocked.is_set():
                wake_loop()
            return finish(*pair)

        pool: _DaemonWorkerPool[tuple[T, D], R] = _DaemonWorkerPool(
            max_workers=self.deep_workers,
            max_inflight=self.deep_workers * 2,
            worker=finish_worker,
            key_fn=None,
            per_key_limit=self.deep_workers,
        )
        cancelled = threading.Event()
        done = threading.Event()
        errors: list[BaseException] = []
        credits: asyncio.Semaphore
        changed: asyncio.Event
        work_available: asyncio.Event
        ready: deque[_Task[tuple[T, D]]] = deque()
        followup_indices: set[int] = set()
        followups_outstanding = 0
        loop_ready = threading.Event()
        loop_ref: list[asyncio.AbstractEventLoop] = []
        task_ref: list[asyncio.Task[None]] = []
        counter = 0
        pending: deque[T] = deque()
        source_lock = threading.Lock()
        roots_done = False
        outstanding = 0

        async def run() -> None:
            nonlocal credits, changed, work_available
            credits = asyncio.Semaphore(self.max_inflight)
            changed = asyncio.Event()
            work_available = asyncio.Event()
            from .clients.async_resolver import install_numeric_resolver

            install_numeric_resolver()
            loop_ref.append(asyncio.get_running_loop())
            admission = None
            started_workers = self.detect_workers
            completed_detects = 0
            active_roots = peak_roots = 0
            longest_detect = 0.0
            resource_errors = 0
            if self.adaptive_max is not None:
                from .adaptive_detection import (
                    AdaptiveDetectLimit,
                    DetectAdmission,
                    DetectResources,
                    fd_detect_budget,
                    observe_connection_errors,
                )

                policy = AdaptiveDetectLimit(self.detect_workers, min(self.adaptive_max, self.max_inflight))
                admission = DetectAdmission(policy.limit)
                started_workers = policy.limit
                resources = DetectResources()

                def report_resource_error(_error: OSError) -> None:
                    nonlocal resource_errors
                    resource_errors += 1

                observe_connection_errors(loop_ref[0], report_resource_error)

                async def monitor() -> None:
                    nonlocal completed_detects, resource_errors, peak_roots, longest_detect, started_workers
                    loop = asyncio.get_running_loop()
                    previous = loop.time()
                    while True:
                        await asyncio.sleep(0.5)
                        now = loop.time()
                        elapsed = now - previous
                        previous = now
                        cpu, rss_growth = resources.sample(elapsed)
                        old = policy.limit
                        assert admission is not None
                        limit = policy.observe(
                            completed=completed_detects,
                            elapsed=elapsed,
                            saturated=peak_roots >= policy.limit and len(ready) <= self.deep_workers * 2,
                            cpu=cpu,
                            rss_growth=rss_growth,
                            lag=max(0, elapsed - 0.5),
                            fd_limit=fd_detect_budget(self.deep_workers, self.retained_fds, active=admission.active),
                            resource_errors=resource_errors,
                            latency=longest_detect,
                        )
                        completed_detects = resource_errors = 0
                        longest_detect = 0.0
                        peak_roots = active_roots
                        admission.peak = admission.active
                        if limit != old:
                            await admission.resize(limit)
                            while started_workers < limit:
                                group.create_task(worker())
                                started_workers += 1
                            if self.on_limit_change is not None:
                                self.on_limit_change(limit, policy.reason)

            task = asyncio.current_task()
            assert task is not None
            task_ref.append(task)
            loop_ready.set()

            async def worker() -> None:
                nonlocal \
                    counter, \
                    roots_done, \
                    outstanding, \
                    followups_outstanding, \
                    completed_detects, \
                    active_roots, \
                    peak_roots, \
                    longest_detect
                while not cancelled.is_set():
                    await credits.acquire()
                    if admission is not None:
                        await admission.acquire()
                    have_item = False
                    followup = False
                    with source_lock:
                        # Children get priority without monopolizing all root
                        # credits. Once roots end, their unused capacity is free
                        # for followups; sync workers are never partitioned.
                        if pending and (
                            roots_done
                            or followups_outstanding < self.deep_workers * 2
                            or len(pending) >= self.max_inflight
                        ):
                            item = pending.popleft()
                            have_item = followup = True
                        elif not roots_done:
                            try:
                                item = next(source)
                                have_item = True
                            except StopIteration:
                                roots_done = True
                                if pending:
                                    item = pending.popleft()
                                    have_item = followup = True
                        finished = roots_done and not pending and outstanding == 0
                        if have_item:
                            outstanding += 1
                            if followup:
                                followups_outstanding += 1
                    if not have_item:
                        if admission is not None:
                            await admission.release()
                        credits.release()
                        if finished:
                            changed.set()
                            return
                        work_available.clear()
                        await work_available.wait()
                        continue
                    index = counter
                    counter += 1
                    if followup:
                        with source_lock:
                            followup_indices.add(index)
                    if not followup:
                        active_roots += 1
                        peak_roots = max(peak_roots, active_roots)
                    detect_started = loop_ref[0].time()
                    try:
                        result = await detect(item)
                    finally:
                        if not followup:
                            active_roots -= 1
                            completed_detects += 1
                            longest_detect = max(longest_detect, loop_ref[0].time() - detect_started)
                        if admission is not None:
                            await admission.release()
                    if inline_finish is not None and inline_finish(item, result):
                        try:
                            value = finish(item, result)
                            outcome = _Outcome(index=index, item=(item, result), value=value)
                        except BaseException as exc:
                            outcome = _Outcome(index=index, item=(item, result), error=exc)
                        pool.results.put(outcome)
                    else:
                        # Total credits bound this queue, including retained
                        # sockets/results. Detect slots do not wait on sync IO.
                        ready.append(_Task(index, (item, result)))
                    changed.set()

            async def dispatch() -> None:
                while not cancelled.is_set():
                    changed.clear()
                    capacity_blocked.clear()
                    while ready and not pool._tasks.full():
                        pool.submit(ready.popleft())
                    if ready:
                        capacity_blocked.set()
                        # A worker may have dequeued just before the flag was
                        # set; recheck so that notification cannot be lost.
                        if not pool._tasks.full():
                            continue
                    with source_lock:
                        finished = roots_done and not pending and outstanding == 0
                    if finished:
                        return
                    await changed.wait()

            async def watch_cancel() -> None:
                while cancel_event is not None and not cancel_event.is_set():
                    await asyncio.sleep(0.01)
                cancelled.set()
                task.cancel()

            watcher = asyncio.create_task(watch_cancel()) if cancel_event is not None else None
            monitor_task = asyncio.create_task(monitor()) if admission is not None else None
            if monitor_task is not None:

                def monitor_done(result: asyncio.Task[None]) -> None:
                    if not result.cancelled() and (error := result.exception()) is not None:
                        errors.append(error)
                        task.cancel()

                monitor_task.add_done_callback(monitor_done)
            try:
                async with asyncio.TaskGroup() as group:
                    group.create_task(dispatch())
                    for _ in range(started_workers):
                        group.create_task(worker())
            finally:
                if monitor_task is not None:
                    monitor_task.cancel()
                    await asyncio.gather(monitor_task, return_exceptions=True)
                if watcher is not None:
                    watcher.cancel()
                    await asyncio.gather(watcher, return_exceptions=True)

        def background() -> None:
            try:
                asyncio.run(run())
                pool.close()
            except BaseException as exc:
                if not cancelled.is_set():
                    if isinstance(exc, BaseExceptionGroup):
                        exc = exc.exceptions[0]
                    errors.append(exc)
                pool.cancel()
            finally:
                try:
                    close = getattr(source, "close", None)
                    if callable(close):
                        close()
                except BaseException as exc:
                    if not cancelled.is_set():
                        errors.append(exc)
                finally:
                    done.set()
                    # Pool work is drained/cancelled before this marker. Wake
                    # the coordinator directly, without a polling tail delay.
                    pool.results.put(cast(Any, _FINISHED))

        thread = threading.Thread(
            target=copy_context().run, args=(background,), name="redposture-async-detect", daemon=True
        )
        thread.start()
        complete = False
        try:
            while True:
                outcome = pool.results.get()
                if outcome is _FINISHED:
                    if errors:
                        raise errors[0]
                    break
                if outcome.error is not None:
                    raise outcome.error
                item = outcome.item[0]
                value = cast(R, outcome.value)
                yield item, value
                new_items = list(children(item, value)) if children is not None else []
                with source_lock:
                    pending.extend(new_items)
                    outstanding -= 1
                    if outcome.index in followup_indices:
                        followup_indices.remove(outcome.index)
                        followups_outstanding -= 1

                wake_loop(release=True, source_ready=bool(new_items) or (roots_done and outstanding == 0))

            complete = True
        finally:
            if not complete:
                cancelled.set()
                pool.cancel()
                if loop_ready.wait(0.1) and not done.is_set():
                    try:
                        loop_ref[0].call_soon_threadsafe(task_ref[0].cancel)
                    except RuntimeError:
                        pass
            thread.join(timeout=1)


def async_detection_allowed(args: object) -> bool:
    """Keep explicit proxies and socket interposers on the proven sync path."""
    import os

    from .network_proxy import ProxySocketPatch

    with ProxySocketPatch._lock:
        proxy_active = ProxySocketPatch._active_proxy is not None

    return not (
        proxy_active
        or getattr(args, "_proxy_config", None)
        or getattr(args, "_disable_async_detection", False)
        or any(os.environ.get(name) for name in ("DYLD_INSERT_LIBRARIES", "LD_PRELOAD"))
    )
