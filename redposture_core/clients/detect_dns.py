"""System DNS for HTTP detection without asyncio's non-daemon executor.

The system resolver retains hosts/NSS/search-domain semantics. Work is bounded,
same-name concurrent calls share only an in-flight result (no DNS TTL cache),
and idle daemon workers retire. Saturation/timeout requests legacy verification.
"""

from __future__ import annotations

import asyncio
import queue
import socket
import threading
from concurrent.futures import Future
from typing import Any


class ResolutionUnavailable(Exception):
    pass


class BoundedSystemResolver:
    def __init__(self, *, workers: int = 16, queued: int = 64, idle_timeout: float = 1.0) -> None:
        self.workers = max(1, workers)
        self._queue: queue.Queue[tuple[str, int, Future[list[Any]]]] = queue.Queue(maxsize=max(1, queued))
        self._pending: dict[tuple[str, int], Future[list[Any]]] = {}
        self._lock = threading.Lock()
        self._running = 0
        self._idle_timeout = idle_timeout

    def submit(self, host: str, port: int) -> Future[list[Any]]:
        key = host, port
        with self._lock:
            existing = self._pending.get(key)
            if existing is not None:
                return existing
            future: Future[list[Any]] = Future()
            # Producers share this lock and workers only remove entries. Start
            # the worker before publishing its job so a thread resource error
            # cannot leave an orphan Future or poison the bounded queue.
            if self._queue.full():
                raise ResolutionUnavailable("bounded hostname resolver saturated")
            if self._running < self.workers:
                self._running += 1
                try:
                    threading.Thread(target=self._work, name="redposture-detect-dns", daemon=True).start()
                except (RuntimeError, OSError) as exc:
                    self._running -= 1
                    raise ResolutionUnavailable("bounded hostname resolver worker unavailable") from exc
            self._pending[key] = future
            self._queue.put_nowait((host, port, future))
            return future

    def _work(self) -> None:
        while True:
            try:
                host, port, future = self._queue.get(timeout=self._idle_timeout)
            except queue.Empty:
                with self._lock:
                    if self._queue.empty():
                        self._running -= 1
                        return
                continue
            try:
                if not future.set_running_or_notify_cancel():
                    continue
                try:
                    result = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
                except Exception as exc:
                    future.set_exception(exc)
                else:
                    future.set_result(result)
            finally:
                with self._lock:
                    self._pending.pop((host, port), None)
                self._queue.task_done()

    async def resolve(self, host: str, port: int, timeout: float) -> list[Any]:
        # Shield the shared operation: one cancelled waiter must not cancel DNS
        # needed by another target. No DNS job owns an asyncio executor thread.
        operation = asyncio.wrap_future(self.submit(host, port))
        operation.add_done_callback(lambda result: None if result.cancelled() else result.exception())
        try:
            return await asyncio.wait_for(asyncio.shield(operation), timeout)
        except TimeoutError as exc:
            # The system call itself cannot be killed; bounded daemon workers
            # cannot grow without limit or block asyncio.run()/process exit.
            raise ResolutionUnavailable("bounded hostname resolver timed out") from exc


_SYSTEM_RESOLVER = BoundedSystemResolver()


async def resolve_http_addresses(host: str, port: int, timeout: float) -> list[Any]:
    return await _SYSTEM_RESOLVER.resolve(host, port, timeout)
