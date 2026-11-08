"""Release an async detect slot only during an explicit socket-free retry pause."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable
from contextvars import ContextVar

from .runtime_diagnostics import RuntimeDiagnostics


class DetectSlots:
    """FIFO active slots; consume each waiting Future once, including cancellation."""

    def __init__(self, limit: int, on_change: Callable[[int], None] | None = None) -> None:
        self.limit = limit
        self.active = 0
        self.on_change = on_change
        self.waiters: deque[asyncio.Future[None]] = deque()

    async def acquire(self) -> None:
        if self.active < self.limit and not self.waiters:
            self.active += 1
            if self.on_change is not None:
                self.on_change(self.active)
            return
        future = asyncio.get_running_loop().create_future()
        self.waiters.append(future)
        try:
            await future
        except BaseException:
            if not future.cancelled():
                # Cancellation after a permit was granted must pass it on.
                self.release()
            raise

    def release(self) -> None:
        self.release_many(1)

    def release_many(self, count: int) -> None:
        """Transfer a batch in FIFO order without rescanning granted waiters."""
        while count and self.waiters:
            future = self.waiters.popleft()
            if not future.done():
                future.set_result(None)
                count -= 1
        self.active -= count
        if self.on_change is not None:
            self.on_change(self.active)


class DetectLease:
    def __init__(
        self,
        slots: DetectSlots,
        replace_waiter: Callable[[], None],
        *,
        observer: RuntimeDiagnostics | None = None,
    ) -> None:
        self.slots = slots
        self.replace_waiter = replace_waiter
        self.observer = observer
        self.owner = asyncio.current_task()
        self.held = False
        self.retained_socket = False

    async def acquire(self) -> None:
        await self.slots.acquire()
        self.held = True

    def release(self) -> None:
        if self.held:
            self.held = False
            self.slots.release()

    async def pause(self, seconds: float) -> None:
        self.release()
        self.replace_waiter()
        if self.observer is None:
            await asyncio.sleep(seconds)
        else:
            self.observer.adjust_queue("backoff", 1)
            try:
                with self.observer.measure("retry_wait"):
                    await asyncio.sleep(seconds)
            finally:
                self.observer.adjust_queue("backoff", -1)
        await self.acquire()


current_detect_lease: ContextVar[DetectLease | None] = ContextVar("detect_slot_lease", default=None)


def retain_detect_slot() -> None:
    lease = current_detect_lease.get()
    if lease is not None:
        # A socket handed to a later phase is still open, even though the
        # current transport no longer owns it. Do not expand retries around it.
        lease.retained_socket = True


async def detect_backoff(seconds: float, *, socket_free: bool = True) -> None:
    lease = current_detect_lease.get()
    if (
        seconds > 0
        and socket_free
        and lease is not None
        and not lease.retained_socket
        and lease.owner is asyncio.current_task()
    ):
        await lease.pause(seconds)
    else:
        await asyncio.sleep(seconds)
