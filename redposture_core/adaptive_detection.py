"""Command-local admission control; protocol decisions and retries stay untouched."""

from __future__ import annotations

import asyncio
import errno
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast


def is_local_resource_error(error: BaseException) -> bool:
    return isinstance(error, OSError) and error.errno in {
        errno.EMFILE,
        errno.ENFILE,
        errno.ENOBUFS,
        errno.ENOMEM,
        errno.EADDRNOTAVAIL,
    }


def observe_connection_errors(loop: asyncio.AbstractEventLoop, report: Callable[[OSError], None]) -> None:
    """Observe only this command's loop; SDKs may otherwise swallow OSErrors."""

    def wrap(operation: Callable[..., Any]) -> Callable[..., Any]:
        async def observed(*args: Any, **kwargs: Any) -> Any:
            try:
                return await operation(*args, **kwargs)
            except OSError as exc:
                if is_local_resource_error(exc):
                    report(exc)
                raise

        return observed

    owner = cast(Any, loop)
    owner.create_connection = wrap(loop.create_connection)
    owner.sock_connect = wrap(loop.sock_connect)


class DetectAdmission:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.active = 0
        self.peak = 0
        self._changed = asyncio.Condition()
        self._waiting = 0

    async def acquire(self) -> None:
        # All mutations occur on the same private event loop. The normal path
        # needs no lock/context manager when there is already a free permit.
        if self.active >= self.limit:
            self._waiting += 1
            try:
                async with self._changed:
                    await self._changed.wait_for(lambda: self.active < self.limit)
            finally:
                self._waiting -= 1
        self.active += 1
        self.peak = max(self.peak, self.active)

    async def release(self) -> None:
        self.active -= 1
        if self._waiting:
            async with self._changed:
                self._changed.notify(1)

    async def resize(self, limit: int) -> None:
        async with self._changed:
            self.limit = limit
            self._changed.notify_all()


def fd_detect_budget(deep_workers: int, retained_fds: int = 0, *, active: int = 0) -> int | None:
    """Reserve future sync/idle descriptors as well as currently open ones."""
    try:
        import resource

        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft == resource.RLIM_INFINITY or int(soft) < 0:
            return None
        opened = 0
        for directory in ("/proc/self/fd", "/dev/fd"):
            try:
                opened = len(os.listdir(directory))
                break
            except OSError:
                continue
        return max(0, active + (int(soft) - opened - 64 - max(1, deep_workers) * 2 - max(0, retained_fds)) // 2)
    except (ImportError, AttributeError, OSError, TypeError, ValueError):
        return None


def peak_rss() -> int:
    try:
        import resource

        value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        return value if sys.platform == "darwin" else value * 1024
    except (ImportError, AttributeError, OSError, ValueError):
        return 0


@dataclass
class _ThroughputProbe:
    previous: int
    rate: float
    settle: float


@dataclass
class AdaptiveDetectLimit:
    initial: int
    maximum: int

    def __post_init__(self) -> None:
        self.maximum = max(1, self.maximum)
        self.limit = min(max(1, self.initial), self.maximum)
        self.peak = self.limit
        self.reason = "initial"
        self._probe: _ThroughputProbe | None = None
        self._growth = True
        self._reset_window()

    def _reset_window(self) -> None:
        self._completed = 0
        self._elapsed = 0.0
        self._latency = 0.0

    def observe(
        self,
        *,
        completed: int,
        elapsed: float,
        saturated: bool = True,
        cpu: float = 0,
        lag: float = 0,
        rss_growth: int = 0,
        fd_limit: int | None = None,
        resource_errors: int = 0,
        latency: float = 0,
    ) -> int:
        if elapsed <= 0:
            return self.limit
        pressure = (
            "local_resource"
            if resource_errors
            else "fd"
            if fd_limit is not None and fd_limit < self.limit
            else "event_loop"
            if lag > 0.05
            else "memory"
            if rss_growth > 64_000_000
            else "cpu"
            if cpu > 1.25
            else ""
        )
        if pressure:
            self.limit = max(1, min(self.limit // 2, fd_limit if fd_limit is not None else self.maximum))
            self.reason = pressure
            self._reset_window()
            self._probe = None
            self._growth = True
            return self.limit
        if not saturated or cpu >= 0.85:
            self._reset_window()
            if self._probe is not None:
                self.limit = self._probe.previous
                self._probe = None
                self.reason = "incomparable_probe"
            return self.limit
        if self._probe is not None and self._probe.settle > 0:
            self._probe.settle -= elapsed
            return self.limit
        self._completed += max(0, completed)
        self._elapsed += elapsed
        self._latency = max(self._latency, latency)
        # Compare full windows, at least two observed round trips. Bursty,
        # slow checks must not be judged before new admissions can finish.
        if self._elapsed < max(1.0, self._latency * 2) or not self._completed:
            return self.limit
        rate = self._completed / self._elapsed
        observed_latency = self._latency
        self._reset_window()
        if self._probe is not None:
            previous, previous_rate = self._probe.previous, self._probe.rate
            self._probe = None
            if rate < previous_rate * 1.05:
                self.limit = previous
                self._growth = False
                self.reason = "no_throughput_gain"
                return self.limit
            self.reason = "throughput_gain"
        ceiling = min(self.maximum, fd_limit if fd_limit is not None else self.maximum)
        if self._growth and self.limit < ceiling:
            previous = self.limit
            self.limit = min(ceiling, self.limit + max(1, self.limit // 4))
            self._probe = _ThroughputProbe(previous, rate, observed_latency)
            self.peak = max(self.peak, self.limit)
            self.reason = "probe"
        return self.limit


class DetectResources:
    """Cheap process snapshots, once per control window rather than per target."""

    def __init__(self) -> None:
        self.cpu = time.process_time()
        self.rss = peak_rss()

    def sample(self, elapsed: float) -> tuple[float, int]:
        cpu = time.process_time()
        ratio = (cpu - self.cpu) / max(elapsed, 0.001)
        self.cpu = cpu
        rss = peak_rss()
        growth = max(0, rss - self.rss)
        self.rss = rss
        return ratio, growth
