"""One bounded identity-scoped session waiting between synchronous phases."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(eq=False)
class SessionLease:
    key: tuple[Any, ...]
    value: Any
    close: Callable[[], None]
    release_budget: Callable[[], None] | None = None


class SessionHandoff:
    def __init__(self, budget: Any = None, *, budget_units: int = 1) -> None:
        self.budget = budget
        self.budget_units = budget_units
        self._ready: SessionLease | None = None
        self._active: dict[int, SessionLease] = {}
        self._closed = False
        self._lock = threading.Lock()

    def track(self, key: tuple[Any, ...], value: Any, close: Callable[[], None]) -> SessionLease:
        lease = SessionLease(key, value, close)
        with self._lock:
            if not self._closed:
                self._active[id(lease)] = lease
                return lease
        close()
        raise RuntimeError("session lifecycle is closed")

    def take(self, key: tuple[Any, ...]) -> SessionLease | None:
        with self._lock:
            lease = self._ready
            if self._closed or lease is None or lease.key != key:
                return None
            self._ready = None
            if lease.release_budget is not None:
                lease.release_budget()
                lease.release_budget = None
            # Keep cancellation ownership until the worker finishes using it.
            return lease

    def finish(self, lease: SessionLease, *, keep: bool = False) -> bool:
        with self._lock:
            if id(lease) not in self._active:
                return False
            if keep and not self._closed and self._ready is None:
                releases = []
                if self.budget is not None:
                    for _ in range(self.budget_units):
                        release = self.budget.acquire()
                        if release is None:
                            break
                        releases.append(release)
                if self.budget is None or len(releases) == self.budget_units:

                    def release_all() -> None:
                        for release in releases:
                            release()

                    lease.release_budget = release_all
                    self._ready = lease
                    return True
                for release in releases:
                    release()
            self._active.pop(id(lease), None)
            if self._ready is lease:
                self._ready = None
            if lease.release_budget is not None:
                lease.release_budget()
                lease.release_budget = None
        lease.close()
        return False

    def close(self) -> None:
        with self._lock:
            self._closed = True
            leases = list(self._active.values())
            self._active.clear()
            self._ready = None
        for lease in leases:
            if lease.release_budget is not None:
                lease.release_budget()
                lease.release_budget = None
            try:
                lease.close()
            except Exception:
                pass
