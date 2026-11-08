"""Bound the backlog of stopped PyMongo monitor threads, not live clients.

PyMongo 4's synchronous close signals its executors but does not join them.
Short-lived authentication clients can therefore exhaust a process's threads
even with very few audit workers. Keep only thread handles from *closed*
clients; wait for the oldest ones only when the fixed backlog is full.
No client, pool, credential, socket or executor is retained by this queue.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Any


def _alive(thread: Any) -> bool:
    try:
        return bool(thread.is_alive())
    except (ReferenceError, RuntimeError):
        return False


def _identity(thread: Any) -> int | None:
    # PyMongo stores weak proxies. A thread can exit between is_alive and
    # reading ident, so both observations must tolerate collection.
    try:
        ident: int | None = thread.ident
        return ident
    except ReferenceError:
        return None


class MongoRetirements:
    """Fixed backpressure on retiring clients; active workers stay unchanged."""

    def __init__(self, limit: int = 128) -> None:
        if limit < 1:
            raise ValueError("retirement limit must be positive")
        self.limit = limit
        self._lock = threading.Lock()
        self._pending: deque[tuple[Any, ...]] = deque()

    def retire(self, threads: tuple[Any, ...]) -> None:
        # The caller has already closed the client and cancelled its monitors.
        # Never join oneself, including unusual embedded/listener callers.
        current = threading.current_thread().ident
        threads = tuple(t for t in threads if _alive(t) and _identity(t) not in (None, current))
        while True:
            with self._lock:
                self._pending = deque(
                    living for group in self._pending if (living := tuple(t for t in group if _alive(t)))
                )
                known = {_identity(t) for group in self._pending for t in group}
                threads = tuple(t for t in threads if _alive(t) and _identity(t) not in known | {None})
                if not threads:
                    return
                if len(self._pending) < self.limit:
                    self._pending.append(threads)
                    return
                oldest = self._pending[0][0]
            # No pool/topology/budget lock is held while waiting. A short join
            # remains interruptible and allows concurrent close calls to reap.
            try:
                oldest.join(0.05)
            except (ReferenceError, RuntimeError):
                pass


def mongodb_monitor_threads(client: Any) -> tuple[Any, ...]:
    """Read the isolated PyMongo 4 sync adapter without opening any resources.

    This deliberately inspects only known driver classes/attributes. Embedded
    factories and AsyncMongoClient retain their existing close behavior. The
    private handles are only observed, never modified or used for network I/O.
    An unsupported layout falls back to the driver's ordinary close.
    """
    if not any(
        cls.__name__ == "MongoClient" and cls.__module__ in {"pymongo.mongo_client", "pymongo.synchronous.mongo_client"}
        for cls in type(client).__mro__
    ):
        return ()
    try:
        fields = vars(client)
        executors = [fields.get("_kill_cursors_executor")]
        topology = fields.get("_topology")
        if topology is not None:
            with topology._lock:
                monitors = [server._monitor for server in topology._servers.values()]
                if topology._srv_monitor is not None:
                    monitors.append(topology._srv_monitor)
                for monitor in monitors:
                    executors.append(monitor._executor)
                    rtt = vars(monitor).get("_rtt_monitor")
                    if rtt is not None:
                        executors.append(rtt._executor)
                executors.append(vars(topology).get("_Topology__events_executor"))
        return tuple(t for executor in executors if executor is not None and (t := executor._thread) is not None)
    except (AttributeError, TypeError, ReferenceError):
        return ()


MONGODB_RETIREMENTS = MongoRetirements()
