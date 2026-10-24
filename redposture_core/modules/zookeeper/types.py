"""Canonical types used by the ZooKeeper-compatible audit engine."""

from __future__ import annotations

import asyncio
import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import Any, Literal

from ...clients.zookeeper import ZkImplementationFingerprint


class ZooKeeperFingerprintCache:
    """Bounded per-command LRU/single-flight cache; sockets are never retained."""

    def __init__(self, *, max_entries: int = 32) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._max_entries = int(max_entries)
        self._lock = threading.Lock()
        self._values: OrderedDict[tuple[Any, ...], ZkImplementationFingerprint] = OrderedDict()
        self._pending: dict[tuple[Any, ...], threading.Event] = {}
        self._transports: OrderedDict[tuple[Any, ...], Literal["plaintext", "tls"]] = OrderedDict()

    def _trim(self, values: OrderedDict[tuple[Any, ...], Any]) -> None:
        while len(values) > self._max_entries:
            values.popitem(last=False)

    def get_transport(self, key: tuple[Any, ...]) -> Literal["plaintext", "tls"] | None:
        with self._lock:
            transport = self._transports.get(key)
            if transport is not None:
                self._transports.move_to_end(key)
            return transport

    def remember_transport(
        self,
        key: tuple[Any, ...],
        transport: Literal["plaintext", "tls"],
    ) -> None:
        with self._lock:
            self._transports.setdefault(key, transport)
            self._transports.move_to_end(key)
            self._trim(self._transports)

    async def get_or_probe_async(self, key: tuple[Any, ...], probe: Any) -> ZkImplementationFingerprint:
        """Share the sync LRU without ever waiting on threading.Event on-loop."""
        loop = asyncio.get_running_loop()
        while True:
            with self._lock:
                cached = self._values.get(key)
                if cached is not None:
                    self._values.move_to_end(key)
                    return cached
                pending = self._pending.get(key)
                async_pending = getattr(self, "_async_pending", None)
                if async_pending is None:
                    self._async_pending = async_pending = {}
                if pending is None:
                    pending = threading.Event()
                    self._pending[key] = pending
                    future = loop.create_future()
                    async_pending[key] = (loop, future)
                    owner = True
                else:
                    owner = False
                    existing = async_pending.get(key)
            if owner:
                break
            if existing is not None and existing[0] is loop:
                await asyncio.shield(existing[1])
            else:
                # A synchronous owner (or another event loop) can publish at
                # any time. Poll its bounded lookup without blocking this loop.
                await asyncio.sleep(0.01)
        try:
            value = await probe()
            with self._lock:
                self._values[key] = value
                self._values.move_to_end(key)
                self._trim(self._values)
            return value
        finally:
            with self._lock:
                self._pending.pop(key, None)
                async_pending.pop(key, None)
                pending.set()
                if not future.done():
                    # Waiters re-check the LRU after an owner failure too;
                    # no unobserved Future exception remains on cancellation.
                    future.set_result(None)

    def get_or_probe(
        self,
        key: tuple[Any, ...],
        probe: Callable[[], ZkImplementationFingerprint],
    ) -> ZkImplementationFingerprint:
        while True:
            with self._lock:
                cached = self._values.get(key)
                if cached is not None:
                    self._values.move_to_end(key)
                    return cached
                pending = self._pending.get(key)
                if pending is None:
                    pending = threading.Event()
                    self._pending[key] = pending
                    owner = True
                else:
                    owner = False
            if owner:
                break
            pending.wait()

        try:
            value = probe()
            with self._lock:
                self._values[key] = value
                self._values.move_to_end(key)
                self._trim(self._values)
            return value
        finally:
            with self._lock:
                event = self._pending.pop(key, None)
                if event is not None:
                    event.set()


__all__ = ["ZooKeeperFingerprintCache"]
