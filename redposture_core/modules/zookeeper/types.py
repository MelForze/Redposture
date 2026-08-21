"""Canonical types used by the ZooKeeper-compatible audit engine."""

from __future__ import annotations

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
