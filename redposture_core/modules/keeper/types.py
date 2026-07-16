"""Types used by the ClickHouse Keeper audit module."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any, Literal

from ...clients.zookeeper import ZkImplementationFingerprint


class KeeperFingerprintCache:
    """Per-command single-flight cache; sockets are never retained."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[tuple[Any, ...], ZkImplementationFingerprint] = {}
        self._pending: dict[tuple[Any, ...], threading.Event] = {}
        self._transports: dict[tuple[Any, ...], Literal["plaintext", "tls"]] = {}

    def get_transport(self, key: tuple[Any, ...]) -> Literal["plaintext", "tls"] | None:
        with self._lock:
            return self._transports.get(key)

    def remember_transport(
        self,
        key: tuple[Any, ...],
        transport: Literal["plaintext", "tls"],
    ) -> None:
        with self._lock:
            self._transports.setdefault(key, transport)

    def get_or_probe(
        self,
        key: tuple[Any, ...],
        probe: Callable[[], ZkImplementationFingerprint],
    ) -> ZkImplementationFingerprint:
        while True:
            with self._lock:
                cached = self._values.get(key)
                if cached is not None:
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
            return value
        finally:
            with self._lock:
                event = self._pending.pop(key, None)
                if event is not None:
                    event.set()


__all__ = ["KeeperFingerprintCache"]
