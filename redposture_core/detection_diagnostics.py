"""Bounded detection diagnostics; never stores targets or credentials."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar


def fallback_category(reason: str) -> str:
    text = reason.lower()
    for category, words in (
        ("dns", ("resolver", "hostname", "numeric target", "scoped ipv6")),
        ("proxy", ("proxy", "proxied")),
        ("tls", ("tls", "ssl")),
        ("redirect", ("redirect",)),
        ("framing", ("framing", "chunk", "header", "encoding", "interim", "http status")),
        ("body_limit", ("full synchronous response", "response needs", "large", "truncated")),
        ("timeout", ("timeout", "timed out")),
        ("override", ("override", "factory", "helper", "cache")),
    ):
        if any(word in text for word in words):
            return category
    return "unsupported"


class FallbackDiagnostics:
    """Fixed category space and bounded module names, independent of target count.

    http_requests counts observed HTTP requests only, not native protocol frames.
    Native fallback time/count remain available when no HTTP client is involved."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rows: dict[tuple[str, str], dict[str, int]] = {}
        self._surface_rows: dict[tuple[str, str, str], dict[str, int]] = {}
        self._modules: set[str] = set()

    def record(
        self, module: str, reason: str, *, seconds: float = 0, requests: int = 0, surface: str | None = None
    ) -> None:
        self._add(
            module,
            fallback_category(reason),
            count=1,
            native_us=max(0, int(seconds * 1_000_000)),
            http_requests=requests,
            surface=surface,
        )

    def record_sync(self, module: str, seconds: float) -> None:
        self._add(module, "sync_work", count=1, worker_us=max(0, int(seconds * 1_000_000)))

    def _add(self, module: str, category: str, *, surface: str | None = None, **values: int) -> None:
        with self._lock:
            # Caller-provided labels must never turn a million URLs into keys.
            if module not in self._modules:
                if len(self._modules) >= 64 or len(module) > 64:
                    module = "other"
                self._modules.add(module)
            row = self._rows.setdefault(
                (module, category), {"count": 0, "native_us": 0, "http_requests": 0, "worker_us": 0}
            )
            for key, value in values.items():
                row[key] += max(0, int(value))
            if surface is not None:
                surface = surface if surface in {"backend", "ui", "mixed"} else "unspecified"
                detail = self._surface_rows.setdefault(
                    (module, category, surface), {"count": 0, "native_us": 0, "http_requests": 0}
                )
                for key in detail:
                    detail[key] += max(0, int(values.get(key, 0)))

    def snapshot(self) -> list[dict[str, str | int]]:
        with self._lock:
            return [
                {"module": module, "category": category, **row}
                for (module, category), row in sorted(self._rows.items())
            ]

    def debug_lines(self) -> Iterator[str]:
        for row in self.snapshot():
            yield "detect fallback summary: " + " ".join(f"{key}={value}" for key, value in row.items())
        for row in self.surface_snapshot():
            yield "detect fallback surface summary: " + " ".join(f"{key}={value}" for key, value in row.items())

    def surface_snapshot(self) -> list[dict[str, str | int]]:
        """Explicit surface attribution; sync-worker time remains aggregate."""
        with self._lock:
            return [
                {"module": module, "category": category, "surface": surface, **row}
                for (module, category, surface), row in sorted(self._surface_rows.items())
            ]

    def flat_stats(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for row in self.snapshot():
            for key in ("count", "native_us", "http_requests", "worker_us"):
                name = f"fallback_{row['category']}_{key}"
                result[name] = result.get(name, 0) + int(row[key])
        return result


_ACTIVE: ContextVar[FallbackDiagnostics | None] = ContextVar("detect_fallback_diagnostics", default=None)
_SYNC_MODULE: ContextVar[str | None] = ContextVar("detect_fallback_sync_module", default=None)


@contextmanager
def capture_fallbacks(observer: FallbackDiagnostics) -> Iterator[None]:
    token = _ACTIVE.set(observer)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def note_fallback(module: str, reason: str, *, seconds: float = 0, requests: int = 0) -> None:
    observer = _ACTIVE.get()
    if observer is not None:
        observer.record(module, reason, seconds=seconds, requests=requests)


@contextmanager
def sync_fallback(module: str | None) -> Iterator[None]:
    token = _SYNC_MODULE.set(module)
    try:
        yield
    finally:
        _SYNC_MODULE.reset(token)


@contextmanager
def measure_sync_detect() -> Iterator[None]:
    observer, module = _ACTIVE.get(), _SYNC_MODULE.get()
    started = time.monotonic() if observer is not None and module is not None else 0
    try:
        yield
    finally:
        if observer is not None and module is not None:
            observer.record_sync(module, time.monotonic() - started)
