"""Opt-in bounded pipeline measurements, independent of target cardinality.

Durations are summed service time, not elapsed run time: concurrent work can
sum to more than wall time. Histograms provide explicit percentile upper bounds
rather than claiming exact percentiles. Targets, values and credentials are
never retained in this observer.
"""

from __future__ import annotations

import functools
import math
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from typing import Any, ParamSpec, TypeVar

_PHASES = frozenset(
    {
        "detect_async",
        "detect_sync",
        "auth",
        "capabilities",
        "rce_probe",
        "data",
        "render",
        "write",
        "finish",
        "finish_wait",
        "queue_wait",
        "retry_wait",
    }
)
_QUEUES = frozenset(
    {"ready", "prepared", "deep_tasks", "results", "inflight", "children", "backoff", "detect_slots", "finish_wait"}
)
_CONFIG = frozenset({"detect_limit", "deep_workers", "max_inflight", "targets"})
_BUCKETS = 32


class RuntimeDiagnostics:
    def __init__(self, *, clock_ns: Callable[[], int] | None = None) -> None:
        self._clock = clock_ns or time.perf_counter_ns
        self._lock = threading.Lock()
        self._phases: dict[str, dict[str, Any]] = {}
        self._queues: dict[str, dict[str, int]] = {}
        self._configuration: dict[str, int] = {}
        self._report_errors = 0

    def configure(self, **values: int) -> None:
        with self._lock:
            for name, value in values.items():
                if name in _CONFIG:
                    self._configuration[name] = max(0, int(value))

    def queue(self, name: str, size: int) -> None:
        name = name if name in _QUEUES else "other"
        with self._lock:
            row = self._queues.setdefault(name, {"current": 0, "peak": 0})
            row["current"] = max(0, int(size))
            row["peak"] = max(row["peak"], row["current"])

    def adjust_queue(self, name: str, change: int) -> None:
        """Track overlapping waits without losing updates between threads."""
        name = name if name in _QUEUES else "other"
        with self._lock:
            row = self._queues.setdefault(name, {"current": 0, "peak": 0})
            row["current"] = max(0, row["current"] + change)
            row["peak"] = max(row["peak"], row["current"])

    def _phase(self, name: str) -> dict[str, Any]:
        row = self._phases.get(name)
        if row is None:
            row = {"calls": 0, "active": 0, "peak_active": 0, "total_ns": 0, "max_ns": 0, "histogram": [0] * _BUCKETS}
            self._phases[name] = row
        return row

    def duration(self, name: str, seconds: float) -> None:
        """Record an already measured wait without retaining its target."""
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("finite nonnegative duration required")
        name = name if name in _PHASES else "other"
        with self._lock:
            self._record(self._phase(name), int(seconds * 1_000_000_000))

    @staticmethod
    def _record(row: dict[str, Any], nanoseconds: int) -> None:
        row["calls"] += 1
        row["total_ns"] += nanoseconds
        row["max_ns"] = max(row["max_ns"], nanoseconds)
        microseconds = (nanoseconds + 999) // 1000
        bucket = min(_BUCKETS - 1, max(0, max(0, microseconds - 1).bit_length()))
        row["histogram"][bucket] += 1

    @contextmanager
    def measure(self, name: str) -> Iterator[None]:
        name = name if name in _PHASES else "other"
        with self._lock:
            row = self._phase(name)
            row["active"] += 1
            row["peak_active"] = max(row["peak_active"], row["active"])
        started = self._clock()
        try:
            yield
        finally:
            elapsed = max(0, self._clock() - started)
            with self._lock:
                row["active"] -= 1
                self._record(row, elapsed)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            phases: dict[str, Any] = {}
            for name, row in self._phases.items():
                summary = {key: value for key, value in row.items() if key != "histogram"}
                for percent in (50, 95, 99):
                    if not row["calls"]:
                        summary[f"p{percent}_upper_us"] = None
                        continue
                    required = (row["calls"] * percent + 99) // 100
                    cumulative = 0
                    for bucket, count in enumerate(row["histogram"]):
                        cumulative += count
                        if cumulative >= required:
                            summary[f"p{percent}_upper_us"] = max(
                                1 << bucket, (row["max_ns"] + 999) // 1000 if bucket == _BUCKETS - 1 else 0
                            )
                            break
                phases[name] = summary
            return {
                "configuration": dict(self._configuration),
                "phases": phases,
                "queues": {name: dict(row) for name, row in self._queues.items()},
                "report_errors": self._report_errors,
            }

    def progress_line(self) -> str:
        snapshot = self.snapshot()
        phases, queues = snapshot["phases"], snapshot["queues"]
        fields = {
            "detect_limit": snapshot["configuration"].get("detect_limit", 0),
            "deep_workers": snapshot["configuration"].get("deep_workers", 0),
            "detect_slots": queues.get("detect_slots", {}).get("current", 0),
            "auth_jobs": phases.get("auth", {}).get("active", 0),
            "rce_jobs": phases.get("rce_probe", {}).get("active", 0),
            "data_jobs": phases.get("data", {}).get("active", 0),
            "ready": queues.get("ready", {}).get("current", 0),
            "prepared": queues.get("prepared", {}).get("current", 0),
            "deep_queue": queues.get("deep_tasks", {}).get("current", 0),
            "inflight": queues.get("inflight", {}).get("current", 0),
            "backoff": queues.get("backoff", {}).get("current", 0),
            "finish_wait": queues.get("finish_wait", {}).get("current", 0),
        }
        return "runtime progress: " + " ".join(f"{key}={value}" for key, value in fields.items())

    @contextmanager
    def reporting(self, emit: Callable[[str], None] | None, *, interval: float = 1.0) -> Iterator[None]:
        """Publish progress even when no target has completed; debug only."""
        if emit is None:
            yield
            return
        if interval <= 0 or not math.isfinite(interval):
            raise ValueError("positive finite reporting interval required")
        stopped = threading.Event()

        def report() -> None:
            while not stopped.wait(interval):
                try:
                    emit(self.progress_line())
                except Exception:  # A diagnostic sink must not cancel an audit.
                    with self._lock:
                        self._report_errors += 1

        thread = threading.Thread(target=report, name="redposture-runtime-debug", daemon=True)
        thread.start()
        try:
            yield
        finally:
            stopped.set()
            thread.join(2)

    def debug_lines(self) -> Iterator[str]:
        snapshot = self.snapshot()
        if snapshot["configuration"]:
            yield "runtime limits: " + " ".join(f"{k}={v}" for k, v in sorted(snapshot["configuration"].items()))
        for name, row in sorted(snapshot["phases"].items()):
            yield (
                f"runtime phase={name} calls={row['calls']} active={row['active']} peak_active={row['peak_active']} "
                f"service_ms={row['total_ns'] / 1_000_000:.3f} p95_upper_us={row.get('p95_upper_us', 0)}"
            )
        for name, row in sorted(snapshot["queues"].items()):
            kind = "slots" if name == "detect_slots" else "queue"
            yield f"runtime {kind}={name} current={row['current']} peak={row['peak']}"


P = ParamSpec("P")
R = TypeVar("R")


def observe_phase(name: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Instrument a runner method only when its opt-in observer is present."""

    def decorate(function: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(function)
        def call(*args: P.args, **kwargs: P.kwargs) -> R:
            observer = getattr(args[0], "_runtime_stats", None)
            if observer is None:
                return function(*args, **kwargs)
            with observer.measure(name):
                return function(*args, **kwargs)

        return call

    return decorate


def observe_async_phase(name: str) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    def decorate(function: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
        @functools.wraps(function)
        async def call(*args: P.args, **kwargs: P.kwargs) -> R:
            observer = getattr(args[0], "_runtime_stats", None)
            if observer is None:
                return await function(*args, **kwargs)
            with observer.measure(name):
                return await function(*args, **kwargs)

        return call

    return decorate
