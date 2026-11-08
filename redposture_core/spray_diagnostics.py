"""Opt-in bounded spray diagnostics; credentials and destinations are not retained."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager

from .runtime_diagnostics import RuntimeDiagnostics


class SprayDiagnostics:
    """Keep detect-source capacity separate from credential worker capacity."""

    def __init__(self, emit: Callable[[str], None]) -> None:
        self.detect = RuntimeDiagnostics()
        self.work = RuntimeDiagnostics()
        self._emit = emit
        self.emit_errors = 0

    def _safe_emit(self, message: str) -> None:
        try:
            self._emit(message)
        except Exception:
            # A closed diagnostic stream must not cancel credential work.
            self.emit_errors += 1

    def _progress(self, work_line: str) -> None:
        self._safe_emit("spray work " + work_line)
        self._safe_emit("spray detect " + self.detect.progress_line())

    @contextmanager
    def reporting(self, *, targets: int, detect_limit: int, workers: int, interval: float = 1.0) -> Iterator[None]:
        self.work.configure(targets=targets, deep_workers=workers, max_inflight=workers * 2)
        self.detect.configure(targets=targets, detect_limit=detect_limit)
        self._safe_emit(f"spray worker profile: targets={targets} detect_limit={detect_limit} workers={workers}")
        try:
            # One reporter thread publishes both bounded observers.
            with self.work.reporting(self._progress, interval=interval):
                yield
        finally:
            for label, observer in (("detect", self.detect), ("work", self.work)):
                for line in observer.debug_lines():
                    self._safe_emit(f"spray {label} {line}")
