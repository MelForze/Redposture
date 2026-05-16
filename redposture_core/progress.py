"""TTY progress helpers for long-running module scans."""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from collections.abc import Iterator, Mapping
from concurrent.futures import Future, as_completed
from contextlib import contextmanager
from typing import Any, Protocol, TextIO

_PROGRESS_BAR_WIDTH = 38
_NO_PROGRESS_ENV = "REDPOSTURE_NO_PROGRESS"
_ANSI_RESET = "\033[0m"
_ANSI_GREEN = "\033[32m"
_ANSI_CYAN = "\033[36m"
_ANSI_DIM = "\033[2m"
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_ACTIVE_PROGRESS_LOCK = threading.Lock()
_ACTIVE_PROGRESS_BY_STREAM: dict[int, ProgressBar] = {}


def _progress_enabled(stream: TextIO, *, enabled: bool) -> bool:
    if not enabled:
        return False
    disabled = str(os.getenv(_NO_PROGRESS_ENV, "")).strip().lower()
    if disabled in {"1", "true", "yes", "on"}:
        return False
    try:
        return bool(stream.isatty())
    except Exception:
        return False


class ProgressBar:
    """Simple carriage-return progress bar rendered to stdout."""

    def __init__(
        self,
        label: str,
        total: int,
        *,
        enabled: bool = True,
        stream: TextIO | None = None,
        leave: bool = True,
        allow_nested: bool = False,
    ) -> None:
        self._label = str(label or "TASK").upper().strip() or "TASK"
        self._total = max(0, int(total))
        self._done = 0
        # Use stdout to avoid cross-stream progress/log interleaving artifacts.
        self._stream = stream or sys.stdout
        self._lock = threading.RLock()
        self._last_len = 0
        nested_progress_active = _active_progress_for_stream(self._stream) is not None
        self._enabled = (
            _progress_enabled(self._stream, enabled=enabled)
            and self._total > 0
            and (bool(allow_nested) or not nested_progress_active)
        )
        self._leave = bool(leave)
        self._started = time.monotonic()
        self._resume_after_output_pending = False
        item_word = "target" if self._total == 1 else "targets"
        self._description = f"Running redposture against {self._total} {item_word}"
        self._register_active_progress()

    def _register_active_progress(self) -> None:
        if not self._enabled:
            return
        with _ACTIVE_PROGRESS_LOCK:
            _ACTIVE_PROGRESS_BY_STREAM[id(self._stream)] = self

    def _unregister_active_progress(self) -> None:
        with _ACTIVE_PROGRESS_LOCK:
            key = id(self._stream)
            current = _ACTIVE_PROGRESS_BY_STREAM.get(key)
            if current is self:
                _ACTIVE_PROGRESS_BY_STREAM.pop(key, None)

    def advance(self, step: int = 1) -> None:
        if not self._enabled:
            return
        inc = max(0, int(step))
        if inc <= 0:
            return
        with self._lock:
            self._done = min(self._total, self._done + inc)
            if not self._leave and self._done >= self._total:
                return
            self._render()

    def set_total(self, total: int) -> None:
        """Adjust progress total while preserving current done counter."""
        new_total = max(0, int(total))
        if not self._enabled:
            self._total = max(self._done, new_total)
            return
        with self._lock:
            self._total = max(self._done, new_total)
            if not self._leave and self._done >= self._total:
                return
            self._render()

    def close(self) -> None:
        if not self._enabled:
            self._unregister_active_progress()
            return
        with self._lock:
            if not self._leave:
                if self._last_len > 0:
                    self._stream.write("\r" + (" " * self._last_len) + "\r")
                    self._stream.flush()
                self._enabled = False
            elif self._done >= self._total and self._last_len > 0:
                self._stream.write("\n")
                self._stream.flush()
                self._enabled = False
            else:
                self._done = self._total
                self._render(final=True)
                self._enabled = False
        self._unregister_active_progress()

    def pause_for_output(self) -> None:
        """Temporarily clear the in-place progress row before normal log output."""
        if not self._enabled:
            return
        with self._lock:
            self._pause_for_output_locked()

    def resume_after_output(self) -> None:
        """Re-render in-place progress row after normal log output."""
        if not self._enabled:
            return
        with self._lock:
            self._resume_after_output_locked()

    def begin_output(self) -> bool:
        """Pause progress row and hold lock across external output writes."""
        if not self._enabled:
            return False
        self._lock.acquire()
        self._resume_after_output_pending = self._last_len > 0
        if self._resume_after_output_pending:
            self._pause_for_output_locked()
        return True

    def end_output(self) -> None:
        """Resume progress row and release lock after external output writes."""
        try:
            if self._enabled and self._resume_after_output_pending:
                self._resume_after_output_locked()
        finally:
            self._resume_after_output_pending = False
            self._lock.release()

    def _pause_for_output_locked(self) -> None:
        if self._last_len <= 0:
            return
        self._stream.write("\r" + (" " * self._last_len) + "\r")
        self._stream.flush()

    def _resume_after_output_locked(self) -> None:
        if not self._leave and self._done >= self._total:
            return
        self._render()

    @staticmethod
    def _format_eta(seconds: float | None) -> str:
        if seconds is None:
            return "-:--:--"
        total = max(0, int(seconds))
        hours, rem = divmod(total, 3600)
        minutes, secs = divmod(rem, 60)
        return f"{hours:d}:{minutes:02d}:{secs:02d}"

    def _line(self) -> str:
        ratio = 1.0 if self._total <= 0 else (self._done / self._total)
        percent = int(round(ratio * 100))
        fill = int(ratio * _PROGRESS_BAR_WIDTH)
        if self._done > 0 and fill <= 0:
            fill = 1
        fill = max(0, min(_PROGRESS_BAR_WIDTH, fill))

        if fill <= 0:
            complete_segment = ""
            marker_segment = ""
            remaining_segment = "━" * _PROGRESS_BAR_WIDTH
        elif fill >= _PROGRESS_BAR_WIDTH:
            complete_segment = "━" * _PROGRESS_BAR_WIDTH
            marker_segment = ""
            remaining_segment = ""
        else:
            complete_segment = "━" * max(0, fill - 1)
            marker_segment = "╸"
            remaining_segment = "━" * (_PROGRESS_BAR_WIDTH - fill)

        bar = f"{_ANSI_CYAN}{complete_segment}{marker_segment}{_ANSI_RESET}{_ANSI_DIM}{remaining_segment}{_ANSI_RESET}"

        elapsed = max(0.0, time.monotonic() - self._started)
        rate = (self._done / elapsed) if elapsed > 0 else 0.0
        if self._done >= self._total:
            remaining: float | None = 0.0
        elif rate > 0:
            remaining = (self._total - self._done) / rate
        else:
            remaining = None
        eta_text = self._format_eta(remaining)

        return f"{_ANSI_GREEN}{self._description}{_ANSI_RESET} {bar} {percent:3d}% {eta_text}"

    @staticmethod
    def _visible_len(line: str) -> int:
        return len(_ANSI_RE.sub("", line))

    def _render(self, *, final: bool = False) -> None:
        line = self._line()
        visible_len = self._visible_len(line)
        pad = ""
        if self._last_len > visible_len:
            pad = " " * (self._last_len - visible_len)
        self._stream.write("\r" + line + pad)
        if final:
            self._stream.write("\n")
        self._stream.flush()
        self._last_len = visible_len


class ProgressHandle(Protocol):
    def advance(self, step: int = 1) -> None: ...

    def set_total(self, total: int) -> None: ...

    def pause_for_output(self) -> None: ...

    def close(self) -> None: ...


class NoOpProgress:
    """Progress-compatible handle used when command-level progress is disabled."""

    def advance(self, step: int = 1) -> None:
        return None

    def set_total(self, total: int) -> None:
        return None

    def pause_for_output(self) -> None:
        return None

    def close(self) -> None:
        return None


class CommandProgressOwner:
    """Single owner for progress bars during one CLI command execution."""

    def __init__(self, *, enabled: bool = True, stream: TextIO | None = None) -> None:
        self._enabled = bool(enabled)
        self._stream = stream
        self._active: ProgressHandle | None = None
        self._closed = False

    def start(self, label: str, total: int, *, enabled: bool = True, leave: bool = True) -> ProgressHandle:
        if self._closed or not self._enabled or not enabled or int(total) <= 0:
            return NoOpProgress()
        if self._active is not None:
            self._active.close()
        self._active = ProgressBar(label, int(total), enabled=True, stream=self._stream, leave=leave)
        return self._active

    def close(self) -> None:
        if self._closed:
            return
        if self._active is not None:
            self._active.close()
            self._active = None
        self._closed = True


def iter_completed_with_progress(
    future_map: Mapping[Future[Any], Any], *, label: str, enabled: bool = True, leave: bool = True
) -> Iterator[Future[Any]]:
    """Yield futures as they complete and update a TTY progress bar."""
    progress = ProgressBar(label, len(future_map), enabled=enabled, leave=leave)
    try:
        for future in as_completed(future_map):
            progress.pause_for_output()
            yield future
            progress.advance()
    finally:
        progress.close()


def _active_progress_for_stream(stream: TextIO) -> ProgressBar | None:
    with _ACTIVE_PROGRESS_LOCK:
        candidate = _ACTIVE_PROGRESS_BY_STREAM.get(id(stream))
    if candidate is None or not candidate._enabled:
        return None
    return candidate


@contextmanager
def suspend_active_progress_for_output(stream: TextIO) -> Iterator[None]:
    progress = _active_progress_for_stream(stream)
    locked = progress.begin_output() if progress is not None else False
    try:
        yield
    finally:
        if progress is not None and locked:
            progress.end_output()
