"""TTY progress helpers for long-running module scans."""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from collections.abc import Iterator, Mapping
from concurrent.futures import Future, as_completed
from typing import Any, TextIO

_PROGRESS_BAR_WIDTH = 38
_NO_PROGRESS_ENV = "REDPOSTURE_NO_PROGRESS"
_ANSI_RESET = "\033[0m"
_ANSI_GREEN = "\033[32m"
_ANSI_CYAN = "\033[36m"
_ANSI_DIM = "\033[2m"
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


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
    ) -> None:
        self._label = str(label or "TASK").upper().strip() or "TASK"
        self._total = max(0, int(total))
        self._done = 0
        # Use stdout to avoid cross-stream progress/log interleaving artifacts.
        self._stream = stream or sys.stdout
        self._lock = threading.Lock()
        self._last_len = 0
        self._enabled = _progress_enabled(self._stream, enabled=enabled) and self._total > 0
        self._leave = bool(leave)
        self._started = time.monotonic()
        item_word = "target" if self._total == 1 else "targets"
        self._description = f"Running redposture against {self._total} {item_word}"

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

    def close(self) -> None:
        if not self._enabled:
            return
        with self._lock:
            if not self._leave:
                if self._last_len > 0:
                    self._stream.write("\r" + (" " * self._last_len) + "\r")
                    self._stream.flush()
                self._enabled = False
                return
            if self._done >= self._total and self._last_len > 0:
                self._stream.write("\n")
                self._stream.flush()
                self._enabled = False
                return
            self._done = self._total
            self._render(final=True)
            self._enabled = False

    def pause_for_output(self) -> None:
        """Temporarily clear the in-place progress row before normal log output."""
        if not self._enabled:
            return
        with self._lock:
            if self._last_len <= 0:
                return
            self._stream.write("\r" + (" " * self._last_len) + "\r")
            self._stream.flush()

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
