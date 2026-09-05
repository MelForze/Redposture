"""Colored console output helpers for module stages."""

from __future__ import annotations

import os
import sys
from typing import TextIO

from .progress import suspend_active_progress_for_output

_COLORS = {
    "blue": "1;94",
    "green": "1;92",
    "bright_green": "1;92",
    "orange": "1;38;5;208",
    "yellow": "1;93",
    "red": "1;91",
    # 256-color pure red (#ff0000): unlike ANSI bright-red (91), it is taken from
    # the 256-palette and is not remapped by a terminal theme, so it stays clearly
    # red next to the 256-color orange above (some themes render 91 orange-ish).
    "true_red": "1;38;5;196",
    "magenta": "1;95",
    "cyan": "1;96",
    "white": "1;97",
}

_FORCE_NO_COLOR = False


def set_console_no_color(enabled: bool) -> None:
    global _FORCE_NO_COLOR
    _FORCE_NO_COLOR = bool(enabled)


def is_console_no_color() -> bool:
    return _FORCE_NO_COLOR


def _env_present(name: str) -> bool:
    """True when ``name`` is set to a non-empty value (a presence flag)."""
    value = os.environ.get(name)
    return bool(value and value.strip())


def _env_truthy(name: str) -> bool:
    """True when ``name`` is set to anything other than a falsy token."""
    value = os.environ.get(name)
    return value is not None and value.strip().lower() not in {"", "0", "false", "no", "off"}


# D4 fix: cache the result for the default (stdout) path. `should_use_color`
# is called for every single log line emitted from listener storms, so its
# `os.environ.get` reads + `isatty()` syscall added up under load. Only the
# `stream is None` branch is cached — callers that pass explicit streams are
# rare (~test fixtures) and get the fully-recomputed value. Env changes during
# a run are exotic; the sentinel invalidates cache when they happen.
_DEFAULT_COLOR_CACHE: bool | None = None
_COLOR_CACHE_SENTINEL: tuple[str | None, str | None] | None = None


def _current_env_sentinel() -> tuple[str | None, str | None]:
    return (os.environ.get("NO_COLOR"), os.environ.get("FORCE_COLOR"))


def should_use_color(stream: TextIO | None = None) -> bool:
    """Whether ANSI color should be written to ``stream`` (default stdout).

    This is the shared environment/terminal policy: ``NO_COLOR`` disables color,
    ``FORCE_COLOR`` forces it on (pager, CI, tests), otherwise color is emitted
    only when the destination is a real terminal so redirected or piped output
    stays clean (matching the progress bar's gating). The ``--no-color`` flag is
    layered on by the callers (`Console._use_color` / `logger._paint`).
    """
    global _DEFAULT_COLOR_CACHE, _COLOR_CACHE_SENTINEL

    def _compute(target: TextIO) -> bool:
        if _env_present("NO_COLOR"):
            return False
        if _env_truthy("FORCE_COLOR"):
            return True
        try:
            return bool(target.isatty())
        except Exception:
            return False

    if stream is None:
        sentinel = _current_env_sentinel()
        if sentinel != _COLOR_CACHE_SENTINEL:
            _DEFAULT_COLOR_CACHE = None
            _COLOR_CACHE_SENTINEL = sentinel
        if _DEFAULT_COLOR_CACHE is None:
            _DEFAULT_COLOR_CACHE = _compute(sys.stdout)
        return _DEFAULT_COLOR_CACHE

    return _compute(stream)


def _reset_color_cache() -> None:
    """Test helper: forget the memoized should_use_color result."""
    global _DEFAULT_COLOR_CACHE, _COLOR_CACHE_SENTINEL
    _DEFAULT_COLOR_CACHE = None
    _COLOR_CACHE_SENTINEL = None


class Console:
    def __init__(
        self,
        debug: bool = False,
        *,
        no_color: bool | None = None,
        structured_output: bool = False,
    ) -> None:
        self.debug_enabled = debug
        self._no_color = _FORCE_NO_COLOR if no_color is None else bool(no_color)
        self.structured_output = bool(structured_output)

    def set_structured_output(self, enabled: bool) -> None:
        self.structured_output = bool(enabled)

    def _diagnostic_stream(self) -> TextIO:
        return sys.stderr if self.structured_output else sys.stdout

    def _use_color(self, stream: TextIO) -> bool:
        if self._no_color:
            return False
        return should_use_color(stream)

    def _paint(self, text: str, color: str, stream: TextIO) -> str:
        if not self._use_color(stream):
            return text
        code = _COLORS.get(color)
        if not code:
            return text
        return f"\x1b[{code}m{text}\x1b[0m"

    def _line(self, prefix: str, message: str, color: str, stream: TextIO) -> None:
        mark = self._paint(prefix, color, stream)
        with suspend_active_progress_for_output(stream):
            print(f"{mark} {message}", file=stream, flush=True)

    def plain(self, message: str, color: str | None = None, stream: TextIO | None = None) -> None:
        out = stream or sys.stdout
        with suspend_active_progress_for_output(out):
            if color:
                print(self._paint(message, color, out), file=out, flush=True)
                return
            print(message, file=out, flush=True)

    def render_tagged_payload_line(
        self,
        line: str,
        tag: str,
        *,
        payload_color: str = "white",
        stream: TextIO | None = None,
    ) -> bool:
        out = stream or sys.stdout
        if not line.startswith(tag):
            return False
        parts = line.split("\t", 3)
        if len(parts) < 4:
            return False

        left = parts[0]
        left_tail = left[len(tag) :] if left.startswith(tag) else left
        host = parts[1]
        port = parts[2]
        payload = parts[3]

        rendered = (
            self._paint(tag, "blue", out)
            + self._paint(left_tail, "white", out)
            + self._paint(f"\t{host}\t{port}\t", "white", out)
            + self._paint(payload, payload_color, out)
        )
        with suspend_active_progress_for_output(out):
            print(rendered, file=out, flush=True)
        return True

    def info(self, message: str) -> None:
        self._line("[*]", message, "blue", self._diagnostic_stream())

    def success(self, message: str) -> None:
        self._line("[+]", message, "green", self._diagnostic_stream())

    def warn(self, message: str) -> None:
        self._line("[-]", message, "yellow", self._diagnostic_stream())

    def error(self, message: str) -> None:
        self._line("[!]", message, "red", sys.stderr)

    def debug(self, message: str) -> None:
        if not self.debug_enabled:
            return
        self._line("[d]", message, "magenta", self._diagnostic_stream())
