"""Colored console output helpers for module stages."""

from __future__ import annotations

import sys
from typing import TextIO


_COLORS = {
    "blue": "1;94",
    "green": "1;92",
    "bright_green": "1;92",
    "orange": "1;38;5;208",
    "yellow": "1;93",
    "red": "1;91",
    "magenta": "1;95",
    "cyan": "1;96",
    "white": "1;97",
}


class Console:
    def __init__(self, debug: bool = False) -> None:
        self.debug_enabled = debug

    def _use_color(self, stream: TextIO) -> bool:
        return True

    def _paint(self, text: str, color: str, stream: TextIO) -> str:
        if not self._use_color(stream):
            return text
        code = _COLORS.get(color)
        if not code:
            return text
        return f"\x1b[{code}m{text}\x1b[0m"

    def _line(self, prefix: str, message: str, color: str, stream: TextIO) -> None:
        mark = self._paint(prefix, color, stream)
        print(f"{mark} {message}", file=stream, flush=True)

    def plain(self, message: str, color: str | None = None, stream: TextIO | None = None) -> None:
        out = stream or sys.stdout
        if color:
            print(self._paint(message, color, out), file=out, flush=True)
            return
        print(message, file=out, flush=True)

    def info(self, message: str) -> None:
        self._line("[*]", message, "blue", sys.stdout)

    def success(self, message: str) -> None:
        self._line("[+]", message, "green", sys.stdout)

    def warn(self, message: str) -> None:
        self._line("[-]", message, "yellow", sys.stdout)

    def error(self, message: str) -> None:
        self._line("[!]", message, "red", sys.stderr)

    def debug(self, message: str) -> None:
        if not self.debug_enabled:
            return
        self._line("[d]", message, "magenta", sys.stdout)
