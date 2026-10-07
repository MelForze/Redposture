"""Airflow-style terminal colors for credential-only spray rows."""

from __future__ import annotations

from .console import Console
from .rendering import render_module_marker_line


def render_spray_line(console: Console, line: str, *, tag: str, spans: list[tuple[int, int, str]]) -> bool:
    return render_module_marker_line(
        console,
        line,
        tag=tag,
        spans=spans,
        marker_colors={"[*]": "cyan", "[+]": "red", "[-]": "green", "[!]": "red"},
    )


__all__ = ["render_spray_line"]
