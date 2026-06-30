"""Render helpers for the consul audit module."""

from __future__ import annotations

from typing import Any

from .actions import (
    _auth_summary_line,
    _cx_prefix,
    _detail_lines,
    _detect_line,
    _render_colored_consul_line,
    _summary_line,
)


def _format_consul_detail_lines(record: dict[str, Any], output_format: str, *, debug: bool = False) -> list[str]:
    if output_format == "json":
        return []
    prefix = _cx_prefix(record)
    lines: list[str] = []
    for summary in (_summary_line(record), _auth_summary_line(record)):
        if summary:
            lines.append(f"{prefix} {summary}")
    lines.extend(_detail_lines(record, output_format, debug=debug))
    return lines


__all__ = [
    "_cx_prefix",
    "_detect_line",
    "_format_consul_detail_lines",
    "_render_colored_consul_line",
]
