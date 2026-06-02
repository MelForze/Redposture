"""Render helpers for the zookeeper audit module."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .actions import (
    _format_detect_record,
    _format_record,
    _format_znodes_detail_records,
    _nxc_prefix,
    _render_colored_zookeeper_line,
)


def _emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(str(line) + "\n")
    if emit_line is not None:
        emit_line(str(line))


__all__ = [
    "_nxc_prefix",
    "_emit_line",
    "_format_detect_record",
    "_format_record",
    "_format_znodes_detail_records",
    "_render_colored_zookeeper_line",
]
