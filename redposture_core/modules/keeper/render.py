"""Render helpers for the ClickHouse Keeper audit module."""

from __future__ import annotations

from ...exporters.output import emit_line as _emit_line
from ..zookeeper.actions import (
    _format_detect_record,
    _format_record,
    _format_znodes_detail_records,
    _nxc_prefix,
    _render_colored_zookeeper_line,
)


def _render_colored_keeper_line(console, line: str) -> bool:
    return _render_colored_zookeeper_line(console, line)


__all__ = [
    "_nxc_prefix",
    "_emit_line",
    "_format_detect_record",
    "_format_record",
    "_format_znodes_detail_records",
    "_render_colored_keeper_line",
]
