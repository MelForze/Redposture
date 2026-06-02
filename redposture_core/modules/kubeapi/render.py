"""Render helpers for the kubeapi audit module."""

from __future__ import annotations

from .actions import (
    _format_detail_records,
    _format_detect_record,
    _kxc_prefix,
    _render_colored_kubeapi_line,
    _status_summary_line,
)


def _format_record(record: dict, output_format: str) -> str:
    if output_format == "json":
        return ""
    summary = _status_summary_line(record)
    return f"{_kxc_prefix(record)} {summary}" if summary else ""


__all__ = [
    "_kxc_prefix",
    "_format_detect_record",
    "_format_record",
    "_format_detail_records",
    "_render_colored_kubeapi_line",
]
