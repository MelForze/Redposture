"""Render helpers for the gitlab audit module."""

from __future__ import annotations

from .actions import (
    _format_detail_records,
    _format_gitlab_text,
    _format_record,
    _nxc_prefix,
    _render_colored_gitlab_line,
)

__all__ = [
    "_nxc_prefix",
    "_format_gitlab_text",
    "_format_record",
    "_format_detail_records",
    "_render_colored_gitlab_line",
]
