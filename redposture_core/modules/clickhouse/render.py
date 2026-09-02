"""Render helpers for the clickhouse audit module."""

from __future__ import annotations

# Re-export the canonical emit_line helper (`exporters/output.py`) under the historical
# `_emit_line` name so callers (and tests) keep the same import surface, but the actual
# flush policy lives in one place instead of being duplicated per module.
from ...exporters.output import emit_line as _emit_line
from .actions import (
    _format_auth_attempt_detail_records,
    _format_database_fallback_detail_records,
    _format_databases_detail_records,
    _format_detect_record,
    _format_discover_detail_records,
    _format_execute_detail_records,
    _format_record,
    _format_sql_detail_records,
    _format_table_columns_detail_records,
    _format_table_dump_detail_records,
    _format_tables_detail_records,
    _nxc_prefix,
    _render_colored_clickhouse_line,
)

__all__ = [
    "_nxc_prefix",
    "_emit_line",
    "_format_detect_record",
    "_format_record",
    "_format_auth_attempt_detail_records",
    "_format_database_fallback_detail_records",
    "_format_databases_detail_records",
    "_format_tables_detail_records",
    "_format_table_columns_detail_records",
    "_format_table_dump_detail_records",
    "_format_execute_detail_records",
    "_format_discover_detail_records",
    "_format_sql_detail_records",
    "_render_colored_clickhouse_line",
]
