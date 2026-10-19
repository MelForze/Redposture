"""Render helpers for the postgres audit module."""

from __future__ import annotations

from .actions import (
    _format_credential_attempts_records,
    _format_databases_detail_records,
    _format_detect_record,
    _format_execute_detail_records,
    _format_os_read_detail_records,
    _format_privesc_detail_records,
    _format_record,
    _format_sql_detail_records,
    _format_table_columns_detail_records,
    _format_table_dump_detail_records,
    _format_table_row_count_detail_records,
    _format_tables_detail_records,
    _nxc_prefix,
    _render_colored_postgres_line,
)


def _format_grouped_table_detail_records(record: dict, output_format: str) -> list[str]:
    """Keep each table's bounded row sample beside its inventory entry."""
    table_lines = _format_tables_detail_records(record, output_format)
    dump_lines = _format_table_dump_detail_records(record, output_format)
    if output_format != "txt" or not table_lines or not dump_lines:
        return table_lines + dump_lines

    dumps = record.get("table_dumps")
    if not isinstance(dumps, list):
        return table_lines + dump_lines
    names = record.get("table_names")
    if not isinstance(names, list):
        return table_lines + dump_lines
    limit = record.get("show_tables_limit")
    displayed = names[:limit] if isinstance(limit, int) and not isinstance(limit, bool) else names
    lines = table_lines[:1]
    rendered: set[int] = set()
    dumps_by_table: dict[str, list[tuple[int, dict]]] = {}
    for index, item in enumerate(dumps):
        if isinstance(item, dict):
            dumps_by_table.setdefault(str(item.get("table") or ""), []).append((index, item))
    for table_line, name in zip(table_lines[1:], displayed, strict=False):
        lines.append(table_line)
        for index, item in dumps_by_table.get(str(name), []):
            if index not in rendered:
                lines.extend(_format_table_dump_detail_records({**record, "table_dumps": [item]}, output_format))
                rendered.add(index)
    remaining = [item for index, item in enumerate(dumps) if index not in rendered]
    if remaining:
        lines.extend(_format_table_dump_detail_records({**record, "table_dumps": remaining}, output_format))
    return lines


__all__ = [
    "_nxc_prefix",
    "_format_detect_record",
    "_format_databases_detail_records",
    "_format_grouped_table_detail_records",
    "_format_table_columns_detail_records",
    "_format_table_row_count_detail_records",
    "_format_execute_detail_records",
    "_format_sql_detail_records",
    "_format_os_read_detail_records",
    "_format_privesc_detail_records",
    "_format_credential_attempts_records",
    "_format_record",
    "_render_colored_postgres_line",
]
