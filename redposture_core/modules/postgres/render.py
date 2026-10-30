"""Render helpers for the postgres audit module."""

from __future__ import annotations

import tempfile
from pathlib import Path

from ...discovery_values import DiskBackedText
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
    if record.get("_postgres_dump_streamed"):
        return table_lines
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


def spool_table_dump_details(record: dict) -> str:
    """Keep explicit discovery dump values out of the formatter's line list."""
    escapes = {index: f"\\u{index:04x}" for index in range(32)}
    escapes.update({9: "\\t", 10: "\\n", 13: "\\r"})
    prefix = _nxc_prefix(record)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="redposture-pg-dump-", delete=False) as output:
        path = output.name
        try:
            for item in record.get("table_dumps") or []:
                if not isinstance(item, dict):
                    continue
                rows = item.get("rows") or []
                metadata = {**record, "table_dumps": [{**item, "rows": []}]}
                for line in _format_table_dump_detail_records(metadata, "txt"):
                    if rows and line.endswith(" <no rows>"):
                        continue
                    output.write(line + "\n")
                if item.get("error"):
                    continue
                for row in rows:
                    output.write(prefix + " ")
                    chunks = row.iter_text_chunks() if isinstance(row, DiskBackedText) else (str(row),)
                    for chunk in chunks:
                        output.write(chunk.translate(escapes))
                    output.write("\n")
        except BaseException:
            Path(path).unlink(missing_ok=True)
            raise
    return path


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
