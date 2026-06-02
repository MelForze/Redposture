"""Policy helpers for the postgres audit module."""

from __future__ import annotations

from typing import Any

from ...stage_runtime import validate_basic_module_args
from .actions import _pg_group_table_targets, _pg_normalize_column_names, _pg_split_csv_identifiers


def validate_args(args: Any, console: Any) -> int | None:
    common_rc = validate_basic_module_args(args, console, module="postgres", pure_http=False)
    if common_rc is not None:
        return common_rc
    table_targets = list(getattr(args, "tables", None) or getattr(args, "table", None) or [])
    normalized_tables, _grouped, table_error = _pg_group_table_targets(
        _pg_split_csv_identifiers([str(item) for item in table_targets]),
        getattr(args, "database", None),
    )
    if table_error:
        console.error(table_error)
        return 2
    columns, column_error = _pg_normalize_column_names(
        [str(item) for item in (getattr(args, "columns", None) or getattr(args, "column", None) or [])]
    )
    if column_error:
        console.error(column_error)
        return 2
    if bool(getattr(args, "show_columns", False)) and not normalized_tables:
        console.error("--show-columns requires --table")
        return 2
    if columns and not normalized_tables:
        console.error("--column requires --table")
        return 2

    execute_command = str(getattr(args, "execute", "") or "").strip()
    sql_command = str(getattr(args, "sql_cmd", "") or "").strip()
    os_read = str(getattr(args, "os_read", "") or "").strip()
    os_shell = bool(getattr(args, "os_shell", False))
    sql_shell = bool(getattr(args, "sql_shell", False))
    if execute_command and sql_command:
        console.error("--execute cannot be combined with --sql-cmd")
        return 2
    if execute_command and os_read:
        console.error("--execute cannot be combined with --os-read")
        return 2
    if os_read and sql_command:
        console.error("--os-read cannot be combined with --sql-cmd")
        return 2
    if os_shell and sql_shell:
        console.error("--os-shell cannot be combined with --sql-shell")
        return 2
    if os_shell and os_read:
        console.error("--os-shell cannot be combined with --os-read")
        return 2
    if sql_shell and os_read:
        console.error("--sql-shell cannot be combined with --os-read")
        return 2
    return None


__all__ = ["validate_args"]
