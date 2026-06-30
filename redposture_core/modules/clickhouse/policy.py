"""Policy helpers for the clickhouse audit module."""

from __future__ import annotations

from typing import Any

from ...audit_config import AuditConfig
from ...stage_runtime import build_basic_audit_plan, validate_basic_module_args
from .actions import _normalize_column_names, _normalize_table_targets


def validate_args(args: Any, console: Any) -> int | None:
    cfg = AuditConfig.from_namespace(args)
    common_rc = validate_basic_module_args(args, console, module="clickhouse", pure_http=False)
    if common_rc is not None:
        return common_rc

    table_targets = _normalize_table_targets(list(getattr(args, "tables", None) or getattr(args, "table", None) or []))
    _columns, columns_error = _normalize_column_names(
        list(getattr(args, "columns", None) or getattr(args, "column", None) or [])
    )
    if columns_error:
        console.error(columns_error)
        return 2
    if bool(getattr(args, "show_columns", False)) and not table_targets:
        console.error("--show-columns requires --table")
        return 2
    if _columns and not table_targets:
        console.error("--column requires --table")
        return 2

    execute_command = str(getattr(args, "execute", "") or "").strip()
    sql_command = str(getattr(args, "sql_cmd", "") or "").strip()
    os_shell = bool(getattr(args, "os_shell", False))
    sql_shell = bool(getattr(args, "sql_shell", False))
    if execute_command and sql_command:
        console.error("--execute cannot be combined with --sql-cmd")
        return 2
    if os_shell and sql_shell:
        console.error("--os-shell cannot be combined with --sql-shell")
        return 2
    if os_shell and sql_command:
        console.error("--os-shell cannot be combined with --sql-cmd")
        return 2
    if os_shell and execute_command:
        console.error("--os-shell cannot be combined with --execute")
        return 2
    if sql_shell and execute_command:
        console.error("--sql-shell cannot be combined with --execute")
        return 2
    if sql_shell and sql_command:
        console.error("--sql-shell cannot be combined with --sql-cmd")
        return 2

    shell_flag = "--os-shell" if os_shell else "--sql-shell"
    if (os_shell or sql_shell) and cfg.output:
        console.error(f"{shell_flag} cannot be used with -o/--output")
        return 2
    if os_shell or sql_shell:
        if cfg.output_format != "txt":
            console.error(f"{shell_flag} requires --format txt")
            return 2
        try:
            plan = build_basic_audit_plan(args, default_port=9000)
        except ValueError as exc:
            console.error(str(exc))
            return 2
        try:
            plan.require_single_target_spec()
        except ValueError as exc:
            console.error(f"{shell_flag} {exc}")
            return 2
    return None


__all__ = ["validate_args"]
