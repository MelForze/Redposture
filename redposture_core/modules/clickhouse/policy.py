"""Policy helpers for the clickhouse audit module."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from ...audit_config import AuditConfig
from ...secret_detection import detector_names
from ...stage_runtime import build_basic_audit_plan, validate_basic_module_args
from .actions import _normalize_column_names, _normalize_table_targets


def validate_args(args: Any, console: Any) -> int | None:
    cfg = AuditConfig.from_namespace(args)
    common_rc = validate_basic_module_args(args, console, module="clickhouse", pure_http=False)
    if common_rc is not None:
        return common_rc
    explicit_protocol = getattr(args, "protocol", None)
    if (
        bool(getattr(args, "http", False))
        and bool(getattr(args, "_clickhouse_protocol_explicit", False))
        and explicit_protocol != "http"
    ):
        console.error("--http conflicts with --protocol native/auto")
        return 2
    if getattr(args, "tls_key", None) and not getattr(args, "tls_cert", None):
        console.error("--tls-key requires --tls-cert")
        return 2
    if any(getattr(args, name, None) for name in ("tls_ca", "tls_cert", "tls_key", "tls_server_name")) and not bool(
        getattr(args, "tls", False)
    ):
        console.error("ClickHouse TLS certificate options require --tls")
        return 2
    proxy = str(getattr(args, "proxy", "") or "").strip()
    if proxy:
        protocol = "http" if bool(getattr(args, "http", False)) else str(explicit_protocol or "native")
        if protocol != "http":
            console.error("ClickHouse native driver cannot guarantee --proxy routing; use --http or a tunnel")
            return 2
        if urlsplit(proxy).scheme.lower() not in {"http", "https"}:
            console.error("ClickHouse HTTP transport supports only http:// or https:// proxies")
            return 2

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
    discover_enabled = bool(getattr(args, "discover", False))
    if bool(getattr(args, "resume", False)) and not discover_enabled:
        console.error("--resume requires --discover")
        return 2
    if bool(getattr(args, "resume", False)) and not getattr(args, "checkpoint", None):
        console.error("--resume requires --checkpoint")
        return 2
    if getattr(args, "checkpoint", None) and not discover_enabled:
        console.error("--checkpoint requires --discover")
        return 2
    for name in (
        "discover_chunk_rows",
        "max_query_rows",
        "max_query_bytes",
        "max_query_memory",
        "discover_max_threads",
    ):
        if int(getattr(args, name, 1) or 0) <= 0:
            console.error(f"--{name.replace('_', '-')} must be greater than zero")
            return 2
    if float(getattr(args, "max_query_time", 1.0) or 0.0) <= 0:
        console.error("--max-query-time must be greater than zero")
        return 2
    selected_detectors = {item.strip() for item in str(getattr(args, "detectors", "") or "").split(",") if item.strip()}
    unknown_detectors = sorted(selected_detectors - set(detector_names()))
    if unknown_detectors:
        console.error(f"unknown ClickHouse detector(s): {','.join(unknown_detectors)}")
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
