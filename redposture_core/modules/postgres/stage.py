"""Runtime entrypoint for the postgres audit module."""

from __future__ import annotations

from typing import Any

from ...audit_models import AuditRecord
from ...console import Console
from ...show_limits import dump_flag_enabled, dump_flag_limit
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    has_username_password_credential_file,
    render_record_with_module,
)
from . import actions, policy, render

_DEFAULT_PORT = 5432
_DEFAULT_PORTS = None


def _dummy_detect(host: str, port: int) -> AuditRecord:
    return AuditRecord(
        host=str(host),
        port=int(port),
        service="postgres",
        status="not_run",
        module="postgres",
    )


def build_postgres_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_postgres_spec(args: Any) -> ModuleAuditSpec:
    def _render(record: dict[str, Any]) -> list[str]:
        return render_record_with_module(
            render,
            record,
            str(getattr(args, "output_format", "txt") or "txt"),
            debug=bool(getattr(args, "debug", False)),
        )

    return ModuleAuditSpec(
        module="postgres",
        label="POSTGRES",
        default_port=_DEFAULT_PORT,
        detect=_dummy_detect,
        detect_context=actions.host_hook,
        render=_render,
    )


def run_postgres_stage(args: Any, logger: Any) -> int:
    console = Console(debug=bool(getattr(args, "debug", False)))
    if getattr(args, "password", None) is not None and getattr(args, "username", None) is None:
        args.username = "postgres"
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    _normalize_postgres_action_args(args)
    if not has_username_password_credential_file(args) and not (
        getattr(args, "username", None) is not None and getattr(args, "password", None) is None
    ):
        args._audit_credential_runs = tuple(
            AuditCredentialRun(username=user, password=password, source="default" if is_default else "provided")
            for user, password, is_default in actions._postgres_credential_runs(
                getattr(args, "username", None),
                getattr(args, "password", None),
                defcreds=bool(getattr(args, "defcreds", False)),
            )
        )
    if bool(getattr(args, "os_shell", False)) or bool(getattr(args, "sql_shell", False)):
        return _run_postgres_shell(args, console)
    try:
        plan = build_postgres_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if bool(getattr(args, "debug", False)) and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if bool(getattr(args, "debug", False)):
        suffix = f" format={getattr(args, 'output_format', 'txt') or 'txt'}"
        if getattr(args, "output", None):
            suffix += f" output={args.output}"
        console.info("postgres audit started:" + suffix)
    runner = AuditCommandRunner(args=args, spec=build_postgres_spec(args), logger=logger, emit_line=console.plain)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process postgres output: {exc}")
        return 2
    if result.detected_count == 0 and hasattr(console, "warn"):
        console.warn("all postgres targets are unreachable")
    return 0


__all__ = ["build_postgres_plan", "build_postgres_spec", "run_postgres_stage"]


def _normalize_postgres_action_args(args: Any) -> None:
    table_values = actions._pg_split_csv_identifiers(
        [str(item) for item in (getattr(args, "tables", None) or getattr(args, "table", None) or [])]
    )
    normalized_tables, grouped_tables, _table_error = actions._pg_group_table_targets(
        table_values,
        getattr(args, "database", None),
    )
    columns, _column_error = actions._pg_normalize_column_names(
        [str(item) for item in (getattr(args, "columns", None) or getattr(args, "column", None) or [])]
    )
    args.table_targets = normalized_tables
    args.table_targets_by_database = grouped_tables
    args.table_columns = columns
    args.show_row_counts = bool(getattr(args, "rows", False) or getattr(args, "show_row_counts", False))
    args.dump_table_rows = dump_flag_enabled(getattr(args, "dump", False))
    args.dump_row_limit = dump_flag_limit(getattr(args, "dump", None))


def _run_postgres_shell(args: Any, console: Any) -> int:
    try:
        plan = build_postgres_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if plan.target_count != 1:
        mode = "--os-shell" if bool(getattr(args, "os_shell", False)) else "--sql-shell"
        console.error(f"{mode} requires exactly one target host")
        return 2
    _idx, host, port, _target = plan.iter_target_specs()[0]
    record = actions._audit_postgres_host(
        host=str(host),
        port=int(port),
        timeout=float(getattr(args, "timeout", 5.0) or 5.0),
        retries=int(getattr(args, "retries", 0) or 0),
        username=getattr(args, "username", None),
        password=getattr(args, "password", None),
        defcreds=bool(getattr(args, "defcreds", False)),
        database=str(getattr(args, "database", "postgres") or "postgres"),
        show_databases=False,
        show_tables=False,
        show_row_counts=False,
        show_columns=False,
        table_targets=[],
        table_targets_by_database={},
        table_columns=[],
        dump_table_rows=False,
        dump_row_limit=None,
        execute_command=None,
        sql_command=None,
    )
    if not bool(record.get("is_postgres")) or str(record.get("status") or "") in {"auth_required", "fail"}:
        return 1
    username = str(record.get("effective_username") or getattr(args, "username", None) or "postgres")
    password = getattr(args, "password", None)
    database = str(getattr(args, "database", "postgres") or "postgres")
    if bool(getattr(args, "os_shell", False)):
        while True:
            command = input("pg-os> ").strip()
            if not command:
                continue
            if command.lower() in {"exit", "quit"}:
                break
            actions._pg_execute_remote_command(
                host=str(host),
                port=int(port),
                timeout=float(getattr(args, "timeout", 5.0) or 5.0),
                retries=int(getattr(args, "retries", 0) or 0),
                username=username,
                password=password,
                database=database,
                command=command,
            )
        return 0
    while True:
        query = input("pg-sql> ").strip()
        if not query:
            continue
        if query.lower() in {"exit", "quit"}:
            break
        actions._pg_execute_sql_query(
            host=str(host),
            port=int(port),
            timeout=float(getattr(args, "timeout", 5.0) or 5.0),
            retries=int(getattr(args, "retries", 0) or 0),
            username=username,
            password=password,
            database=database,
            query=query,
        )
    return 0
