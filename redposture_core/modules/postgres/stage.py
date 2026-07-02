"""Runtime entrypoint for the postgres audit module."""

from __future__ import annotations

from typing import Any

from ...audit_config import AuditConfig
from ...console import Console
from ...show_limits import dump_flag_enabled, dump_flag_limit
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    has_username_password_credential_file,
)
from . import actions, policy, render

_DEFAULT_PORT = 5432
_DEFAULT_PORTS: tuple[int, ...] | None = (5432, 6432, 15432)


def build_postgres_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_postgres_spec(args: Any) -> ModuleAuditSpec:
    return ModuleAuditSpec(
        module="postgres",
        label="POSTGRES",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render_module=render,
        colorize=render._render_colored_postgres_line,
        # E3 opt-in: PostgreSQL `trust auth` (no password requested) means the
        # detect probe already logged in without any credential; the defcreds
        # loop can't improve on that and just adds round-trips.
        keep_anonymous_open_no_auth=True,
    )


def run_postgres_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
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
    if cfg.debug and not getattr(args, "debug_emit", None):
        args.debug_emit = console.info
    if cfg.debug:
        suffix = f" format={cfg.output_format}"
        if cfg.output:
            suffix += f" output={args.output}"
        console.info("postgres audit started:" + suffix)
    runner = AuditCommandRunner(args=args, spec=build_postgres_spec(args), logger=logger, console=console)
    try:
        result = runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process postgres output: {exc}")
        return 2
    if cfg.debug and result.detected_count == 0 and hasattr(console, "warn"):
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


def _force_single_default_port(args: Any) -> None:
    if getattr(args, "port", None) is None and getattr(args, "ports", None) is None:
        args.port = _DEFAULT_PORT


def _run_postgres_shell(args: Any, console: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    _force_single_default_port(args)
    try:
        plan = build_postgres_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    mode = "--os-shell" if bool(getattr(args, "os_shell", False)) else "--sql-shell"
    try:
        _idx, host, port, _target = plan.require_single_target_spec()
    except ValueError as exc:
        console.error(f"{mode} {exc}")
        return 2
    record = actions._audit_postgres_host(
        host=str(host),
        port=int(port),
        timeout=cfg.timeout,
        retries=cfg.retries,
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
            try:
                command = input("pg-os> ").strip()
            except (EOFError, KeyboardInterrupt):
                console.plain("")
                break
            if not command:
                continue
            if command.lower() in {"exit", "quit"}:
                break
            output, exec_error = actions._pg_execute_remote_command(
                host=str(host),
                port=int(port),
                timeout=cfg.timeout,
                retries=cfg.retries,
                username=username,
                password=password,
                database=database,
                command=command,
            )
            for line in output or []:
                console.plain(str(line))
            if exec_error:
                console.error(exec_error)
        return 0
    while True:
        try:
            query = input("pg-sql> ").strip()
        except (EOFError, KeyboardInterrupt):
            console.plain("")
            break
        if not query:
            continue
        if query.lower() in {"exit", "quit"}:
            break
        output, query_error = actions._pg_execute_sql_query(
            host=str(host),
            port=int(port),
            timeout=cfg.timeout,
            retries=cfg.retries,
            username=username,
            password=password,
            database=database,
            query=query,
        )
        for line in output or []:
            console.plain(str(line))
        if query_error:
            console.error(query_error)
    return 0
