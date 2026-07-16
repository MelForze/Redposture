"""Runtime entrypoint for the postgres audit module."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...show_limits import dump_flag_enabled, dump_flag_limit, show_flag_enabled, show_flag_limit
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    AuditHookContext,
    ModuleAuditSpec,
    build_basic_audit_plan,
    has_username_password_credential_file,
)
from . import actions, policy, render

_DEFAULT_PORT = 5432
_DEFAULT_PORTS: tuple[int, ...] | None = (5432, 6432, 15432)
_POSTGRES_HOST_STAGE = actions.host_stage
_POSTGRES_HOST_STAGE_NAME = actions.host_stage.__name__
_POSTGRES_HOST_STAGE_IMPL = getattr(actions, _POSTGRES_HOST_STAGE_NAME, actions.host_stage)
_POSTGRES_AUDIT_HOST_IMPL = actions._audit_postgres_host


@dataclass
class _PostgresLifecycleState:
    detect_record: AuditRecord | None = None
    deep_records: dict[tuple[str | None, str | None, str], AuditRecord] = field(default_factory=dict)


def build_postgres_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def _postgres_credential_key(ctx: AuditHookContext) -> tuple[str | None, str | None, str]:
    credential = ctx.credential
    return credential.username, credential.password, credential.source


def _postgres_lifecycle_state_factory(_ctx: AuditHookContext) -> _PostgresLifecycleState:
    return _PostgresLifecycleState()


def _postgres_record(payload: AuditRecord | dict[str, Any]) -> AuditRecord:
    if isinstance(payload, AuditRecord):
        return payload
    return AuditRecord.from_mapping(dict(payload), module="postgres", service="postgres")


def _resolved_postgres_host_stage() -> Any:
    if actions.host_stage is not _POSTGRES_HOST_STAGE:
        return actions.host_stage
    return getattr(actions, _POSTGRES_HOST_STAGE_NAME, actions.host_stage)


def _postgres_host_stage_is_replaced() -> bool:
    return (
        _resolved_postgres_host_stage() is not _POSTGRES_HOST_STAGE_IMPL
        or actions._audit_postgres_host is not _POSTGRES_AUDIT_HOST_IMPL
    )


def _postgres_detect(ctx: AuditHookContext) -> AuditRecord:
    """Classify PostgreSQL with one anonymous startup and no capability queries."""

    if _postgres_host_stage_is_replaced():
        record = _postgres_run_host_stage(ctx, run_deep_checks=False, username=None, password=None, source="anonymous")
        if isinstance(ctx.lifecycle_state, _PostgresLifecycleState):
            ctx.lifecycle_state.detect_record = record
        return record

    cfg = AuditConfig.from_namespace(ctx.args)
    target_database = str(getattr(ctx.args, "database", "") or "").strip() or "postgres"
    attempts = max(1, cfg.retries + 1)
    started = time.monotonic()
    last_error: str | None = None

    for attempt in range(attempts):
        try:
            with actions.socket.create_connection((ctx.host, ctx.port), timeout=cfg.timeout) as sock:
                sock.settimeout(cfg.timeout)
                try:
                    session = actions._pg_startup_and_auth(
                        sock,
                        username="postgres",
                        password=None,
                        database=target_database,
                    )
                finally:
                    try:
                        actions._pg_send_terminate(sock)
                    except Exception:
                        pass
            payload = {
                "timestamp": actions.utc_now_iso(),
                "host": ctx.host,
                "port": ctx.port,
                "service": "postgres",
                "module": "postgres",
                "database": target_database,
                "auth_database": target_database,
                "is_postgres": True,
                "status": "open_no_auth",
                "auth_required": session.auth_required,
                "auth_method": session.auth_method,
                "server_version": session.server_version,
                "provided_credentials": False,
                "defcreds_enabled": False,
                "effective_username": "postgres",
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": None,
            }
            record = _postgres_record(payload)
            if isinstance(ctx.lifecycle_state, _PostgresLifecycleState):
                ctx.lifecycle_state.detect_record = record
            return record
        except actions._PgAuditError as exc:
            status = (
                "auth_required"
                if exc.detected and exc.auth_required is True
                else ("unknown_auth" if exc.detected else "fail")
            )
            payload = {
                "timestamp": actions.utc_now_iso(),
                "host": ctx.host,
                "port": ctx.port,
                "service": "postgres",
                "module": "postgres",
                "database": target_database,
                "auth_database": target_database,
                "is_postgres": bool(exc.detected),
                "status": status,
                "auth_required": True if status == "auth_required" else exc.auth_required,
                "auth_method": exc.auth_method,
                "sqlstate": exc.sqlstate,
                "failure_phase": exc.failure_phase or ("startup" if exc.detected else "connect"),
                "error_kind": exc.error_kind or ("startup_rejected" if exc.detected else "connection_error"),
                "provided_credentials": False,
                "defcreds_enabled": False,
                "effective_username": "postgres",
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": str(exc),
            }
            record = _postgres_record(payload)
            if isinstance(ctx.lifecycle_state, _PostgresLifecycleState):
                ctx.lifecycle_state.detect_record = record
            return record
        except (OSError, ValueError, ConnectionError) as exc:
            last_error = str(exc)
            if attempt < attempts - 1:
                time.sleep(actions._retry_delay(attempt))

    record = _postgres_record(
        {
            "timestamp": actions.utc_now_iso(),
            "host": ctx.host,
            "port": ctx.port,
            "service": "postgres",
            "module": "postgres",
            "database": target_database,
            "auth_database": target_database,
            "is_postgres": False,
            "status": "fail",
            "auth_required": None,
            "provided_credentials": False,
            "defcreds_enabled": False,
            "effective_username": "postgres",
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": last_error or "connection failed",
        }
    )
    if isinstance(ctx.lifecycle_state, _PostgresLifecycleState):
        ctx.lifecycle_state.detect_record = record
    return record


def _postgres_run_host_stage(
    ctx: AuditHookContext,
    *,
    run_deep_checks: bool,
    username: str | None,
    password: str | None,
    source: str,
) -> AuditRecord:
    cfg = AuditConfig.from_namespace(ctx.args)
    record = _resolved_postgres_host_stage()(
        host=ctx.host,
        port=ctx.port,
        timeout=cfg.timeout,
        retries=cfg.retries,
        username=username,
        password=password,
        defcreds=source == "default",
        database=str(getattr(ctx.args, "database", "") or "").strip() or None,
        show_databases=run_deep_checks and show_flag_enabled(getattr(ctx.args, "show_databases", False)),
        show_tables=run_deep_checks and show_flag_enabled(getattr(ctx.args, "show_tables", False)),
        show_row_counts=run_deep_checks and bool(getattr(ctx.args, "show_row_counts", False)),
        show_columns=run_deep_checks and show_flag_enabled(getattr(ctx.args, "show_columns", False)),
        table_targets=list(getattr(ctx.args, "table_targets", []) or []) if run_deep_checks else [],
        table_targets_by_database=(
            dict(getattr(ctx.args, "table_targets_by_database", {}) or {}) if run_deep_checks else {}
        ),
        table_columns=list(getattr(ctx.args, "table_columns", []) or []) if run_deep_checks else [],
        dump_table_rows=run_deep_checks and bool(getattr(ctx.args, "dump_table_rows", False)),
        dump_row_limit=getattr(ctx.args, "dump_row_limit", None) if run_deep_checks else None,
        execute_command=str(getattr(ctx.args, "execute", "") or "").strip() or None if run_deep_checks else None,
        sql_command=str(getattr(ctx.args, "sql_cmd", "") or "").strip() or None if run_deep_checks else None,
        os_read_path=str(getattr(ctx.args, "os_read", "") or "").strip() or None if run_deep_checks else None,
        privesc_check=run_deep_checks and bool(getattr(ctx.args, "privesc_check", False)),
        show_databases_limit=(show_flag_limit(getattr(ctx.args, "show_databases", False)) if run_deep_checks else None),
        show_tables_limit=show_flag_limit(getattr(ctx.args, "show_tables", False)) if run_deep_checks else None,
        show_columns_limit=show_flag_limit(getattr(ctx.args, "show_columns", False)) if run_deep_checks else None,
        run_deep_checks=run_deep_checks,
        debug=cfg.debug,
        debug_emit=ctx.debug_emit,
    )
    return _postgres_record(record)


def _postgres_auth(ctx: AuditHookContext, _detect_record: AuditRecord) -> AuditRecord:
    record = _postgres_run_host_stage(
        ctx,
        run_deep_checks=True,
        username=ctx.credential.username,
        password=ctx.credential.password,
        source=ctx.credential.source,
    )
    if isinstance(ctx.lifecycle_state, _PostgresLifecycleState):
        ctx.lifecycle_state.deep_records[_postgres_credential_key(ctx)] = record
    return record


def _postgres_data(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
    if isinstance(ctx.lifecycle_state, _PostgresLifecycleState):
        cached = ctx.lifecycle_state.deep_records.get(_postgres_credential_key(ctx))
        if cached is not None:
            return cached
        if str(record.status or "") == "open_no_auth":
            anonymous_record = _postgres_run_host_stage(
                ctx,
                run_deep_checks=True,
                username=None,
                password=None,
                source="anonymous",
            )
            ctx.lifecycle_state.deep_records[_postgres_credential_key(ctx)] = anonymous_record
            return anonymous_record
    return record


def build_postgres_spec(args: Any) -> ModuleAuditSpec:
    return ModuleAuditSpec(
        module="postgres",
        label="POSTGRES",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        detect=_postgres_detect,
        auth=_postgres_auth,
        data=_postgres_data,
        lifecycle_state_factory=_postgres_lifecycle_state_factory,
        render_module=render,
        colorize=render._render_colored_postgres_line,
        keep_anonymous_open_no_auth=True,
    )


def run_postgres_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
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
            AuditCredentialRun(
                username=user,
                password=password,
                source="default" if is_default else ("anonymous" if user is None and password is None else "provided"),
            )
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
