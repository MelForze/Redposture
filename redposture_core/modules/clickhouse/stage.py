"""Runtime entrypoint for the clickhouse audit module."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...console import Console
from ...show_limits import dump_flag_enabled, dump_flag_limit, show_flag_enabled, show_flag_limit
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    ModuleAuditSpec,
    build_basic_audit_plan,
    merge_audit_credential_runs,
)
from . import actions, policy, render

_DEFAULT_PORT = 9000
_DEFAULT_PORTS: tuple[int, ...] | None = (9000, 19000)
_DEFAULT_HTTP_PORT = 8123
_DEFAULT_HTTP_PORTS: tuple[int, ...] | None = (8123, 18123)
_PRODUCTION_HOST_STAGE = actions.host_stage
_PRODUCTION_AUDIT_HOST = actions._audit_clickhouse_host


def build_clickhouse_plan(args: Any) -> AuditCommandPlan:
    if _raw_protocol(args) == "http":
        plan = build_basic_audit_plan(args, default_port=_DEFAULT_HTTP_PORT, default_ports=_DEFAULT_HTTP_PORTS)
    else:
        plan = build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)
    defaults = (
        tuple(
            AuditCredentialRun(username=username, password=password, source=source)
            for username, password, source in actions._build_credential_candidates(None, None, True)
        )
        if bool(getattr(args, "defcreds", False))
        else ()
    )
    return replace(
        plan,
        credential_runs=merge_audit_credential_runs(plan.credential_runs, defaults),
    )


def _force_single_default_port(args: Any) -> None:
    if getattr(args, "port", None) is None and getattr(args, "ports", None) is None:
        args.port = _DEFAULT_HTTP_PORT if _raw_protocol(args) == "http" else _DEFAULT_PORT


def _build_clickhouse_host_stage_options(args: Any) -> dict[str, Any]:
    table_targets = actions._normalize_table_targets(list(getattr(args, "tables", None) or []))
    table_columns, columns_error = actions._normalize_column_names(list(getattr(args, "columns", None) or []))
    if columns_error:
        raise ValueError(columns_error)
    return {
        "database": str(getattr(args, "database", "default") or "default"),
        "protocol": _raw_protocol(args),
        "show_databases": show_flag_enabled(getattr(args, "show_databases", False)),
        "show_tables": show_flag_enabled(getattr(args, "show_tables", False)),
        "show_columns": show_flag_enabled(getattr(args, "show_columns", False)),
        "table_targets": table_targets,
        "table_columns": table_columns,
        "dump_table_rows": dump_flag_enabled(getattr(args, "dump", False)),
        "execute_command": str(getattr(args, "execute", "") or "").strip() or None,
        "sql_command": str(getattr(args, "sql_cmd", "") or "").strip() or None,
        "show_databases_limit": show_flag_limit(getattr(args, "show_databases", False)),
        "show_tables_limit": show_flag_limit(getattr(args, "show_tables", False)),
        "show_columns_limit": show_flag_limit(getattr(args, "show_columns", False)),
        "port_protocols": None,
        "dump_row_limit": dump_flag_limit(getattr(args, "dump", False)),
    }


def build_clickhouse_spec(args: Any) -> ModuleAuditSpec:
    options = _build_clickhouse_host_stage_options(args)
    resolved_host_stage = getattr(actions, _PRODUCTION_HOST_STAGE.__name__, _PRODUCTION_HOST_STAGE)
    use_lifecycle_hooks = (
        actions.host_stage is _PRODUCTION_HOST_STAGE
        and resolved_host_stage is _PRODUCTION_HOST_STAGE
        and actions._audit_clickhouse_host is _PRODUCTION_AUDIT_HOST
    )

    def _state_factory(_ctx: Any) -> actions.ClickHouseLifecycleState:
        return actions.ClickHouseLifecycleState()

    def _detect(ctx: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.detect_clickhouse(ctx, options),
            module="clickhouse",
            service="clickhouse",
        )

    def _auth(ctx: Any, record: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.authenticate_clickhouse(ctx, record, options),
            module="clickhouse",
            service="clickhouse",
        )

    def _data(ctx: Any, record: Any) -> AuditRecord:
        return AuditRecord.from_mapping(
            actions.collect_clickhouse_data(ctx, record, options),
            module="clickhouse",
            service="clickhouse",
        )

    return ModuleAuditSpec(
        module="clickhouse",
        label="CLICKHOUSE",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        host_stage_options=options,
        detect=_detect if use_lifecycle_hooks else None,
        auth=_auth if use_lifecycle_hooks else None,
        data=_data if use_lifecycle_hooks else None,
        lifecycle_state_factory=_state_factory if use_lifecycle_hooks else None,
        lifecycle_state_close=(lambda state: state.close()) if use_lifecycle_hooks else None,
        render_module=render,
        colorize=render._render_colored_clickhouse_line,
        # E3 opt-in: ClickHouse anon-open (default_user w/ empty password) is
        # already confirmed by the detect probe.
        keep_anonymous_open_no_auth=True,
        continue_after_credential_error=bool(getattr(args, "defcreds", False)),
        continue_after_credential_success=bool(getattr(args, "defcreds", False)),
    )


def run_clickhouse_stage(args: Any, logger: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    console = Console(debug=cfg.debug)
    if hasattr(console, "set_structured_output"):
        console.set_structured_output(cfg.output_format == "json")
    actions._configure_clickhouse_loggers()
    validation_rc = policy.validate_args(args, console)
    if validation_rc is not None:
        return int(validation_rc)
    try:
        if _raw_protocol(args) == "http":
            actions._load_clickhouse_connect_module()
        else:
            actions._load_clickhouse_driver_client()
    except RuntimeError as exc:
        console.error(str(exc))
        return 2
    if bool(getattr(args, "os_shell", False)):
        return _run_clickhouse_os_shell(args, logger, console)
    if bool(getattr(args, "sql_shell", False)):
        return _run_clickhouse_sql_shell(args, logger, console)
    try:
        plan = build_clickhouse_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    _emit_debug_start(args, console, plan)
    try:
        runner = AuditCommandRunner(args=args, spec=build_clickhouse_spec(args), logger=logger, console=console)
        runner.run_plan(plan)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    except OSError as exc:
        console.error(f"failed to process clickhouse output: {exc}")
        return 2
    return 0


def _emit_debug_start(args: Any, console: Any, plan: AuditCommandPlan) -> None:
    cfg = AuditConfig.from_namespace(args)
    if not cfg.debug:
        return
    mode = "detect-only"
    if getattr(args, "password", None) is not None:
        mode = "provided-creds"
    elif bool(getattr(args, "defcreds", False)):
        mode = "default-creds"
    suffix = f" format={cfg.output_format}"
    if cfg.output:
        suffix += f" output={args.output}"
    console.info(
        "clickhouse audit started: "
        f"hosts={plan.target_count} ports={len(plan.ports) or len(plan.targets_by_port)} "
        f"timeout={getattr(args, 'timeout', 5.0)}s "
        f"workers={getattr(args, 'workers', 1)} retries={getattr(args, 'retries', 0)} mode={mode} "
        f"protocol={_raw_protocol(args)} database={getattr(args, 'database', 'default')}{suffix}"
    )


def _raw_protocol(args: Any) -> str:
    if bool(getattr(args, "http", False)):
        return "http"
    return str(getattr(args, "protocol", None) or "native")


def _check_clickhouse_shell_target(
    args: Any,
    cfg: AuditConfig,
    plan: AuditCommandPlan,
    *,
    host: str,
    port: int,
    protocol: str,
    table_targets: list[str],
    table_columns: list[str],
) -> dict[str, Any]:
    """Audit the shell target with the already-normalized credential plan."""

    credential_candidates = [
        {
            "username": credential.username,
            "password": credential.password,
            "source": credential.source,
        }
        for credential in plan.credential_runs
        if credential.username is not None or credential.password is not None
    ]
    return actions._audit_clickhouse_host(
        host=str(host),
        port=int(port),
        timeout=cfg.timeout,
        retries=cfg.retries,
        username=None,
        password=None,
        defcreds=False,
        database=str(getattr(args, "database", "default") or "default"),
        protocol=protocol,
        show_databases=bool(getattr(args, "show_databases", False)),
        show_tables=bool(getattr(args, "show_tables", False)),
        show_columns=bool(getattr(args, "show_columns", False)),
        table_targets=table_targets,
        table_columns=table_columns,
        dump_table_rows=bool(getattr(args, "dump", False)),
        execute_command=None,
        sql_command=None,
        credential_candidates=credential_candidates,
    )


def _run_clickhouse_sql_shell(args: Any, logger: Any, console: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    _force_single_default_port(args)
    try:
        plan = build_clickhouse_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    try:
        _idx, host, port, _target = plan.require_single_target_spec()
    except ValueError as exc:
        console.error(f"--sql-shell {exc}")
        return 2
    protocol = "http" if _raw_protocol(args) == "http" else "native"
    table_targets = actions._normalize_table_targets(list(getattr(args, "tables", None) or []))
    table_columns, _columns_error = actions._normalize_column_names(list(getattr(args, "columns", None) or []))
    record = _check_clickhouse_shell_target(
        args,
        cfg,
        plan,
        host=str(host),
        port=int(port),
        protocol=protocol,
        table_targets=table_targets,
        table_columns=table_columns,
    )
    _emit_clickhouse_record(record, "txt")
    if not bool(record.get("is_clickhouse")):
        return 1
    if str(record.get("status") or "") in {"auth_required", "fail"}:
        return 1

    shell_user = str(record.get("effective_username") or "default")
    effective_password = record.get("effective_password")
    shell_password = "" if effective_password is None else str(effective_password)
    shell_protocol = str(record.get("protocol") or protocol)
    readline_module = actions._load_readline_module()
    console.success("clickhouse sql-shell ready; type 'exit' or 'quit' to stop")
    while True:
        try:
            raw_query = input("ch-sql> ")
        except (EOFError, KeyboardInterrupt):
            console.plain("")
            break
        query = raw_query.strip()
        if not query:
            continue
        if query.lower() in {"exit", "quit"}:
            break
        actions._add_readline_history(readline_module, query)
        output, error = actions._run_sql_query_once(
            host=str(host),
            port=int(port),
            timeout=cfg.timeout,
            retries=cfg.retries,
            protocol=shell_protocol,
            username=shell_user,
            password=shell_password,
            database=str(getattr(args, "database", "default") or "default"),
            query=query,
        )
        shell_record = dict(record)
        shell_record.update(
            {
                "sql_command": query,
                "sql_attempted": True,
                "sql_ok": error is None,
                "sql_output": output,
                "sql_error": error,
            }
        )
        for line in render._format_sql_detail_records(shell_record, "txt"):
            print(line)
        if cfg.debug and hasattr(logger, "log"):
            logger.log(
                "clickhouse",
                (str(host), int(port)),
                phase="sql_shell",
                query=query,
                sql_ok=error is None,
                sql_error=error,
            )
    return 0


def _run_clickhouse_os_shell(args: Any, logger: Any, console: Any) -> int:
    cfg = AuditConfig.from_namespace(args)
    _force_single_default_port(args)
    try:
        plan = build_clickhouse_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    try:
        _idx, host, port, _target = plan.require_single_target_spec()
    except ValueError as exc:
        console.error(f"--os-shell {exc}")
        return 2
    protocol = "http" if _raw_protocol(args) == "http" else "native"
    table_targets = actions._normalize_table_targets(list(getattr(args, "tables", None) or []))
    table_columns, _columns_error = actions._normalize_column_names(list(getattr(args, "columns", None) or []))
    record = _check_clickhouse_shell_target(
        args,
        cfg,
        plan,
        host=str(host),
        port=int(port),
        protocol=protocol,
        table_targets=table_targets,
        table_columns=table_columns,
    )
    _emit_clickhouse_record(record, "txt")
    if not bool(record.get("is_clickhouse")):
        return 1
    if str(record.get("status") or "") in {"auth_required", "fail"}:
        return 1

    shell_user = str(record.get("effective_username") or "default")
    effective_password = record.get("effective_password")
    shell_password = "" if effective_password is None else str(effective_password)
    shell_protocol = str(record.get("protocol") or protocol)
    readline_module = actions._load_readline_module()
    console.success("clickhouse os-shell ready; type 'exit' or 'quit' to stop")
    while True:
        try:
            raw_command = input("ch-os> ")
        except (EOFError, KeyboardInterrupt):
            console.plain("")
            break
        command = raw_command.strip()
        if not command:
            continue
        if command.lower() in {"exit", "quit"}:
            break
        actions._add_readline_history(readline_module, command)
        output, error = actions._run_execute_command_once(
            host=str(host),
            port=int(port),
            timeout=cfg.timeout,
            retries=cfg.retries,
            protocol=shell_protocol,
            username=shell_user,
            password=shell_password,
            database=str(getattr(args, "database", "default") or "default"),
            command=command,
        )
        shell_record = dict(record)
        shell_record.update(
            {
                "execute_command": command,
                "execute_attempted": True,
                "execute_ok": error is None,
                "execute_output": output,
                "execute_error": error,
            }
        )
        for line in render._format_execute_detail_records(shell_record, "txt"):
            print(line)
        if cfg.debug and hasattr(logger, "log"):
            logger.log(
                "clickhouse",
                (str(host), int(port)),
                phase="os_shell",
                command=command,
                execute_ok=error is None,
                execute_error=error,
            )
    return 0


def _emit_clickhouse_record(record: dict[str, Any], output_format: str) -> None:
    if bool(record.get("is_clickhouse")) and str(record.get("status") or "") != "fail":
        print(render._format_detect_record(record, output_format))
    for formatter in (
        render._format_auth_attempt_detail_records,
        render._format_record,
        render._format_databases_detail_records,
        render._format_tables_detail_records,
        render._format_table_columns_detail_records,
        render._format_table_dump_detail_records,
        render._format_execute_detail_records,
    ):
        lines = formatter(record, output_format)
        if isinstance(lines, str):
            lines = [lines]
        for line in lines:
            if line:
                print(line)


__all__ = [
    "build_clickhouse_plan",
    "build_clickhouse_spec",
    "_build_clickhouse_host_stage_options",
    "run_clickhouse_stage",
]
