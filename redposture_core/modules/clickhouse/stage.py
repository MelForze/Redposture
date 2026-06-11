"""Runtime entrypoint for the clickhouse audit module."""

from __future__ import annotations

from typing import Any

from ...audit_models import AuditRecord
from ...console import Console
from ...stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    ModuleAuditSpec,
    build_basic_audit_plan,
    render_record_with_module,
)
from . import actions, policy, render

_DEFAULT_PORT = 9000
_DEFAULT_PORTS = None


def build_clickhouse_plan(args: Any) -> AuditCommandPlan:
    return build_basic_audit_plan(args, default_port=_DEFAULT_PORT, default_ports=_DEFAULT_PORTS)


def build_clickhouse_spec(args: Any) -> ModuleAuditSpec:
    def _render(record: AuditRecord) -> list[str]:
        return render_record_with_module(
            render,
            record,
            str(getattr(args, "output_format", "txt") or "txt"),
            debug=bool(getattr(args, "debug", False)),
        )

    return ModuleAuditSpec(
        module="clickhouse",
        label="CLICKHOUSE",
        default_port=_DEFAULT_PORT,
        host_stage=actions.host_stage,
        render=_render,
    )


def run_clickhouse_stage(args: Any, logger: Any) -> int:
    console = Console(debug=bool(getattr(args, "debug", False)))
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
    if bool(getattr(args, "sql_shell", False)):
        return _run_clickhouse_sql_shell(args, logger, console)
    try:
        plan = build_clickhouse_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    _emit_debug_start(args, console, plan)
    runner = AuditCommandRunner(args=args, spec=build_clickhouse_spec(args), logger=logger, emit_line=console.plain)
    try:
        runner.run_plan(plan)
    except OSError as exc:
        console.error(f"failed to process clickhouse output: {exc}")
        return 2
    return 0


def _emit_debug_start(args: Any, console: Any, plan: AuditCommandPlan) -> None:
    if not bool(getattr(args, "debug", False)):
        return
    mode = "detect-only"
    if getattr(args, "password", None) is not None:
        mode = "provided-creds"
    elif bool(getattr(args, "defcreds", False)):
        mode = "default-creds"
    suffix = f" format={getattr(args, 'output_format', 'txt') or 'txt'}"
    if getattr(args, "output", None):
        suffix += f" output={args.output}"
    console.info(
        "clickhouse audit started: "
        f"hosts={plan.target_count} ports={len(plan.targets_by_port)} timeout={getattr(args, 'timeout', 5.0)}s "
        f"workers={getattr(args, 'workers', 1)} retries={getattr(args, 'retries', 0)} mode={mode} "
        f"protocol={_raw_protocol(args)} database={getattr(args, 'database', 'default')}{suffix}"
    )


def _raw_protocol(args: Any) -> str:
    if bool(getattr(args, "http", False)):
        return "http"
    return str(getattr(args, "protocol", None) or "native")


def _run_clickhouse_sql_shell(args: Any, logger: Any, console: Any) -> int:
    try:
        plan = build_clickhouse_plan(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    item = plan.iter_target_specs()[0]
    _idx, host, port, _target = item
    protocol = "http" if _raw_protocol(args) == "http" else "native"
    table_targets = actions._normalize_table_targets(list(getattr(args, "tables", None) or []))
    table_columns, _columns_error = actions._normalize_column_names(list(getattr(args, "columns", None) or []))
    username = getattr(args, "username", None)
    password = getattr(args, "password", None)
    if password is not None and not username:
        username = "default"
    record = actions._audit_clickhouse_host(
        host=str(host),
        port=int(port),
        timeout=float(getattr(args, "timeout", 5.0) or 5.0),
        retries=int(getattr(args, "retries", 0) or 0),
        username=username,
        password=password,
        defcreds=bool(getattr(args, "defcreds", False)),
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
    )
    _emit_clickhouse_record(record, "txt")
    if not bool(record.get("is_clickhouse")):
        return 1
    if str(record.get("status") or "") in {"auth_required", "fail"}:
        return 1

    shell_user = str(record.get("effective_username") or username or "default")
    shell_password = str(record.get("effective_password") or password or "")
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
            timeout=float(getattr(args, "timeout", 5.0) or 5.0),
            retries=int(getattr(args, "retries", 0) or 0),
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
        if bool(getattr(args, "debug", False)) and hasattr(logger, "log"):
            logger.log(
                "clickhouse",
                (str(host), int(port)),
                phase="sql_shell",
                query=query,
                sql_ok=error is None,
                sql_error=error,
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
    "run_clickhouse_stage",
]
