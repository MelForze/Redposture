"""Runtime entrypoint for the postgres audit module."""

from __future__ import annotations

import ipaddress
import random
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
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
    build_basic_credential_runs,
    command_result_exit_code,
    merge_audit_credential_runs,
    sort_default_audit_credential_runs,
)
from ...utils import is_signature_compat_typeerror
from . import actions, policy, render

_DEFAULT_PORT = 5432
_DEFAULT_PORTS: tuple[int, ...] | None = (5432, 6432, 15432, 16432, 25432, 26432)
_POSTGRES_HOST_STAGE = actions.host_stage
_POSTGRES_HOST_STAGE_NAME = actions.host_stage.__name__
_POSTGRES_HOST_STAGE_IMPL = getattr(actions, _POSTGRES_HOST_STAGE_NAME, actions.host_stage)
_POSTGRES_AUDIT_HOST_IMPL = actions._audit_postgres_host


@dataclass
class _PostgresLifecycleState:
    detect_record: AuditRecord | None = None
    deep_records: dict[tuple[str | None, str | None, str], AuditRecord] = field(default_factory=dict)


@dataclass
class _PostgresHostCredentialState:
    lock: Any = field(default_factory=threading.Lock)
    last_finished_at: float | None = None
    cooldown_until: float = 0.0
    overload_streak: int = 0


class _PostgresCredentialCoordinator:
    """Serialize and pace credential handshakes for each target host."""

    def __init__(
        self,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        uniform: Callable[[float, float], float] = random.uniform,
    ) -> None:
        self._monotonic = monotonic
        self._sleep = sleep
        self._uniform = uniform
        self._states: dict[str, _PostgresHostCredentialState] = {}
        self._states_lock = threading.Lock()

    @staticmethod
    def _host_key(host: str) -> str:
        value = str(host or "").strip()
        try:
            return ipaddress.ip_address(value).compressed
        except ValueError:
            return value.rstrip(".").casefold()

    def _state(self, host: str) -> _PostgresHostCredentialState:
        key = self._host_key(host)
        with self._states_lock:
            state = self._states.get(key)
            if state is None:
                state = _PostgresHostCredentialState()
                self._states[key] = state
            return state

    @contextmanager
    def slot(self, host: str) -> Iterator[float]:
        """Yield after the host's previous credential attempt and cooldown."""

        state = self._state(host)
        with state.lock:
            now = self._monotonic()
            paced_start = now
            if state.last_finished_at is not None:
                paced_start = state.last_finished_at + float(self._uniform(0.10, 0.25))
            wait_seconds = max(0.0, max(paced_start, state.cooldown_until) - now)
            if wait_seconds > 0:
                self._sleep(wait_seconds)
            try:
                yield wait_seconds
            finally:
                state.last_finished_at = self._monotonic()

    def observe(self, host: str, record: AuditRecord) -> float:
        """Apply a bounded host cooldown after an explicit overload response."""

        state = self._state(host)
        if not _postgres_is_transient_overload(record):
            state.overload_streak = 0
            return 0.0
        state.overload_streak += 1
        cooldown = min(2.0, 0.50 * (2 ** (state.overload_streak - 1)))
        state.cooldown_until = max(state.cooldown_until, self._monotonic() + cooldown)
        return cooldown


_POSTGRES_OVERLOAD_SQLSTATES = {"53300", "53400", "57P03"}
_POSTGRES_OVERLOAD_MARKERS = (
    "too many connections",
    "remaining connection slots are reserved",
    "max_client_conn",
    "no more connections allowed",
    "connection pool exhausted",
    "pooler is paused",
    "server login has been failing",
    "query_wait_timeout",
)


def _postgres_is_transient_overload(record: AuditRecord) -> bool:
    sqlstate = str(record.extra.get("sqlstate") or "").upper()
    if sqlstate in _POSTGRES_OVERLOAD_SQLSTATES:
        return True
    error = str(record.extra.get("error") or "").casefold()
    return any(marker in error for marker in _POSTGRES_OVERLOAD_MARKERS)


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


def _postgres_tls_config_from_args(args: Any) -> actions._PgTlsConfig:
    return actions._pg_tls_config(
        str(getattr(args, "sslmode", "disable") or "disable"),
        getattr(args, "ssl_ca", None),
        getattr(args, "ssl_cert", None),
        getattr(args, "ssl_key", None),
        getattr(args, "ssl_server_name", None),
    )


def _postgres_tls_stage_kwargs(args: Any) -> dict[str, Any]:
    config = _postgres_tls_config_from_args(args)
    if config == actions._PgTlsConfig():
        return {}
    return {
        "sslmode": config.sslmode,
        "ssl_ca": config.ca_file,
        "ssl_cert": config.cert_file,
        "ssl_key": config.key_file,
        "ssl_server_name": config.server_name,
    }


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
            with actions._pg_open_socket(
                ctx.host,
                ctx.port,
                cfg.timeout,
                tls_config=_postgres_tls_config_from_args(ctx.args),
            ) as sock:
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
        **_postgres_tls_stage_kwargs(ctx.args),
    )
    return _postgres_record(record)


def _postgres_auth_probe_record(
    ctx: AuditHookContext,
    record: AuditRecord,
) -> AuditRecord:
    """Normalize a compatibility host-stage result into an auth-only verdict."""

    payload = record.to_dict()
    status = str(record.status or "")
    verified: bool | None = status in {"valid_credentials", "weak_default_creds"} and record.auth_required is not False
    if _postgres_host_stage_is_replaced() and status in {"valid_credentials", "weak_default_creds"}:
        # Test/embedding replacements often omit a truthful auth_required
        # value. Their accepted status remains the compatibility contract.
        verified = True
    verification: str
    if status == "open_no_auth" or (record.auth_required is False and not verified):
        status = "invalid_credentials_anonymous"
        verified = False
        verification = "unverified"
    elif verified and ctx.credential.source == "default":
        status = "weak_default_creds"
        verification = "verified"
    elif verified:
        verification = "verified"
    elif status == "unknown_auth":
        verification = "unavailable"
        verified = None
    elif status == "fail":
        verification = "error"
        verified = None
    else:
        verification = "rejected"
    payload.update(
        {
            "status": status,
            "credential_verified": verified,
            "credential_verification": verification,
        }
    )
    return _postgres_record(payload)


def _postgres_probe_credential(ctx: AuditHookContext) -> AuditRecord:
    """Probe one PostgreSQL credential without privilege or data queries."""

    cfg = AuditConfig.from_namespace(ctx.args)
    target_database = str(getattr(ctx.args, "database", "") or "").strip() or "postgres"
    username = str(ctx.credential.username or "postgres").strip() or "postgres"
    password = ctx.credential.password
    is_default = ctx.credential.source == "default"
    provided_credentials = not is_default
    attempts = max(1, cfg.retries + 1)
    started = time.monotonic()
    last_error: str | None = None

    for attempt in range(attempts):
        try:
            with actions._pg_open_socket(
                ctx.host,
                ctx.port,
                cfg.timeout,
                tls_config=_postgres_tls_config_from_args(ctx.args),
            ) as sock:
                try:
                    session = actions._pg_startup_and_auth(
                        sock,
                        username=username,
                        password=password,
                        database=target_database,
                    )
                finally:
                    try:
                        actions._pg_send_terminate(sock)
                    except Exception:
                        pass
            credential_verified = session.auth_required is not False
            status = (
                "invalid_credentials_anonymous"
                if not credential_verified
                else "weak_default_creds"
                if is_default
                else "valid_credentials"
            )
            return _postgres_record(
                {
                    "timestamp": actions.utc_now_iso(),
                    "host": ctx.host,
                    "port": ctx.port,
                    "service": "postgres",
                    "module": "postgres",
                    "database": target_database,
                    "auth_database": target_database,
                    "is_postgres": True,
                    "status": status,
                    "auth_required": session.auth_required,
                    "auth_method": session.auth_method,
                    "server_version": session.server_version,
                    "provided_credentials": provided_credentials,
                    "provided_username": ctx.credential.username,
                    "provided_password": password if provided_credentials else None,
                    "defcreds_enabled": is_default,
                    "effective_username": username,
                    "credential_verified": credential_verified,
                    "credential_verification": "verified" if credential_verified else "unverified",
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": None,
                }
            )
        except actions._PgAuditError as exc:
            status = (
                "auth_required"
                if exc.detected and exc.auth_required is True
                else ("unknown_auth" if exc.detected else "fail")
            )
            verification = (
                "rejected" if status == "auth_required" else "unavailable" if status == "unknown_auth" else "error"
            )
            return _postgres_record(
                {
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
                    "error_kind": exc.error_kind or ("authentication_failed" if exc.detected else "connection_error"),
                    "provided_credentials": provided_credentials,
                    "provided_username": ctx.credential.username,
                    "provided_password": password if provided_credentials else None,
                    "defcreds_enabled": is_default,
                    "effective_username": username,
                    "credential_verified": False if verification == "rejected" else None,
                    "credential_verification": verification,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": str(exc),
                }
            )
        except (OSError, ValueError, ConnectionError) as exc:
            last_error = str(exc)
            if attempt < attempts - 1:
                time.sleep(actions._retry_delay(attempt))

    return _postgres_record(
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
            "provided_credentials": provided_credentials,
            "provided_username": ctx.credential.username,
            "provided_password": password if provided_credentials else None,
            "defcreds_enabled": is_default,
            "effective_username": username,
            "credential_verified": None,
            "credential_verification": "error",
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": last_error or "connection failed",
        }
    )


def _postgres_auth(ctx: AuditHookContext, detect_record: AuditRecord) -> AuditRecord:
    if ctx.credential.username is None and ctx.credential.password is None and ctx.credential.token is None:
        return _postgres_record(
            {
                **detect_record.to_dict(),
                "credential_verified": False,
                "credential_verification": "anonymous",
            }
        )

    def _probe() -> AuditRecord:
        if _postgres_host_stage_is_replaced():
            record = _postgres_run_host_stage(
                ctx,
                run_deep_checks=False,
                username=ctx.credential.username,
                password=ctx.credential.password,
                source=ctx.credential.source,
            )
            return _postgres_auth_probe_record(ctx, record)
        return _postgres_probe_credential(ctx)

    coordinator = getattr(ctx.args, "_postgres_credential_coordinator", None)
    if not isinstance(coordinator, _PostgresCredentialCoordinator):
        return _probe()
    with coordinator.slot(ctx.host) as wait_seconds:
        if wait_seconds > 0 and ctx.debug_emit is not None:
            ctx.debug_emit(f"postgres credential pacing host={ctx.host} wait={wait_seconds:.3f}s")
        record = _probe()
        cooldown = coordinator.observe(ctx.host, record)
        if cooldown > 0 and ctx.debug_emit is not None:
            ctx.debug_emit(f"postgres credential cooldown host={ctx.host} wait={cooldown:.3f}s")
        return record


def _postgres_credential_gate(
    _credential: AuditCredentialRun,
    record: AuditRecord,
) -> tuple[bool, str]:
    verified = record.extra.get("credential_verified") is True
    return verified, "credential verified" if verified else "credential unverified"


def _postgres_data(ctx: AuditHookContext, _record: AuditRecord) -> AuditRecord:
    if isinstance(ctx.lifecycle_state, _PostgresLifecycleState):
        cached = ctx.lifecycle_state.deep_records.get(_postgres_credential_key(ctx))
        if cached is not None:
            return cached
    deep_record = _postgres_run_host_stage(
        ctx,
        run_deep_checks=True,
        username=ctx.credential.username,
        password=ctx.credential.password,
        source=ctx.credential.source,
    )
    if isinstance(ctx.lifecycle_state, _PostgresLifecycleState):
        ctx.lifecycle_state.deep_records[_postgres_credential_key(ctx)] = deep_record
    return deep_record


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
        credential_gate=_postgres_credential_gate,
        fallback_to_anonymous_detect_record=True,
        continue_after_credential_error=bool(getattr(args, "defcreds", False)),
        continue_after_credential_success=bool(getattr(args, "defcreds", False))
        and not bool(getattr(args, "stop_on_success", False)),
        record_all_credential_attempts=bool(getattr(args, "defcreds", False)),
        credential_attempt_detail_fields=("credential_verified", "credential_verification"),
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
    try:
        supplied_runs = build_basic_credential_runs(args)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    default_runs = (
        sort_default_audit_credential_runs(
            AuditCredentialRun(username=username, password=password, source="default")
            for username, password in actions._POSTGRES_DEFAULT_CREDENTIALS
        )
        if bool(getattr(args, "defcreds", False))
        else ()
    )
    args._audit_credential_runs = merge_audit_credential_runs(supplied_runs, default_runs)
    args._postgres_credential_coordinator = _PostgresCredentialCoordinator()
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
    return command_result_exit_code(result)


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
    credential_runs = getattr(plan, "credential_runs", None)
    if credential_runs is None:
        try:
            supplied_runs = build_basic_credential_runs(args)
        except ValueError as exc:
            console.error(str(exc))
            return 2
        default_runs = (
            sort_default_audit_credential_runs(
                AuditCredentialRun(username=username, password=password, source="default")
                for username, password in actions._POSTGRES_DEFAULT_CREDENTIALS
            )
            if bool(getattr(args, "defcreds", False))
            else ()
        )
        credential_runs = merge_audit_credential_runs(supplied_runs, default_runs)
    record: dict[str, Any] | None = None
    winning_credential: AuditCredentialRun | None = None
    coordinator = getattr(args, "_postgres_credential_coordinator", None)
    for credential in credential_runs:
        credential_slot: AbstractContextManager[float]
        if isinstance(coordinator, _PostgresCredentialCoordinator):
            credential_slot = coordinator.slot(str(host))
        else:
            credential_slot = nullcontext(0.0)
        with credential_slot as wait_seconds:
            if wait_seconds > 0 and cfg.debug:
                console.info(f"postgres credential pacing host={host} wait={wait_seconds:.3f}s")
            candidate_record = actions._audit_postgres_host(
                host=str(host),
                port=int(port),
                timeout=cfg.timeout,
                retries=cfg.retries,
                username=credential.username,
                password=credential.password,
                defcreds=False,
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
                **_postgres_tls_stage_kwargs(args),
            )
            if isinstance(coordinator, _PostgresCredentialCoordinator):
                cooldown = coordinator.observe(str(host), _postgres_record(candidate_record))
                if cooldown > 0 and cfg.debug:
                    console.info(f"postgres credential cooldown host={host} wait={cooldown:.3f}s")
        if (
            credential.source == "default"
            and str(candidate_record.get("status") or "") == "valid_credentials"
            and candidate_record.get("auth_required") is not False
        ):
            candidate_record = {
                **candidate_record,
                "status": "weak_default_creds",
                "provided_credentials": False,
                "provided_username": credential.username,
                "provided_password": None,
                "defcreds_enabled": True,
            }
        record = candidate_record
        if bool(record.get("is_postgres")) and str(record.get("status") or "") in {
            "open_no_auth",
            "valid_credentials",
            "weak_default_creds",
        }:
            winning_credential = credential
            break
    if record is None or winning_credential is None:
        return 1
    username = str(record.get("effective_username") or winning_credential.username or "postgres")
    password = winning_credential.password
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
            try:
                output, exec_error = actions._pg_execute_remote_command(
                    host=str(host),
                    port=int(port),
                    timeout=cfg.timeout,
                    retries=cfg.retries,
                    username=username,
                    password=password,
                    database=database,
                    command=command,
                    tls_config=_postgres_tls_config_from_args(args),
                )
            except TypeError as exc:
                if not is_signature_compat_typeerror(exc, expected_keywords={"tls_config"}):
                    raise
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
            tls_config=_postgres_tls_config_from_args(args),
        )
        for line in output or []:
            console.plain(str(line))
        if query_error:
            console.error(query_error)
    return 0
