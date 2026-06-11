"""ClickHouse audit stage."""

from __future__ import annotations

import datetime as dt
import json
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from uuid import UUID

from ...console import Console
from ...rendering import BooleanColorRule, CountColorRule, render_colored_marker_line
from ...show_limits import (
    limit_metadata,
    limit_sequence,
)
from ...stage_runtime import (
    merge_stage_records,
)
from ...utils import (
    is_signature_compat_typeerror,
    utc_now_iso,
)

_CH_DEFAULT_NATIVE_PORT = 9000
_CH_DEFAULT_HTTP_PORT = 8123
_CH_MAX_SQL_LINES = 500
_CH_MAX_DUMP_ROWS = 100
_CH_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CH_EXEC_SCRIPT = "redposture_exec.sh"
_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_CLICKHOUSE_DEEP_STATUSES = {
    "open_no_auth",
    "weak_default_creds",
    "valid_credentials",
    "invalid_credentials_anonymous",
}


@dataclass
class _ChSession:
    protocol: str
    client: Any
    username: str
    password: str
    database: str


def _configure_clickhouse_loggers() -> None:
    """Suppress noisy third-party connection warnings/tracebacks.

    clickhouse-driver and clickhouse-connect log connection failures as warnings
    (often with traceback) for each retry attempt. We keep these internals out of
    regular CLI output and use redposture's own formatted status lines instead.
    """
    logger_names = (
        "clickhouse_driver",
        "clickhouse_driver.connection",
        "clickhouse_connect",
        "clickhouse_connect.driver",
        "clickhouse_connect.driver.httpclient",
    )
    for logger_name in logger_names:
        logger_obj = logging.getLogger(logger_name)
        if not any(isinstance(handler, logging.NullHandler) for handler in logger_obj.handlers):
            logger_obj.addHandler(logging.NullHandler())
        logger_obj.propagate = False
        if logger_obj.level in {logging.NOTSET} or logger_obj.level < logging.ERROR:
            logger_obj.setLevel(logging.ERROR)


def _clip(text: str, width: int = 80) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _load_readline_module() -> Any | None:
    try:
        import readline  # noqa: PLC0415
    except Exception:
        return None
    try:
        readline.parse_and_bind("set bell-style none")
    except Exception:
        pass
    return readline


def _add_readline_history(readline_module: Any | None, line: str) -> None:
    if readline_module is None:
        return
    value = str(line or "").strip()
    if not value:
        return
    try:
        history_length = int(readline_module.get_current_history_length())
        if history_length > 0 and readline_module.get_history_item(history_length) == value:
            return
        readline_module.add_history(value)
    except Exception:
        return


def _friendly_error_from_exception(exc: BaseException) -> str:
    text = str(exc or "").strip() or exc.__class__.__name__
    lower = text.lower()
    if isinstance(exc, TimeoutError) or "timed out" in lower or "timeout" in lower:
        return "connection timeout"
    if "connection refused" in lower or "[errno 111]" in lower:
        return "connection refused (service is not listening on target port)"
    return _clip(text, 180)


def _is_timeout_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and ("timed out" in text or "timeout" in text)


def _is_connection_refused_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and "connection refused" in text


def _is_connection_timeout_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail" and _is_timeout_error(record.get("error"))


def _is_connection_refused_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail" and _is_connection_refused_error(record.get("error"))


def _should_emit_status_line(record: dict[str, Any], output_format: str) -> bool:
    if output_format != "txt":
        return True
    return str(record.get("status") or "") != "auth_required"


def _is_auth_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    markers = (
        "authentication",
        "password",
        "unauthorized",
        "access denied",
        "code: 193",
        "code: 194",
        "code: 516",
        "code: 497",
    )
    return any(marker in text for marker in markers)


def _looks_like_clickhouse_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    markers = (
        "clickhouse",
        "db::exception",
        "code:",
        "unexpected packet from server",
        "unknown packet",
    )
    return any(marker in text for marker in markers)


def _load_clickhouse_driver_client() -> Any:
    try:
        from clickhouse_driver import Client as DriverClient

        return DriverClient
    except Exception as exc:  # pragma: no cover - exercised in runtime only
        raise RuntimeError("clickhouse-driver is required for native protocol support") from exc


def _load_clickhouse_connect_module() -> Any:
    try:
        import clickhouse_connect

        return clickhouse_connect
    except Exception as exc:  # pragma: no cover - exercised in runtime only
        raise RuntimeError("clickhouse-connect is required for http protocol support") from exc


def _close_client(protocol: str, client: Any) -> None:
    if client is None:
        return
    if protocol == "native":
        disconnect = getattr(client, "disconnect", None)
        if callable(disconnect):
            try:
                disconnect()
            except Exception:
                return
        return
    close = getattr(client, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            return


def _open_clickhouse_client(
    protocol: str,
    host: str,
    port: int,
    timeout: float,
    username: str,
    password: str,
    database: str,
) -> Any:
    if protocol == "native":
        driver_client = _load_clickhouse_driver_client()
        kwargs: dict[str, Any] = {
            "host": host,
            "port": int(port),
            "user": username,
            "password": password,
            "database": database,
            "connect_timeout": float(timeout),
            "send_receive_timeout": float(timeout),
            "sync_request_timeout": float(timeout),
        }
        try:
            return driver_client(**kwargs)
        except TypeError as exc:
            if not is_signature_compat_typeerror(exc, expected_keywords={"sync_request_timeout"}):
                raise
            kwargs.pop("sync_request_timeout", None)
            return driver_client(**kwargs)

    if protocol == "http":
        clickhouse_connect = _load_clickhouse_connect_module()
        kwargs = {
            "host": host,
            "port": int(port),
            "username": username,
            "password": password,
            "database": database,
            "interface": "http",
            "connect_timeout": float(timeout),
        }
        try:
            return clickhouse_connect.get_client(**kwargs)
        except TypeError as exc:
            if not is_signature_compat_typeerror(exc, expected_keywords={"connect_timeout"}):
                raise
            kwargs.pop("connect_timeout", None)
            return clickhouse_connect.get_client(**kwargs)

    raise ValueError(f"unsupported protocol: {protocol}")


def _query_rows(session: _ChSession, query: str) -> tuple[list[list[Any]] | None, str | None]:
    try:
        if session.protocol == "native":
            raw_rows = session.client.execute(query)
        else:
            result = session.client.query(query)
            raw_rows = getattr(result, "result_rows", None)
            if raw_rows is None:
                raw_rows = []
    except Exception as exc:
        return None, _friendly_error_from_exception(exc)

    rows: list[list[Any]] = []
    if isinstance(raw_rows, list):
        for row in raw_rows:
            if isinstance(row, (list, tuple)):
                rows.append(list(row))
            else:
                rows.append([row])
    return rows, None


def _connect_and_probe(
    protocol: str,
    host: str,
    port: int,
    timeout: float,
    username: str,
    password: str,
    *,
    database: str = "default",
) -> tuple[_ChSession | None, str | None]:
    client: Any | None = None
    try:
        client = _open_clickhouse_client(protocol, host, port, timeout, username, password, database)
        session = _ChSession(
            protocol=protocol,
            client=client,
            username=username,
            password=password,
            database=database,
        )
        _rows, query_error = _query_rows(session, "SELECT 1")
        if query_error:
            _close_client(protocol, client)
            return None, query_error
        return session, None
    except Exception as exc:
        if client is not None:
            _close_client(protocol, client)
        return None, _friendly_error_from_exception(exc)


def _bool_text(value: bool | None) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "unknown"


def _password_text(value: Any) -> str:
    if value == "":
        return "<empty>"
    if value is None:
        return "<none>"
    return str(value)


def _build_credential_candidates(
    username: str | None,
    password: str | None,
    defcreds: bool,
) -> list[tuple[str, str, str]]:
    candidates: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    if password is not None:
        user = str(username or "default").strip() or "default"
        pair = (user, password)
        candidates.append((user, password, "provided"))
        seen.add(pair)

    if defcreds:
        defaults = (("default", ""), ("default", "default"))
        for user, secret in defaults:
            pair = (user, secret)
            if pair in seen:
                continue
            candidates.append((user, secret, "default"))
            seen.add(pair)

    return candidates


def _quote_ident(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"


def _quote_literal(value: str) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def _split_quoted(raw: str, *, separator: str) -> list[str] | None:
    parts: list[str] = []
    current: list[str] = []
    in_quote = False
    idx = 0
    while idx < len(raw):
        ch = raw[idx]
        if ch == "`":
            current.append(ch)
            if in_quote and idx + 1 < len(raw) and raw[idx + 1] == "`":
                current.append("`")
                idx += 2
                continue
            in_quote = not in_quote
            idx += 1
            continue
        if ch == separator and not in_quote:
            parts.append("".join(current).strip())
            current = []
            idx += 1
            continue
        current.append(ch)
        idx += 1
    if in_quote:
        return None
    parts.append("".join(current).strip())
    return parts


def _parse_identifier_part(value: str) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.startswith("`"):
        if not raw.endswith("`") or len(raw) < 2:
            return None
        inner = raw[1:-1]
        out: list[str] = []
        idx = 0
        while idx < len(inner):
            ch = inner[idx]
            if ch == "`":
                if idx + 1 < len(inner) and inner[idx + 1] == "`":
                    out.append("`")
                    idx += 2
                    continue
                return None
            out.append(ch)
            idx += 1
        parsed = "".join(out)
        return parsed if parsed else None
    if not _CH_IDENT_RE.fullmatch(raw):
        return None
    return raw


def _parse_identifier_path(value: str) -> list[str] | None:
    parts = _split_quoted(str(value or "").strip(), separator=".")
    if parts is None or not parts:
        return None
    parsed: list[str] = []
    for part in parts:
        item = _parse_identifier_part(part)
        if item is None:
            return None
        parsed.append(item)
    return parsed


def _split_csv_values(raw_values: list[str]) -> list[str]:
    values: list[str] = []
    for raw in raw_values:
        parts = _split_quoted(str(raw), separator=",")
        if parts is None:
            parts = [str(raw)]
        for part in parts:
            item = part.strip()
            if item:
                values.append(item)
    return values


def _normalize_column_names(raw_values: list[str]) -> tuple[list[str], str | None]:
    normalized: list[str] = []
    seen: set[str] = set()
    for part in _split_csv_values(raw_values):
        name = _parse_identifier_part(part)
        if name is None:
            return [], f"invalid column name: {part}"
        lowered = name.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        normalized.append(name)
    return normalized, None


def _normalize_table_targets(raw_values: list[str]) -> list[str]:
    tables: list[str] = []
    seen: set[str] = set()
    for target in _split_csv_values(raw_values):
        key = target.lower()
        if key in seen:
            continue
        seen.add(key)
        tables.append(target)
    return tables


def _split_table_name(value: str, fallback_database: str) -> tuple[str, str] | tuple[None, None]:
    raw = str(value or "").strip()
    if not raw:
        return None, None
    parts = _parse_identifier_path(raw)
    if parts is None:
        return None, None
    if len(parts) == 1:
        fallback_parts = _parse_identifier_path(fallback_database)
        if fallback_parts is None or len(fallback_parts) != 1:
            return None, None
        db_name, table_name = fallback_parts[0], parts[0]
    elif len(parts) == 2:
        db_name, table_name = parts
    else:
        return None, None
    return db_name, table_name


def _query_database_names(session: _ChSession) -> tuple[list[str] | None, str | None]:
    rows, error = _query_rows(session, "SELECT name FROM system.databases ORDER BY name")
    if error:
        return None, error
    names: list[str] = []
    for row in rows or []:
        if not row:
            continue
        names.append(str(row[0]))
    return names, None


def _query_readable_tables(session: _ChSession) -> tuple[list[str] | None, str | None]:
    rows, error = _query_rows(
        session,
        (
            "SELECT database, name FROM system.tables "
            "WHERE database NOT IN ('system','information_schema','INFORMATION_SCHEMA') "
            "ORDER BY database, name"
        ),
    )
    if error:
        return None, error

    tables: list[str] = []
    for row in rows or []:
        if len(row) < 2:
            continue
        tables.append(f"{row[0]}.{row[1]}")
    return tables, None


def _query_table_columns(
    session: _ChSession,
    db_name: str,
    table_name: str,
    *,
    only_columns: list[str] | None = None,
) -> tuple[list[str] | None, str | None]:
    sql = (
        "SELECT name FROM system.columns WHERE database = "
        f"{_quote_literal(db_name)} AND table = {_quote_literal(table_name)} ORDER BY position"
    )
    rows, error = _query_rows(session, sql)
    if error:
        return None, error

    allowed = {item.lower() for item in only_columns or []}
    columns: list[str] = []
    for row in rows or []:
        if not row:
            continue
        name = str(row[0])
        if allowed and name.lower() not in allowed:
            continue
        columns.append(name)
    return columns, None


def _row_text(values: list[Any]) -> str:
    def _normalize_value(value: Any) -> Any:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, dt.datetime):
            return value.isoformat()
        if isinstance(value, (dt.date, dt.time)):
            return value.isoformat()
        if isinstance(value, dt.timedelta):
            return str(value)
        if isinstance(value, (Decimal, UUID)):
            return str(value)
        if isinstance(value, dict):
            return {str(key): _normalize_value(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [_normalize_value(item) for item in value]
        if isinstance(value, set):
            return [_normalize_value(item) for item in sorted(value, key=lambda item: str(item))]
        return str(value)

    normalized = [_normalize_value(item) for item in values]
    return json.dumps(normalized, ensure_ascii=False)


def _query_table_rows(
    session: _ChSession,
    db_name: str,
    table_name: str,
    *,
    columns: list[str] | None = None,
    max_rows: int = _CH_MAX_DUMP_ROWS,
) -> tuple[list[str] | None, str | None]:
    if columns:
        select_part = ", ".join(_quote_ident(column) for column in columns)
    else:
        select_part = "*"
    sql = f"SELECT {select_part} FROM {_quote_ident(db_name)}.{_quote_ident(table_name)} LIMIT {max(1, int(max_rows))}"
    rows, error = _query_rows(session, sql)
    if error:
        return None, error
    return [_row_text(row) for row in rows or []], None


def _query_show_grants(session: _ChSession) -> tuple[list[str] | None, str | None]:
    rows, error = _query_rows(session, "SHOW GRANTS")
    if error:
        return None, error
    grants: list[str] = []
    for row in rows or []:
        if not row:
            continue
        grants.append(" ".join(str(item) for item in row if item is not None))
    return grants, None


def _collect_capabilities(
    session: _ChSession,
) -> tuple[bool | None, bool | None, bool | None, int | None, list[str] | None, str | None]:
    db_names, db_error = _query_database_names(session)
    db_count = len(db_names) if isinstance(db_names, list) else None

    grants, grants_error = _query_show_grants(session)
    read_cap: bool | None = None
    execute_cap: bool | None = None
    admin_cap: bool | None = None

    if isinstance(grants, list):
        grant_text = "\n".join(grants).upper()
        read_cap = any(token in grant_text for token in ("GRANT SELECT", "ALL", "READ", "SELECT ON"))
        admin_cap = any(
            token in grant_text
            for token in ("ACCESS MANAGEMENT", "ROLE ADMIN", "SYSTEM", "GRANT ALL", "ALL PRIVILEGES")
        )
    else:
        read_cap = None

    # Validate read capability with a lightweight probe to avoid false negatives
    # when SHOW GRANTS output does not explicitly include SELECT/READ text.
    read_probe_error: str | None = None
    probe_rows, probe_error = _query_rows(session, "SELECT name FROM system.tables LIMIT 1")
    if probe_error is None:
        _ = probe_rows
        read_probe_capability: bool | None = True
    else:
        lowered_probe_error = str(probe_error).lower()
        if (
            _is_auth_error(probe_error)
            or "not enough privileges" in lowered_probe_error
            or "required grant" in lowered_probe_error
        ):
            read_probe_capability = False
        else:
            read_probe_capability = None
            read_probe_error = str(probe_error)

    if read_probe_capability is True:
        read_cap = True
    elif read_cap is None:
        read_cap = read_probe_capability

    exec_output, exec_error = _run_execute_command(session, "echo redposture_exec_probe")
    if exec_error is None:
        _ = exec_output
        execute_cap = True
    else:
        lowered_exec_error = str(exec_error).lower()
        if (
            _is_auth_error(exec_error)
            or "not enough privileges" in lowered_exec_error
            or "required grant" in lowered_exec_error
            or "unknown table function executable" in lowered_exec_error
            or "unknown function executable" in lowered_exec_error
            or "does not exist inside user scripts folder" in lowered_exec_error
            or "table function executable does not exist" in lowered_exec_error
        ):
            execute_cap = False
        else:
            execute_cap = None

    merged_errors: list[str] = []
    for err in (
        db_error,
        grants_error,
        read_probe_error if read_cap is None else None,
        exec_error if execute_cap is None else None,
    ):
        if not err:
            continue
        clean = str(err).strip()
        if clean and clean not in merged_errors:
            merged_errors.append(clean)

    return read_cap, execute_cap, admin_cap, db_count, db_names, "; ".join(merged_errors) if merged_errors else None


def _run_sql_query(
    session: _ChSession, query: str, *, max_lines: int = _CH_MAX_SQL_LINES
) -> tuple[list[str], str | None]:
    rows, error = _query_rows(session, query)
    if error:
        return [], error
    output: list[str] = []
    for row in rows or []:
        output.append(_row_text(row))
        if len(output) >= max_lines:
            output.append(f"<output truncated at {max_lines} lines>")
            break
    return output, None


def _normalize_execute_command(command: str) -> str:
    normalized = str(command or "").strip().rstrip(";")
    return normalized


def _quote_sql_literal(value: str) -> str:
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def _build_os_exec_query(command: str) -> str:
    return (
        "SELECT output FROM executable("
        f"'{_CH_EXEC_SCRIPT}', "
        "'LineAsString', "
        "'output String', "
        f"(SELECT {_quote_sql_literal(command)})"
        ")"
    )


def _run_execute_command(
    session: _ChSession, command: str, *, max_lines: int = _CH_MAX_SQL_LINES
) -> tuple[list[str], str | None]:
    query = _normalize_execute_command(command)
    if not query:
        return [], "empty command"
    if query.upper().startswith("SYSTEM "):
        sql = query
    else:
        sql = _build_os_exec_query(query)
    rows, error = _query_rows(session, sql)
    if error:
        return [], error
    output: list[str] = []
    for row in rows or []:
        output.append(_row_text(row))
        if len(output) >= max_lines:
            output.append(f"<output truncated at {max_lines} lines>")
            break
    return output, None


def _open_operational_session(
    protocol: str,
    host: str,
    port: int,
    timeout: float,
    username: str,
    password: str,
    database: str,
) -> tuple[_ChSession | None, str | None]:
    session, error = _connect_and_probe(
        protocol,
        host,
        port,
        timeout,
        username,
        password,
        database=database,
    )
    if session is not None:
        return session, None

    if (
        database != "default"
        and error
        and any(token in error.lower() for token in ("unknown database", "database does not exist"))
    ):
        fallback, fallback_error = _connect_and_probe(
            protocol,
            host,
            port,
            timeout,
            username,
            password,
            database="default",
        )
        if fallback is not None:
            return fallback, f"database '{database}' unavailable; connected to default"
        return None, fallback_error or error

    return None, error


def _protocol_attempt_order(protocol: str) -> tuple[str, ...]:
    normalized = str(protocol or "native").strip().lower()
    if normalized == "http":
        return ("http",)
    if normalized == "auto":
        return ("native", "http")
    return ("native",)


def _audit_clickhouse_host_on_protocol(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    defcreds: bool,
    database: str,
    protocol: str,
    show_databases: bool,
    show_tables: bool,
    show_columns: bool,
    table_targets: list[str],
    table_columns: list[str],
    dump_table_rows: bool,
    execute_command: str | None,
    sql_command: str | None,
    dump_row_limit: int | None = None,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    provided_credentials = password is not None
    provided_credentials_ok: bool | None = False if provided_credentials else None
    candidates = _build_credential_candidates(username, password, defcreds)

    last_error: str | None = None

    for attempt in range(attempts):
        started = time.monotonic()
        auth_required: bool | None = None
        anonymous_ok = False
        auth_attempts: list[dict[str, Any]] = []
        attempted_credentials = 0
        effective_username: str | None = None
        effective_password: str | None = None
        credentials_source: str | None = None
        default_credentials = False

        anon_session, anon_error = _connect_and_probe(protocol, host, port, timeout, "default", "", database="default")
        if anon_session is not None:
            anonymous_ok = True
            auth_required = False
            _close_client(protocol, anon_session.client)
        else:
            last_error = anon_error or last_error
            if _is_auth_error(anon_error):
                auth_required = True
            elif _looks_like_clickhouse_error(anon_error):
                auth_required = None
            else:
                if attempt >= attempts - 1:
                    break
                time.sleep(_retry_delay(attempt))
                continue

        if provided_credentials and provided_credentials_ok is None:
            provided_credentials_ok = False

        for cand_user, cand_pass, source in candidates:
            attempted_credentials += 1
            cred_session, cred_error = _connect_and_probe(
                protocol,
                host,
                port,
                timeout,
                cand_user,
                cand_pass,
                database="default",
            )
            ok = cred_session is not None
            auth_attempts.append(
                {
                    "username": cand_user,
                    "password": cand_pass,
                    "source": source,
                    "ok": bool(ok),
                    "error": str(cred_error or ""),
                }
            )
            if ok and effective_username is None:
                effective_username = cand_user
                effective_password = cand_pass
                credentials_source = source
            if ok and source == "default":
                default_credentials = True
            if source == "provided" and ok:
                provided_credentials_ok = True
            if cred_session is not None:
                _close_client(protocol, cred_session.client)

        operation_username = effective_username if effective_username is not None else "default"
        operation_password = effective_password if effective_password is not None else ""
        operation_session: _ChSession | None = None
        operation_session_error: str | None = None

        if effective_username is not None:
            operation_session, operation_session_error = _open_operational_session(
                protocol,
                host,
                port,
                timeout,
                operation_username,
                operation_password,
                database,
            )
        elif anonymous_ok:
            operation_session, operation_session_error = _open_operational_session(
                protocol,
                host,
                port,
                timeout,
                "default",
                "",
                database,
            )

        database_names: list[str] | None = None
        database_count: int | None = None
        table_names: list[str] | None = None
        table_columns_info: list[dict[str, Any]] = []
        table_dumps: list[dict[str, Any]] = []
        sql_attempted = False
        sql_ok: bool | None = None
        sql_output: list[str] | None = None
        sql_error: str | None = None
        execute_attempted = False
        execute_ok: bool | None = None
        execute_output: list[str] | None = None
        execute_error: str | None = None

        read_capability: bool | None = None
        execute_capability: bool | None = None
        admin_capability: bool | None = None
        capability_error: str | None = None

        if operation_session is not None:
            (
                read_capability,
                execute_capability,
                admin_capability,
                database_count,
                database_names,
                capability_error,
            ) = _collect_capabilities(operation_session)

            if show_tables or (dump_table_rows and not table_targets):
                table_names, table_names_error = _query_readable_tables(operation_session)
                if table_names_error and not capability_error:
                    capability_error = table_names_error

            normalized_targets: list[str] = []
            normalized_target_pairs: list[tuple[str, str]] = []
            if table_targets:
                for raw_target in table_targets:
                    db_name, table_name = _split_table_name(raw_target, database)
                    if db_name is None or table_name is None:
                        table_columns_info.append(
                            {
                                "table": raw_target,
                                "columns": [],
                                "error": f"invalid table name: {raw_target}",
                            }
                        )
                        continue
                    normalized_target_pairs.append((db_name, table_name))
                    normalized_targets.append(f"{db_name}.{table_name}")
            elif dump_table_rows and isinstance(table_names, list):
                for table_name_full in table_names:
                    db_name, table_name = _split_table_name(table_name_full, database)
                    if db_name is None or table_name is None:
                        continue
                    normalized_target_pairs.append((db_name, table_name))
                    normalized_targets.append(f"{db_name}.{table_name}")

            if show_columns:
                for db_name, table_name in normalized_target_pairs:
                    columns, columns_error = _query_table_columns(
                        operation_session,
                        db_name,
                        table_name,
                        only_columns=table_columns,
                    )
                    table_columns_info.append(
                        {
                            "table": f"{db_name}.{table_name}",
                            "columns": columns or [],
                            "error": columns_error,
                        }
                    )

            if dump_table_rows:
                for db_name, table_name in normalized_target_pairs:
                    dump_columns: list[str] = []
                    dump_columns_error: str | None = None
                    if table_columns:
                        dump_columns = [str(column) for column in table_columns]
                    else:
                        dump_columns, dump_columns_error = _query_table_columns(
                            operation_session,
                            db_name,
                            table_name,
                            only_columns=None,
                        )
                    rows, dump_error = _query_table_rows(
                        operation_session,
                        db_name,
                        table_name,
                        columns=table_columns,
                        max_rows=dump_row_limit if dump_row_limit is not None else _CH_MAX_DUMP_ROWS,
                    )
                    combined_dump_error = dump_error
                    if dump_columns_error:
                        if combined_dump_error:
                            combined_dump_error = f"{combined_dump_error}; columns: {dump_columns_error}"
                        else:
                            combined_dump_error = f"columns: {dump_columns_error}"
                    table_dumps.append(
                        {
                            "table": f"{db_name}.{table_name}",
                            "columns": dump_columns or [],
                            "rows": rows or [],
                            "error": combined_dump_error,
                        }
                    )

            if sql_command:
                sql_attempted = True
                sql_output, sql_error = _run_sql_query(operation_session, sql_command)
                sql_ok = sql_error is None

            if execute_command:
                execute_attempted = True
                if execute_capability is False:
                    execute_ok = False
                    execute_output = []
                    execute_error = "insufficient privileges for OS command execution"
                else:
                    execute_output, execute_error = _run_execute_command(operation_session, execute_command)
                    execute_ok = execute_error is None

            if not table_targets and normalized_targets:
                table_targets = normalized_targets

            _close_client(protocol, operation_session.client)

        if effective_username is not None:
            status = "weak_default_creds" if credentials_source == "default" else "valid_credentials"
        elif auth_required is False and attempted_credentials > 0 and (provided_credentials or defcreds):
            status = "invalid_credentials_anonymous"
        elif auth_required is False:
            status = "open_no_auth"
        elif auth_required is True:
            status = "auth_required"
        else:
            status = "fail"

        errors: list[str] = []
        for err in (last_error, capability_error, operation_session_error, execute_error, sql_error):
            if not err:
                continue
            clean = str(err).strip()
            if clean and clean not in errors:
                errors.append(clean)

        return {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "protocol": protocol,
            "is_clickhouse": status != "fail",
            "status": status,
            "auth_required": auth_required,
            "database": database,
            "provided_credentials": provided_credentials,
            "provided_username": username,
            "provided_password": password,
            "provided_credentials_ok": provided_credentials_ok,
            "defcreds_enabled": defcreds,
            "default_credentials": default_credentials,
            "attempted_credentials": attempted_credentials,
            "credentials_source": credentials_source,
            "effective_username": effective_username,
            "effective_password": effective_password,
            "auth_attempts": auth_attempts,
            "show_databases": show_databases,
            "database_names": database_names,
            "database_count": database_count,
            "show_tables": show_tables,
            "table_names": table_names,
            "show_columns": show_columns,
            "table_targets": list(table_targets),
            "table_columns": list(table_columns),
            "table_columns_info": table_columns_info,
            "table_dump_enabled": dump_table_rows,
            "table_dump_limit": dump_row_limit,
            "table_dumps": table_dumps,
            "execute_command": execute_command,
            "execute_attempted": execute_attempted,
            "execute_ok": execute_ok,
            "execute_output": execute_output,
            "execute_error": execute_error,
            "sql_command": sql_command,
            "sql_attempted": sql_attempted,
            "sql_ok": sql_ok,
            "sql_output": sql_output,
            "sql_error": sql_error,
            "read_capability": read_capability,
            "execute_capability": execute_capability,
            "admin_capability": admin_capability,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": "; ".join(errors) if errors else None,
        }

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "protocol": protocol,
        "is_clickhouse": False,
        "status": "fail",
        "auth_required": None,
        "database": database,
        "provided_credentials": provided_credentials,
        "provided_username": username,
        "provided_password": password,
        "provided_credentials_ok": provided_credentials_ok,
        "defcreds_enabled": defcreds,
        "default_credentials": None,
        "attempted_credentials": 0,
        "credentials_source": None,
        "effective_username": None,
        "effective_password": None,
        "auth_attempts": [],
        "show_databases": show_databases,
        "database_names": None,
        "database_count": None,
        "show_tables": show_tables,
        "table_names": None,
        "show_columns": show_columns,
        "table_targets": list(table_targets),
        "table_columns": list(table_columns),
        "table_columns_info": [],
        "table_dump_enabled": dump_table_rows,
        "table_dump_limit": dump_row_limit,
        "table_dumps": [],
        "execute_command": execute_command,
        "execute_attempted": False,
        "execute_ok": None,
        "execute_output": None,
        "execute_error": None,
        "sql_command": sql_command,
        "sql_attempted": False,
        "sql_ok": None,
        "sql_output": None,
        "sql_error": None,
        "read_capability": None,
        "execute_capability": None,
        "admin_capability": None,
        "elapsed_ms": None,
        "error": last_error or "connection failed",
    }


def _audit_clickhouse_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    defcreds: bool,
    database: str,
    protocol: str,
    show_databases: bool,
    show_tables: bool,
    show_columns: bool,
    table_targets: list[str],
    table_columns: list[str],
    dump_table_rows: bool,
    execute_command: str | None,
    sql_command: str | None,
    dump_row_limit: int | None = None,
) -> dict[str, Any]:
    sequence = _protocol_attempt_order(protocol)
    last_record: dict[str, Any] | None = None
    for proto in sequence:
        try:
            record = _audit_clickhouse_host_on_protocol(
                host,
                port,
                timeout,
                retries,
                username,
                password,
                defcreds,
                database,
                proto,
                show_databases,
                show_tables,
                show_columns,
                list(table_targets),
                list(table_columns),
                dump_table_rows,
                execute_command,
                sql_command,
                dump_row_limit=dump_row_limit,
            )
        except TypeError as exc:
            if "dump_row_limit" not in str(exc):
                raise
            record = _audit_clickhouse_host_on_protocol(
                host,
                port,
                timeout,
                retries,
                username,
                password,
                defcreds,
                database,
                proto,
                show_databases,
                show_tables,
                show_columns,
                list(table_targets),
                list(table_columns),
                dump_table_rows,
                execute_command,
                sql_command,
            )
        last_record = record
        if bool(record.get("is_clickhouse")) and str(record.get("status") or "") != "fail":
            return record
    if last_record is not None:
        return last_record

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "protocol": protocol,
        "is_clickhouse": False,
        "status": "fail",
        "auth_required": None,
        "database": database,
        "provided_credentials": password is not None,
        "provided_username": username,
        "provided_password": password,
        "provided_credentials_ok": None,
        "defcreds_enabled": defcreds,
        "default_credentials": None,
        "attempted_credentials": 0,
        "credentials_source": None,
        "effective_username": None,
        "effective_password": None,
        "auth_attempts": [],
        "show_databases": show_databases,
        "database_names": None,
        "database_count": None,
        "show_tables": show_tables,
        "table_names": None,
        "show_columns": show_columns,
        "table_targets": list(table_targets),
        "table_columns": list(table_columns),
        "table_columns_info": [],
        "table_dump_enabled": dump_table_rows,
        "table_dump_limit": dump_row_limit,
        "table_dumps": [],
        "execute_command": execute_command,
        "execute_attempted": False,
        "execute_ok": None,
        "execute_output": None,
        "execute_error": None,
        "sql_command": sql_command,
        "sql_attempted": False,
        "sql_ok": None,
        "sql_output": None,
        "sql_error": None,
        "read_capability": None,
        "execute_capability": None,
        "admin_capability": None,
        "elapsed_ms": None,
        "error": "connection failed",
    }


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{'CLICKHOUSE':<10}\t{host}\t{port}\t"


def _caps_suffix(record: dict[str, Any]) -> str:
    read_text = _bool_text(record.get("read_capability"))
    execute_text = _bool_text(record.get("execute_capability"))
    admin_text = _bool_text(record.get("admin_capability"))
    db_count = record.get("database_count")
    if isinstance(db_count, int):
        db_count_text = str(db_count)
    else:
        db_names = record.get("database_names")
        db_count_text = str(len(db_names)) if isinstance(db_names, list) else "-"
    return f"(read:{read_text}) (execute:{execute_text}) (admin:{admin_text}) (DBs:{db_count_text})"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    auth_required_value = record.get("auth_required")
    auth_required_text = (
        "True" if auth_required_value is True else "False" if auth_required_value is False else "unknown"
    )
    if output_format == "json":
        return json.dumps(
            {
                "timestamp": record.get("timestamp"),
                "type": "detect",
                "host": record.get("host"),
                "port": record.get("port"),
                "service": "clickhouse",
                "protocol": record.get("protocol"),
                "detected": bool(record.get("is_clickhouse")),
                "auth_required": auth_required_value,
            },
            ensure_ascii=False,
        )
    return f"{_nxc_prefix(record)} [*] ClickHouse Database (auth required:{auth_required_text})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        payload = dict(record)
        payload.pop("provided_password", None)
        payload.pop("effective_password", None)
        payload.pop("auth_attempts", None)
        return json.dumps(payload, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 92)

    if status == "open_no_auth":
        return f"{prefix} [+] anonymous access {_caps_suffix(record)}"

    if status == "weak_default_creds":
        user = str(record.get("effective_username") or "default")
        password_text = _password_text(record.get("effective_password"))
        return f"{prefix} [+] {user}:{password_text} {_caps_suffix(record)}"

    if status == "valid_credentials":
        user = str(record.get("effective_username") or "default")
        password_text = _password_text(record.get("effective_password"))
        return f"{prefix} [+] {user}:{password_text} {_caps_suffix(record)}"

    if status == "invalid_credentials_anonymous":
        return f"{prefix} [-] credentials invalid (anonymous access) {_caps_suffix(record)}"

    if status == "auth_required":
        if int(record.get("attempted_credentials") or 0) > 0:
            return f"{prefix} [-] authentication required (credentials invalid)"
        return f"{prefix} [-] authentication required"

    fail_line = f"{prefix} [!] connection failed"
    if err != "-":
        return f"{fail_line} err={err}"
    return fail_line


def _format_auth_attempt_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []

    attempts_raw = record.get("auth_attempts")
    if not isinstance(attempts_raw, list) or not attempts_raw:
        return []

    attempts = [item for item in attempts_raw if isinstance(item, dict)]
    if not attempts:
        return []

    prefix = _nxc_prefix(record)
    lines: list[str] = []
    for attempt in attempts:
        user = str(attempt.get("username") or "default")
        password = _password_text(attempt.get("password"))
        if bool(attempt.get("ok")):
            lines.append(f"{prefix} [+] {user}:{password}")
        else:
            lines.append(f"{prefix} [-] {user}:{password}")
    return lines


def _format_databases_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if not bool(record.get("show_databases")):
        return []

    database_names = record.get("database_names")
    if not isinstance(database_names, list) or not database_names:
        return []
    raw_limit = record.get("show_databases_limit")
    limit = raw_limit if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) else None
    database_meta = limit_metadata(database_names, limit)
    displayed_database_names = limit_sequence(database_names, limit)

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "databases_dump",
                    "service": "clickhouse",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "database_count": len(database_names),
                    "databases": [str(item) for item in displayed_database_names],
                    "databases_shown": database_meta["shown"],
                    "databases_limit": database_meta["limit"],
                    "databases_truncated": database_meta["truncated"],
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    if limit is not None and len(database_names) > len(displayed_database_names):
        lines = [f"{prefix} [*] Dump Databases (showing:{len(displayed_database_names)} of {len(database_names)})"]
    else:
        lines = [f"{prefix} [*] Dump Databases"]
    for name in displayed_database_names:
        lines.append(f"{prefix} {str(name)}")
    return lines


def _format_tables_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if not bool(record.get("show_tables")):
        return []

    table_names = record.get("table_names")
    if not isinstance(table_names, list) or not table_names:
        return []
    raw_limit = record.get("show_tables_limit")
    limit = raw_limit if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) else None
    table_meta = limit_metadata(table_names, limit)
    displayed_table_names = limit_sequence(table_names, limit)

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "tables_dump",
                    "service": "clickhouse",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "table_count": len(table_names),
                    "tables": [str(item) for item in displayed_table_names],
                    "tables_shown": table_meta["shown"],
                    "tables_limit": table_meta["limit"],
                    "tables_truncated": table_meta["truncated"],
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    if limit is not None and len(table_names) > len(displayed_table_names):
        lines = [f"{prefix} [*] Dump Tables (showing:{len(displayed_table_names)} of {len(table_names)})"]
    else:
        lines = [f"{prefix} [*] Dump Tables"]
    for name in displayed_table_names:
        lines.append(f"{prefix} {str(name)}")
    return lines


def _format_table_columns_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    table_columns_info = record.get("table_columns_info")
    if not isinstance(table_columns_info, list) or not table_columns_info:
        return []
    raw_limit = record.get("show_columns_limit")
    limit = raw_limit if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) else None

    if output_format == "json":
        lines: list[str] = []
        for item in table_columns_info:
            if not isinstance(item, dict):
                continue
            columns = item.get("columns")
            column_names = [str(column) for column in columns] if isinstance(columns, list) else []
            column_meta = limit_metadata(column_names, limit)
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "table_columns",
                        "service": "clickhouse",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "table": str(item.get("table") or ""),
                        "columns": limit_sequence(column_names, limit),
                        "columns_shown": column_meta["shown"],
                        "columns_limit": column_meta["limit"],
                        "columns_truncated": column_meta["truncated"],
                        "error": str(item.get("error")) if item.get("error") else None,
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    prefix = _nxc_prefix(record)
    lines: list[str] = []
    for item in table_columns_info:
        if not isinstance(item, dict):
            continue
        table_name = str(item.get("table") or "").strip() or "<unknown>"
        lines.append(f"{prefix} [*] Table Columns {table_name}")
        item_error = item.get("error")
        if item_error:
            lines.append(f"{prefix} <error:{_clip(str(item_error), 160)}>")
            continue
        columns = item.get("columns")
        if isinstance(columns, list) and columns:
            column_names = [str(column) for column in columns]
            displayed_columns = limit_sequence(column_names, limit)
            if limit is not None and len(column_names) > len(displayed_columns):
                lines[-1] = (
                    f"{prefix} [*] Table Columns {table_name} (showing:{len(displayed_columns)} of {len(column_names)})"
                )
            for column in displayed_columns:
                lines.append(f"{prefix} {str(column)}")
        else:
            lines.append(f"{prefix} <no columns>")
    return lines


def _format_table_dump_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if not bool(record.get("table_dump_enabled")):
        return []

    table_dumps = record.get("table_dumps")
    if not isinstance(table_dumps, list) or not table_dumps:
        return []

    selected_columns = record.get("table_columns")
    selected_columns_text = (
        ",".join(str(item) for item in selected_columns)
        if isinstance(selected_columns, list) and selected_columns
        else ""
    )

    if output_format == "json":
        lines: list[str] = []
        for item in table_dumps:
            if not isinstance(item, dict):
                continue
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "table_dump",
                        "service": "clickhouse",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "table": str(item.get("table") or ""),
                        "columns": [str(col) for col in item.get("columns") or selected_columns or []],
                        "rows": [str(row) for row in item.get("rows") or []],
                        "error": str(item.get("error")) if item.get("error") else None,
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    prefix = _nxc_prefix(record)
    lines: list[str] = []
    for item in table_dumps:
        if not isinstance(item, dict):
            continue
        table_name = str(item.get("table") or "").strip() or "<unknown>"
        item_columns = [str(col) for col in item.get("columns") or []]
        header_columns = item_columns or [str(col) for col in selected_columns or []]
        if selected_columns_text:
            lines.append(f"{prefix} [*] Dump Table {table_name} (columns:{selected_columns_text})")
        elif item_columns:
            lines.append(f"{prefix} [*] Dump Table {table_name} (columns:auto)")
        else:
            lines.append(f"{prefix} [*] Dump Table {table_name}")
        if header_columns:
            lines.append(f"{prefix} [{', '.join(header_columns)}]")
        item_error = item.get("error")
        if item_error:
            lines.append(f"{prefix} <error:{_clip(str(item_error), 160)}>")
            continue
        rows = item.get("rows")
        if isinstance(rows, list) and rows:
            for row in rows:
                lines.append(f"{prefix} {str(row)}")
        else:
            lines.append(f"{prefix} <no rows>")
    return lines


def _format_execute_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    execute_command = record.get("execute_command")
    if not execute_command:
        return []
    if not bool(record.get("execute_attempted")):
        return []

    execute_ok = record.get("execute_ok")
    execute_output = record.get("execute_output")
    execute_error = record.get("execute_error")

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "execute_dump",
                    "service": "clickhouse",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "command": str(execute_command),
                    "ok": execute_ok,
                    "output": [str(item) for item in execute_output] if isinstance(execute_output, list) else [],
                    "error": str(execute_error) if execute_error else None,
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Execute Command", f"{prefix} command={str(execute_command)}"]
    if execute_ok is True:
        if isinstance(execute_output, list) and execute_output:
            for line in execute_output:
                lines.append(f"{prefix} {line}")
        else:
            lines.append(f"{prefix} <ok>")
    elif execute_ok is False:
        lines.append(f"{prefix} <error:{_clip(str(execute_error or 'execute failed'), 160)}>")
    else:
        lines.append(f"{prefix} <not attempted>")
    return lines


def _format_sql_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    sql_command = record.get("sql_command")
    if not sql_command:
        return []
    if not bool(record.get("sql_attempted")):
        return []

    sql_ok = record.get("sql_ok")
    sql_output = record.get("sql_output")
    sql_error = record.get("sql_error")

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "sql_dump",
                    "service": "clickhouse",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "query": str(sql_command),
                    "ok": sql_ok,
                    "output": [str(item) for item in sql_output] if isinstance(sql_output, list) else [],
                    "error": str(sql_error) if sql_error else None,
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] SQL Query", f"{prefix} query={str(sql_command)}"]
    if sql_ok is True:
        if isinstance(sql_output, list) and sql_output:
            for line in sql_output:
                lines.append(f"{prefix} {line}")
        else:
            lines.append(f"{prefix} <ok>")
    elif sql_ok is False:
        lines.append(f"{prefix} <error:{_clip(str(sql_error or 'query failed'), 160)}>")
    else:
        lines.append(f"{prefix} <not attempted>")
    return lines


def _render_colored_clickhouse_line(console: Console, line: str) -> bool:
    return render_colored_marker_line(
        console,
        line,
        tag="CLICKHOUSE",
        booleans=(
            BooleanColorRule("read"),
            BooleanColorRule("execute"),
            BooleanColorRule("admin"),
        ),
        counts=(CountColorRule("DBs", "orange"),),
    )


def _call_audit_clickhouse_host_with_stage_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    defcreds: bool,
    database: str,
    protocol: str,
    show_databases: bool,
    show_tables: bool,
    show_columns: bool,
    table_targets: list[str],
    table_columns: list[str],
    dump_table_rows: bool,
    execute_command: str | None,
    sql_command: str | None,
    show_databases_limit: int | None = None,
    show_tables_limit: int | None = None,
    show_columns_limit: int | None = None,
    *,
    port_protocols: list[tuple[int, str]] | None,
    run_deep_checks: bool,
    debug: bool,
    debug_emit: Callable[[str], None] | None,
    dump_row_limit: int | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    if port_protocols:
        record = _audit_clickhouse_host_with_port_fallback(
            host=host,
            port_protocols=list(port_protocols),
            timeout=timeout,
            retries=retries,
            username=username,
            password=password,
            defcreds=defcreds,
            database=database,
            show_databases=show_databases if run_deep_checks else False,
            show_tables=show_tables if run_deep_checks else False,
            show_columns=show_columns if run_deep_checks else False,
            table_targets=list(table_targets) if run_deep_checks else [],
            table_columns=list(table_columns) if run_deep_checks else [],
            dump_table_rows=dump_table_rows if run_deep_checks else False,
            dump_row_limit=dump_row_limit if run_deep_checks else None,
            execute_command=execute_command if run_deep_checks else None,
            sql_command=sql_command if run_deep_checks else None,
        )
    else:
        record = _audit_clickhouse_host(
            host=host,
            port=port,
            timeout=timeout,
            retries=retries,
            username=username,
            password=password,
            defcreds=defcreds,
            database=database,
            protocol=protocol,
            show_databases=show_databases if run_deep_checks else False,
            show_tables=show_tables if run_deep_checks else False,
            show_columns=show_columns if run_deep_checks else False,
            table_targets=list(table_targets) if run_deep_checks else [],
            table_columns=list(table_columns) if run_deep_checks else [],
            dump_table_rows=dump_table_rows if run_deep_checks else False,
            dump_row_limit=dump_row_limit if run_deep_checks else None,
            execute_command=execute_command if run_deep_checks else None,
            sql_command=sql_command if run_deep_checks else None,
        )

    record["show_databases_limit"] = show_databases_limit if run_deep_checks else None
    record["show_tables_limit"] = show_tables_limit if run_deep_checks else None
    record["show_columns_limit"] = show_columns_limit if run_deep_checks else None
    result: dict[str, Any] = dict(record)
    debug_events: list[str] = []

    def _debug(message: str) -> None:
        if not debug:
            return
        debug_events.append(message)
        if debug_emit is not None:
            debug_emit(f"{host}:{int(result.get('port') or port)} {message}")

    status = str(result.get("status") or "fail")
    is_clickhouse = bool(result.get("is_clickhouse"))
    attempts = max(1, retries + 1)
    elapsed_ms = int((time.monotonic() - started) * 1000)

    if attempts > 1 and status == "fail":
        _debug(
            f"retry_decision stage={_STAGE_DETECT_PROTOCOL} attempt=1/{attempts} "
            f"backoff={_retry_delay(0):.2f}s reason=error"
        )

    stages: list[dict[str, Any]] = []

    def _push_stage(stage_name: str, stage_result: str, stage_error: str | None = None, duration_ms: int = 0) -> None:
        entry = {
            "stage_name": stage_name,
            "attempt": 1,
            "duration_ms": int(max(0, duration_ms)),
            "result": stage_result,
            "error": stage_error or None,
        }
        stages.append(entry)
        _debug(
            f"stage_trace stage_name={stage_name} attempt=1 duration_ms={entry['duration_ms']} "
            f"result={stage_result} error={entry['error'] or '-'}"
        )

    detect_result = "ok" if is_clickhouse else ("error" if status == "fail" else "skip")
    detect_error = str(result.get("error") or "") if detect_result == "error" else None
    _push_stage(_STAGE_DETECT_PROTOCOL, detect_result, detect_error, 0)

    auth_result = (
        "ok" if is_clickhouse and status in _CLICKHOUSE_DEEP_STATUSES.union({"auth_required"}) else detect_result
    )
    _push_stage(_STAGE_AUTH_INFERENCE, auth_result, detect_error if auth_result == "error" else None, 0)

    if run_deep_checks and status in _CLICKHOUSE_DEEP_STATUSES:
        _push_stage(_STAGE_ACCESS_CAPABILITIES, "ok", None, 0)
        data_result = "error" if status == "fail" and result.get("error") else "ok"
        _push_stage(
            _STAGE_DATA, data_result, str(result.get("error") or "") if data_result == "error" else None, elapsed_ms
        )
    else:
        _push_stage(_STAGE_ACCESS_CAPABILITIES, "skip", "deep checks disabled", 0)
        _push_stage(_STAGE_DATA, "skip", "deep checks disabled", 0)

    stage_failed_at: str | None = None
    for stage_entry in stages:
        if str(stage_entry.get("result") or "") == "error":
            stage_failed_at = str(stage_entry.get("stage_name") or "")
            break

    stage_durations_ms = {str(item.get("stage_name") or ""): int(item.get("duration_ms") or 0) for item in stages}
    stage_attempts = {str(item.get("stage_name") or ""): attempts for item in stages}

    _debug(
        f"stage_timing_summary status={status} attempts=1/{attempts} "
        f"detect_ms={stage_durations_ms.get(_STAGE_DETECT_PROTOCOL, 0)} "
        f"auth_ms={stage_durations_ms.get(_STAGE_AUTH_INFERENCE, 0)} "
        f"capabilities_ms={stage_durations_ms.get(_STAGE_ACCESS_CAPABILITIES, 0)} "
        f"data_ms={stage_durations_ms.get(_STAGE_DATA, 0)} total_ms={elapsed_ms}"
    )

    result["stages"] = stages
    result["stage_failed_at"] = stage_failed_at
    result["stage_durations_ms"] = stage_durations_ms
    result["stage_attempts"] = stage_attempts
    result["debug_events"] = debug_events
    result["debug_events_streamed"] = bool(debug and debug_emit is not None)
    return result


def _merge_stage2_record(detect_record: dict[str, Any], deep_record: dict[str, Any]) -> dict[str, Any]:
    return merge_stage_records(detect_record, deep_record)


def _run_sql_query_once(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    protocol: str,
    username: str,
    password: str,
    database: str,
    query: str,
) -> tuple[list[str], str | None]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    for attempt in range(attempts):
        session, error = _open_operational_session(protocol, host, port, timeout, username, password, database)
        if session is None:
            last_error = error or last_error
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))
            continue
        output, query_error = _run_sql_query(session, query)
        _close_client(session.protocol, session.client)
        return output, query_error
    return [], last_error or "query failed"


def _run_execute_command_once(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    protocol: str,
    username: str,
    password: str,
    database: str,
    command: str,
) -> tuple[list[str], str | None]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    for attempt in range(attempts):
        session, error = _open_operational_session(protocol, host, port, timeout, username, password, database)
        if session is None:
            last_error = error or last_error
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))
            continue
        output, command_error = _run_execute_command(session, command)
        _close_client(session.protocol, session.client)
        return output, command_error
    return [], last_error or "execute failed"


def _resolve_port_protocols(protocol: str, base_port: int, multi_ports: list[int]) -> list[tuple[int, str]]:
    if multi_ports:
        return [(int(port), protocol) for port in dict.fromkeys(int(port) for port in multi_ports)]

    if protocol == "http":
        if int(base_port) == _CH_DEFAULT_NATIVE_PORT:
            return [(_CH_DEFAULT_HTTP_PORT, "http")]
        return [(int(base_port), "http")]

    return [(int(base_port), protocol)]


def _resolve_ports(protocol: str, base_port: int, multi_ports: list[int]) -> list[int]:
    return [port for port, _ in _resolve_port_protocols(protocol, base_port, multi_ports)]


def _audit_clickhouse_host_with_port_fallback(
    host: str,
    port_protocols: list[tuple[int, str]],
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    defcreds: bool,
    database: str,
    show_databases: bool,
    show_tables: bool,
    show_columns: bool,
    table_targets: list[str],
    table_columns: list[str],
    dump_table_rows: bool,
    execute_command: str | None,
    sql_command: str | None,
    dump_row_limit: int | None = None,
) -> dict[str, Any]:
    last_record: dict[str, Any] | None = None
    for port, protocol in port_protocols:
        if protocol == "auto":
            record = _audit_clickhouse_host(
                host=host,
                port=port,
                timeout=timeout,
                retries=retries,
                username=username,
                password=password,
                defcreds=defcreds,
                database=database,
                protocol=protocol,
                show_databases=show_databases,
                show_tables=show_tables,
                show_columns=show_columns,
                table_targets=list(table_targets),
                table_columns=list(table_columns),
                dump_table_rows=dump_table_rows,
                dump_row_limit=dump_row_limit,
                execute_command=execute_command,
                sql_command=sql_command,
            )
        else:
            dump_kwargs = {"dump_row_limit": dump_row_limit} if dump_row_limit is not None else {}
            record = _audit_clickhouse_host_on_protocol(
                host=host,
                port=port,
                timeout=timeout,
                retries=retries,
                username=username,
                password=password,
                defcreds=defcreds,
                database=database,
                protocol=protocol,
                show_databases=show_databases,
                show_tables=show_tables,
                show_columns=show_columns,
                table_targets=list(table_targets),
                table_columns=list(table_columns),
                dump_table_rows=dump_table_rows,
                execute_command=execute_command,
                sql_command=sql_command,
                **dump_kwargs,
            )
        last_record = record
        if bool(record.get("is_clickhouse")) and str(record.get("status") or "") != "fail":
            return record

    if last_record is not None:
        return last_record

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port_protocols[0][0] if port_protocols else _CH_DEFAULT_NATIVE_PORT,
        "protocol": port_protocols[0][1] if port_protocols else "native",
        "is_clickhouse": False,
        "status": "fail",
        "auth_required": None,
        "database": database,
        "provided_credentials": password is not None,
        "provided_username": username,
        "provided_password": password,
        "provided_credentials_ok": None,
        "defcreds_enabled": defcreds,
        "default_credentials": None,
        "attempted_credentials": 0,
        "credentials_source": None,
        "effective_username": None,
        "effective_password": None,
        "auth_attempts": [],
        "show_databases": show_databases,
        "database_names": None,
        "database_count": None,
        "show_tables": show_tables,
        "table_names": None,
        "show_columns": show_columns,
        "table_targets": list(table_targets),
        "table_columns": list(table_columns),
        "table_columns_info": [],
        "table_dump_enabled": dump_table_rows,
        "table_dump_limit": dump_row_limit,
        "table_dumps": [],
        "execute_command": execute_command,
        "execute_attempted": False,
        "execute_ok": None,
        "execute_output": None,
        "execute_error": None,
        "sql_command": sql_command,
        "sql_attempted": False,
        "sql_ok": None,
        "sql_output": None,
        "sql_error": None,
        "read_capability": None,
        "execute_capability": None,
        "admin_capability": None,
        "elapsed_ms": None,
        "error": "connection failed",
    }


# Typed runner boundary -----------------------------------------------------
host_stage = _call_audit_clickhouse_host_with_stage_debug
