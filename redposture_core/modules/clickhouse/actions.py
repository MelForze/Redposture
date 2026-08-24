"""ClickHouse audit stage."""

from __future__ import annotations

import datetime as dt
import json
import logging
import random
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any
from uuid import UUID

from ...clients import transport
from ...console import Console
from ...rendering import (
    BooleanColorRule,
    CountColorRule,
    format_count_value,
    render_colored_marker_line,
    render_tagged_detail_line,
)
from ...show_limits import (
    limit_metadata,
    limit_sequence,
)
from ...stage_runtime import (
    StageTelemetryBuilder,
    format_retry_decision,
    merge_stage_records,
)
from ...utils import (
    is_signature_compat_typeerror,
    utc_now_iso,
)

# Connection-error classification + framed reads are shared via the transport layer.
_is_timeout_error = transport.is_connection_timeout
_is_connection_refused_error = transport.is_connection_refused
_is_connection_timeout_fail_record = transport.is_connection_timeout_fail_record
_is_connection_refused_fail_record = transport.is_connection_refused_fail_record

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
    "anonymous_limited",
    "weak_default_creds",
    "valid_credentials",
    "invalid_credentials_anonymous",
}
_CLICKHOUSE_AUTH_ERROR_CODES = {192, 193, 194, 195, 516}
_CLICKHOUSE_ACCESS_DENIED_CODE = 497
_CLICKHOUSE_UNKNOWN_DATABASE_CODE = 81
_CLICKHOUSE_HTTP_EXCEPTION_MARKER = "received clickhouse exception, code:"
_CLICKHOUSE_ERROR_CODE_RE = re.compile(r"\bcode:\s*(\d+)\b", re.IGNORECASE)


class _ChProbeError(str):
    """String-compatible probe error with evidence retained for detection."""

    kind: str
    confirms_service: bool
    retryable: bool
    auth_required: bool | None
    access_limited: bool
    code: int | None

    def __new__(
        cls,
        message: str,
        *,
        kind: str,
        confirms_service: bool = False,
        retryable: bool = False,
        auth_required: bool | None = None,
        access_limited: bool = False,
        code: int | None = None,
    ) -> _ChProbeError:
        instance = str.__new__(cls, message)
        instance.kind = kind
        instance.confirms_service = confirms_service
        instance.retryable = retryable
        instance.auth_required = auth_required
        instance.access_limited = access_limited
        instance.code = code
        return instance


@dataclass
class _ChSession:
    protocol: str
    client: Any
    username: str
    password: str
    database: str
    check_grant_supported: bool | None = None


@dataclass
class _ChProbeResult:
    """Typed result of opening and validating one ClickHouse session."""

    kind: str
    code: int | None = None
    confirms_service: bool = False
    retryable: bool = False
    auth_required: bool | None = None
    access_limited: bool = False
    session: _ChSession | None = None
    error: _ChProbeError | None = None

    def __iter__(self):
        """Keep tuple-unpacking compatibility for older internal callers/tests."""

        yield self.session
        yield self.error


def _probe_result(session: _ChSession | None, error: Any = None) -> _ChProbeResult:
    """Normalize a session/error pair into the public internal probe model."""

    if error is None and session is not None:
        return _ChProbeResult(kind="success", confirms_service=True, session=session)
    info = _probe_error_info(error)
    return _ChProbeResult(
        kind=info.kind,
        code=info.code,
        confirms_service=info.confirms_service,
        retryable=info.retryable,
        auth_required=info.auth_required,
        access_limited=info.access_limited,
        session=session,
        error=info,
    )


def _coerce_probe_result(value: Any) -> _ChProbeResult:
    if isinstance(value, _ChProbeResult):
        return value
    if isinstance(value, tuple) and len(value) == 2:
        return _probe_result(value[0], value[1])
    raise TypeError("invalid ClickHouse probe result")


@dataclass(frozen=True)
class _ChTlsConfig:
    enabled: bool = False
    verify: bool = True
    ca_file: str | None = None
    cert_file: str | None = None
    key_file: str | None = None
    server_name: str | None = None


def _ch_transport_kwargs(
    tls_config: _ChTlsConfig | None,
    proxy: Any | None,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if tls_config is not None and (
        tls_config.enabled
        or tls_config.ca_file
        or tls_config.cert_file
        or tls_config.key_file
        or tls_config.server_name
        or not tls_config.verify
    ):
        kwargs["tls_config"] = tls_config
    if proxy is not None and str(getattr(proxy, "raw_url", proxy) or "").strip():
        kwargs["proxy"] = proxy
    return kwargs


def _ch_transport_from_context(ctx: Any) -> tuple[_ChTlsConfig | None, Any | None]:
    args = ctx.args
    tls = _ChTlsConfig(
        enabled=bool(getattr(args, "tls", False)),
        verify=not bool(getattr(args, "insecure", False)),
        ca_file=getattr(args, "tls_ca", None),
        cert_file=getattr(args, "tls_cert", None),
        key_file=getattr(args, "tls_key", None),
        server_name=getattr(args, "tls_server_name", None),
    )
    proxy = getattr(args, "_proxy_config", getattr(args, "proxy", None))
    return tls, proxy


@dataclass
class ClickHouseLifecycleState:
    """Per-target sessions shared across detect/auth/data hooks."""

    anonymous_session: _ChSession | None = None
    credential_sessions: dict[tuple[str | None, str | None, str], _ChSession] = field(default_factory=dict)
    auth_attempts: list[dict[str, Any]] = field(default_factory=list)
    selected_protocol: str | None = None
    auth_required: bool | None = None
    anonymous_access_limited: bool = False
    credential_limited: set[tuple[str | None, str | None, str]] = field(default_factory=set)

    def take_session(self, username: str | None, password: str | None, source: str) -> _ChSession | None:
        return self.credential_sessions.pop((username, password, source), None)

    def close(self) -> None:
        sessions = list(self.credential_sessions.values())
        self.credential_sessions.clear()
        self.credential_limited.clear()
        if self.anonymous_session is not None:
            sessions.append(self.anonymous_session)
            self.anonymous_session = None
        seen: set[int] = set()
        for session in sessions:
            marker = id(session.client)
            if marker in seen:
                continue
            seen.add(marker)
            _close_client(session.protocol, session.client)


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


def _retry_delay(
    attempt_index: int,
    *,
    jitter: Callable[[float, float], float] | None = None,
) -> float:
    jitter_fn = jitter or random.uniform
    return min(1.50, 0.20 * (2**attempt_index) * float(jitter_fn(0.8, 1.2)))


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
    class_name = exc.__class__.__name__
    if class_name == "SocketTimeoutError":
        return _clip(f"connection timeout: {text}", 180)
    if class_name == "NetworkError":
        return _clip(f"network error: {text}", 180)
    if isinstance(exc, TimeoutError) or "timed out" in lower or "timeout" in lower:
        return "connection timeout"
    if "connection refused" in lower or "[errno 111]" in lower:
        return "connection refused (service is not listening on target port)"
    return _clip(text, 180)


def _should_emit_status_line(record: dict[str, Any], output_format: str) -> bool:
    if output_format != "txt":
        return True
    return str(record.get("status") or "") not in {"auth_required", "open_no_auth"}


def _is_auth_error(value: Any) -> bool:
    if isinstance(value, _ChProbeError):
        return value.auth_required is True
    text = str(value or "").strip()
    code = _error_code(text)
    return bool(
        code in _CLICKHOUSE_AUTH_ERROR_CODES
        and any(marker in text.lower() for marker in ("authentication", "password", "user", "access denied"))
    )


def _looks_like_clickhouse_error(value: Any) -> bool:
    return _probe_error_info(value).confirms_service


def _error_code(value: Any) -> int | None:
    raw_code = getattr(value, "code", None)
    if isinstance(raw_code, int):
        return raw_code
    match = _CLICKHOUSE_ERROR_CODE_RE.search(str(value or ""))
    return int(match.group(1)) if match else None


def _probe_error_info(value: Any) -> _ChProbeError:
    if isinstance(value, _ChProbeError):
        return value
    text = str(value or "").strip() or "connection failed"
    lower = text.lower()
    code = _error_code(text)
    if _CLICKHOUSE_HTTP_EXCEPTION_MARKER in lower:
        access_limited = code == _CLICKHOUSE_ACCESS_DENIED_CODE
        auth_required = True if code in _CLICKHOUSE_AUTH_ERROR_CODES else None
        return _ChProbeError(
            text,
            kind="access_limited" if access_limited else "auth" if auth_required else "server_exception",
            confirms_service=True,
            auth_required=auth_required,
            access_limited=access_limited,
            code=code,
        )
    retryable_markers = (
        "connection reset",
        "connection closed",
        "broken pipe",
        "unexpected eof",
        "temporarily unavailable",
        "network unreachable",
        "no route to host",
    )
    if (
        _is_timeout_error(text)
        or _is_connection_refused_error(text)
        or any(marker in lower for marker in retryable_markers)
    ):
        return _ChProbeError(text, kind="transport", retryable=True, code=code)
    return _ChProbeError(text, kind="client_error", code=code)


def _classify_clickhouse_exception(exc: BaseException, protocol: str) -> _ChProbeError:
    text = _friendly_error_from_exception(exc)
    lower = str(exc or "").lower()
    class_name = exc.__class__.__name__
    module_name = exc.__class__.__module__
    code = _error_code(exc)

    if module_name.startswith("clickhouse_driver"):
        if class_name == "ServerException":
            access_limited = code == _CLICKHOUSE_ACCESS_DENIED_CODE
            auth_required = True if code in _CLICKHOUSE_AUTH_ERROR_CODES else None
            return _ChProbeError(
                text,
                kind="access_limited" if access_limited else "auth" if auth_required else "server_exception",
                confirms_service=True,
                auth_required=auth_required,
                access_limited=access_limited,
                code=code,
            )
        if class_name in {"UnexpectedPacketFromServerError", "UnknownPacketFromServerError"}:
            return _ChProbeError(text, kind="protocol_mismatch", code=code)
        if class_name in {"SocketTimeoutError", "NetworkError"}:
            return _ChProbeError(text, kind="transport", retryable=True, code=code)

    if protocol == "http" and _CLICKHOUSE_HTTP_EXCEPTION_MARKER in lower:
        access_limited = code == _CLICKHOUSE_ACCESS_DENIED_CODE
        auth_required = True if code in _CLICKHOUSE_AUTH_ERROR_CODES else None
        return _ChProbeError(
            text,
            kind="access_limited" if access_limited else "auth" if auth_required else "server_exception",
            confirms_service=True,
            auth_required=auth_required,
            access_limited=access_limited,
            code=code,
        )
    if (
        protocol == "http"
        and module_name.startswith("clickhouse_connect")
        and ("http driver received http status" in lower or class_name == "DatabaseError")
    ):
        return _ChProbeError(text, kind="not_clickhouse", code=code)
    if (
        isinstance(exc, (TimeoutError, ConnectionError, OSError))
        or _is_timeout_error(text)
        or _is_connection_refused_error(text)
        or (module_name.startswith("clickhouse_connect") and class_name == "OperationalError")
    ):
        return _ChProbeError(text, kind="transport", retryable=True, code=code)
    return _ChProbeError(text, kind="client_error", code=code)


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
    *,
    tls_config: _ChTlsConfig | None = None,
    proxy: Any | None = None,
) -> Any:
    tls = tls_config or _ChTlsConfig()
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
        if tls.enabled:
            kwargs.update(
                {
                    "secure": True,
                    "verify": tls.verify,
                    "ca_certs": tls.ca_file,
                    "certfile": tls.cert_file,
                    "keyfile": tls.key_file,
                    "server_hostname": tls.server_name or host,
                }
            )
            kwargs = {key: value for key, value in kwargs.items() if value is not None}
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
            "interface": "https" if tls.enabled else "http",
            "secure": tls.enabled,
            "connect_timeout": float(timeout),
            "send_receive_timeout": float(timeout),
        }
        if tls.enabled:
            kwargs.update(
                {
                    "verify": tls.verify,
                    "ca_cert": tls.ca_file,
                    "client_cert": tls.cert_file,
                    "client_cert_key": tls.key_file,
                    "server_host_name": tls.server_name or host,
                }
            )
        raw_proxy = str(getattr(proxy, "raw_url", proxy) or "").strip()
        if raw_proxy:
            kwargs["https_proxy" if tls.enabled else "http_proxy"] = raw_proxy
        kwargs = {key: value for key, value in kwargs.items() if value is not None}
        try:
            return clickhouse_connect.get_client(**kwargs)
        except TypeError as exc:
            if not is_signature_compat_typeerror(exc, expected_keywords={"connect_timeout", "send_receive_timeout"}):
                raise
            unsupported = "send_receive_timeout" if "send_receive_timeout" in str(exc) else "connect_timeout"
            kwargs.pop(unsupported, None)
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
    tls_config: _ChTlsConfig | None = None,
    proxy: Any | None = None,
) -> _ChProbeResult:
    client: Any | None = None
    try:
        client = _open_clickhouse_client(
            protocol,
            host,
            port,
            timeout,
            username,
            password,
            database,
            **_ch_transport_kwargs(tls_config, proxy),
        )
        session = _ChSession(
            protocol=protocol,
            client=client,
            username=username,
            password=password,
            database=database,
        )
        try:
            if protocol == "native":
                client.execute("SELECT 1")
            else:
                client.query("SELECT 1")
        except Exception as exc:
            error = _classify_clickhouse_exception(exc, protocol)
            if error.access_limited:
                return _probe_result(session, error)
            _close_client(protocol, client)
            return _probe_result(None, error)
        return _probe_result(session)
    except Exception as exc:
        if client is not None:
            _close_client(protocol, client)
        return _probe_result(None, _classify_clickhouse_exception(exc, protocol))


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
        defaults = (
            ("admin", "admin"),
            ("admin", "changeme"),
            ("admin", "password"),
            ("clickhouse", "clickhouse"),
            ("clickhouse", "password"),
            ("default", ""),
            ("default", "changeme"),
            ("default", "clickhouse"),
            ("default", "default"),
            ("default", "password"),
            ("root", "password"),
            ("root", "root"),
            ("user", "password"),
            ("user", "user"),
        )
        for user, secret in defaults:
            pair = (user, secret)
            if pair in seen:
                continue
            candidates.append((user, secret, "default"))
            seen.add(pair)

    return candidates


def _normalize_credential_candidates(
    username: str | None,
    password: str | None,
    defcreds: bool,
    credential_candidates: list[dict[str, Any]] | None,
) -> list[tuple[str, str, str]]:
    """Use a caller-owned ordered batch without expanding defaults again."""

    if credential_candidates is None:
        return _build_credential_candidates(username, password, defcreds)

    normalized: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for candidate in credential_candidates:
        raw_username = candidate.get("username")
        raw_password = candidate.get("password")
        if raw_username is None and raw_password is None:
            continue
        effective_username = str(raw_username or "default").strip() or "default"
        effective_password = "" if raw_password is None else str(raw_password)
        source = str(candidate.get("source") or "provided")
        if source == "anonymous":
            source = "provided"
        pair = (effective_username, effective_password)
        if pair in seen:
            continue
        seen.add(pair)
        normalized.append((effective_username, effective_password, source))
    return normalized


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


def _server_limit_clause(limit: int | None) -> str:
    return f" LIMIT {max(0, int(limit)) + 1}" if isinstance(limit, int) else ""


def _query_database_names(
    session: _ChSession,
    limit: int | None = None,
) -> tuple[list[str] | None, str | None]:
    rows, error = _query_rows(
        session,
        "SELECT name FROM system.databases ORDER BY name" + _server_limit_clause(limit),
    )
    if error:
        return None, error
    names: list[str] = []
    for row in rows or []:
        if not row:
            continue
        names.append(str(row[0]))
    return names, None


def _query_database_count(session: _ChSession) -> tuple[int | None, str | None]:
    rows, error = _query_rows(session, "SELECT count() FROM system.databases")
    if error:
        return None, error
    try:
        return int((rows or [[None]])[0][0]), None
    except (IndexError, TypeError, ValueError):
        return None, "invalid database count response"


def _query_visible_tables(
    session: _ChSession,
    limit: int | None = None,
) -> tuple[list[str] | None, str | None]:
    rows, error = _query_rows(
        session,
        (
            "SELECT database, name FROM system.tables "
            "WHERE database NOT IN ('system','information_schema','INFORMATION_SCHEMA') "
            "ORDER BY database, name" + _server_limit_clause(limit)
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


def _is_access_denied_error(error: Any) -> bool:
    text = str(error or "").lower()
    return _error_code(error) == _CLICKHOUSE_ACCESS_DENIED_CODE or any(
        marker in text for marker in ("not enough privileges", "required grant", "access denied")
    )


def _check_table_read_access(
    session: _ChSession,
    db_name: str,
    table_name: str,
) -> tuple[bool | None, str | None]:
    table_ref = f"{_quote_ident(db_name)}.{_quote_ident(table_name)}"
    if session.check_grant_supported is not False:
        rows, error = _query_rows(session, f"CHECK GRANT SELECT ON {table_ref}")
        if error is None:
            session.check_grant_supported = True
            if rows and rows[0]:
                return bool(rows[0][0]), None
            return True, None
        if _is_access_denied_error(error):
            session.check_grant_supported = True
            return False, None
        if _error_code(error) in {48, 62}:
            session.check_grant_supported = False
        else:
            return None, error

    _rows, fallback_error = _query_rows(session, f"SELECT * FROM {table_ref} LIMIT 0")
    if fallback_error is None:
        return True, None
    if _is_access_denied_error(fallback_error):
        return False, None
    return None, fallback_error


def _query_readable_tables_result(
    session: _ChSession,
    limit: int | None = None,
) -> tuple[list[str] | None, list[dict[str, Any]], bool, list[str]]:
    visible, error = _query_visible_tables(session, limit)
    if error:
        return None, [], False, [error]
    raw_visible = list(visible or [])
    truncated = isinstance(limit, int) and len(raw_visible) > limit
    checked = raw_visible[:limit] if isinstance(limit, int) else raw_visible
    readable: list[str] = []
    access: list[dict[str, Any]] = []
    errors: list[str] = []
    for full_name in checked:
        db_name, table_name = _split_table_name(full_name, session.database)
        if db_name is None or table_name is None:
            access.append({"table": full_name, "readable": "unknown"})
            errors.append(f"invalid table name returned by server: {full_name}")
            continue
        verdict, access_error = _check_table_read_access(session, db_name, table_name)
        access.append({"table": full_name, "readable": verdict if verdict is not None else "unknown"})
        if verdict is True:
            readable.append(full_name)
        if access_error:
            errors.append(f"{full_name}: {access_error}")
    return readable, access, truncated, errors


def _query_readable_tables(
    session: _ChSession,
    limit: int | None = None,
    *,
    detailed: bool = False,
) -> Any:
    result = _query_readable_tables_result(session, limit)
    if detailed:
        return result
    readable, _access, _truncated, errors = result
    return readable, "; ".join(errors) if errors else None


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


def _parse_clickhouse_grants(grants: list[str]) -> tuple[bool, bool]:
    """Return (user_data_read, administrative) from structured GRANT parts.

    Privileges are parsed only from the segment between GRANT and ON.  This is
    deliberately different from substring matching: ``system.tables`` is an
    object scope and must not be interpreted as the ``SYSTEM`` privilege.
    """

    can_read_user_data = False
    administrative = False
    for raw in grants:
        text = " ".join(str(raw or "").strip().upper().split())
        match = re.match(r"^GRANT\s+(.+?)\s+ON\s+(.+?)(?:\s+TO\s+|$)", text)
        if not match:
            continue
        privilege_text, scope = match.groups()
        privileges = [item.strip() for item in privilege_text.split(",") if item.strip()]
        scope_name = re.sub(r"[`\"]", "", scope.strip())
        scope_name = re.sub(r"\s*\.\s*", ".", scope_name)
        system_only = scope_name == "SYSTEM" or scope_name.startswith("SYSTEM.")
        global_scope = scope_name in {"*", "*.*"}
        for privilege in privileges:
            normalized = privilege.removesuffix(" WITH GRANT OPTION").strip()
            if (
                normalized in {"ACCESS MANAGEMENT", "ROLE ADMIN"}
                or normalized.startswith("SYSTEM ")
                or (normalized in {"ALL", "ALL PRIVILEGES"} and global_scope)
            ):
                administrative = True
            if normalized in {"ALL", "ALL PRIVILEGES", "SELECT", "READ"} and not system_only:
                can_read_user_data = True
    return can_read_user_data, administrative


def _collect_capabilities(
    session: _ChSession,
    *,
    include_database_names: bool = True,
) -> tuple[bool | None, bool | None, bool | None, int | None, list[str] | None, str | None]:
    if include_database_names:
        db_names, db_error = _query_database_names(session)
        db_count = len(db_names) if isinstance(db_names, list) else None
    else:
        db_count, db_error = _query_database_count(session)
        db_names = None

    grants, grants_error = _query_show_grants(session)
    read_cap: bool | None = None
    execute_cap: bool | None = None
    admin_cap: bool | None = None

    if isinstance(grants, list):
        read_cap, admin_cap = _parse_clickhouse_grants(grants)
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

    # system.tables is metadata, not proof that user tables are readable.  It
    # can enrich diagnostics but must not promote read_capability to True.
    if read_cap is None and read_probe_capability is False:
        read_probe_error = read_probe_error or "system.tables metadata probe denied"

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
    output: list[str] = []
    stream: Any = None
    stream_owner: Any = None
    try:
        if session.protocol == "native" and callable(getattr(session.client, "execute_iter", None)):
            stream = session.client.execute_iter(query)
        elif session.protocol == "http" and callable(getattr(session.client, "query_rows_stream", None)):
            stream_owner = session.client.query_rows_stream(query)
            stream = stream_owner.__enter__() if hasattr(stream_owner, "__enter__") else stream_owner
        else:
            rows, error = _query_rows(session, query)
            if error:
                return [], error
            stream = iter(rows or [])

        for row_number, row in enumerate(stream):
            if row_number >= max_lines:
                output.append(f"<output truncated at {max_lines} lines>")
                break
            values = list(row) if isinstance(row, (list, tuple)) else [row]
            output.append(_row_text(values))
        return output, None
    except Exception as exc:
        return [], _friendly_error_from_exception(exc)
    finally:
        if stream_owner is not None and hasattr(stream_owner, "__exit__"):
            try:
                stream_owner.__exit__(None, None, None)
            except Exception:
                pass
        elif stream is not None:
            close = getattr(stream, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass


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
    *,
    tls_config: _ChTlsConfig | None = None,
    proxy: Any | None = None,
) -> tuple[_ChSession | None, str | None]:
    result = _coerce_probe_result(
        _connect_and_probe(
            protocol,
            host,
            port,
            timeout,
            username,
            password,
            database=database,
            **_ch_transport_kwargs(tls_config, proxy),
        )
    )
    session, error = result.session, result.error
    if session is not None:
        return session, str(error) if result.access_limited and error else None

    if database != "default" and result.code == _CLICKHOUSE_UNKNOWN_DATABASE_CODE:
        fallback_result = _coerce_probe_result(
            _connect_and_probe(
                protocol,
                host,
                port,
                timeout,
                username,
                password,
                database="default",
                **_ch_transport_kwargs(tls_config, proxy),
            )
        )
        fallback, fallback_error = fallback_result.session, fallback_result.error
        if fallback is not None:
            return fallback, f"database '{database}' unavailable; connected to default"
        return None, str(fallback_error or error)

    return None, str(error) if error else None


def _protocol_attempt_order(protocol: str, port: int | None = None) -> tuple[str, ...]:
    normalized = str(protocol or "native").strip().lower()
    if normalized == "http":
        return ("http",)
    if normalized == "auto":
        if int(port or 0) in {_CH_DEFAULT_HTTP_PORT, 18123, 8443}:
            return ("http", "native")
        return ("native", "http")
    return ("native", "http")


def _run_clickhouse_actions_on_session(
    operation_session: _ChSession,
    *,
    database: str,
    show_databases: bool = False,
    show_tables: bool,
    show_columns: bool,
    table_targets: list[str],
    table_columns: list[str],
    dump_table_rows: bool,
    dump_row_limit: int | None,
    execute_command: str | None,
    sql_command: str | None,
    show_databases_limit: int | None = None,
    show_tables_limit: int | None = None,
    limited_session: bool = False,
) -> dict[str, Any]:
    if limited_session:
        read_capability = execute_capability = admin_capability = None
        database_count = None
        capability_error = None
    else:
        try:
            capability_values = _collect_capabilities(operation_session, include_database_names=False)
        except TypeError as exc:
            if "include_database_names" not in str(exc):
                raise
            capability_values = _collect_capabilities(operation_session)
        (
            read_capability,
            execute_capability,
            admin_capability,
            database_count,
            _unused_database_names,
            capability_error,
        ) = capability_values

    database_names: list[str] | None = None
    table_names: list[str] | None = None
    table_access: list[dict[str, Any]] = []
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
    action_statuses = {
        "databases": "not_requested",
        "tables": "not_requested",
        "columns": "not_requested",
        "dump": "not_requested",
        "sql": "not_requested",
        "execute": "not_requested",
    }
    partial_reasons: list[str] = []

    def _reason(message: str) -> None:
        clean = str(message or "").strip()
        if clean and clean not in partial_reasons:
            partial_reasons.append(clean)

    if show_databases:
        database_names, database_error = _query_database_names(operation_session, show_databases_limit)
        if database_error:
            action_statuses["databases"] = "error"
            _reason(f"databases: {database_error}")
        else:
            db_truncated = bool(
                isinstance(show_databases_limit, int)
                and isinstance(database_names, list)
                and len(database_names) > show_databases_limit
            )
            if db_truncated:
                database_names = list(database_names or [])[:show_databases_limit]
                action_statuses["databases"] = "partial"
                _reason("databases: result truncated by requested limit")
            else:
                action_statuses["databases"] = "ok"
            if database_count is None and isinstance(database_names, list) and not db_truncated:
                database_count = len(database_names)

    if show_tables or (dump_table_rows and not table_targets):
        effective_table_limit = show_tables_limit if show_tables else None
        table_result = _query_readable_tables(operation_session, effective_table_limit, detailed=True)
        if len(table_result) == 2:
            legacy_tables, legacy_error = table_result
            table_names = legacy_tables
            table_access = [{"table": name, "readable": True} for name in (legacy_tables or [])]
            tables_truncated = False
            table_errors = [str(legacy_error)] if legacy_error else []
        else:
            table_names, table_access, tables_truncated, table_errors = table_result
        if show_tables:
            if table_errors and not table_access:
                action_statuses["tables"] = "error"
            elif table_errors or tables_truncated:
                action_statuses["tables"] = "partial"
            else:
                action_statuses["tables"] = "ok"
            for table_error in table_errors:
                _reason(f"tables: {table_error}")
            if tables_truncated:
                _reason("tables: result truncated by requested limit")
        if table_errors and not capability_error:
            capability_error = "; ".join(table_errors)
        if table_names:
            read_capability = True
        elif (
            table_access
            and not tables_truncated
            and not table_errors
            and all(item.get("readable") is False for item in table_access)
        ):
            read_capability = False
        elif table_access or table_errors or tables_truncated:
            read_capability = None

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
                _reason(f"columns: invalid table name: {raw_target}")
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
            if columns_error:
                _reason(f"columns {db_name}.{table_name}: {columns_error}")
        column_errors = [item for item in table_columns_info if item.get("error")]
        if column_errors and len(column_errors) == len(table_columns_info):
            action_statuses["columns"] = "error"
        elif column_errors:
            action_statuses["columns"] = "partial"
        else:
            action_statuses["columns"] = "ok"

    if dump_table_rows:
        for db_name, table_name in normalized_target_pairs:
            dump_columns: list[str] | None = []
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
            if combined_dump_error:
                _reason(f"dump {db_name}.{table_name}: {combined_dump_error}")
        dump_errors = [item for item in table_dumps if item.get("error")]
        if dump_errors and len(dump_errors) == len(table_dumps):
            action_statuses["dump"] = "error"
        elif dump_errors:
            action_statuses["dump"] = "partial"
        else:
            action_statuses["dump"] = "ok"

    if sql_command:
        sql_attempted = True
        sql_output, sql_error = _run_sql_query(operation_session, sql_command)
        sql_ok = sql_error is None
        action_statuses["sql"] = "ok" if sql_ok else "error"
        if sql_error:
            _reason(f"sql: {sql_error}")

    if execute_command:
        execute_attempted = True
        if execute_capability is False:
            execute_ok = False
            execute_output = []
            execute_error = "insufficient privileges for OS command execution"
        else:
            execute_output, execute_error = _run_execute_command(operation_session, execute_command)
            execute_ok = execute_error is None
        action_statuses["execute"] = "ok" if execute_ok else "error"
        if execute_error:
            _reason(f"execute: {execute_error}")

    resolved_targets = list(table_targets)
    if not resolved_targets and normalized_targets:
        resolved_targets = normalized_targets

    return {
        "database_names": database_names,
        "database_count": database_count,
        "table_names": table_names,
        "table_access": table_access,
        "table_targets": resolved_targets,
        "table_columns_info": table_columns_info,
        "table_dumps": table_dumps,
        "sql_attempted": sql_attempted,
        "sql_ok": sql_ok,
        "sql_output": sql_output,
        "sql_error": sql_error,
        "execute_attempted": execute_attempted,
        "execute_ok": execute_ok,
        "execute_output": execute_output,
        "execute_error": execute_error,
        "read_capability": read_capability,
        "execute_capability": execute_capability,
        "admin_capability": admin_capability,
        "capability_error": capability_error,
        "action_statuses": action_statuses,
        "partial_reasons": partial_reasons,
        "partial": bool(partial_reasons),
        "requested_operation_failure": any(value in {"partial", "error"} for value in action_statuses.values()),
    }


def _normalize_action_result(value: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(value)
    defaults: dict[str, Any] = {
        "database_names": None,
        "database_count": None,
        "table_names": None,
        "table_access": [],
        "table_targets": [],
        "table_columns_info": [],
        "table_dumps": [],
        "sql_attempted": False,
        "sql_ok": None,
        "sql_output": None,
        "sql_error": None,
        "execute_attempted": False,
        "execute_ok": None,
        "execute_output": None,
        "execute_error": None,
        "read_capability": None,
        "execute_capability": None,
        "admin_capability": None,
        "capability_error": None,
        "partial_reasons": [],
        "partial": False,
        "requested_operation_failure": False,
        "action_statuses": {
            "databases": "not_requested",
            "tables": "not_requested",
            "columns": "not_requested",
            "dump": "not_requested",
            "sql": "not_requested",
            "execute": "not_requested",
        },
    }
    for key, default in defaults.items():
        result.setdefault(key, default)
    return result


def _clickhouse_lifecycle_payload(
    ctx: Any,
    options: Mapping[str, Any],
    *,
    protocol: str,
    status: str,
    auth_required: bool | None,
    error: str | None = None,
    detection_error_kind: str | None = None,
    operational_failure: bool = False,
    attempts: int = 1,
    max_attempts_total: int | None = None,
) -> dict[str, Any]:
    credential = ctx.credential
    provided = credential.username is not None or credential.password is not None
    return {
        "timestamp": utc_now_iso(),
        "host": str(ctx.host),
        "port": int(ctx.port),
        "protocol": protocol,
        "is_clickhouse": status not in {"fail", "not_clickhouse"},
        "status": status,
        "auth_required": auth_required,
        "auth_status": (
            "anonymous_open"
            if status == "open_no_auth"
            else "limited"
            if status == "anonymous_limited"
            else "not_requested"
        ),
        "database": str(options["database"]),
        "requested_database": str(options["database"]),
        "effective_database": None,
        "database_fallback": False,
        "partial": False,
        "partial_reasons": [],
        "action_statuses": {
            "databases": "not_requested",
            "tables": "not_requested",
            "columns": "not_requested",
            "dump": "not_requested",
            "sql": "not_requested",
            "execute": "not_requested",
        },
        "requested_operation_failure": False,
        "provided_credentials": provided,
        "provided_username": credential.username,
        "provided_password": credential.password if provided else None,
        "provided_credentials_ok": None,
        "defcreds_enabled": credential.source == "default",
        "default_credentials": False,
        "credential_attempt_count": 0,
        "credential_attempts": [],
        "credentials_source": None,
        "effective_username": None,
        "effective_password": None,
        "show_databases": bool(options["show_databases"]),
        "database_names": None,
        "database_count": None,
        "show_tables": bool(options["show_tables"]),
        "table_names": None,
        "show_columns": bool(options["show_columns"]),
        "table_targets": list(options["table_targets"]),
        "table_columns": list(options["table_columns"]),
        "table_columns_info": [],
        "table_dump_enabled": bool(options["dump_table_rows"]),
        "table_dump_limit": options["dump_row_limit"],
        "table_dumps": [],
        "execute_command": options["execute_command"],
        "execute_attempted": False,
        "execute_ok": None,
        "execute_output": None,
        "execute_error": None,
        "sql_command": options["sql_command"],
        "sql_attempted": False,
        "sql_ok": None,
        "sql_output": None,
        "sql_error": None,
        "read_capability": None,
        "execute_capability": None,
        "admin_capability": None,
        "show_databases_limit": options["show_databases_limit"],
        "show_tables_limit": options["show_tables_limit"],
        "show_columns_limit": options["show_columns_limit"],
        "attempts": attempts,
        "max_attempts": max_attempts_total
        if max_attempts_total is not None
        else max(1, int(getattr(ctx.args, "retries", 0) or 0) + 1),
        "stages": [],
        "stage_durations_ms": {},
        "stage_attempts": {},
        "stage_failed_at": None,
        "debug_events": [],
        "debug_events_streamed": False,
        "detection_error_kind": detection_error_kind,
        "operational_failure": operational_failure,
        "error": error,
    }


def _record_payload(record: Any) -> dict[str, Any]:
    if hasattr(record, "to_dict"):
        return dict(record.to_dict())
    return dict(record)


def detect_clickhouse(
    ctx: Any,
    options: Mapping[str, Any],
) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, ClickHouseLifecycleState):
        raise TypeError("clickhouse lifecycle state is unavailable")

    tls_config, proxy = _ch_transport_from_context(ctx)
    max_attempts = max(1, int(getattr(ctx.args, "retries", 0) or 0) + 1)

    def _probe_protocol(protocol: str) -> tuple[_ChProbeResult, int]:
        last_result = _probe_result(None, _ChProbeError("connection failed", kind="client_error"))
        for attempt in range(max_attempts):
            result = _coerce_probe_result(
                _connect_and_probe(
                    protocol,
                    str(ctx.host),
                    int(ctx.port),
                    float(getattr(ctx.args, "timeout", 5.0)),
                    "default",
                    "",
                    database="default",
                    **_ch_transport_kwargs(tls_config, proxy),
                )
            )
            if result.session is not None or result.confirms_service:
                return result, attempt + 1
            last_result = result
            if not result.retryable or attempt >= max_attempts - 1:
                return result, attempt + 1
            time.sleep(_retry_delay(attempt))
        return last_result, max_attempts

    requested_protocol = str(options["protocol"] or "native").lower()
    protocol_order = _protocol_attempt_order(requested_protocol, int(ctx.port))
    primary_protocol = protocol_order[0]
    probe, used_attempts = _probe_protocol(primary_protocol)
    selected_protocol = primary_protocol
    fallback_used = False

    if len(protocol_order) > 1 and probe.session is None and probe.kind == "protocol_mismatch":
        fallback_used = True
        selected_protocol = protocol_order[1]
        probe, fallback_attempts = _probe_protocol(selected_protocol)
        used_attempts += fallback_attempts

    state.selected_protocol = selected_protocol
    if probe.session is not None:
        state.anonymous_session = probe.session
        state.anonymous_access_limited = probe.access_limited
        state.auth_required = False
        return _clickhouse_lifecycle_payload(
            ctx,
            options,
            protocol=selected_protocol,
            status="anonymous_limited" if probe.access_limited else "open_no_auth",
            auth_required=False,
            error=str(probe.error) if probe.access_limited and probe.error else None,
            detection_error_kind=probe.kind if probe.access_limited else None,
            attempts=used_attempts,
            max_attempts_total=max_attempts * (2 if fallback_used else 1),
        )

    if probe.confirms_service:
        state.auth_required = probe.auth_required
        status = "auth_required" if probe.auth_required is True else "detected"
        return _clickhouse_lifecycle_payload(
            ctx,
            options,
            protocol=selected_protocol,
            status=status,
            auth_required=probe.auth_required,
            error=None if status == "auth_required" else str(probe.error or ""),
            detection_error_kind=probe.kind,
            attempts=used_attempts,
            max_attempts_total=max_attempts * (2 if fallback_used else 1),
        )

    operational_failure = probe.kind == "transport"
    status = "fail" if operational_failure else "not_clickhouse"

    return _clickhouse_lifecycle_payload(
        ctx,
        options,
        protocol=selected_protocol,
        status=status,
        auth_required=None,
        error=str(probe.error or "connection failed"),
        detection_error_kind=probe.kind,
        operational_failure=operational_failure,
        attempts=used_attempts,
        max_attempts_total=max_attempts * (2 if fallback_used else 1),
    )


def authenticate_clickhouse(
    ctx: Any,
    detect_record: Any,
    options: Mapping[str, Any],
) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, ClickHouseLifecycleState):
        raise TypeError("clickhouse lifecycle state is unavailable")
    payload = _record_payload(detect_record)
    credential = ctx.credential
    if credential.username is None and credential.password is None:
        return payload

    username = credential.username or "default"
    password = credential.password or ""
    source = str(credential.source or "provided")
    protocol = state.selected_protocol or str(options["protocol"])
    attempts = max(1, int(getattr(ctx.args, "retries", 0) or 0) + 1)
    session: _ChSession | None = None
    error: str | None = None
    transport_attempts = 0
    definitive_rejection = False
    access_limited = False
    tls_config, proxy = _ch_transport_from_context(ctx)
    for attempt in range(attempts):
        transport_attempts += 1
        session, error = _open_operational_session(
            protocol,
            str(ctx.host),
            int(ctx.port),
            float(getattr(ctx.args, "timeout", 5.0)),
            username,
            password,
            str(options["database"]),
            **_ch_transport_kwargs(tls_config, proxy),
        )
        if session is not None:
            access_limited = _error_code(error) == _CLICKHOUSE_ACCESS_DENIED_CODE
            break
        if _is_auth_error(error):
            definitive_rejection = True
            break
        retryable = _probe_error_info(error).retryable
        if not retryable or attempt >= attempts - 1:
            break
        time.sleep(_retry_delay(attempt))
    ok = session is not None
    if session is not None:
        session_key = (credential.username, credential.password, source)
        state.credential_sessions[session_key] = session
        if access_limited:
            state.credential_limited.add(session_key)
    state.auth_attempts.append(
        {
            "username": username,
            "password": password,
            "source": source,
            "ok": ok,
            "error": str(error or ""),
        }
    )
    detect_status = str(payload.get("status") or "")
    if ok:
        status = "weak_default_creds" if source == "default" else "valid_credentials"
    elif definitive_rejection and detect_status == "open_no_auth":
        status = "invalid_credentials_anonymous"
    elif not definitive_rejection:
        status = detect_status or "detected"
    else:
        status = "auth_required"

    payload.update(
        {
            "timestamp": utc_now_iso(),
            "status": status,
            "is_clickhouse": True,
            "auth_required": state.auth_required,
            "auth_status": (
                "limited" if access_limited else "valid" if ok else "rejected" if definitive_rejection else "error"
            ),
            "provided_credentials": source != "default",
            "provided_username": credential.username,
            "provided_password": credential.password if source != "default" else None,
            "provided_credentials_ok": (
                True if ok and source != "default" else False if definitive_rejection and source != "default" else None
            ),
            "defcreds_enabled": source == "default",
            "default_credentials": bool(ok and source == "default"),
            "credential_attempt_count": len(state.auth_attempts),
            "auth_transport_attempts": transport_attempts,
            "credentials_source": source if ok else None,
            "effective_username": username if ok else None,
            "effective_password": password if ok else None,
            "effective_database": session.database if session is not None else None,
            "database_fallback": bool(session is not None and session.database != str(options["database"])),
            "partial": bool(session is not None and session.database != str(options["database"])),
            "credential_attempts": list(state.auth_attempts),
            "requested_operation_failure": bool(not ok and not definitive_rejection),
            "error": error if ok and error else None if status == "invalid_credentials_anonymous" else error,
        }
    )
    return _normalize_clickhouse_record_schema(payload)


def collect_clickhouse_data(
    ctx: Any,
    record: Any,
    options: Mapping[str, Any],
) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, ClickHouseLifecycleState):
        raise TypeError("clickhouse lifecycle state is unavailable")
    payload = _record_payload(record)
    tls_config, proxy = _ch_transport_from_context(ctx)
    runtime_attempts = payload.get("attempted_credentials") or payload.get("credential_attempts")
    merged_attempts = list(state.auth_attempts)
    if isinstance(runtime_attempts, list):
        actual_by_key = {
            (
                str(attempt.get("username") or "default"),
                "" if attempt.get("password") is None else str(attempt.get("password")),
                str(attempt.get("source") or "provided"),
            ): attempt
            for attempt in state.auth_attempts
        }
        merged_attempts = []
        for runtime_attempt in runtime_attempts:
            if not isinstance(runtime_attempt, Mapping):
                continue
            key = (
                str(runtime_attempt.get("username") or "default"),
                "" if runtime_attempt.get("password") is None else str(runtime_attempt.get("password")),
                str(runtime_attempt.get("source") or "provided"),
            )
            actual_attempt = actual_by_key.get(key)
            if actual_attempt is not None:
                merged_attempts.append(dict(actual_attempt))
                continue
            merged_attempts.append(
                {
                    "username": key[0],
                    "password": key[1],
                    "source": key[2],
                    "ok": str(runtime_attempt.get("status") or "") in {"valid_credentials", "weak_default_creds"},
                    "error": str(runtime_attempt.get("error") or ""),
                }
            )
    payload.pop("attempted_credentials", None)
    payload.pop("auth_attempts", None)
    payload["credential_attempts"] = merged_attempts
    payload["credential_attempt_count"] = len(merged_attempts)
    payload["defcreds_enabled"] = bool(payload.get("defcreds_enabled")) or any(
        str(attempt.get("source") or "") == "default" for attempt in merged_attempts
    )
    credential = ctx.credential
    source = str(credential.source or "provided")
    session_key = (credential.username, credential.password, source)
    limited_session = session_key in state.credential_limited
    state.credential_limited.discard(session_key)
    session = state.take_session(credential.username, credential.password, source)
    if session is None and str(payload.get("status") or "") in {
        "open_no_auth",
        "anonymous_limited",
        "invalid_credentials_anonymous",
    }:
        session = state.anonymous_session
        state.anonymous_session = None
        limited_session = state.anonymous_access_limited
    if session is None:
        return payload
    desired_database = str(options["database"])
    database_warning: str | None = None
    if session.database != desired_database:
        _close_client(session.protocol, session.client)
        session, database_warning = _open_operational_session(
            state.selected_protocol or str(options["protocol"]),
            str(ctx.host),
            int(ctx.port),
            float(getattr(ctx.args, "timeout", 5.0)),
            session.username,
            session.password,
            desired_database,
            **_ch_transport_kwargs(tls_config, proxy),
        )
        if session is None:
            payload["error"] = database_warning or f"failed to open database {desired_database}"
            payload["requested_operation_failure"] = True
            return payload

    started = time.monotonic()
    try:
        action_result = _normalize_action_result(
            _run_clickhouse_actions_on_session(
                session,
                database=session.database,
                show_databases=bool(options["show_databases"]),
                show_tables=bool(options["show_tables"]),
                show_columns=bool(options["show_columns"]),
                table_targets=list(options["table_targets"]),
                table_columns=list(options["table_columns"]),
                dump_table_rows=bool(options["dump_table_rows"]),
                dump_row_limit=options["dump_row_limit"],
                execute_command=options["execute_command"],
                sql_command=options["sql_command"],
                show_databases_limit=options["show_databases_limit"],
                show_tables_limit=options["show_tables_limit"],
                limited_session=limited_session,
            )
        )
    finally:
        _close_client(session.protocol, session.client)

    database_names = action_result["database_names"]
    table_names = action_result["table_names"]
    errors = [
        str(value).strip()
        for value in (
            action_result["capability_error"],
            action_result["execute_error"],
            action_result["sql_error"],
            database_warning,
        )
        if str(value or "").strip()
    ]
    payload.update(
        {
            "protocol": session.protocol,
            "requested_database": desired_database,
            "effective_database": session.database,
            "database_fallback": session.database != desired_database,
            "partial": bool(session.database != desired_database),
            "partial_reasons": list(
                dict.fromkeys(
                    (
                        [f"database fallback: {desired_database} -> {session.database}"]
                        if session.database != desired_database
                        else []
                    )
                    + list(action_result["partial_reasons"])
                )
            ),
            "action_statuses": action_result["action_statuses"],
            "requested_operation_failure": bool(action_result["requested_operation_failure"]),
            "database_names": database_names,
            "database_count": action_result["database_count"],
            "table_names": table_names,
            "table_access": action_result["table_access"],
            "table_targets": action_result["table_targets"],
            "table_columns_info": action_result["table_columns_info"],
            "table_dumps": action_result["table_dumps"],
            "sql_attempted": action_result["sql_attempted"],
            "sql_ok": action_result["sql_ok"],
            "sql_output": action_result["sql_output"],
            "sql_error": action_result["sql_error"],
            "execute_attempted": action_result["execute_attempted"],
            "execute_ok": action_result["execute_ok"],
            "execute_output": action_result["execute_output"],
            "execute_error": action_result["execute_error"],
            "read_capability": action_result["read_capability"],
            "execute_capability": action_result["execute_capability"],
            "admin_capability": action_result["admin_capability"],
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": "; ".join(dict.fromkeys(errors)) if errors else None,
        }
    )
    payload["partial"] = bool(payload["partial_reasons"])
    return _normalize_clickhouse_record_schema(payload)


def _audit_clickhouse_host_on_protocol_legacy(
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
    credential_candidates: list[dict[str, Any]] | None = None,
    tls_config: _ChTlsConfig | None = None,
    proxy: Any | None = None,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    candidates = _normalize_credential_candidates(
        username,
        password,
        defcreds,
        credential_candidates,
    )
    if credential_candidates is None:
        provided_username = username
        provided_password = password
        provided_credentials = password is not None
        defaults_enabled = bool(defcreds)
    else:
        provided_candidates = [candidate for candidate in candidates if candidate[2] != "default"]
        provided_username = provided_candidates[0][0] if provided_candidates else None
        provided_password = provided_candidates[0][1] if provided_candidates else None
        provided_credentials = bool(provided_candidates)
        defaults_enabled = any(source == "default" for _user, _secret, source in candidates)
    provided_credentials_ok: bool | None = False if provided_credentials else None

    last_error: str | None = None
    last_error_kind: str | None = None

    for attempt in range(attempts):
        started = time.monotonic()
        auth_required: bool | None = None
        anonymous_ok = False
        anonymous_limited = False
        auth_attempts: list[dict[str, Any]] = []
        attempted_credentials = 0
        effective_username: str | None = None
        effective_password: str | None = None
        credentials_source: str | None = None
        default_credentials = False
        selected_credential_session: _ChSession | None = None
        selected_credential_limited = False
        service_confirmed_without_session = False

        anon_session, anon_error = _connect_and_probe(
            protocol,
            host,
            port,
            timeout,
            "default",
            "",
            database="default",
            **_ch_transport_kwargs(tls_config, proxy),
        )
        if anon_session is not None:
            anonymous_ok = True
            anonymous_limited = _error_code(anon_error) == _CLICKHOUSE_ACCESS_DENIED_CODE
            auth_required = False
            last_error = None
            last_error_kind = None
        else:
            last_error = anon_error or last_error
            error_info = _probe_error_info(anon_error)
            last_error_kind = error_info.kind
            if error_info.auth_required is True:
                auth_required = True
            elif error_info.confirms_service:
                auth_required = error_info.auth_required
                service_confirmed_without_session = True
            else:
                if not error_info.retryable or attempt >= attempts - 1:
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
                **_ch_transport_kwargs(tls_config, proxy),
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
                selected_credential_session = cred_session
                selected_credential_limited = _error_code(cred_error) == _CLICKHOUSE_ACCESS_DENIED_CODE
            if ok and source == "default":
                default_credentials = True
            if source != "default" and ok:
                provided_credentials_ok = True
            if cred_session is not None and cred_session is not selected_credential_session:
                _close_client(protocol, cred_session.client)
            if ok and not defaults_enabled:
                break

        operation_session = selected_credential_session
        operation_session_error: str | None = None

        if operation_session is not None and database != "default":
            _close_client(protocol, operation_session.client)
            operation_session, operation_session_error = _open_operational_session(
                protocol,
                host,
                port,
                timeout,
                effective_username or "default",
                effective_password or "",
                database,
                **_ch_transport_kwargs(tls_config, proxy),
            )

        if operation_session is None and anonymous_ok and effective_username is None:
            if database == "default":
                operation_session = anon_session
            else:
                if anon_session is not None:
                    _close_client(protocol, anon_session.client)
                    anon_session = None
                operation_session, operation_session_error = _open_operational_session(
                    protocol,
                    host,
                    port,
                    timeout,
                    "default",
                    "",
                    database,
                    **_ch_transport_kwargs(tls_config, proxy),
                )
        elif anon_session is not None:
            _close_client(protocol, anon_session.client)
            anon_session = None

        action_result: dict[str, Any] = {
            "database_names": None,
            "database_count": None,
            "table_names": None,
            "table_targets": list(table_targets),
            "table_columns_info": [],
            "table_dumps": [],
            "sql_attempted": False,
            "sql_ok": None,
            "sql_output": None,
            "sql_error": None,
            "execute_attempted": False,
            "execute_ok": None,
            "execute_output": None,
            "execute_error": None,
            "read_capability": None,
            "execute_capability": None,
            "admin_capability": None,
            "capability_error": None,
            "table_access": [],
            "action_statuses": {
                "databases": "not_requested",
                "tables": "not_requested",
                "columns": "not_requested",
                "dump": "not_requested",
                "sql": "not_requested",
                "execute": "not_requested",
            },
            "partial_reasons": [],
            "partial": False,
            "requested_operation_failure": False,
        }
        if operation_session is not None:
            action_result = _normalize_action_result(
                _run_clickhouse_actions_on_session(
                    operation_session,
                    database=operation_session.database,
                    show_databases=show_databases,
                    show_tables=show_tables,
                    show_columns=show_columns,
                    table_targets=list(table_targets),
                    table_columns=list(table_columns),
                    dump_table_rows=dump_table_rows,
                    dump_row_limit=dump_row_limit,
                    execute_command=execute_command,
                    sql_command=sql_command,
                    limited_session=selected_credential_limited or (anonymous_limited and effective_username is None),
                )
            )
            _close_client(protocol, operation_session.client)

        if effective_username is not None:
            status = "weak_default_creds" if credentials_source == "default" else "valid_credentials"
        elif anonymous_limited:
            status = "anonymous_limited"
        elif auth_required is False and attempted_credentials > 0 and (provided_credentials or defaults_enabled):
            status = "invalid_credentials_anonymous"
        elif auth_required is False:
            status = "open_no_auth"
        elif auth_required is True:
            status = "auth_required"
        elif service_confirmed_without_session:
            status = "detected"
        else:
            status = "fail"

        errors: list[str] = []
        for err in (
            last_error,
            action_result["capability_error"],
            operation_session_error,
            action_result["execute_error"],
            action_result["sql_error"],
        ):
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
            "auth_status": (
                "limited"
                if selected_credential_limited or anonymous_limited
                else "valid"
                if effective_username is not None
                else "error"
                if any(_probe_error_info(item.get("error")).retryable for item in auth_attempts)
                else "anonymous_open"
                if auth_required is False
                else "rejected"
                if auth_required is True and attempted_credentials
                else "not_requested"
            ),
            "database": database,
            "requested_database": database,
            "effective_database": operation_session.database if operation_session is not None else None,
            "database_fallback": bool(operation_session is not None and operation_session.database != database),
            "partial": bool(operation_session is not None and operation_session.database != database)
            or bool(action_result["partial"]),
            "partial_reasons": list(action_result["partial_reasons"]),
            "action_statuses": action_result["action_statuses"],
            "requested_operation_failure": bool(action_result["requested_operation_failure"])
            or any(_probe_error_info(item.get("error")).retryable for item in auth_attempts),
            "provided_credentials": provided_credentials,
            "provided_username": provided_username,
            "provided_password": provided_password,
            "provided_credentials_ok": provided_credentials_ok,
            "defcreds_enabled": defaults_enabled,
            "default_credentials": default_credentials,
            "attempted_credentials": attempted_credentials,
            "credentials_source": credentials_source,
            "effective_username": effective_username,
            "effective_password": effective_password,
            "auth_attempts": auth_attempts,
            "show_databases": show_databases,
            "database_names": action_result["database_names"],
            "database_count": action_result["database_count"],
            "show_tables": show_tables,
            "table_names": action_result["table_names"],
            "table_access": action_result["table_access"],
            "show_columns": show_columns,
            "table_targets": action_result["table_targets"],
            "table_columns": list(table_columns),
            "table_columns_info": action_result["table_columns_info"],
            "table_dump_enabled": dump_table_rows,
            "table_dump_limit": dump_row_limit,
            "table_dumps": action_result["table_dumps"],
            "execute_command": execute_command,
            "execute_attempted": action_result["execute_attempted"],
            "execute_ok": action_result["execute_ok"],
            "execute_output": action_result["execute_output"],
            "execute_error": action_result["execute_error"],
            "sql_command": sql_command,
            "sql_attempted": action_result["sql_attempted"],
            "sql_ok": action_result["sql_ok"],
            "sql_output": action_result["sql_output"],
            "sql_error": action_result["sql_error"],
            "read_capability": action_result["read_capability"],
            "execute_capability": action_result["execute_capability"],
            "admin_capability": action_result["admin_capability"],
            "detection_error_kind": last_error_kind,
            "operational_failure": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": "; ".join(errors) if errors else None,
        }

    operational_failure = last_error_kind == "transport"
    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "protocol": protocol,
        "is_clickhouse": False,
        "status": "fail" if operational_failure else "not_clickhouse",
        "auth_required": None,
        "database": database,
        "provided_credentials": provided_credentials,
        "provided_username": provided_username,
        "provided_password": provided_password,
        "provided_credentials_ok": provided_credentials_ok,
        "defcreds_enabled": defaults_enabled,
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
        "detection_error_kind": last_error_kind,
        "operational_failure": operational_failure,
        "elapsed_ms": None,
        "error": last_error or "connection failed",
    }


def _normalize_clickhouse_record_schema(record: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(record)
    legacy_attempts = payload.pop("auth_attempts", None)
    legacy_count = payload.pop("attempted_credentials", None)
    attempts = payload.get("credential_attempts")
    if not isinstance(attempts, list):
        attempts = legacy_attempts if isinstance(legacy_attempts, list) else []
    payload["credential_attempts"] = attempts
    payload["credential_attempt_count"] = len(attempts) if attempts else int(legacy_count or 0)

    status = str(payload.get("status") or "")
    payload.setdefault(
        "auth_status",
        "anonymous_open"
        if status in {"open_no_auth", "invalid_credentials_anonymous"}
        else "limited"
        if status == "anonymous_limited"
        else "valid"
        if status in {"valid_credentials", "weak_default_creds"}
        else "rejected"
        if status == "auth_required" and payload["credential_attempt_count"]
        else "not_requested",
    )
    payload.setdefault("table_access", [])
    payload.setdefault("partial_reasons", [])
    payload.setdefault(
        "action_statuses",
        {
            "databases": "not_requested",
            "tables": "not_requested",
            "columns": "not_requested",
            "dump": "not_requested",
            "sql": "not_requested",
            "execute": "not_requested",
        },
    )
    payload.setdefault("requested_operation_failure", False)
    if bool(payload.get("is_clickhouse")) and status == "fail":
        payload["status"] = "detected"
    return payload


def _audit_clickhouse_host_on_protocol(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Compatibility adapter over the normalized ClickHouse target record."""

    return _normalize_clickhouse_record_schema(_audit_clickhouse_host_on_protocol_legacy(*args, **kwargs))


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
    credential_candidates: list[dict[str, Any]] | None = None,
    tls_config: _ChTlsConfig | None = None,
    proxy: Any | None = None,
) -> dict[str, Any]:
    normalized_protocol = str(protocol or "native").strip().lower()
    sequence = _protocol_attempt_order(normalized_protocol, port)
    last_record: dict[str, Any] | None = None
    for protocol_index, proto in enumerate(sequence):
        if (
            protocol_index > 0
            and last_record is not None
            and str(last_record.get("detection_error_kind") or "") != "protocol_mismatch"
        ):
            break
        optional_kwargs: dict[str, Any] = {"dump_row_limit": dump_row_limit}
        if credential_candidates is not None:
            optional_kwargs["credential_candidates"] = credential_candidates
        if tls_config is not None:
            optional_kwargs["tls_config"] = tls_config
        if proxy is not None:
            optional_kwargs["proxy"] = proxy
        while True:
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
                    **optional_kwargs,
                )
                break
            except TypeError as exc:
                unsupported = next((key for key in optional_kwargs if key in str(exc)), None)
                if unsupported is None:
                    raise
                optional_kwargs.pop(unsupported)
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
    if not isinstance(db_count, int):
        db_names = record.get("database_names")
        db_count = len(db_names) if isinstance(db_names, list) else None
    db_count_text = format_count_value(db_count)
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
    if str(record.get("auth_status") or "") == "limited":
        return f"{_nxc_prefix(record)} [*] ClickHouse Database (access:limited)"
    return f"{_nxc_prefix(record)} [*] ClickHouse Database (auth required:{auth_required_text})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        payload = dict(record)
        payload.pop("provided_password", None)
        payload.pop("effective_password", None)
        payload.pop("auth_attempts", None)
        payload.pop("attempted_credentials", None)
        return json.dumps(payload, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 92)

    if status == "open_no_auth":
        return ""

    if status == "detected":
        return ""

    if status == "not_clickhouse":
        return f"{prefix} [-] not a ClickHouse service"

    if status == "weak_default_creds":
        attempts = record.get("credential_attempts", record.get("auth_attempts"))
        if isinstance(attempts, list) and any(
            isinstance(attempt, dict) and bool(attempt.get("ok")) for attempt in attempts
        ):
            return ""
        user = str(record.get("effective_username") or "default")
        password_text = _password_text(record.get("effective_password"))
        return f"{prefix} [+] {user}:{password_text} {_caps_suffix(record)}"

    if status == "valid_credentials":
        attempts = record.get("credential_attempts", record.get("auth_attempts"))
        if isinstance(attempts, list) and any(
            isinstance(attempt, dict) and bool(attempt.get("ok")) for attempt in attempts
        ):
            return ""
        user = str(record.get("effective_username") or "default")
        password_text = _password_text(record.get("effective_password"))
        return f"{prefix} [+] {user}:{password_text} {_caps_suffix(record)}"

    if status == "invalid_credentials_anonymous":
        attempts = record.get("credential_attempts", record.get("auth_attempts"))
        if isinstance(attempts, list) and attempts:
            return ""
        return f"{prefix} [-] credentials invalid (anonymous access) {_caps_suffix(record)}"

    if status == "auth_required":
        attempts = record.get("credential_attempts", record.get("auth_attempts"))
        if isinstance(attempts, list) and attempts:
            return ""
        if int(record.get("credential_attempt_count", record.get("attempted_credentials", 0)) or 0) > 0:
            return f"{prefix} [-] authentication required (credentials invalid)"
        return f"{prefix} [-] authentication required"

    fail_line = f"{prefix} [!] connection failed"
    if err != "-":
        return f"{fail_line} err={err}"
    return fail_line


def _format_auth_attempt_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []

    attempts_raw = record.get("credential_attempts", record.get("auth_attempts"))
    if not isinstance(attempts_raw, list) or not attempts_raw:
        return []

    attempts = [item for item in attempts_raw if isinstance(item, dict)]
    if not attempts:
        return []

    prefix = _nxc_prefix(record)
    lines: list[str] = []
    effective_username = record.get("effective_username")
    effective_password = record.get("effective_password")
    credentials_source = str(record.get("credentials_source") or "")
    for attempt in attempts:
        user = str(attempt.get("username") or "default")
        raw_password = attempt.get("password")
        password = _password_text("" if raw_password is None else raw_password)
        if bool(attempt.get("ok")):
            selected = (
                effective_username is not None
                and user == str(effective_username)
                and attempt.get("password") == effective_password
                and (
                    not attempt.get("source")
                    or not credentials_source
                    or str(attempt.get("source")) == credentials_source
                )
            )
            suffix = f" {_caps_suffix(record)}" if selected else ""
            lines.append(f"{prefix} [+] {user}:{password}{suffix}")
        else:
            lines.append(f"{prefix} [-] {user}:{password}")
    return lines


def _format_database_fallback_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt" or not bool(record.get("database_fallback")):
        return []
    requested = str(record.get("requested_database") or record.get("database") or "-")
    effective = str(record.get("effective_database") or "-")
    return [
        f"{_nxc_prefix(record)} [!] requested database={requested} unavailable; "
        f"actions used database={effective} (partial result)"
    ]


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
    lines = []
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
    lines = []
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
    if render_colored_marker_line(
        console,
        line,
        tag="CLICKHOUSE",
        booleans=(
            BooleanColorRule("read"),
            BooleanColorRule("execute"),
            BooleanColorRule("admin"),
        ),
        counts=(CountColorRule("DBs", "orange"),),
    ):
        return True
    if line.startswith("CLICKHOUSE") and "\t" in line:
        return render_tagged_detail_line(console, line, tag="CLICKHOUSE", default_color="orange")
    return False


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
    # Apply `--show-X N` limits to the JSON payload as well, not only at TXT render time.
    # Without this the JSON artifact carries the full list while the console shows N --
    # `-o file.json` would silently disagree with the user's specified cap.
    if run_deep_checks:
        if isinstance(show_databases_limit, int) and isinstance(record.get("database_names"), list):
            record["database_names"] = limit_sequence(record["database_names"], show_databases_limit)
        if isinstance(show_tables_limit, int) and isinstance(record.get("table_names"), list):
            record["table_names"] = limit_sequence(record["table_names"], show_tables_limit)
    result: dict[str, Any] = dict(record)
    status = str(result.get("status") or "fail")
    is_clickhouse = bool(result.get("is_clickhouse"))
    attempts = max(1, retries + 1)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    # Use the post-fallback port (port_protocols may swap to a sibling port) so debug
    # lines reflect the port that was actually probed.
    resolved_port = int(result.get("port") or port)
    telemetry = StageTelemetryBuilder(
        host=host, port=resolved_port, attempts=attempts, debug=debug, debug_emit=debug_emit
    )
    if attempts > 1 and status == "fail":
        telemetry.debug(format_retry_decision(_STAGE_DETECT_PROTOCOL, 1, attempts, _retry_delay(0), "error"))

    detect_result = "ok" if is_clickhouse else ("error" if status == "fail" else "skip")
    detect_error = str(result.get("error") or "") if detect_result == "error" else None
    telemetry.stage(_STAGE_DETECT_PROTOCOL, detect_result, detect_error, 0)

    auth_result = (
        "ok" if is_clickhouse and status in _CLICKHOUSE_DEEP_STATUSES.union({"auth_required"}) else detect_result
    )
    telemetry.stage(_STAGE_AUTH_INFERENCE, auth_result, detect_error if auth_result == "error" else None, 0)

    if run_deep_checks and status in _CLICKHOUSE_DEEP_STATUSES:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "ok", None, 0)
        data_result = "error" if status == "fail" and result.get("error") else "ok"
        telemetry.stage(
            _STAGE_DATA, data_result, str(result.get("error") or "") if data_result == "error" else None, elapsed_ms
        )
    else:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "skip", "deep checks disabled", 0)
        telemetry.stage(_STAGE_DATA, "skip", "deep checks disabled", 0)

    stage_durations_ms = {
        str(item.get("stage_name") or ""): int(item.get("duration_ms") or 0) for item in telemetry.stages
    }
    telemetry.debug(
        f"stage_timing_summary status={status} attempts=1/{attempts} "
        f"detect_ms={stage_durations_ms.get(_STAGE_DETECT_PROTOCOL, 0)} "
        f"auth_ms={stage_durations_ms.get(_STAGE_AUTH_INFERENCE, 0)} "
        f"capabilities_ms={stage_durations_ms.get(_STAGE_ACCESS_CAPABILITIES, 0)} "
        f"data_ms={stage_durations_ms.get(_STAGE_DATA, 0)} total_ms={elapsed_ms}"
    )
    result = telemetry.attach(result, status=status, total_ms=elapsed_ms)
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
    tls_config: _ChTlsConfig | None = None,
    proxy: Any | None = None,
) -> tuple[list[str], str | None]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    for attempt in range(attempts):
        session, error = _open_operational_session(
            protocol,
            host,
            port,
            timeout,
            username,
            password,
            database,
            **_ch_transport_kwargs(tls_config, proxy),
        )
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


def _open_shell_session(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    protocol: str,
    username: str,
    password: str,
    database: str,
    tls_config: _ChTlsConfig | None = None,
    proxy: Any | None = None,
) -> tuple[_ChSession | None, str | None]:
    """Open/reconnect a shell session; command execution is deliberately separate."""

    attempts = max(1, retries + 1)
    last_error: str | None = None
    for attempt in range(attempts):
        session, error = _open_operational_session(
            protocol,
            host,
            port,
            timeout,
            username,
            password,
            database,
            **_ch_transport_kwargs(tls_config, proxy),
        )
        if session is not None:
            return session, error
        last_error = error or last_error
        if not _probe_error_info(error).retryable or attempt >= attempts - 1:
            break
        time.sleep(_retry_delay(attempt))
    return None, last_error or "connection failed"


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
    tls_config: _ChTlsConfig | None = None,
    proxy: Any | None = None,
) -> tuple[list[str], str | None]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    for attempt in range(attempts):
        session, error = _open_operational_session(
            protocol,
            host,
            port,
            timeout,
            username,
            password,
            database,
            **_ch_transport_kwargs(tls_config, proxy),
        )
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
    tls_config: _ChTlsConfig | None = None,
    proxy: Any | None = None,
) -> dict[str, Any]:
    last_record: dict[str, Any] | None = None
    for port, protocol in port_protocols:
        if protocol in {"auto", "native"}:
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
                **_ch_transport_kwargs(tls_config, proxy),
            )
        else:
            dump_kwargs: dict[str, Any] = {"dump_row_limit": dump_row_limit} if dump_row_limit is not None else {}
            if tls_config is not None:
                dump_kwargs["tls_config"] = tls_config
            if proxy is not None:
                dump_kwargs["proxy"] = proxy
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
