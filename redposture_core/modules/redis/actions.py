"""redis audit actions and compatibility helpers."""

from __future__ import annotations

import base64
import json
import socket
import ssl as ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ...audit_config import AuditConfig
from ...audit_models import AuditRecord
from ...clients import transport
from ...clients.tls_cache import shared_client_ssl_context
from ...console import Console
from ...rendering import CountColorRule, format_count_value, render_colored_marker_line, render_tagged_detail_line
from ...show_limits import (
    dump_flag_enabled,
    dump_flag_limit,
    limit_metadata,
    limit_sequence,
    show_flag_enabled,
    show_flag_limit,
)
from ...stage_runtime import (
    StageTelemetryBuilder,
    merge_stage_records,
)
from ...utils import (
    utc_now_iso,
)

# Connection-error classification + framed reads are shared via the transport
# layer; bound here so module-qualified references (and the stage facade) keep working.
_is_connection_refused_error = transport.is_connection_refused
_is_timeout_error = transport.is_connection_timeout
_is_connection_refused_fail_record = transport.is_connection_refused_fail_record
_is_connection_timeout_fail_record = transport.is_connection_timeout_fail_record
_recv_exact = transport.recv_exact

_REDIS_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "changeme"),
    ("admin", "password"),
    ("default", "changeme"),
    ("default", "default"),
    ("default", "password"),
    ("default", "redis"),
    ("dev", "dev"),
    ("redis", "changeme"),
    ("redis", "password"),
    ("redis", "redis"),
    ("root", "password"),
    ("root", "root"),
    ("service", "service"),
    ("test", "test"),
    ("user", "password"),
    ("user", "user"),
)


def _clip(text: str, width: int = 64) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _encode_resp_array(parts: list[str | bytes]) -> bytes:
    payload = [f"*{len(parts)}\r\n".encode("ascii")]
    for item in parts:
        raw = item if isinstance(item, bytes) else item.encode("utf-8")
        payload.append(f"${len(raw)}\r\n".encode("ascii"))
        payload.append(raw + b"\r\n")
    return b"".join(payload)


def _recv_line(sock: socket.socket, max_len: int = 65536) -> bytes:
    data = bytearray()
    while len(data) < max_len:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("unexpected EOF")
        data += ch
        if len(data) >= 2 and data[-2:] == b"\r\n":
            return bytes(data[:-2])
    raise ValueError("RESP line too long")


def _read_resp(sock: socket.socket) -> tuple[str, Any]:
    prefix = _recv_exact(sock, 1)
    if prefix == b"+":
        return "simple", _recv_line(sock).decode("utf-8", errors="replace")
    if prefix == b"-":
        return "error", _recv_line(sock).decode("utf-8", errors="replace")
    if prefix == b":":
        raw = _recv_line(sock).decode("ascii", errors="replace")
        return "integer", int(raw)
    if prefix == b"$":
        raw_len = _recv_line(sock).decode("ascii", errors="replace")
        size = int(raw_len)
        if size < 0:
            return "null", None
        body = _recv_exact(sock, size + 2)
        if not body.endswith(b"\r\n"):
            raise ValueError("invalid RESP bulk")
        # Bulk strings are arbitrary octets. Keep them as bytes until the
        # presentation boundary so invalid UTF-8 is never silently replaced.
        return "bulk", body[:-2]
    if prefix == b"*":
        raw_len = _recv_line(sock).decode("ascii", errors="replace")
        count = int(raw_len)
        if count < 0:
            return "null", None
        items: list[Any] = []
        for _ in range(count):
            _, item_value = _read_resp(sock)
            items.append(item_value)
        return "array", items
    raise ValueError(f"unsupported RESP prefix: {prefix!r}")


def _send_cmd(sock: socket.socket, *parts: str | bytes) -> tuple[str, Any]:
    sock.sendall(_encode_resp_array(list(parts)))
    return _read_resp(sock)


def _is_noauth_error(message: str) -> bool:
    upper = message.upper()
    # ACLs may deny PING with NOPERM even though AUTH itself is available.
    # Treat that as an authentication/capability gate so supplied credentials
    # are still attempted instead of stopping after detection.
    return "NOAUTH" in upper or "NOPERM" in upper or "AUTHENTICATION REQUIRED" in upper


def _open_redis_socket(
    host: str,
    port: int,
    timeout: float,
    *,
    use_tls: bool,
    insecure: bool = False,
    ca_file: str | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    if not use_tls:
        return sock
    try:
        context = shared_client_ssl_context(
            insecure=insecure,
            ca_file=ca_file,
            cert_file=cert_file,
            key_file=key_file,
        )
    except ValueError:
        sock.close()
        raise
    try:
        wrapped = context.wrap_socket(sock, server_hostname=host)
        wrapped.settimeout(timeout)
        return wrapped
    except BaseException:
        sock.close()
        raise


def _auth_with_password(sock: socket.socket, password: str) -> tuple[bool, str | None]:
    auth_type, auth_value = _send_cmd(sock, "AUTH", password)
    if auth_type == "simple" and str(auth_value).upper() == "OK":
        return True, None
    if auth_type == "error":
        return False, str(auth_value)
    return False, f"unexpected AUTH response: {auth_type} {auth_value}"


def _auth_with_password_once(
    sock: socket.socket,
    password: str,
    legacy_passwords_attempted: set[str] | None,
) -> tuple[bool, str | None]:
    if legacy_passwords_attempted is not None and password in legacy_passwords_attempted:
        return False, "legacy AUTH already attempted for this password"
    result = _auth_with_password(sock, password)
    if legacy_passwords_attempted is not None:
        legacy_passwords_attempted.add(password)
    return result


def _auth_with_user_password(sock: socket.socket, username: str, password: str) -> tuple[bool, str | None]:
    auth_type, auth_value = _send_cmd(sock, "AUTH", username, password)
    if auth_type == "simple" and str(auth_value).upper() == "OK":
        return True, None
    if auth_type == "error":
        return False, str(auth_value)
    return False, f"unexpected AUTH response: {auth_type} {auth_value}"


def _check_default_credentials(
    sock: socket.socket,
    username: str = "redis",
    password: str = "redis",
    *,
    legacy_passwords_attempted: set[str] | None = None,
) -> tuple[bool, str | None]:
    ok, err = _auth_with_user_password(sock, username, password)
    if ok:
        return True, None

    error = (err or "").lower()
    if "wrong number of arguments" in error or "syntax" in error:
        return _auth_with_password_once(sock, password, legacy_passwords_attempted)
    return False, err


def _check_provided_credentials(
    sock: socket.socket,
    username: str | None,
    password: str | None,
    *,
    legacy_passwords_attempted: set[str] | None = None,
) -> tuple[bool | None, str | None]:
    if password is None:
        return None, None
    if username:
        ok, err = _auth_with_user_password(sock, username, password)
        if ok:
            return True, None
        error_text = str(err or "").lower()
        if "wrong number of arguments" in error_text or "syntax" in error_text:
            return _auth_with_password_once(sock, password, legacy_passwords_attempted)
        return False, err
    return _auth_with_password_once(sock, password, legacy_passwords_attempted)


def _count_redis_keys(sock: socket.socket) -> tuple[int | None, str | None]:
    db_type, db_value = _send_cmd(sock, "DBSIZE")
    if db_type == "integer":
        return int(db_value), None
    if db_type == "error":
        return None, str(db_value)
    return None, f"unexpected DBSIZE response: {db_type} {db_value}"


def _scan_redis_keys(
    sock: socket.socket,
    *,
    count: int = 500,
    limit: int | None = None,
    max_rounds: int = 10000,
) -> tuple[list[str] | None, str | None]:
    cursor = "0"
    rounds = 0
    keys: list[str] = []
    seen: set[str] = set()

    while True:
        rounds += 1
        if rounds > max_rounds:
            return keys, "SCAN aborted: too many iterations"

        resp_type, resp_value = _send_cmd(sock, "SCAN", cursor, "COUNT", str(count))
        if resp_type != "array" or not isinstance(resp_value, list) or len(resp_value) != 2:
            return keys if keys else None, f"unexpected SCAN response: {resp_type} {resp_value}"

        next_cursor = _format_redis_text(resp_value[0] if resp_value[0] is not None else "0")
        batch = resp_value[1]
        if not isinstance(batch, list):
            return keys if keys else None, f"unexpected SCAN keys payload: {type(batch).__name__}"

        for item in batch:
            key = _format_redis_text(item)
            if key in seen:
                continue
            seen.add(key)
            keys.append(key)
            if limit is not None and len(keys) >= limit:
                return keys, None

        cursor = next_cursor
        if cursor == "0":
            break

    return keys, None


# Upper bound on SCAN iterations for a streaming dump. Termination is normally the
# cursor returning to "0"; this is only a guard against a server that never converges
# (1M rounds * COUNT 500 ~= 500M keys, far above any realistic keyspace).
_DUMP_MAX_SCAN_ROUNDS = 1_000_000


def _stream_dump_redis_keys(
    sock: socket.socket,
    *,
    batch: int,
    delay_ms: int,
    limit: int | None = None,
    count: int = 500,
) -> tuple[list[dict[str, str | None]], str | None]:
    """Dump key values gradually, one SCAN page at a time.

    Instead of scanning the whole keyspace, sorting it, then dumping every value in one
    burst, this interleaves enumeration and value reads: SCAN until ``batch`` keys are
    buffered, dump that page, pause ``delay_ms`` milliseconds, then continue from the same
    cursor. This paces the load on the server (so large keyspaces are less likely to knock
    it over) and bounds the keyspace held in memory to one page at a time. Sorting is
    therefore per page rather than global. ``limit`` caps the total number of dumped
    entries; ``None`` dumps everything.
    """
    page_size = max(1, batch)
    delay_seconds = max(0, delay_ms) / 1000.0
    entries: list[dict[str, str | None]] = []
    pending: list[str | bytes] = []
    cursor = "0"
    rounds = 0

    def _flush_page(keys_page: list[str | bytes]) -> bool:  # returns True when the total cap is reached
        for key_name in sorted(keys_page, key=_format_redis_text):
            value_text, value_error = _dump_redis_key_value(sock, key_name)
            display_name = _format_redis_text(key_name)
            if value_error:
                entries.append(_redis_kv_entry(display_name, error=_format_redis_text(value_error)))
            else:
                entries.append(_redis_kv_entry(display_name, value_text))
            if limit is not None and len(entries) >= limit:
                return True
        return False

    while True:
        rounds += 1
        if rounds > _DUMP_MAX_SCAN_ROUNDS:
            return entries, "SCAN aborted: too many iterations"

        resp_type, resp_value = _send_cmd(sock, "SCAN", cursor, "COUNT", str(count))
        if resp_type != "array" or not isinstance(resp_value, list) or len(resp_value) != 2:
            return entries, f"unexpected SCAN response: {resp_type} {resp_value}"

        next_cursor = _format_redis_text(resp_value[0] if resp_value[0] is not None else "0")
        scan_batch = resp_value[1]
        if not isinstance(scan_batch, list):
            return entries, f"unexpected SCAN keys payload: {type(scan_batch).__name__}"

        pending.extend(item if isinstance(item, bytes) else str(item) for item in scan_batch)
        cursor = next_cursor

        while len(pending) >= page_size:
            page = pending[:page_size]
            del pending[:page_size]
            if _flush_page(page):
                return entries, None
            if delay_seconds > 0:
                time.sleep(delay_seconds)

        if cursor == "0":
            break

    if pending:
        _flush_page(pending)
    return entries, None


def _format_redis_text(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            text = "base64:" + base64.b64encode(value).decode("ascii")
    else:
        text = str(value if value is not None else "")
    return text.replace("\n", "\\n")


def _redis_kv_entry(key: str, value: str | None = None, *, error: str | None = None) -> dict[str, str | None]:
    return {"key": str(key), "value": value, "error": error}


def _redis_kv_entry_text(entry: Any) -> str:
    if isinstance(entry, dict):
        key = str(entry.get("key") or "")
        error = entry.get("error")
        if error:
            return f"{key}:<error:{_format_redis_text(error)}>"
        return f"{key}:{_format_redis_text(entry.get('value'))}"
    return str(entry)


def _pairwise(items: list[Any]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    idx = 0
    while idx + 1 < len(items):
        pairs.append((_format_redis_text(items[idx]), _format_redis_text(items[idx + 1])))
        idx += 2
    return pairs


def _dump_redis_key_value(sock: socket.socket, key: str | bytes) -> tuple[str, str | None]:
    key_type_type, key_type_value = _send_cmd(sock, "TYPE", key)
    if key_type_type == "error":
        return "<error>", str(key_type_value)
    key_type = _format_redis_text(key_type_value).strip().lower()
    if not key_type:
        return "<unknown>", None
    if key_type == "none":
        return "<not found>", None

    if key_type == "string":
        value_type, value = _send_cmd(sock, "GET", key)
        if value_type == "error":
            return "<error>", str(value)
        if value_type == "null":
            return "<nil>", None
        return _format_redis_text(value), None

    if key_type == "hash":
        value_type, value = _send_cmd(sock, "HGETALL", key)
        if value_type == "error":
            return "<error>", str(value)
        if value_type == "array" and isinstance(value, list):
            pairs = _pairwise(value)
            if not pairs:
                return "<empty-hash>", None
            return ",".join(f"{field}={field_value}" for field, field_value in pairs), None
        return f"<{key_type}>", None

    if key_type == "list":
        value_type, value = _send_cmd(sock, "LRANGE", key, "0", "-1")
        if value_type == "error":
            return "<error>", str(value)
        if value_type == "array" and isinstance(value, list):
            return ",".join(_format_redis_text(item) for item in value), None
        return f"<{key_type}>", None

    if key_type == "set":
        value_type, value = _send_cmd(sock, "SMEMBERS", key)
        if value_type == "error":
            return "<error>", str(value)
        if value_type == "array" and isinstance(value, list):
            members = sorted(_format_redis_text(item) for item in value)
            return ",".join(members), None
        return f"<{key_type}>", None

    if key_type == "zset":
        value_type, value = _send_cmd(sock, "ZRANGE", key, "0", "-1", "WITHSCORES")
        if value_type == "error":
            return "<error>", str(value)
        if value_type == "array" and isinstance(value, list):
            pairs = _pairwise(value)
            if not pairs:
                return "<empty-zset>", None
            return ",".join(f"{member}={score}" for member, score in pairs), None
        return f"<{key_type}>", None

    if key_type == "stream":
        value_type, value = _send_cmd(sock, "XLEN", key)
        if value_type == "error":
            return "<error>", str(value)
        if value_type == "integer":
            return f"stream_len={value}", None
        return "<stream>", None

    return f"<type:{key_type}>", None


@dataclass
class RedisAuditLifecycleState:
    host: str
    port: int
    timeout: float
    retries: int
    debug: bool
    debug_emit: Callable[[str], None] | None
    started: float
    sock: Any = None
    selected_sock: Any = None
    is_redis: bool = False
    auth_required: bool | None = None
    status: str = "fail"
    error: str | None = None
    default_credentials: bool = False
    default_credentials_attempted: bool = False
    defcreds_enabled: bool = False
    provided_credentials: bool = False
    provided_username: str | None = None
    provided_password: str | None = None
    provided_credentials_ok: bool | None = None
    show_keys: bool = False
    show_keys_limit: int | None = None
    dump_keys: bool = False
    dump_keys_limit: int | None = None
    query_key: str | None = None
    key_count: int | None = None
    keys: list[str] | None = None
    key_values: list[str] | None = None
    key_value_entries: list[dict[str, str | None]] | None = None
    query_key_value: str | None = None
    query_key_entry: dict[str, str | None] | None = None
    active_username: str | None = None
    active_password: str | None = None
    active_source: str = "anonymous"
    auth_attempts_used: int = 0
    data_attempts_used: int = 0
    legacy_auth_passwords_attempted: set[str] = field(default_factory=set)
    use_tls: bool = False
    insecure: bool = False
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    transport_mode: str = "plaintext"


class _RedisAuthenticationRejected(Exception):
    pass


def _close_redis_lifecycle_socket(state: RedisAuditLifecycleState) -> None:
    sock = state.sock
    state.sock = None
    close = getattr(sock, "close", None)
    if callable(close):
        try:
            close()
        except OSError:
            pass


def _open_redis_lifecycle_socket(state: RedisAuditLifecycleState) -> None:
    state.sock = _open_redis_socket(
        state.host,
        state.port,
        state.timeout,
        use_tls=state.use_tls,
        insecure=state.insecure,
        ca_file=state.tls_ca,
        cert_file=state.tls_cert,
        key_file=state.tls_key,
    )
    state.transport_mode = "tls" if state.use_tls else "plaintext"


def redis_lifecycle_state_factory(ctx: Any) -> RedisAuditLifecycleState:
    cfg = AuditConfig.from_namespace(ctx.args)
    target_scheme = str(getattr(getattr(ctx, "target", None), "scheme", "") or "").lower()
    use_tls = bool(
        getattr(ctx.args, "tls", False)
        or getattr(ctx.args, "insecure", False)
        or getattr(ctx.args, "tls_ca", None)
        or getattr(ctx.args, "tls_cert", None)
        or getattr(ctx.args, "tls_key", None)
        or target_scheme in {"rediss", "tls"}
    )
    return RedisAuditLifecycleState(
        host=str(ctx.host),
        port=int(ctx.port),
        timeout=float(cfg.timeout),
        retries=int(cfg.retries),
        debug=bool(cfg.debug),
        debug_emit=ctx.debug_emit,
        started=time.monotonic(),
        defcreds_enabled=bool(getattr(ctx.args, "defcreds", False)),
        use_tls=use_tls,
        insecure=bool(getattr(ctx.args, "insecure", False)),
        tls_ca=str(getattr(ctx.args, "tls_ca", "") or "").strip() or None,
        tls_cert=str(getattr(ctx.args, "tls_cert", "") or "").strip() or None,
        tls_key=str(getattr(ctx.args, "tls_key", "") or "").strip() or None,
        transport_mode="tls" if use_tls else "plaintext",
    )


def close_redis_lifecycle_state(state: Any) -> None:
    if isinstance(state, RedisAuditLifecycleState):
        _close_redis_lifecycle_socket(state)
        selected_sock = state.selected_sock
        state.selected_sock = None
        close = getattr(selected_sock, "close", None)
        if callable(close):
            try:
                close()
            except OSError:
                pass


def _redis_lifecycle_record(state: RedisAuditLifecycleState, *, include_data: bool) -> AuditRecord:
    elapsed_ms = int((time.monotonic() - state.started) * 1000)
    payload: dict[str, Any] = {
        "timestamp": utc_now_iso(),
        "host": state.host,
        "port": state.port,
        "module": "redis",
        "service": "redis",
        "is_redis": state.is_redis,
        "status": state.status,
        "auth_required": state.auth_required,
        "default_credentials": state.default_credentials,
        "provided_credentials": state.provided_credentials,
        "provided_username": state.provided_username,
        "provided_password": state.provided_password if state.provided_credentials else None,
        "provided_credentials_ok": state.provided_credentials_ok,
        "effective_username": state.active_username,
        "effective_password": state.active_password,
        "defcreds_enabled": state.defcreds_enabled,
        "default_credentials_attempted": state.default_credentials_attempted,
        "show_keys": state.show_keys if include_data else False,
        "show_keys_limit": state.show_keys_limit if include_data else None,
        "dump_keys": state.dump_keys if include_data else False,
        "query_key": state.query_key if include_data else None,
        "key_count": state.key_count if include_data else None,
        "keys": state.keys if include_data else None,
        "key_values": state.key_values if include_data else None,
        "key_value_entries": state.key_value_entries if include_data else None,
        "query_key_value": state.query_key_value if include_data else None,
        "query_key_entry": state.query_key_entry if include_data else None,
        "elapsed_ms": elapsed_ms,
        "error": state.error,
        "transport_mode": state.transport_mode,
        "tls_client_cert_used": bool(state.use_tls and state.tls_cert and state.tls_key),
    }
    attempts = max(1, state.retries + 1)
    telemetry = StageTelemetryBuilder(
        host=state.host,
        port=state.port,
        attempts=attempts,
        debug=state.debug,
        debug_emit=state.debug_emit,
    )
    detect_result = "ok" if state.is_redis else "error"
    telemetry.stage("detect_protocol", detect_result, state.error if detect_result == "error" else None, 0)
    auth_result = (
        "ok"
        if state.status in _REDIS_DEEP_STATUSES.union({"auth_required"})
        else ("error" if state.status == "fail" else "skip")
    )
    telemetry.stage(
        "auth_inference_credentials",
        auth_result,
        state.error if auth_result == "error" else None,
        0,
    )
    if include_data and state.status in _REDIS_DEEP_STATUSES:
        telemetry.stage("access_capabilities", "ok", None, 0)
        telemetry.stage("data", "error" if state.error else "ok", state.error, elapsed_ms)
    else:
        telemetry.stage("access_capabilities", "skip", "deep checks disabled", 0)
        telemetry.stage("data", "skip", "deep checks disabled", 0)
    payload = telemetry.attach(payload, status=state.status, total_ms=elapsed_ms)
    payload["attempts"] = 1
    payload["max_attempts"] = attempts
    return AuditRecord.from_mapping(payload, module="redis", service="redis")


def redis_detect_hook(ctx: Any) -> AuditRecord:
    state = ctx.lifecycle_state
    if not isinstance(state, RedisAuditLifecycleState):
        raise TypeError("redis lifecycle state is missing")
    attempts = max(1, state.retries + 1)
    last_error: str | None = None
    for attempt in range(attempts):
        try:
            _open_redis_lifecycle_socket(state)
            ping_type, ping_value = _send_cmd(state.sock, "PING")
            if ping_type == "simple" and str(ping_value).upper() == "PONG":
                state.is_redis = True
                state.auth_required = False
                state.status = "open_no_auth"
                state.error = None
                return _redis_lifecycle_record(state, include_data=False)
            if ping_type == "error" and _is_noauth_error(str(ping_value)):
                state.is_redis = True
                state.auth_required = True
                state.status = "auth_required"
                state.error = None
                return _redis_lifecycle_record(state, include_data=False)
            state.is_redis = ping_type == "error"
            state.auth_required = None
            state.status = "fail"
            state.error = f"unexpected PING response: {ping_type} {ping_value}"
            if not state.is_redis:
                _close_redis_lifecycle_socket(state)
            return _redis_lifecycle_record(state, include_data=False)
        except (OSError, ValueError, ConnectionError) as exc:
            last_error = str(exc)
            _close_redis_lifecycle_socket(state)
            if attempt < attempts - 1:
                time.sleep(_retry_delay(attempt))
    state.is_redis = False
    state.auth_required = None
    state.status = "fail"
    state.error = last_error or "connection failed"
    return _redis_lifecycle_record(state, include_data=False)


def redis_auth_hook(ctx: Any, _detect_record: AuditRecord) -> AuditRecord:
    state = ctx.lifecycle_state
    if not isinstance(state, RedisAuditLifecycleState):
        raise TypeError("redis lifecycle state is missing")
    if not state.is_redis or state.status == "fail":
        return _redis_lifecycle_record(state, include_data=False)
    credential = ctx.credential
    exhaustive_credentials = bool(getattr(ctx.args, "defcreds", False))
    if credential.username is None and credential.password is None:
        state.status = "open_no_auth" if state.auth_required is False else "auth_required"
        return _redis_lifecycle_record(state, include_data=False)

    attempts = max(1, state.retries + 1)
    last_error: str | None = None
    for attempt in range(attempts):
        state.auth_attempts_used = attempt + 1
        try:
            if state.sock is None:
                _open_redis_lifecycle_socket(state)
            if credential.source == "default":
                state.default_credentials_attempted = True
                if credential.username == "redis" and credential.password == "redis":
                    default_ok, default_error = _check_default_credentials(
                        state.sock,
                        legacy_passwords_attempted=state.legacy_auth_passwords_attempted,
                    )
                else:
                    default_ok, default_error = _check_default_credentials(
                        state.sock,
                        credential.username or "",
                        credential.password or "",
                        legacy_passwords_attempted=state.legacy_auth_passwords_attempted,
                    )
                state.default_credentials = bool(default_ok)
                if default_ok:
                    state.status = "weak_default_creds"
                    state.error = None
                    if not exhaustive_credentials:
                        state.active_username = credential.username
                        state.active_password = credential.password
                        state.active_source = "default"
                    elif state.selected_sock is None:
                        state.selected_sock = state.sock
                        state.sock = None
                        state.active_username = credential.username
                        state.active_password = credential.password
                        state.active_source = "default"
                    else:
                        _close_redis_lifecycle_socket(state)
                else:
                    state.status = "invalid_credentials_anonymous" if state.auth_required is False else "auth_required"
                    state.error = default_error
                    if state.selected_sock is not None:
                        _close_redis_lifecycle_socket(state)
                return _redis_lifecycle_record(state, include_data=False)

            state.provided_credentials = True
            state.provided_username = credential.username
            state.provided_password = credential.password
            provided_ok, provided_error = _check_provided_credentials(
                state.sock,
                credential.username,
                credential.password,
                legacy_passwords_attempted=state.legacy_auth_passwords_attempted,
            )
            state.provided_credentials_ok = bool(provided_ok)
            if provided_ok:
                state.status = "valid_credentials"
                state.error = None
                if not exhaustive_credentials:
                    state.active_username = credential.username
                    state.active_password = credential.password
                    state.active_source = credential.source
                elif state.selected_sock is None:
                    state.selected_sock = state.sock
                    state.sock = None
                    state.active_username = credential.username
                    state.active_password = credential.password
                    state.active_source = credential.source
                else:
                    _close_redis_lifecycle_socket(state)
            else:
                state.status = "invalid_credentials_anonymous" if state.auth_required is False else "auth_required"
                state.error = provided_error
                if state.selected_sock is not None:
                    _close_redis_lifecycle_socket(state)
            return _redis_lifecycle_record(state, include_data=False)
        except (OSError, ValueError, ConnectionError) as exc:
            last_error = str(exc)
            _close_redis_lifecycle_socket(state)
            if attempt < attempts - 1:
                time.sleep(_retry_delay(attempt))
    state.status = "fail"
    state.error = last_error or "authentication request failed"
    return _redis_lifecycle_record(state, include_data=False)


def _redis_reset_lifecycle_data(state: RedisAuditLifecycleState, args: Any) -> tuple[int, int]:
    state.show_keys = show_flag_enabled(getattr(args, "show_keys", False))
    state.show_keys_limit = show_flag_limit(getattr(args, "show_keys", False))
    state.dump_keys = dump_flag_enabled(getattr(args, "dump", False))
    state.dump_keys_limit = dump_flag_limit(getattr(args, "dump", False))
    state.query_key = str(getattr(args, "key", None) or getattr(args, "query_key", None) or "").strip() or None
    dump_batch = int(getattr(args, "dump_batch", 10000) or 10000)
    dump_delay = int(getattr(args, "dump_delay", 20) or 0)
    state.key_count = None
    state.keys = None
    state.key_values = None
    state.key_value_entries = None
    state.query_key_value = None
    state.query_key_entry = None
    return dump_batch, dump_delay


def _redis_reauthenticate_lifecycle_state(state: RedisAuditLifecycleState) -> None:
    if state.active_source == "anonymous":
        return
    ok: bool | None
    error: str | None
    if state.active_source == "default":
        if (state.active_username, state.active_password) in {(None, None), ("redis", "redis")}:
            ok, error = _check_default_credentials(state.sock)
        else:
            ok, error = _check_default_credentials(
                state.sock,
                state.active_username or "",
                state.active_password or "",
            )
    else:
        ok, error = _check_provided_credentials(
            state.sock,
            state.active_username,
            state.active_password,
        )
    if not ok:
        raise _RedisAuthenticationRejected(error or "authentication rejected during data retry")


def _redis_collect_lifecycle_data_once(
    state: RedisAuditLifecycleState,
    *,
    dump_batch: int,
    dump_delay: int,
) -> None:
    state.key_count, count_error = _count_redis_keys(state.sock)
    if count_error:
        state.error = count_error
    if state.dump_keys:
        dumped_entries, dump_error = _stream_dump_redis_keys(
            state.sock,
            batch=dump_batch,
            delay_ms=dump_delay,
            limit=state.dump_keys_limit,
        )
        if dump_error:
            state.error = dump_error if state.error is None else f"{state.error}; {dump_error}"
        state.key_value_entries = dumped_entries
        state.key_values = [_redis_kv_entry_text(item) for item in dumped_entries]
        state.keys = [str(entry.get("key") or "") for entry in dumped_entries]
        if state.key_count is None:
            state.key_count = len(dumped_entries)
    elif state.show_keys:
        state.keys, keys_error = _scan_redis_keys(state.sock, limit=state.show_keys_limit)
        if keys_error:
            state.error = keys_error if state.error is None else f"{state.error}; {keys_error}"
        if state.key_count is None and isinstance(state.keys, list):
            state.key_count = len(state.keys)

    if state.query_key:
        value_text, value_error = _dump_redis_key_value(state.sock, state.query_key)
        if value_error:
            state.error = value_error if state.error is None else f"{state.error}; {value_error}"
        else:
            state.query_key_entry = _redis_kv_entry(state.query_key, value_text)
            state.query_key_value = _redis_kv_entry_text(state.query_key_entry)


def redis_data_hook(ctx: Any, _auth_record: AuditRecord) -> AuditRecord:
    state = ctx.lifecycle_state
    if not isinstance(state, RedisAuditLifecycleState):
        raise TypeError("redis lifecycle state is missing")
    args = ctx.args
    # The shared state may currently reflect a later credential from an
    # exhaustive sweep. Deep actions deliberately use the first confirmed
    # identity, so reconnect and restore that selected credential first.
    if bool(getattr(args, "defcreds", False)):
        state.status = str(_auth_record.status)
        state.error = _auth_record.extra.get("error")
        state.active_username = ctx.credential.username
        state.active_password = ctx.credential.password
        state.active_source = str(ctx.credential.source or "provided")
        state.default_credentials = state.status == "weak_default_creds"
        state.provided_credentials = ctx.credential.source != "default"
        state.provided_username = ctx.credential.username
        state.provided_password = ctx.credential.password
        state.provided_credentials_ok = state.status in {
            "valid_credentials",
            "weak_default_creds",
        }
        if state.selected_sock is not None:
            _close_redis_lifecycle_socket(state)
            state.sock = state.selected_sock
            state.selected_sock = None
    dump_batch, dump_delay = _redis_reset_lifecycle_data(state, args)

    if state.status not in _REDIS_DEEP_STATUSES:
        return _redis_lifecycle_record(state, include_data=False)

    attempts = max(1, state.retries + 1)
    last_error: str | None = None
    for attempt in range(attempts):
        state.data_attempts_used = attempt + 1
        try:
            if state.sock is None:
                _open_redis_lifecycle_socket(state)
                _redis_reauthenticate_lifecycle_state(state)
            state.error = None
            _redis_collect_lifecycle_data_once(
                state,
                dump_batch=dump_batch,
                dump_delay=dump_delay,
            )
            return _redis_lifecycle_record(state, include_data=True)
        except _RedisAuthenticationRejected as exc:
            state.status = "auth_required"
            state.error = str(exc)
            break
        except (OSError, ValueError, ConnectionError) as exc:
            last_error = str(exc)
            _close_redis_lifecycle_socket(state)
            if attempt < attempts - 1:
                time.sleep(_retry_delay(attempt))
                _redis_reset_lifecycle_data(state, args)
    if state.status in _REDIS_DEEP_STATUSES:
        state.status = "fail"
    state.error = state.error or last_error or "data request failed"
    return _redis_lifecycle_record(state, include_data=True)


def _audit_redis_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    defcreds: bool,
    show_keys: bool,
    dump_keys: bool,
    query_key: str | None,
    show_keys_limit: int | None = None,
    dump_keys_limit: int | None = None,
    dump_batch: int = 10000,
    dump_delay: int = 20,
    credential_candidates: list[dict[str, Any]] | None = None,
    *,
    use_tls: bool = False,
    insecure: bool = False,
    tls_ca: str | None = None,
    tls_cert: str | None = None,
    tls_key: str | None = None,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    normalized_candidates: list[tuple[str | None, str | None, bool]] = []
    seen_candidates: set[tuple[str | None, str | None]] = set()

    def add_candidate(
        candidate_username: str | None,
        candidate_password: str | None,
        *,
        default: bool,
    ) -> None:
        pair = (candidate_username, candidate_password)
        if pair in seen_candidates:
            return
        seen_candidates.add(pair)
        normalized_candidates.append((candidate_username, candidate_password, default))

    for candidate in credential_candidates or []:
        if not isinstance(candidate, dict):
            continue
        candidate_username = candidate.get("username")
        candidate_password = candidate.get("password")
        if candidate_username is None and candidate_password is None:
            continue
        add_candidate(
            str(candidate_username) if candidate_username is not None else None,
            str(candidate_password) if candidate_password is not None else None,
            default=bool(candidate.get("default")) or str(candidate.get("source") or "") == "default",
        )
    if not normalized_candidates and (username is not None or password is not None):
        add_candidate(username, password, default=False)
    if defcreds and not any(candidate[2] for candidate in normalized_candidates):
        for default_username, default_password in _REDIS_DEFAULT_CREDENTIALS:
            add_candidate(default_username, default_password, default=True)

    provided_candidates = [candidate for candidate in normalized_candidates if not candidate[2]]
    provided_credentials = bool(provided_candidates)
    provided_username = provided_candidates[0][0] if provided_candidates else username
    provided_password = provided_candidates[0][1] if provided_candidates else password
    defaults_enabled = any(candidate[2] for candidate in normalized_candidates)

    for attempt in range(attempts):
        started = time.monotonic()
        try:
            with _open_redis_socket(
                host,
                port,
                timeout,
                use_tls=use_tls,
                insecure=insecure,
                ca_file=tls_ca,
                cert_file=tls_cert,
                key_file=tls_key,
            ) as sock:
                ping_type, ping_value = _send_cmd(sock, "PING")
                auth_required = False
                if ping_type == "simple" and str(ping_value).upper() == "PONG":
                    auth_required = False
                elif ping_type == "error" and _is_noauth_error(str(ping_value)):
                    auth_required = True
                else:
                    # RESP-shaped `-` errors (LOADING/BUSY/MISCONF/READONLY) still identify a
                    # Redis-compatible server; anything else (bulk/integer/array/null/simple
                    # non-PONG) is not Redis — a proxy or gRPC service that happened to accept
                    # bytes must not be labelled as Redis in the report.
                    is_redis_response = ping_type == "error"
                    return {
                        "timestamp": utc_now_iso(),
                        "host": host,
                        "port": port,
                        "is_redis": is_redis_response,
                        "status": "fail",
                        "auth_required": None,
                        "default_credentials": None,
                        "provided_credentials": provided_credentials,
                        "provided_username": provided_username,
                        "provided_password": provided_password if provided_credentials else None,
                        "provided_credentials_ok": None,
                        "defcreds_enabled": defaults_enabled,
                        "show_keys": show_keys,
                        "show_keys_limit": show_keys_limit,
                        "dump_keys": dump_keys,
                        "query_key": query_key,
                        "key_count": None,
                        "keys": None,
                        "key_values": None,
                        "key_value_entries": None,
                        "query_key_value": None,
                        "query_key_entry": None,
                        "elapsed_ms": int((time.monotonic() - started) * 1000),
                        "error": f"unexpected PING response: {ping_type} {ping_value}",
                    }

                default_credentials = False
                default_credentials_attempted = False
                provided_credentials_ok: bool | None = None
                effective_username: str | None = None
                effective_password: str | None = None
                auth_error: str | None = None
                legacy_passwords_attempted: set[str] = set()

                if auth_required:
                    for candidate_username, candidate_password, candidate_is_default in normalized_candidates:
                        candidate_ok: bool | None
                        if candidate_is_default:
                            default_credentials_attempted = True
                            if candidate_username == "redis" and candidate_password == "redis":
                                candidate_ok, candidate_error = _check_default_credentials(
                                    sock,
                                    legacy_passwords_attempted=legacy_passwords_attempted,
                                )
                            else:
                                candidate_ok, candidate_error = _check_default_credentials(
                                    sock,
                                    candidate_username or "",
                                    candidate_password or "",
                                    legacy_passwords_attempted=legacy_passwords_attempted,
                                )
                            if candidate_ok:
                                default_credentials = True
                                effective_username = candidate_username
                                effective_password = candidate_password
                                auth_error = None
                                break
                            if candidate_error:
                                auth_error = candidate_error
                        else:
                            candidate_ok, provided_error = _check_provided_credentials(
                                sock,
                                candidate_username,
                                candidate_password,
                                legacy_passwords_attempted=legacy_passwords_attempted,
                            )
                            provided_credentials_ok = bool(candidate_ok)
                            provided_username = candidate_username
                            provided_password = candidate_password
                            if candidate_ok:
                                effective_username = candidate_username
                                effective_password = candidate_password
                                auth_error = None
                                break
                            if provided_error:
                                auth_error = provided_error or auth_error

                key_count: int | None = None
                keys: list[str] | None = None
                key_values: list[str] | None = None
                key_value_entries: list[dict[str, str | None]] | None = None
                query_key_value: str | None = None
                query_key_entry: dict[str, str | None] | None = None
                can_read_keys = (not auth_required) or default_credentials or bool(provided_credentials_ok)
                if can_read_keys:
                    key_count, count_error = _count_redis_keys(sock)
                    if count_error:
                        auth_error = count_error if auth_error is None else f"{auth_error}; {count_error}"

                if dump_keys and can_read_keys:
                    dumped_entries, dump_error = _stream_dump_redis_keys(
                        sock,
                        batch=dump_batch,
                        delay_ms=dump_delay,
                        limit=dump_keys_limit,
                    )
                    if dump_error:
                        auth_error = dump_error if auth_error is None else f"{auth_error}; {dump_error}"
                    key_value_entries = dumped_entries
                    key_values = [_redis_kv_entry_text(item) for item in dumped_entries]
                    keys = [str(entry.get("key") or "") for entry in dumped_entries]
                    if key_count is None:
                        key_count = len(dumped_entries)
                elif show_keys and can_read_keys:
                    keys, key_error = _scan_redis_keys(sock, limit=show_keys_limit)
                    if key_error:
                        auth_error = key_error if auth_error is None else f"{auth_error}; {key_error}"
                    if key_count is None and isinstance(keys, list):
                        key_count = len(keys)

                if query_key and can_read_keys:
                    key_name = query_key.strip()
                    if key_name:
                        value_text, value_error = _dump_redis_key_value(sock, key_name)
                        if value_error:
                            auth_error = value_error if auth_error is None else f"{auth_error}; {value_error}"
                        else:
                            query_key_entry = _redis_kv_entry(key_name, value_text)
                            query_key_value = _redis_kv_entry_text(query_key_entry)

                if not auth_required:
                    status = "open_no_auth"
                elif default_credentials:
                    status = "weak_default_creds"
                elif provided_credentials_ok:
                    status = "valid_credentials"
                else:
                    status = "auth_required"

                return {
                    "timestamp": utc_now_iso(),
                    "host": host,
                    "port": port,
                    "is_redis": True,
                    "status": status,
                    "auth_required": auth_required,
                    "default_credentials": default_credentials,
                    "provided_credentials": provided_credentials,
                    "provided_username": provided_username,
                    "provided_password": provided_password if provided_credentials else None,
                    "provided_credentials_ok": provided_credentials_ok,
                    "effective_username": effective_username,
                    "effective_password": effective_password,
                    "defcreds_enabled": defaults_enabled,
                    "default_credentials_attempted": default_credentials_attempted,
                    "show_keys": show_keys,
                    "show_keys_limit": show_keys_limit,
                    "dump_keys": dump_keys,
                    "query_key": query_key,
                    "key_count": key_count,
                    "keys": keys,
                    "key_values": key_values,
                    "key_value_entries": key_value_entries,
                    "query_key_value": query_key_value,
                    "query_key_entry": query_key_entry,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": auth_error,
                    "transport_mode": "tls" if use_tls else "plaintext",
                    "tls_client_cert_used": bool(use_tls and tls_cert and tls_key),
                }
        except (OSError, ValueError, ConnectionError) as exc:
            last_error = str(exc)
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_redis": False,
        "status": "fail",
        "auth_required": None,
        "default_credentials": None,
        "provided_credentials": provided_credentials,
        "provided_username": provided_username,
        "provided_password": provided_password if provided_credentials else None,
        "provided_credentials_ok": None,
        "defcreds_enabled": defaults_enabled,
        "default_credentials_attempted": False,
        "show_keys": show_keys,
        "show_keys_limit": show_keys_limit,
        "dump_keys": dump_keys,
        "query_key": query_key,
        "key_count": None,
        "keys": None,
        "key_values": None,
        "key_value_entries": None,
        "query_key_value": None,
        "query_key_entry": None,
        "elapsed_ms": None,
        "error": last_error or "connection failed",
    }


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{'REDIS':<8}\t{host}\t{port}\t"


def _with_optional_keys(record: dict[str, Any], message: str) -> str:
    return f"{message} (keys:{format_count_value(record.get('key_count'))})"


def _format_keys_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    show_keys = bool(record.get("show_keys"))
    dump_keys = bool(record.get("dump_keys"))
    query_key = str(record.get("query_key") or "").strip()
    query_key_value = record.get("query_key_value")
    query_key_entry = record.get("query_key_entry")
    if not show_keys and not dump_keys and not query_key:
        return []

    keys = record.get("keys")
    key_names: list[str] = []
    if isinstance(keys, list):
        key_names = sorted(str(item) for item in keys)
    show_keys_limit = record.get("show_keys_limit")
    key_limit = show_keys_limit if isinstance(show_keys_limit, int) and not isinstance(show_keys_limit, bool) else None
    key_meta = limit_metadata(key_names, key_limit)
    displayed_key_names = limit_sequence(key_names, key_limit)

    key_entries = record.get("key_value_entries")
    key_values = record.get("key_values")
    dumped_key_values: list[str] = []
    dumped_key_entries: list[dict[str, str | None]] = []
    if isinstance(key_entries, list):
        for item in key_entries:
            if isinstance(item, dict):
                entry = _redis_kv_entry(str(item.get("key") or ""), item.get("value"), error=item.get("error"))
                dumped_key_entries.append(entry)
        dumped_key_values = [_redis_kv_entry_text(item) for item in dumped_key_entries]
    elif isinstance(key_values, list):
        dumped_key_values = [str(item) for item in key_values]

    if output_format == "json":
        lines: list[str] = []
        if show_keys and key_names:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "keys_list",
                        "service": "redis",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "key_count": record.get("key_count"),
                        "keys": displayed_key_names,
                        "keys_shown": key_meta["shown"],
                        "keys_limit": key_meta["limit"],
                        "keys_truncated": key_meta["truncated"],
                    },
                    ensure_ascii=False,
                )
            )
        if query_key and isinstance(query_key_value, str):
            query_entry = query_key_entry if isinstance(query_key_entry, dict) else None
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "key_dump",
                        "service": "redis",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "query_key": query_key,
                        "key_value": query_key_value,
                        "key_entry": query_entry,
                    },
                    ensure_ascii=False,
                )
            )
        if dump_keys and dumped_key_values:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "keys_dump",
                        "service": "redis",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "key_count": record.get("key_count"),
                        "key_values": dumped_key_values,
                        "key_value_entries": dumped_key_entries,
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    prefix = _nxc_prefix(record)
    lines = []
    if show_keys and key_names:
        total = record.get("key_count")
        if key_limit is not None and isinstance(total, int) and total > len(displayed_key_names):
            lines.append(f"{prefix} [*] Show Keys (showing:{len(displayed_key_names)} of {total})")
        else:
            lines.append(f"{prefix} [*] Show Keys")
        for item in displayed_key_names:
            lines.append(f"{prefix} {_format_redis_text(item)}")
    if query_key and isinstance(query_key_value, str):
        lines.append(f"{prefix} [*] Dump Key {query_key}")
        lines.append(f"{prefix} {_format_redis_text(query_key_value)}")
    if dump_keys and dumped_key_values:
        lines.append(f"{prefix} [*] Dump Keys")
        for item in dumped_key_values:
            lines.append(f"{prefix} {_format_redis_text(item)}")
    return lines


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 64)
    attempted_credentials = record.get("attempted_credentials")
    has_attempt_details = isinstance(attempted_credentials, list) and len(attempted_credentials) > 1

    if status == "open_no_auth":
        return ""

    if status == "weak_default_creds":
        if has_attempt_details:
            return ""
        username = str(record.get("effective_username") or "redis").strip() or "redis"
        effective_password = record.get("effective_password")
        password_text = (
            "<empty>"
            if effective_password == ""
            else str(effective_password)
            if effective_password is not None
            else "redis"
        )
        return _with_optional_keys(record, f"{prefix} [+] {username}:{password_text}")

    if status == "valid_credentials":
        if has_attempt_details:
            return ""
        username = str(record.get("provided_username") or "default").strip() or "default"
        provided_password = record.get("provided_password")
        password_text = "<empty>" if provided_password == "" else str(provided_password or "")
        return _with_optional_keys(record, f"{prefix} [+] {username}:{password_text}")

    if status == "auth_required":
        if has_attempt_details:
            return ""
        if record.get("provided_credentials"):
            username = str(record.get("provided_username") or "default").strip() or "default"
            provided_password = record.get("provided_password")
            password_text = "<empty>" if provided_password == "" else str(provided_password or "")
            base = f"{prefix} [-] {username}:{password_text}"
        elif record.get("default_credentials_attempted"):
            base = f"{prefix} [-] redis:redis"
        else:
            base = f"{prefix} [-] authentication required"
        return base

    fail_line = f"{prefix} [!] connection failed"
    if err != "-":
        return f"{fail_line} err={err}"
    return fail_line


def _format_credential_attempts_records(record: dict[str, Any], output_format: str) -> list[str]:
    attempts = record.get("attempted_credentials")
    if output_format == "json" or not isinstance(attempts, list) or len(attempts) < 2:
        return []

    prefix = _nxc_prefix(record)
    selected_username = record.get("effective_username")
    selected_password = record.get("effective_password")
    selected_success_rendered = False
    lines: list[str] = []
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        username = str(attempt.get("username") or "default")
        password = attempt.get("password")
        if password is None:
            password_text = "<no-password>"
        elif password == "":
            password_text = "<empty>"
        else:
            password_text = str(password)
        status = str(attempt.get("status") or "")
        if status not in {"valid_credentials", "weak_default_creds"}:
            lines.append(f"{prefix} [-] {username}:{password_text}")
            continue
        selected = (
            not selected_success_rendered
            and attempt.get("username") == selected_username
            and password == selected_password
        )
        suffix = f" (keys:{format_count_value(record.get('key_count'))})" if selected else ""
        selected_success_rendered = selected_success_rendered or selected
        lines.append(f"{prefix} [+] {username}:{password_text}{suffix}")
    return lines


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
                "service": "redis",
                "detected": bool(record.get("is_redis")),
                "auth_required": auth_required_value,
            },
            ensure_ascii=False,
        )

    prefix = _nxc_prefix(record)
    return f"{prefix} [*] Redis Database (auth required:{auth_required_text})"


def _render_colored_redis_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(console, line, tag="REDIS", counts=(CountColorRule("keys", "red"),)):
        return True
    if line.startswith("REDIS") and "\t" in line:
        return render_tagged_detail_line(console, line, tag="REDIS", default_color="orange")
    return False


_REDIS_DEEP_STATUSES = {"open_no_auth", "weak_default_creds", "valid_credentials", "invalid_credentials_anonymous"}


def _call_audit_redis_host_with_stage_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    defcreds: bool,
    show_keys: bool,
    dump_keys: bool,
    query_key: str | None,
    show_keys_limit: int | None = None,
    dump_keys_limit: int | None = None,
    dump_batch: int = 10000,
    dump_delay: int = 20,
    credential_candidates: list[dict[str, Any]] | None = None,
    *,
    tls: bool = False,
    insecure: bool = False,
    tls_ca: str | None = None,
    tls_cert: str | None = None,
    tls_key: str | None = None,
    run_deep_checks: bool,
    debug: bool,
    debug_emit: Callable[[str], None] | None,
) -> dict[str, Any]:
    started = time.monotonic()
    record = _audit_redis_host(
        host,
        port,
        timeout,
        retries,
        username,
        password,
        defcreds,
        show_keys if run_deep_checks else False,
        dump_keys if run_deep_checks else False,
        query_key if run_deep_checks else None,
        show_keys_limit=show_keys_limit if run_deep_checks else None,
        dump_keys_limit=dump_keys_limit if run_deep_checks else None,
        dump_batch=dump_batch,
        dump_delay=dump_delay,
        credential_candidates=credential_candidates,
        use_tls=bool(tls or insecure or tls_ca or tls_cert or tls_key),
        insecure=insecure,
        tls_ca=tls_ca,
        tls_cert=tls_cert,
        tls_key=tls_key,
    )

    result: dict[str, Any] = dict(record)
    status = str(result.get("status") or "fail")
    is_redis = bool(result.get("is_redis"))
    attempts = max(1, retries + 1)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    telemetry = StageTelemetryBuilder(host=host, port=port, attempts=attempts, debug=debug, debug_emit=debug_emit)
    # Preserve any debug events the underlying audit had already recorded before reaching
    # this wrapper. Without this, telemetry would start empty and lose pre-existing events.
    existing_debug = result.get("debug_events")
    if isinstance(existing_debug, list):
        for item in existing_debug:
            if isinstance(item, str) and item.strip():
                telemetry.events.append(item)

    detect_result = "ok" if is_redis else ("error" if status == "fail" else "skip")
    telemetry.stage(
        "detect_protocol", detect_result, str(result.get("error") or "") if detect_result == "error" else None, 0
    )
    telemetry.stage(
        "auth_inference_credentials",
        "ok" if status in _REDIS_DEEP_STATUSES.union({"auth_required"}) else ("error" if status == "fail" else "skip"),
        None,
        0,
    )

    if run_deep_checks and status in _REDIS_DEEP_STATUSES:
        telemetry.stage("access_capabilities", "ok", None, 0)
        data_result = "error" if (status == "fail" and result.get("error")) else "ok"
        telemetry.stage(
            "data", data_result, str(result.get("error") or "") if data_result == "error" else None, elapsed_ms
        )
    else:
        telemetry.stage("access_capabilities", "skip", "deep checks disabled", 0)
        telemetry.stage("data", "skip", "deep checks disabled", 0)

    stage_durations_ms = {
        str(item.get("stage_name") or ""): int(item.get("duration_ms") or 0) for item in telemetry.stages
    }
    telemetry.debug(
        f"stage_timing_summary status={status} attempts=1/{attempts} "
        f"detect_ms={stage_durations_ms.get('detect_protocol', 0)} "
        f"auth_ms={stage_durations_ms.get('auth_inference_credentials', 0)} "
        f"capabilities_ms={stage_durations_ms.get('access_capabilities', 0)} "
        f"data_ms={stage_durations_ms.get('data', 0)} "
        f"total_ms={elapsed_ms}"
    )
    result = telemetry.attach(result, status=status, total_ms=elapsed_ms)
    result["attempts"] = 1
    result["max_attempts"] = attempts
    return result


def _merge_stage2_record(detect_record: dict[str, Any], deep_record: dict[str, Any]) -> dict[str, Any]:
    return merge_stage_records(detect_record, deep_record)


# Typed runner boundary -----------------------------------------------------
host_stage = _call_audit_redis_host_with_stage_debug
