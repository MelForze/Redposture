"""redis audit actions and compatibility helpers."""

from __future__ import annotations

import json
import socket
import time
from collections.abc import Callable
from typing import Any

from ...clients import transport
from ...console import Console
from ...rendering import CountColorRule, render_colored_marker_line
from ...show_limits import (
    limit_metadata,
    limit_sequence,
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


def _clip(text: str, width: int = 64) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _encode_resp_array(parts: list[str]) -> bytes:
    payload = [f"*{len(parts)}\r\n".encode("ascii")]
    for item in parts:
        raw = item.encode("utf-8")
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
        return "bulk", body[:-2].decode("utf-8", errors="replace")
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


def _send_cmd(sock: socket.socket, *parts: str) -> tuple[str, Any]:
    sock.sendall(_encode_resp_array(list(parts)))
    return _read_resp(sock)


def _is_noauth_error(message: str) -> bool:
    upper = message.upper()
    return "NOAUTH" in upper or "AUTHENTICATION REQUIRED" in upper


def _auth_with_password(sock: socket.socket, password: str) -> tuple[bool, str | None]:
    auth_type, auth_value = _send_cmd(sock, "AUTH", password)
    if auth_type == "simple" and str(auth_value).upper() == "OK":
        return True, None
    if auth_type == "error":
        return False, str(auth_value)
    return False, f"unexpected AUTH response: {auth_type} {auth_value}"


def _auth_with_user_password(sock: socket.socket, username: str, password: str) -> tuple[bool, str | None]:
    auth_type, auth_value = _send_cmd(sock, "AUTH", username, password)
    if auth_type == "simple" and str(auth_value).upper() == "OK":
        return True, None
    if auth_type == "error":
        return False, str(auth_value)
    return False, f"unexpected AUTH response: {auth_type} {auth_value}"


def _check_default_credentials(sock: socket.socket) -> tuple[bool, str | None]:
    ok, err = _auth_with_user_password(sock, "redis", "redis")
    if ok:
        return True, None

    error = (err or "").lower()
    if "wrong number of arguments" in error or "syntax" in error:
        return _auth_with_password(sock, "redis")
    return False, err


def _check_provided_credentials(
    sock: socket.socket, username: str | None, password: str | None
) -> tuple[bool | None, str | None]:
    if password is None:
        return None, None
    if username:
        ok, err = _auth_with_user_password(sock, username, password)
        if ok:
            return True, None
        error_text = str(err or "").lower()
        if "wrong number of arguments" in error_text or "syntax" in error_text:
            return _auth_with_password(sock, password)
        return False, err
    return _auth_with_password(sock, password)


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

        next_cursor = str(resp_value[0] if resp_value[0] is not None else "0")
        batch = resp_value[1]
        if not isinstance(batch, list):
            return keys if keys else None, f"unexpected SCAN keys payload: {type(batch).__name__}"

        for item in batch:
            key = str(item)
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
    pending: list[str] = []
    cursor = "0"
    rounds = 0

    def _flush_page(keys_page: list[str]) -> bool:  # returns True when the total cap is reached
        for key_name in sorted(keys_page):
            value_text, value_error = _dump_redis_key_value(sock, key_name)
            if value_error:
                entries.append(_redis_kv_entry(key_name, error=_format_redis_text(value_error)))
            else:
                entries.append(_redis_kv_entry(key_name, value_text))
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

        next_cursor = str(resp_value[0] if resp_value[0] is not None else "0")
        scan_batch = resp_value[1]
        if not isinstance(scan_batch, list):
            return entries, f"unexpected SCAN keys payload: {type(scan_batch).__name__}"

        pending.extend(str(item) for item in scan_batch)
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


def _dump_redis_key_value(sock: socket.socket, key: str) -> tuple[str, str | None]:
    key_type_type, key_type_value = _send_cmd(sock, "TYPE", key)
    if key_type_type == "error":
        return "<error>", str(key_type_value)
    key_type = str(key_type_value or "").strip().lower()
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
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    provided_credentials = password is not None

    for attempt in range(attempts):
        started = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)

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
                        "provided_username": username,
                        "provided_credentials_ok": None,
                        "defcreds_enabled": defcreds,
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
                auth_error: str | None = None

                if auth_required:
                    if defcreds:
                        default_credentials_attempted = True
                        default_credentials, default_error = _check_default_credentials(sock)
                        if default_credentials:
                            auth_error = None
                        else:
                            auth_error = default_error

                    if not default_credentials:
                        provided_credentials_ok, provided_error = _check_provided_credentials(sock, username, password)
                        if provided_credentials_ok:
                            auth_error = None
                        elif provided_error:
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
                    "provided_username": username,
                    "provided_password": password if provided_credentials else None,
                    "provided_credentials_ok": provided_credentials_ok,
                    "defcreds_enabled": defcreds,
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
        "provided_username": username,
        "provided_password": password if provided_credentials else None,
        "provided_credentials_ok": None,
        "defcreds_enabled": defcreds,
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
    key_count = record.get("key_count")
    if not isinstance(key_count, int):
        return f"{message} (keys:-)"
    return f"{message} (keys:{key_count})"


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

    if status == "open_no_auth":
        return _with_optional_keys(record, f"{prefix} [+] anonymous access")

    if status == "weak_default_creds":
        return _with_optional_keys(record, f"{prefix} [+] redis:redis")

    if status == "valid_credentials":
        username = str(record.get("provided_username") or "default").strip() or "default"
        provided_password = record.get("provided_password")
        password_text = "<empty>" if provided_password == "" else str(provided_password or "")
        return _with_optional_keys(record, f"{prefix} [+] {username}:{password_text}")

    if status == "auth_required":
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
    return render_colored_marker_line(console, line, tag="REDIS", counts=(CountColorRule("keys", "red"),))


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
    *,
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
