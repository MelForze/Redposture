"""Redis audit stage."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .console import Console
from .logger import AttemptLogger
from .utils import collect_scan_ports, collect_scan_targets, utc_now_iso


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


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data += chunk
    return data


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
        return _auth_with_user_password(sock, username, password)
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

        cursor = next_cursor
        if cursor == "0":
            break

    return keys, None


def _format_redis_text(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("\n", "\\n")


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
                    return {
                        "timestamp": utc_now_iso(),
                        "host": host,
                        "port": port,
                        "is_redis": True,
                        "status": "fail",
                        "auth_required": None,
                        "default_credentials": None,
                        "provided_credentials": provided_credentials,
                        "provided_username": username,
                        "provided_credentials_ok": None,
                        "defcreds_enabled": defcreds,
                        "show_keys": show_keys,
                        "dump_keys": dump_keys,
                        "query_key": query_key,
                        "key_count": None,
                        "keys": None,
                        "key_values": None,
                        "query_key_value": None,
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
                query_key_value: str | None = None
                can_read_keys = (not auth_required) or default_credentials or bool(provided_credentials_ok)
                if can_read_keys:
                    key_count, count_error = _count_redis_keys(sock)
                    if count_error:
                        auth_error = count_error if auth_error is None else f"{auth_error}; {count_error}"

                if (show_keys or dump_keys) and can_read_keys:
                    keys, key_error = _scan_redis_keys(sock)
                    if key_error:
                        auth_error = key_error if auth_error is None else f"{auth_error}; {key_error}"
                    if key_count is None and isinstance(keys, list):
                        key_count = len(keys)
                    if dump_keys and isinstance(keys, list):
                        dumped: list[str] = []
                        for key_name in sorted(str(item) for item in keys):
                            value_text, value_error = _dump_redis_key_value(sock, key_name)
                            if value_error:
                                dumped.append(f"{key_name}:<error:{_format_redis_text(value_error)}>")
                            else:
                                dumped.append(f"{key_name}:{value_text}")
                        key_values = dumped

                if query_key and can_read_keys:
                    key_name = query_key.strip()
                    if key_name:
                        value_text, value_error = _dump_redis_key_value(sock, key_name)
                        if value_error:
                            auth_error = value_error if auth_error is None else f"{auth_error}; {value_error}"
                        else:
                            query_key_value = f"{key_name}:{value_text}"

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
                    "dump_keys": dump_keys,
                    "query_key": query_key,
                    "key_count": key_count,
                    "keys": keys,
                    "key_values": key_values,
                    "query_key_value": query_key_value,
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
        "dump_keys": dump_keys,
        "query_key": query_key,
        "key_count": None,
        "keys": None,
        "key_values": None,
        "query_key_value": None,
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
    if not show_keys and not dump_keys and not query_key:
        return []

    keys = record.get("keys")
    key_names: list[str] = []
    if isinstance(keys, list):
        key_names = sorted(str(item) for item in keys)

    key_values = record.get("key_values")
    dumped_key_values: list[str] = []
    if isinstance(key_values, list):
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
                        "keys": key_names,
                    },
                    ensure_ascii=False,
                )
            )
        if query_key and isinstance(query_key_value, str):
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
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    prefix = _nxc_prefix(record)
    lines: list[str] = []
    if show_keys and key_names:
        lines.append(f"{prefix} [*] Show Keys")
        for item in key_names:
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
        return _with_optional_keys(record, f"{prefix} [+] no-auth access")

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
            base = f"{prefix} [-] {username}:{password_text} invalid"
        elif record.get("default_credentials_attempted"):
            base = f"{prefix} [-] redis:redis invalid"
        else:
            base = f"{prefix} [-] authentication required"
        if err != "-":
            return f"{base} err={err}"
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
    if not line.startswith("REDIS"):
        return False

    marker_color = {
        "[*]": "cyan",
        "[+]": "bright_green",
        "[-]": "yellow",
        "[!]": "red",
    }
    for marker in ("[!]", "[-]", "[+]", "[*]"):
        token = f" {marker} "
        if token not in line:
            continue
        left, right = line.split(token, 1)
        tag = "REDIS"
        rest = left[len(tag) :] if left.startswith(tag) else left

        spans: list[tuple[int, int, str]] = []
        auth_true = "(auth required:True)"
        auth_false = "(auth required:False)"
        idx_true = right.find(auth_true)
        if idx_true >= 0:
            spans.append((idx_true, idx_true + len(auth_true), "bright_green"))
        idx_false = right.find(auth_false)
        if idx_false >= 0:
            spans.append((idx_false, idx_false + len(auth_false), "red"))

        key_match = re.search(r"\(keys:(\d+)(?: [^)]*)?\)", right)
        if key_match:
            key_value = key_match.group(1).strip()
            if key_value.isdigit() and int(key_value) > 0:
                spans.append((key_match.start(), key_match.end(), "red"))

        if not spans:
            right_colored = console._paint(right, "white", sys.stdout)
        else:
            chunks: list[str] = []
            cursor = 0
            for start, end, color in sorted(spans, key=lambda item: item[0]):
                if start < cursor:
                    continue
                if start > cursor:
                    chunks.append(console._paint(right[cursor:start], "white", sys.stdout))
                chunks.append(console._paint(right[start:end], color, sys.stdout))
                cursor = end
            if cursor < len(right):
                chunks.append(console._paint(right[cursor:], "white", sys.stdout))
            right_colored = "".join(chunks)

        colored = (
            f"{console._paint(tag, 'blue', sys.stdout)}"
            f"{console._paint(rest, 'white', sys.stdout)} "
            f"{console._paint(marker, marker_color[marker], sys.stdout)} "
            f"{right_colored}"
        )
        console.plain(colored)
        return True
    return False


def _emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
    if emit_line is not None:
        emit_line(line)


def audit_redis_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
    username: str | None,
    password: str | None,
    defcreds: bool,
    show_keys: bool,
    dump_keys: bool,
    query_key: str | None,
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
) -> tuple[int, int, int, int, int, int]:
    total = 0
    open_no_auth = 0
    weak = 0
    valid = 0
    auth_required = 0
    fail = 0

    out_fh: Any = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, "a" if append_output else "w", encoding="utf-8")

    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            future_map = {
                executor.submit(
                    _audit_redis_host,
                    host,
                    port,
                    timeout,
                    retries,
                    username,
                    password,
                    defcreds,
                    show_keys,
                    dump_keys,
                    query_key,
                ): host
                for host in hosts
            }
            for future in as_completed(future_map):
                record = future.result()
                total += 1
                status = str(record.get("status") or "fail")
                if status == "open_no_auth":
                    open_no_auth += 1
                elif status == "weak_default_creds":
                    weak += 1
                elif status == "valid_credentials":
                    valid += 1
                elif status == "auth_required":
                    auth_required += 1
                else:
                    fail += 1

                if bool(record.get("is_redis")):
                    _emit_line(out_fh, emit_line, _format_detect_record(record, output_format))

                _emit_line(out_fh, emit_line, _format_record(record, output_format))
                for keys_detail in _format_keys_detail_records(record, output_format):
                    _emit_line(out_fh, emit_line, keys_detail)

                if logger is not None:
                    logger.log(
                        "redis",
                        (str(record.get("host") or "-"), int(record.get("port") or port)),
                        phase="audit",
                        status=record.get("status"),
                        auth_required=record.get("auth_required"),
                        default_credentials=record.get("default_credentials"),
                        provided_credentials_ok=record.get("provided_credentials_ok"),
                        keys=record.get("keys"),
                        error=record.get("error"),
                    )

    finally:
        if out_fh is not None:
            out_fh.close()

    return total, open_no_auth, weak, valid, auth_required, fail


def run_redis_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
        return 2
    if args.username and args.password is None:
        console.error("--password is required when --username is set")
        return 2
    try:
        ports = collect_scan_ports(getattr(args, "ports", None))
    except ValueError as exc:
        console.error(f"failed to parse --port: {exc}")
        return 2
    if not ports:
        ports = [int(args.port)]

    targets = getattr(args, "targets", None) or getattr(args, "hosts", None)
    hosts_file = getattr(args, "hosts_file", None)
    if hosts_file:
        targets = f"{targets},{hosts_file}" if targets else hosts_file

    try:
        hosts = collect_scan_targets(targets)
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2

    if not hosts:
        console.error("redis requires -t/--targets")
        return 2

    stream_to_stdout = not bool(args.output)
    dump_keys_flag = bool(getattr(args, "dump", False))

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith("REDIS") and all(token not in line for token in (" [*] ", " [+] ", " [-] ", " [!] ")):
            if console.render_tagged_payload_line(line, "REDIS", payload_color="orange"):
                return
            console.plain(line, color="white")
            return
        if _render_colored_redis_line(console, line):
            return
        if args.debug:
            console.plain(line)

    if args.debug and stream_to_stdout and args.output_format == "txt":
        mode_parts = ["count-keys"]
        if args.defcreds:
            mode_parts.append("defcreds")
        if args.show_keys:
            mode_parts.append("show-keys")
        if dump_keys_flag:
            mode_parts.append("dump")
        if args.key:
            mode_parts.append(f"key={args.key}")
        mode = "+".join(mode_parts)
        console.info(
            f"redis audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={mode} format=txt"
        )
    if args.debug and not stream_to_stdout:
        mode_parts = ["count-keys"]
        if args.defcreds:
            mode_parts.append("defcreds")
        if args.show_keys:
            mode_parts.append("show-keys")
        if dump_keys_flag:
            mode_parts.append("dump")
        if args.key:
            mode_parts.append(f"key={args.key}")
        mode = "+".join(mode_parts)
        console.info(
            f"redis audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={mode} "
            f"format={args.output_format} output={args.output}"
        )

    total = 0
    open_no_auth = 0
    weak = 0
    valid = 0
    auth_required = 0
    failed = 0
    try:
        for idx, audit_port in enumerate(ports):
            part_total, part_open, part_weak, part_valid, part_auth, part_failed = audit_redis_targets(
                hosts=hosts,
                port=audit_port,
                timeout=args.timeout,
                retries=args.retries,
                workers=args.workers,
                username=args.username,
                password=args.password,
                defcreds=args.defcreds,
                show_keys=args.show_keys,
                dump_keys=dump_keys_flag,
                query_key=args.key,
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                logger=logger if args.debug else None,
                append_output=idx > 0,
            )
            total += part_total
            open_no_auth += part_open
            weak += part_weak
            valid += part_valid
            auth_required += part_auth
            failed += part_failed
    except OSError as exc:
        console.error(f"failed to process redis output: {exc}")
        return 2

    if stream_to_stdout:
        if args.debug and args.output_format == "txt":
            console.info(
                f"redis audit complete: total={total} open={open_no_auth} "
                f"weak={weak} valid={valid} auth={auth_required} fail={failed}"
            )
        return 0

    if args.debug:
        console.info(
            f"redis audit complete: total={total} open={open_no_auth} "
            f"weak={weak} valid={valid} auth={auth_required} fail={failed} "
            f"format={args.output_format} output={args.output}"
        )
    return 0
