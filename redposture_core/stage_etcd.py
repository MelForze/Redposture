"""etcd audit stage."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from .console import Console
from .logger import AttemptLogger
from .rendering import CountColorRule, render_colored_marker_line
from .show_limits import limit_metadata, limit_sequence, show_flag_enabled, show_flag_limit
from .stage_runtime import (
    TwoPassAuditRunner,
    merge_stage_records,
    should_use_global_progress,
    start_audit_progress,
    start_command_progress,
)
from .utils import build_scan_execution_groups, collect_scan_ports, collect_scan_target_specs, utc_now_iso

_CONNECTION_REFUSED_PREFIX = "connection refused"
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_ETCD_DEEP_STATUSES = {"open_no_auth"}
_ETCD_V3_ALL_RANGE_KEY_B64 = "AA=="


def _clip(text: str, width: int = 64) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _friendly_error_text(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return "connection failed"

    if text.startswith("<urlopen error ") and text.endswith(">"):
        text = text[len("<urlopen error ") : -1].strip()

    lower = text.lower()
    if "connection refused" in lower:
        return "connection refused (service is not listening on target port)"
    if "timed out" in lower or "timeout" in lower:
        return "connection timeout"
    if "name or service not known" in lower or "nodename nor servname provided" in lower:
        return "dns lookup failed"
    if "temporary failure in name resolution" in lower:
        return "dns lookup temporary failure"
    if "no route to host" in lower or "network is unreachable" in lower:
        return "network unreachable"
    if "operation not permitted" in lower:
        return "operation not permitted by local environment"

    match = re.search(r"\[errno\s+(-?\d+)\]\s*(.*)", text, flags=re.IGNORECASE)
    if match:
        errno_num = match.group(1)
        detail = (match.group(2) or "").strip()
        if errno_num in {"61", "111"}:
            return "connection refused (service is not listening on target port)"
        if errno_num in {"60", "110"}:
            return "connection timeout"
        if errno_num in {"8", "-2"}:
            return "dns lookup failed"
        if errno_num in {"65", "101", "113"}:
            return "network unreachable"
        if detail:
            return detail
    return text


def _friendly_error_from_exception(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, BaseException):
            return _friendly_error_text(str(reason))
        return _friendly_error_text(str(reason or exc))
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "connection timeout"
    return _friendly_error_text(str(exc))


def _is_connection_refused_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text.startswith(_CONNECTION_REFUSED_PREFIX)


def _is_connection_refused_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail" and _is_connection_refused_error(record.get("error"))


def _is_connection_timeout_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text.startswith(_CONNECTION_TIMEOUT_PREFIX)


def _is_suppressed_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail"


def _http_json_request(
    host: str,
    port: int,
    method: str,
    path: str,
    timeout: float,
    *,
    payload: dict[str, Any] | None = None,
) -> tuple[int, str]:
    url = f"http://{host}:{port}{path}"
    body_bytes: bytes | None = None
    headers = {"User-Agent": "RedPosture/1.0"}
    if payload is not None:
        body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body_bytes, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = int(response.status)
            body = response.read().decode("utf-8", errors="replace")
            return status, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return int(exc.code), body


def _load_json(body: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _body_indicates_auth_required(body: str) -> bool:
    text = (body or "").lower()
    needles = (
        "authentication required",
        "requires user authentication",
        "permission denied",
        "invalid auth token",
        "invalid authentication",
        "etcdserver: user name is empty",
        "etcdserver: authentication failed",
        "unauthenticated",
    )
    return any(needle in text for needle in needles)


def _major_version(value: str | None) -> int | None:
    raw = (value or "").strip()
    if not raw:
        return None
    part = raw.split(".", 1)[0]
    if not part.isdigit():
        return None
    return int(part)


def _count_v2_nodes(node: Any) -> int:
    if not isinstance(node, dict):
        return 0
    if bool(node.get("dir")):
        children = node.get("nodes")
        if not isinstance(children, list):
            return 0
        return sum(_count_v2_nodes(item) for item in children)
    if "key" in node:
        return 1
    return 0


def _count_v2_keys(body: str) -> int | None:
    payload = _load_json(body)
    if payload is None:
        return None
    node = payload.get("node")
    return _count_v2_nodes(node)


def _count_v3_keys(body: str) -> int | None:
    payload = _load_json(body)
    if payload is None:
        return None
    raw_count = payload.get("count")
    if isinstance(raw_count, int):
        return raw_count
    if isinstance(raw_count, str) and raw_count.isdigit():
        return int(raw_count)
    return None


def _join_api_versions(v2_supported: bool, v3_supported: bool) -> str:
    versions: list[str] = []
    if v2_supported:
        versions.append("v2")
    if v3_supported:
        versions.append("v3")
    if not versions:
        return "-"
    return ",".join(versions)


def _format_etcd_text(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("\n", "\\n")


def _normalize_etcd_key(value: str | None) -> str | None:
    raw = (value or "").strip()
    if not raw:
        return None
    if raw.startswith("/"):
        return raw
    return f"/{raw}"


def _key_name_from_pair(pair: str) -> str:
    key, _sep, _value = str(pair).partition(":")
    return key.strip()


def _b64_encode_text(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _b64_decode_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    padded = value + ("=" * (-len(value) % 4))
    try:
        raw = base64.b64decode(padded, validate=False)
    except Exception:
        return ""
    return raw.decode("utf-8", errors="replace")


def _collect_v2_pairs(node: Any, sink: list[tuple[str, str]]) -> None:
    if not isinstance(node, dict):
        return
    if bool(node.get("dir")):
        children = node.get("nodes")
        if isinstance(children, list):
            for child in children:
                _collect_v2_pairs(child, sink)
        return

    key = str(node.get("key") or "").strip()
    if not key:
        return
    if bool(node.get("dir")):
        sink.append((key, "<dir>"))
        return

    value = _format_etcd_text(node.get("value"))
    sink.append((key, value))


def _dump_v2_all_from_body(body: str) -> list[str] | None:
    payload = _load_json(body)
    if payload is None:
        return None
    node = payload.get("node")
    pairs: list[tuple[str, str]] = []
    _collect_v2_pairs(node, pairs)
    pairs.sort(key=lambda item: item[0])
    return [f"{key}:{value}" for key, value in pairs]


def _dump_v2_key(host: str, port: int, key: str, timeout: float) -> tuple[str | None, str | None]:
    status, body = _http_json_request(host, port, "GET", f"/v2/keys{key}", timeout)
    if status == 404:
        return f"{key}:<not found>", None
    if status != 200:
        return None, f"/v2/keys{key} returned status {status}"

    payload = _load_json(body)
    if payload is None:
        return None, f"/v2/keys{key} returned invalid JSON"
    node = payload.get("node")
    if not isinstance(node, dict):
        return None, f"/v2/keys{key} returned invalid node"
    if bool(node.get("dir")):
        return f"{key}:<dir>", None
    return f"{key}:{_format_etcd_text(node.get('value'))}", None


def _dump_v3_all(
    host: str, port: int, timeout: float, *, limit: int | None = None
) -> tuple[list[str] | None, str | None]:
    payload: dict[str, Any] = {"key": _ETCD_V3_ALL_RANGE_KEY_B64, "range_end": _ETCD_V3_ALL_RANGE_KEY_B64}
    if limit is not None:
        payload["limit"] = limit
    status, body = _http_json_request(
        host,
        port,
        "POST",
        "/v3/kv/range",
        timeout,
        payload=payload,
    )
    if status in (401, 403) or _body_indicates_auth_required(body):
        return None, "authentication required"
    if status != 200:
        return None, f"/v3/kv/range returned status {status}"

    payload = _load_json(body)
    if payload is None:
        return None, "/v3/kv/range returned invalid JSON"
    kvs = payload.get("kvs")
    if not isinstance(kvs, list):
        return [], None

    result: list[str] = []
    for item in kvs:
        if not isinstance(item, dict):
            continue
        key = _b64_decode_text(item.get("key"))
        if not key:
            continue
        value = _format_etcd_text(_b64_decode_text(item.get("value")))
        result.append(f"{key}:{value}")
    result.sort()
    return result, None


def _dump_v3_key(host: str, port: int, key: str, timeout: float) -> tuple[str | None, str | None]:
    status, body = _http_json_request(
        host,
        port,
        "POST",
        "/v3/kv/range",
        timeout,
        payload={"key": _b64_encode_text(key)},
    )
    if status in (401, 403) or _body_indicates_auth_required(body):
        return None, "authentication required"
    if status != 200:
        return None, f"/v3/kv/range returned status {status}"

    payload = _load_json(body)
    if payload is None:
        return None, "/v3/kv/range returned invalid JSON"
    kvs = payload.get("kvs")
    if not isinstance(kvs, list) or not kvs:
        return f"{key}:<not found>", None
    first = kvs[0]
    if not isinstance(first, dict):
        return f"{key}:<not found>", None
    resolved_key = _b64_decode_text(first.get("key")) or key
    value = _format_etcd_text(_b64_decode_text(first.get("value")))
    return f"{resolved_key}:{value}", None


def _audit_etcd_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    show_keys: bool,
    dump_keys: bool,
    query_key: str | None,
    show_keys_limit: int | None = None,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None

    for attempt in range(attempts):
        started = time.monotonic()
        try:
            version_status, version_body = _http_json_request(host, port, "GET", "/version", timeout)
            version_json = _load_json(version_body)

            server_version: str | None = None
            is_etcd = False
            if version_status == 200 and isinstance(version_json, dict):
                etcdserver = version_json.get("etcdserver")
                if isinstance(etcdserver, str) and etcdserver:
                    server_version = etcdserver
                    is_etcd = True
                elif "etcdcluster" in version_json:
                    is_etcd = True

            major = _major_version(server_version)
            v3_supported = bool(is_etcd and (major is None or major >= 3))

            v2_supported = False
            v2_auth_required: bool | None = None
            key_count_v2: int | None = None
            v2_error: str | None = None

            v2_status, v2_body = _http_json_request(host, port, "GET", "/v2/keys?recursive=true", timeout)
            if v2_status in (200, 401, 403):
                v2_supported = True
                if v2_status == 200:
                    v2_auth_required = False
                    key_count_v2 = _count_v2_keys(v2_body)
                else:
                    v2_auth_required = True
            elif _body_indicates_auth_required(v2_body):
                v2_supported = True
                v2_auth_required = True
            elif v2_status not in (404,):
                v2_error = f"/v2/keys returned status {v2_status}"

            v3_auth_required: bool | None = None
            key_count_v3: int | None = None
            v3_error: str | None = None

            if v3_supported:
                auth_status, auth_body = _http_json_request(host, port, "POST", "/v3/auth/status", timeout, payload={})
                auth_json = _load_json(auth_body)
                if auth_status == 200 and isinstance(auth_json, dict) and isinstance(auth_json.get("enabled"), bool):
                    v3_auth_required = bool(auth_json.get("enabled"))
                elif auth_status in (401, 403) or _body_indicates_auth_required(auth_body):
                    v3_auth_required = True

                if v3_auth_required is None or v3_auth_required is False:
                    range_status, range_body = _http_json_request(
                        host,
                        port,
                        "POST",
                        "/v3/kv/range",
                        timeout,
                        payload={
                            "key": _ETCD_V3_ALL_RANGE_KEY_B64,
                            "range_end": _ETCD_V3_ALL_RANGE_KEY_B64,
                            "count_only": True,
                        },
                    )
                    if range_status == 200:
                        v3_auth_required = False
                        key_count_v3 = _count_v3_keys(range_body)
                    elif range_status in (401, 403) or _body_indicates_auth_required(range_body):
                        v3_auth_required = True
                    elif v3_auth_required is None:
                        v3_error = f"/v3/kv/range returned status {range_status}"

            auth_candidates = [value for value in (v2_auth_required, v3_auth_required) if isinstance(value, bool)]
            auth_required: bool | None
            if auth_candidates:
                auth_required = any(auth_candidates)
            else:
                auth_required = None

            key_count: int | None = None
            keys: list[str] | None = None
            key_values: list[str] | None = None
            query_key_value: str | None = None
            key_dump_error: str | None = None
            if auth_required is False:
                key_count = key_count_v2 if key_count_v2 is not None else key_count_v3
                if show_keys or dump_keys:
                    all_key_values: list[str] | None = None
                    if v2_supported:
                        all_key_values = _dump_v2_all_from_body(v2_body)
                        if all_key_values is None:
                            key_dump_error = "/v2/keys returned invalid JSON"
                    elif v3_supported:
                        all_key_values, key_dump_error = _dump_v3_all(
                            host,
                            port,
                            timeout,
                            limit=show_keys_limit if show_keys and not dump_keys else None,
                        )

                    if isinstance(all_key_values, list):
                        if show_keys:
                            names = {_key_name_from_pair(item) for item in all_key_values}
                            keys = sorted(item for item in names if item)
                            if show_keys_limit is not None:
                                keys = keys[:show_keys_limit]
                        if dump_keys:
                            key_values = [str(item) for item in all_key_values]

                if query_key:
                    if v2_supported:
                        key_line, one_key_error = _dump_v2_key(host, port, query_key, timeout)
                    elif v3_supported:
                        key_line, one_key_error = _dump_v3_key(host, port, query_key, timeout)
                    else:
                        key_line, one_key_error = None, "no supported API for key dump"

                    if one_key_error:
                        key_dump_error = (
                            one_key_error if key_dump_error is None else f"{key_dump_error}; {one_key_error}"
                        )
                    elif key_line:
                        query_key_value = str(key_line)

            api_versions = _join_api_versions(v2_supported=v2_supported, v3_supported=v3_supported)

            errors = [item for item in (v2_error, v3_error) if item]
            if key_dump_error:
                errors.append(key_dump_error)
            error = "; ".join(errors) if errors else None

            if not is_etcd and not v2_supported:
                return {
                    "timestamp": utc_now_iso(),
                    "host": host,
                    "port": port,
                    "is_etcd": False,
                    "status": "fail",
                    "api_versions": "-",
                    "server_version": None,
                    "auth_required": None,
                    "key_count": None,
                    "show_keys": show_keys,
                    "show_keys_limit": show_keys_limit,
                    "dump_keys": dump_keys,
                    "query_key": query_key,
                    "keys": None,
                    "key_values": None,
                    "query_key_value": None,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": "service is not etcd",
                }

            status = "open_no_auth"
            if auth_required is True:
                status = "auth_required"
            elif auth_required is None:
                status = "unknown_auth"

            return {
                "timestamp": utc_now_iso(),
                "host": host,
                "port": port,
                "is_etcd": True,
                "status": status,
                "api_versions": api_versions,
                "server_version": server_version,
                "auth_required": auth_required,
                "key_count": key_count,
                "show_keys": show_keys,
                "show_keys_limit": show_keys_limit,
                "dump_keys": dump_keys,
                "query_key": query_key,
                "keys": keys,
                "key_values": key_values,
                "query_key_value": query_key_value,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": error,
            }
        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
            last_error = _friendly_error_from_exception(exc)
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_etcd": False,
        "status": "fail",
        "api_versions": "-",
        "server_version": None,
        "auth_required": None,
        "key_count": None,
        "show_keys": show_keys,
        "show_keys_limit": show_keys_limit,
        "dump_keys": dump_keys,
        "query_key": query_key,
        "keys": None,
        "key_values": None,
        "query_key_value": None,
        "elapsed_ms": None,
        "error": last_error or "connection failed",
    }


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{'ETCD':<8}\t{host}\t{port}\t"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    api_versions = str(record.get("api_versions") or "-")
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
                "service": "etcd",
                "detected": bool(record.get("is_etcd")),
                "api_versions": api_versions,
                "auth_required": auth_required_value,
                "server_version": record.get("server_version"),
            },
            ensure_ascii=False,
        )

    prefix = _nxc_prefix(record)
    return f"{prefix} [*] etcd Database (api:{api_versions}) (auth required:{auth_required_text})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 72)

    if status == "open_no_auth":
        key_count = record.get("key_count")
        if isinstance(key_count, int):
            return f"{prefix} [+] anonymous access (keys:{key_count})"
        return f"{prefix} [+] anonymous access (keys:-)"

    if status == "auth_required":
        return f"{prefix} [-] authentication required"

    if status == "unknown_auth":
        line = f"{prefix} [!] auth status unknown"
        if err != "-":
            return f"{line} err={err}"
        return line

    line = f"{prefix} [!] connection failed"
    if err != "-":
        return f"{line} err={err}"
    return line


def _format_keys_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    show_keys = bool(record.get("show_keys"))
    dump_keys = bool(record.get("dump_keys"))
    query_key = str(record.get("query_key") or "").strip()
    query_key_value = record.get("query_key_value")
    keys = record.get("keys")
    key_values = record.get("key_values")
    if not show_keys and not dump_keys and not query_key:
        return []

    key_names: list[str] = []
    if isinstance(keys, list):
        key_names = sorted(str(item) for item in keys)
    raw_limit = record.get("show_keys_limit")
    show_keys_limit = raw_limit if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) else None
    key_meta = limit_metadata(key_names, show_keys_limit)
    displayed_key_names = limit_sequence(key_names, show_keys_limit)

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
                        "service": "etcd",
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
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "key_dump",
                        "service": "etcd",
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
                        "service": "etcd",
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
        total = record.get("key_count")
        if show_keys_limit is not None and isinstance(total, int) and total > len(displayed_key_names):
            lines.append(f"{prefix} [*] Show Keys (showing:{len(displayed_key_names)} of {total})")
        else:
            lines.append(f"{prefix} [*] Show Keys")
        for item in displayed_key_names:
            lines.append(f"{prefix} {_format_etcd_text(item)}")
    if query_key and isinstance(query_key_value, str):
        lines.append(f"{prefix} [*] Dump Key {query_key}")
        lines.append(f"{prefix} {_format_etcd_text(query_key_value)}")
    if dump_keys and dumped_key_values:
        lines.append(f"{prefix} [*] Dump Keys")
        for item in dumped_key_values:
            lines.append(f"{prefix} {_format_etcd_text(item)}")
    return lines


def _render_colored_etcd_line(console: Console, line: str) -> bool:
    return render_colored_marker_line(console, line, tag="ETCD", counts=(CountColorRule("keys", "red"),))


def _emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
    if emit_line is not None:
        emit_line(line)


def _call_audit_etcd_host_with_stage_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    show_keys: bool,
    dump_keys: bool,
    query_key: str | None,
    show_keys_limit: int | None = None,
    *,
    run_deep_checks: bool,
    debug: bool,
    debug_emit: Callable[[str], None] | None,
) -> dict[str, Any]:
    started = time.monotonic()
    audit_limit_kwargs = (
        {"show_keys_limit": show_keys_limit if run_deep_checks else None} if show_keys_limit is not None else {}
    )
    record = _audit_etcd_host(
        host,
        port,
        timeout,
        retries,
        show_keys if run_deep_checks else False,
        dump_keys if run_deep_checks else False,
        query_key if run_deep_checks else None,
        **audit_limit_kwargs,
    )

    result: dict[str, Any] = dict(record)
    debug_events: list[str] = []

    def _debug(message: str) -> None:
        if not debug:
            return
        debug_events.append(message)
        if debug_emit is not None:
            debug_emit(f"{host}:{port} {message}")

    status = str(result.get("status") or "fail")
    is_etcd = bool(result.get("is_etcd"))
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

    detect_result = "ok" if is_etcd else ("error" if status == "fail" else "skip")
    detect_error = str(result.get("error") or "") if detect_result == "error" else None
    _push_stage(_STAGE_DETECT_PROTOCOL, detect_result, detect_error, 0)

    auth_result = "ok" if is_etcd and status in _ETCD_DEEP_STATUSES.union({"auth_required"}) else detect_result
    _push_stage(_STAGE_AUTH_INFERENCE, auth_result, detect_error if auth_result == "error" else None, 0)

    if run_deep_checks and status in _ETCD_DEEP_STATUSES:
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


def audit_etcd_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
    show_keys: bool,
    dump_keys: bool,
    query_key: str | None,
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
    suppress_connection_refused_status_lines: bool = False,
    debug_emit: Callable[[str], None] | None = None,
    show_progress: bool = False,
    command_progress: Any | None = None,
    show_keys_limit: int | None = None,
) -> tuple[int, int, int, int]:
    total = 0
    open_no_auth = 0
    auth_required = 0
    failed = 0

    out_fh: Any = None
    progress = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, "a" if append_output else "w", encoding="utf-8")

    try:
        indexed_hosts = list(enumerate(hosts))
        progress = (
            command_progress
            if command_progress is not None
            else start_audit_progress("ETCD", len(indexed_hosts), enabled=show_progress, leave=True)
        )
        deep_requested = bool(show_keys or dump_keys or query_key)

        def _detect_task(host: str) -> dict[str, Any]:
            limit_kwargs = {"show_keys_limit": show_keys_limit} if show_keys_limit is not None else {}
            return _call_audit_etcd_host_with_stage_debug(
                host,
                port,
                timeout,
                retries,
                show_keys,
                dump_keys,
                query_key,
                run_deep_checks=False,
                debug=bool(debug_emit),
                debug_emit=debug_emit,
                **limit_kwargs,
            )

        def _deep_task(host: str) -> dict[str, Any]:
            limit_kwargs = {"show_keys_limit": show_keys_limit} if show_keys_limit is not None else {}
            return _call_audit_etcd_host_with_stage_debug(
                host,
                port,
                timeout,
                retries,
                show_keys,
                dump_keys,
                query_key,
                run_deep_checks=True,
                debug=bool(debug_emit),
                debug_emit=debug_emit,
                **limit_kwargs,
            )

        def _emit_detect(detect_record: dict[str, Any]) -> None:
            if bool(detect_record.get("is_etcd")) and output_format == "txt":
                _emit_line(out_fh, emit_line, _format_detect_record(detect_record, output_format))

        def _deep_gate(detect_record: dict[str, Any]) -> tuple[bool, str]:
            detect_status = str(detect_record.get("status") or "fail")
            if deep_requested and detect_status in _ETCD_DEEP_STATUSES:
                return True, f"status={detect_status}"
            reason = "no_data_actions" if not deep_requested else f"status={detect_status}"
            return False, reason

        pass_result = TwoPassAuditRunner(
            label="ETCD",
            workers=workers,
            debug_emit=debug_emit,
            progress=progress,
            detected_name="etcd",
        ).run(
            indexed_hosts,
            detect_task=_detect_task,
            deep_task=_deep_task,
            is_detected=lambda record: bool(record.get("is_etcd")),
            deep_gate=_deep_gate,
            emit_detect=_emit_detect,
            merge_records=_merge_stage2_record,
            not_detected_reason="not_etcd",
        )

        if command_progress is None and progress is not None:
            progress.close()
            progress = None

        final_records = pass_result.final_records

        for idx, _host in indexed_hosts:
            record = final_records[idx]
            total += 1
            status = str(record.get("status") or "fail")

            if status == "open_no_auth":
                open_no_auth += 1
            elif status == "auth_required":
                auth_required += 1
            else:
                failed += 1

            if debug_emit is not None and not bool(record.get("debug_events_streamed")):
                for event in record.get("debug_events") or []:
                    if isinstance(event, str) and event.strip():
                        debug_emit(event)

            if output_format != "txt" and bool(record.get("is_etcd")):
                _emit_line(out_fh, emit_line, _format_detect_record(record, output_format))

            suppress_auth_required_status_line = (
                output_format == "txt" and bool(record.get("is_etcd")) and status == "auth_required"
            )
            suppress_connection_refused_status_line = (
                suppress_connection_refused_status_lines
                and output_format == "txt"
                and _is_suppressed_fail_record(record)
            )
            if not suppress_auth_required_status_line and not suppress_connection_refused_status_line:
                _emit_line(out_fh, emit_line, _format_record(record, output_format))
            for key_line in _format_keys_detail_records(record, output_format):
                _emit_line(out_fh, emit_line, key_line)

            if logger is not None and not (
                suppress_connection_refused_status_lines and _is_suppressed_fail_record(record)
            ):
                logger.log(
                    "etcd",
                    (str(record.get("host") or "-"), int(record.get("port") or port)),
                    phase="audit",
                    status=record.get("status"),
                    auth_required=record.get("auth_required"),
                    api_versions=record.get("api_versions"),
                    server_version=record.get("server_version"),
                    key_count=record.get("key_count"),
                    error=record.get("error"),
                )
    finally:
        if command_progress is None and progress is not None:
            progress.close()
        if out_fh is not None:
            out_fh.close()

    return total, open_no_auth, auth_required, failed


def run_etcd_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
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
        target_specs = collect_scan_target_specs(targets)
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2

    if not target_specs:
        console.error("etcd requires -t/--targets")
        return 2
    if any(spec.scheme == "https" for spec in target_specs):
        console.error("etcd accepts only http:// URL targets for -t/--targets")
        return 2
    hosts = list(dict.fromkeys(spec.host for spec in target_specs))
    execution_groups = build_scan_execution_groups(target_specs, ports, include_scheme_in_key=False)

    stream_to_stdout = not bool(args.output)
    query_key = _normalize_etcd_key(getattr(args, "key", None))
    show_keys = show_flag_enabled(getattr(args, "show_keys", False))
    show_keys_limit = show_flag_limit(getattr(args, "show_keys", False))
    dump_keys = bool(getattr(args, "dump", False))

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith("ETCD") and all(token not in line for token in (" [*] ", " [+] ", " [-] ", " [!] ")):
            if console.render_tagged_payload_line(line, "ETCD", payload_color="orange"):
                return
            console.plain(line, color="white")
            return
        if _render_colored_etcd_line(console, line):
            return
        if args.debug:
            console.plain(line)

    def emit_debug(message: str) -> None:
        if not args.debug:
            return
        debug_method = getattr(console, "debug", None)
        if callable(debug_method):
            debug_method(message)
            return
        console.info(message)

    if args.debug and stream_to_stdout and args.output_format == "txt":
        console.info(
            f"etcd audit started: hosts={len(hosts)} ports={len(execution_groups)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} format=txt"
        )
    if args.debug and not stream_to_stdout:
        console.info(
            f"etcd audit started: hosts={len(hosts)} ports={len(execution_groups)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} format={args.output_format} output={args.output}"
        )

    total = 0
    open_no_auth = 0
    auth_required = 0
    failed = 0
    outer_progress = None
    use_single_global_progress = should_use_global_progress(args.output_format, len(execution_groups))
    if use_single_global_progress:
        outer_progress = start_command_progress(
            args, "ETCD", len(hosts) * len(execution_groups), enabled=True, leave=True
        )
    try:
        for idx, group in enumerate(execution_groups):
            part_total, part_open, part_auth, part_failed = audit_etcd_targets(
                hosts=group.hosts,
                port=group.port,
                timeout=args.timeout,
                retries=args.retries,
                workers=args.workers,
                show_keys=show_keys,
                show_keys_limit=show_keys_limit,
                dump_keys=dump_keys,
                query_key=query_key,
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                logger=logger if args.debug else None,
                append_output=idx > 0,
                suppress_connection_refused_status_lines=not bool(args.debug),
                debug_emit=emit_debug if args.debug else None,
                show_progress=not use_single_global_progress,
                command_progress=outer_progress,
            )
            total += part_total
            open_no_auth += part_open
            auth_required += part_auth
            failed += part_failed
    except OSError as exc:
        console.error(f"failed to process etcd output: {exc}")
        return 2
    finally:
        if outer_progress is not None:
            outer_progress.close()

    if stream_to_stdout:
        if total > 0 and open_no_auth == 0 and auth_required == 0 and failed == total and args.output_format == "txt":
            console.warn("all etcd targets are unreachable; check host/port, network reachability, and service status")
        if args.debug and args.output_format == "txt":
            console.info(
                f"etcd audit complete: total={total} anonymous={open_no_auth} auth_required={auth_required} "
                f"fail={failed}"
            )
        return 0

    if args.debug:
        console.info(
            f"etcd audit complete: total={total} anonymous={open_no_auth} auth_required={auth_required} "
            f"fail={failed} "
            f"format={args.output_format} output={args.output}"
        )
    return 0
