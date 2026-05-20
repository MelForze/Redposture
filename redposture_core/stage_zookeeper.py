"""ZooKeeper audit stage."""

from __future__ import annotations

import argparse
import json
import os
import re
import threading
import time
from collections import Counter
from collections.abc import Callable
from typing import Any

from .clients.zookeeper import (
    _decode_zk_buffer,
    _decode_zk_string,
    _encode_acl_world_anyone_all,
    _encode_zk_string,
    _enumerate_znodes,
    _enumerate_znodes_parallel,
    _format_znode_data,
    _is_system_znode,
    _join_znode_path,
    _normalize_znode_path,
    _parse_children_vector,
    _parse_stat,
    _probe_znode_create_delete,
    _recv_exact,
    _recv_frame,
    _send_frame,
    _zk_error_name,
    _ZkClient,
    _znode_detail_entry,
)
from .console import Console
from .logger import AttemptLogger
from .rendering import BooleanColorRule, CountColorRule, render_colored_marker_line
from .stage_runtime import (
    TwoPassAuditRunner,
    progress_total_from_groups,
    should_use_global_progress,
    start_audit_progress,
    start_command_progress,
)
from .utils import (
    collect_scan_ports,
    collect_scan_targets,
    filter_open_tcp_hosts_for_credential_file,
    is_signature_compat_typeerror,
    parse_username_password_credential_file,
    utc_now_iso,
)

__all__ = [
    "_ZkClient",
    "_decode_zk_buffer",
    "_decode_zk_string",
    "_encode_acl_world_anyone_all",
    "_encode_zk_string",
    "_enumerate_znodes",
    "_enumerate_znodes_parallel",
    "_format_znode_data",
    "_is_system_znode",
    "_join_znode_path",
    "_normalize_znode_path",
    "_parse_children_vector",
    "_parse_stat",
    "_probe_znode_create_delete",
    "_recv_exact",
    "_recv_frame",
    "_send_frame",
    "_zk_error_name",
    "_znode_detail_entry",
]

_ZK_PROTOCOL_VERSION = 0
_ZK_PASSWD_DEFAULT = b"\x00" * 16
_ZK_OP_CREATE = 1
_ZK_OP_DELETE = 2
_ZK_OP_GET_DATA = 4
_ZK_OP_GET_CHILDREN2 = 12
_ZK_OP_CLOSE_SESSION = -11
_ZK_OP_AUTH = 100
_ZK_ERR_OK = 0
_ZK_ERR_NONODE = -101
_ZK_ERR_NOAUTH = -102
_ZK_ERR_RETRYABLE_ROOT_QUERY = -124
_ZK_ERR_NODEEXISTS = -110
_ZK_MAX_FRAME = 64 * 1024 * 1024
_ZK_SYSTEM_PREFIX = "/zookeeper"
_ZK_ACL_ALL_PERMS = 0x1F
_ZK_CREATE_EPHEMERAL = 1
_CONNECTION_REFUSED_PREFIX = "connection refused"
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_UNEXPECTED_EOF_PREFIX = "unexpected eof"
_ROOT_QUERY_ERR_124_PREFIX = "root query failed: err_-124"
_ZK_AUTH_XID = -4
_ZK_ENUM_PROGRESS_INTERVAL_SECONDS = 2.0

_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"

_THREAD_LOCAL_DEBUG_EMIT = threading.local()


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
    if isinstance(exc, TimeoutError):
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


def _is_unexpected_eof_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text.startswith(_UNEXPECTED_EOF_PREFIX)


def _is_root_query_err_124_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text.startswith(_ROOT_QUERY_ERR_124_PREFIX)


def _is_remote_closed_connection_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return "remote end closed connection without response" in text


def _is_retryable_stage_error(value: Any) -> bool:
    return (
        _is_connection_timeout_error(value)
        or _is_unexpected_eof_error(value)
        or _is_remote_closed_connection_error(value)
        or _is_root_query_err_124_error(value)
    )


def _is_suppressed_fail_record(record: dict[str, Any]) -> bool:
    if str(record.get("status") or "") != "fail":
        return False
    err = str(record.get("error") or "").strip().lower()
    if bool(record.get("provided_credentials")) and err.startswith("authentication failed"):
        return False
    return True


def _normalize_auth_probe_result(err_code: int) -> tuple[str, str]:
    if err_code == _ZK_ERR_NOAUTH:
        return "noauth", "noauth"
    if err_code == _ZK_ERR_OK:
        return "ok", "ok"
    if err_code == _ZK_ERR_RETRYABLE_ROOT_QUERY:
        return "retryable_auth_hint", "err_-124"
    if err_code == _ZK_ERR_NONODE:
        return "neutral", "nonode"
    return "error", _zk_error_name(err_code).lower()


def _run_anonymous_auth_probe(host: str, port: int, timeout: float, path: str) -> tuple[int | None, str | None]:
    probe_client = _ZkClient(host, port, timeout)
    try:
        probe_client.connect()
        _children, probe_err, _stat = probe_client.get_children2(path)
        return int(probe_err), None
    except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
        return None, _friendly_error_from_exception(exc)
    finally:
        probe_client.close()


def _infer_auth_required_from_anonymous_probes(
    host: str, port: int, timeout: float, root_err: int, query_znode: str | None
) -> tuple[bool | None, str, list[str]]:
    root_state, root_code = _normalize_auth_probe_result(root_err)
    trace = [f"/:{root_code}"]
    if root_state == "noauth":
        return True, "root_noauth", trace
    if root_state == "ok":
        return False, "root_ok", trace

    probe_paths: list[str] = ["/zookeeper", "/zookeeper/config"]
    if query_znode:
        probe_paths.append(query_znode)

    saw_ok = False
    saw_retryable_auth_hint = root_state == "retryable_auth_hint"
    probe_count = 1
    retryable_count = 1 if root_state == "retryable_auth_hint" else 0
    for probe_path in probe_paths:
        probe_err, probe_exc = _run_anonymous_auth_probe(host, port, timeout, probe_path)
        if probe_exc:
            trace.append(f"{probe_path}:error:{probe_exc}")
            continue
        if probe_err is None:
            trace.append(f"{probe_path}:error:unknown")
            continue
        probe_count += 1
        probe_state, probe_code = _normalize_auth_probe_result(probe_err)
        trace.append(f"{probe_path}:{probe_code}")
        if probe_state == "noauth":
            return True, "probe_noauth", trace
        if probe_state == "ok":
            saw_ok = True
        if probe_state == "retryable_auth_hint":
            saw_retryable_auth_hint = True
            retryable_count += 1

    if saw_ok:
        return False, "probe_ok", trace
    if saw_retryable_auth_hint and retryable_count == probe_count and retryable_count >= 2:
        # Balanced fallback: some ZooKeeper deployments consistently return err_-124 on anonymous reads.
        # If every anonymous probe returns this marker, treat it as auth-required signal.
        return True, "probe_retryable_124", trace
    return None, "inconclusive", trace


def _get_thread_debug_emitter() -> Callable[[str], None] | None:
    candidate = getattr(_THREAD_LOCAL_DEBUG_EMIT, "callback", None)
    return candidate if callable(candidate) else None


def _call_audit_host_with_thread_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    show_znodes: bool,
    dump: bool,
    query_znode: str | None,
    max_znodes: int,
    debug: bool,
    run_deep_checks: bool,
    enum_workers: int,
    debug_emit: Callable[[str], None] | None,
) -> dict[str, Any]:
    def _invoke() -> dict[str, Any]:
        try:
            return _audit_zookeeper_host(
                host,
                port,
                timeout,
                retries,
                username,
                password,
                show_znodes,
                dump,
                query_znode,
                max_znodes,
                debug,
                run_deep_checks,
                enum_workers=enum_workers,
            )
        except TypeError as exc:
            if not is_signature_compat_typeerror(exc, expected_keywords={"enum_workers"}):
                raise
            # Backward-safe for patched tests/helpers with legacy signature.
            return _audit_zookeeper_host(
                host,
                port,
                timeout,
                retries,
                username,
                password,
                show_znodes,
                dump,
                query_znode,
                max_znodes,
                debug,
                run_deep_checks,
            )

    if debug_emit is None:
        return _invoke()
    _THREAD_LOCAL_DEBUG_EMIT.callback = debug_emit
    try:
        return _invoke()
    finally:
        try:
            delattr(_THREAD_LOCAL_DEBUG_EMIT, "callback")
        except AttributeError:
            pass


def _audit_zookeeper_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    show_znodes: bool,
    dump: bool,
    query_znode: str | None,
    max_znodes: int,
    debug: bool = False,
    run_deep_checks: bool = True,
    enum_workers: int = 3,
) -> dict[str, Any]:
    normalized_username = str(username).strip() if username is not None else None
    if normalized_username == "":
        normalized_username = None
    normalized_password = str(password).strip() if password is not None else None
    if normalized_username is None and normalized_password == "":
        normalized_password = None

    base_attempts = max(1, retries + 1)
    bonus_retry_for_root_query_124 = False
    last_error: str | None = None
    provided_credentials = normalized_username is not None and normalized_password is not None
    debug_events: list[str] = []
    stages: list[dict[str, Any]] = []
    stage_durations_ms: dict[str, int] = {}
    stage_attempts: dict[str, int] = {}
    stage_failed_at: str | None = None
    debug_events_streamed = False

    last_connect_ms: int | None = None
    last_auth_ms: int | None = None
    last_enumerate_ms: int | None = None
    last_dump_ms: int | None = None

    last_connect_error: str | None = None
    last_auth_error: str | None = None
    last_enum_error: str | None = None
    last_query_error: str | None = None
    last_dump_error: str | None = None
    last_attempts = 0
    last_max_attempts = base_attempts

    def _debug(message: str) -> None:
        nonlocal debug_events_streamed
        if debug:
            debug_line = f"{host}:{port} {message}"
            debug_events.append(debug_line)
            live_emitter = _get_thread_debug_emitter()
            if live_emitter is not None:
                live_emitter(debug_line)
                debug_events_streamed = True

    def _debug_retry_decision(
        stage_name: str,
        *,
        attempt: int,
        max_attempts: int,
        delay_s: float,
        reason: str | None,
    ) -> None:
        reason_text = str(reason or "").strip() or "-"
        _debug(
            f"retry_decision stage={stage_name} attempt={attempt}/{max_attempts} "
            f"backoff={delay_s:.2f}s reason={reason_text}"
        )

    def _emit_stage_timing_summary(
        *,
        status: str,
        attempts: int,
        max_attempts: int,
        stage_duration_totals: dict[str, int],
        stage_attempt_totals: dict[str, int],
    ) -> None:
        duration_map = dict(stage_duration_totals)
        attempt_map = dict(stage_attempt_totals)

        def _duration(stage_name: str) -> str:
            raw = duration_map.get(stage_name)
            if isinstance(raw, int):
                return f"{raw}ms"
            return "-"

        def _attempt_count(stage_name: str) -> int:
            raw = attempt_map.get(stage_name)
            return int(raw) if isinstance(raw, int) else 0

        _debug(
            f"stage_timing_summary status={status} attempts={attempts}/{max_attempts} "
            f"detect={_duration(_STAGE_DETECT_PROTOCOL)} "
            f"auth={_duration(_STAGE_AUTH_INFERENCE)} "
            f"capabilities={_duration(_STAGE_ACCESS_CAPABILITIES)} "
            f"data={_duration(_STAGE_DATA)} "
            f"stage_attempts="
            f"detect:{_attempt_count(_STAGE_DETECT_PROTOCOL)},"
            f"auth:{_attempt_count(_STAGE_AUTH_INFERENCE)},"
            f"capabilities:{_attempt_count(_STAGE_ACCESS_CAPABILITIES)},"
            f"data:{_attempt_count(_STAGE_DATA)}"
        )

    def _stage_trace(
        stage_name: str,
        *,
        attempt: int,
        started_at: float,
        result: str,
        error: str | None = None,
    ) -> None:
        nonlocal stage_failed_at
        duration_ms = int((time.monotonic() - started_at) * 1000)
        stage_attempts[stage_name] = max(int(stage_attempts.get(stage_name, 0)), int(attempt))
        stage_durations_ms[stage_name] = int(stage_durations_ms.get(stage_name, 0)) + duration_ms
        entry = {
            "stage_name": stage_name,
            "attempt": int(attempt),
            "duration_ms": int(duration_ms),
            "result": str(result),
            "error": str(error or "").strip() or None,
        }
        stages.append(entry)
        if stage_failed_at is None and result in {"fail", "timeout"}:
            stage_failed_at = stage_name
        _debug(
            f"stage_trace stage_name={stage_name} attempt={attempt} duration_ms={duration_ms} "
            f"result={result} error={str(error or '-').strip() or '-'}"
        )

    def _record(
        *,
        is_zookeeper: bool,
        status: str,
        auth_required: bool | None,
        provided_credentials_ok: bool | None,
        znode_count: int | None,
        znodes: list[str] | None,
        znode_details: list[dict[str, Any]] | None,
        znode_values: list[str] | None,
        znodes_truncated: bool,
        query_znode_value: str | None,
        query_znode_dump: str | None,
        query_znode_dump_error: str | None,
        can_create_znode: bool | None,
        can_delete_znode: bool | None,
        znode_capability_error: str | None,
        auth_inference_source: str,
        auth_probe_trace: list[str],
        elapsed_ms: int | None,
        error: str | None,
        connect_ms: int | None,
        auth_ms: int | None,
        enumerate_ms: int | None,
        dump_ms: int | None,
        connect_error: str | None,
        auth_error: str | None,
        enum_error: str | None,
        query_error: str | None,
        dump_error: str | None,
        attempts: int,
        max_attempts: int,
        znode_count_unknown: bool = False,
        znode_count_attempt_timeouts: list[float] | None = None,
        znode_count_partial: bool = False,
        stage2_error: str | None = None,
        stage_records: list[dict[str, Any]] | None = None,
        stage_fail_at: str | None = None,
        stage_duration_totals_ms: dict[str, int] | None = None,
        stage_attempt_totals: dict[str, int] | None = None,
    ) -> dict[str, Any]:
        resolved_stage_durations = dict(stage_duration_totals_ms or stage_durations_ms)
        resolved_stage_attempts = dict(stage_attempt_totals or stage_attempts)
        if debug:
            _emit_stage_timing_summary(
                status=status,
                attempts=int(attempts),
                max_attempts=int(max_attempts),
                stage_duration_totals=resolved_stage_durations,
                stage_attempt_totals=resolved_stage_attempts,
            )
        return {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "is_zookeeper": is_zookeeper,
            "status": status,
            "auth_required": auth_required,
            "provided_credentials": provided_credentials,
            "provided_username": normalized_username,
            "provided_password": normalized_password if provided_credentials else None,
            "provided_credentials_ok": provided_credentials_ok,
            "show_znodes": show_znodes,
            "dump": dump,
            "query_znode": query_znode,
            "max_znodes": max_znodes,
            "znode_count": znode_count,
            "znodes": znodes,
            "znode_details": znode_details,
            "znode_values": znode_values,
            "znodes_truncated": znodes_truncated,
            "query_znode_value": query_znode_value,
            "query_znode_dump": query_znode_dump,
            "query_znode_dump_error": query_znode_dump_error,
            "can_create_znode": can_create_znode,
            "can_delete_znode": can_delete_znode,
            "znode_capability_error": znode_capability_error,
            "auth_inference_source": auth_inference_source,
            "auth_probe_trace": auth_probe_trace,
            "connect_ms": connect_ms,
            "auth_ms": auth_ms,
            "enumerate_ms": enumerate_ms,
            "dump_ms": dump_ms,
            "elapsed_ms": elapsed_ms,
            "connect_error": connect_error,
            "auth_error": auth_error,
            "enum_error": enum_error,
            "query_error": query_error,
            "dump_error": dump_error,
            "attempts": attempts,
            "max_attempts": max_attempts,
            "znode_count_unknown": bool(znode_count_unknown),
            "znode_count_attempt_timeouts": list(znode_count_attempt_timeouts or []),
            "znode_count_partial": bool(znode_count_partial),
            "stage2_error": stage2_error,
            "stages": list(stage_records or stages),
            "stage_failed_at": stage_fail_at if stage_fail_at is not None else stage_failed_at,
            "stage_durations_ms": resolved_stage_durations,
            "stage_attempts": resolved_stage_attempts,
            "debug_events": list(debug_events) if debug else [],
            "debug_events_streamed": bool(debug_events_streamed),
            "error": error,
        }

    for attempt in range(base_attempts + 1):
        max_attempts = base_attempts + (1 if bonus_retry_for_root_query_124 else 0)
        last_max_attempts = max_attempts
        if attempt >= max_attempts:
            break
        last_attempts = attempt + 1
        started = time.monotonic()

        connect_ms: int | None = None
        auth_ms: int | None = None
        enumerate_ms: int | None = None
        dump_ms: int | None = None

        connect_error_detail: str | None = None
        auth_error_detail: str | None = None
        enum_error_detail: str | None = None
        query_error_detail: str | None = None
        dump_error_detail: str | None = None

        _debug(f"attempt={attempt + 1}/{max_attempts} start timeout={timeout}s")
        stage1_started = time.monotonic()
        client = _ZkClient(host, port, timeout)
        try:
            connect_started = time.monotonic()
            client.connect()
            connect_ms = int((time.monotonic() - connect_started) * 1000)
            last_connect_ms = connect_ms
            _debug(f"connect ok connect_ms={connect_ms}")

            provided_credentials_ok: bool | None = None
            invalid_provided_credentials = False
            auth_applied_ok: bool | None = None
            auth_error: str | None = None
            root_children, root_err, _ = client.get_children2("/")
            anonymous_root_err = root_err

            if root_err == _ZK_ERR_RETRYABLE_ROOT_QUERY and not bonus_retry_for_root_query_124:
                bonus_retry_for_root_query_124 = True
                last_error = f"root query failed: {_zk_error_name(root_err)}"
                _stage_trace(
                    _STAGE_DETECT_PROTOCOL,
                    attempt=attempt + 1,
                    started_at=stage1_started,
                    result="retry",
                    error=last_error,
                )
                delay = _retry_delay(attempt)
                _debug_retry_decision(
                    _STAGE_DETECT_PROTOCOL,
                    attempt=attempt + 1,
                    max_attempts=max_attempts,
                    delay_s=delay,
                    reason=last_error,
                )
                time.sleep(delay)
                continue

            _stage_trace(
                _STAGE_DETECT_PROTOCOL,
                attempt=attempt + 1,
                started_at=stage1_started,
                result="ok",
                error=None,
            )

            stage2_started = time.monotonic()
            inferred_auth_required, auth_inference_source, auth_probe_trace = (
                _infer_auth_required_from_anonymous_probes(host, port, timeout, anonymous_root_err, query_znode)
            )

            if provided_credentials and normalized_username is not None and normalized_password is not None:
                auth_started = time.monotonic()
                auth_applied_ok, auth_error = client.auth_digest(normalized_username, normalized_password)
                auth_ms = int((time.monotonic() - auth_started) * 1000)
                last_auth_ms = auth_ms
                if auth_applied_ok:
                    root_children, root_err, _ = client.get_children2("/")
                    if root_err == _ZK_ERR_OK:
                        provided_credentials_ok = anonymous_root_err != _ZK_ERR_OK
                    elif anonymous_root_err in {_ZK_ERR_NOAUTH, _ZK_ERR_RETRYABLE_ROOT_QUERY}:
                        # Digest auth succeeded, but root listing may still be ACL-restricted.
                        provided_credentials_ok = True
                else:
                    provided_credentials_ok = False
                if not auth_applied_ok and not auth_error:
                    auth_error = "authentication failed"
                auth_error_detail = auth_error
                last_auth_error = auth_error_detail

            _debug(
                f"auth decision root_err={_zk_error_name(int(root_err))} source={auth_inference_source} "
                f"final_auth_required={inferred_auth_required} provided_credentials_ok={provided_credentials_ok} "
                f"trace={','.join(auth_probe_trace) if auth_probe_trace else '-'}"
            )

            if provided_credentials and provided_credentials_ok is False:
                auth_required_value = inferred_auth_required

                auth_error_text = str(auth_error or "").strip()
                if auth_required_value is True and (
                    _is_unexpected_eof_error(auth_error_text) or _is_remote_closed_connection_error(auth_error_text)
                ):
                    auth_error_text = (
                        "authentication failed: server closed connection during digest auth "
                        "(invalid credentials or unsupported auth mode)"
                    )
                if (
                    auth_required_value is not False
                    and auth_error_text
                    and not auth_error_text.lower().startswith("authentication failed")
                ):
                    auth_error_detail = auth_error_text
                    _stage_trace(
                        _STAGE_AUTH_INFERENCE,
                        attempt=attempt + 1,
                        started_at=stage2_started,
                        result="fail",
                        error=auth_error_text,
                    )
                    _debug(
                        f"attempt={attempt + 1}/{max_attempts} result=fail auth_error={auth_error_text} "
                        f"connect_ms={connect_ms if connect_ms is not None else '-'} "
                        f"auth_ms={auth_ms if auth_ms is not None else '-'} "
                        f"enumerate_ms=- dump_ms=- total_ms={int((time.monotonic() - started) * 1000)}"
                    )
                    return _record(
                        is_zookeeper=True,
                        status="fail",
                        auth_required=auth_required_value,
                        provided_credentials_ok=provided_credentials_ok,
                        znode_count=None,
                        znodes=None,
                        znode_details=None,
                        znode_values=None,
                        znodes_truncated=False,
                        query_znode_value=None,
                        query_znode_dump=None,
                        query_znode_dump_error=None,
                        can_create_znode=None,
                        can_delete_znode=None,
                        znode_capability_error=None,
                        auth_inference_source=auth_inference_source,
                        auth_probe_trace=auth_probe_trace,
                        elapsed_ms=int((time.monotonic() - started) * 1000),
                        error=auth_error_text,
                        connect_ms=connect_ms,
                        auth_ms=auth_ms,
                        enumerate_ms=None,
                        dump_ms=None,
                        connect_error=connect_error_detail,
                        auth_error=auth_error_detail,
                        enum_error=enum_error_detail,
                        query_error=query_error_detail,
                        dump_error=dump_error_detail,
                        attempts=attempt + 1,
                        max_attempts=max_attempts,
                    )
                if auth_required_value is False:
                    invalid_provided_credentials = True
                else:
                    invalid_status = "auth_required" if auth_required_value is True else "fail"
                    query_error_detail = "NOAUTH"
                    _stage_trace(
                        _STAGE_AUTH_INFERENCE,
                        attempt=attempt + 1,
                        started_at=stage2_started,
                        result="auth_required" if invalid_status == "auth_required" else "fail",
                        error=auth_error_text or "authentication failed",
                    )
                    _debug(
                        f"attempt={attempt + 1}/{max_attempts} result={invalid_status} "
                        f"connect_ms={connect_ms if connect_ms is not None else '-'} "
                        f"auth_ms={auth_ms if auth_ms is not None else '-'} "
                        f"enumerate_ms=- dump_ms=- total_ms={int((time.monotonic() - started) * 1000)}"
                    )
                    return _record(
                        is_zookeeper=True,
                        status=invalid_status,
                        auth_required=auth_required_value,
                        provided_credentials_ok=provided_credentials_ok,
                        znode_count=None,
                        znodes=None,
                        znode_details=None,
                        znode_values=None,
                        znodes_truncated=False,
                        query_znode_value=None,
                        query_znode_dump=None,
                        query_znode_dump_error="Access Denied",
                        can_create_znode=None,
                        can_delete_znode=None,
                        znode_capability_error=None,
                        auth_inference_source=auth_inference_source,
                        auth_probe_trace=auth_probe_trace,
                        elapsed_ms=int((time.monotonic() - started) * 1000),
                        error=auth_error_text or "authentication failed",
                        connect_ms=connect_ms,
                        auth_ms=auth_ms,
                        enumerate_ms=None,
                        dump_ms=None,
                        connect_error=connect_error_detail,
                        auth_error=auth_error_detail,
                        enum_error=enum_error_detail,
                        query_error=query_error_detail,
                        dump_error=dump_error_detail,
                        attempts=attempt + 1,
                        max_attempts=max_attempts,
                    )

            if root_err == _ZK_ERR_NOAUTH:
                query_error_detail = "NOAUTH"
                _stage_trace(
                    _STAGE_AUTH_INFERENCE,
                    attempt=attempt + 1,
                    started_at=stage2_started,
                    result="auth_required",
                    error=auth_error,
                )
                _debug(
                    f"attempt={attempt + 1}/{max_attempts} result=auth_required "
                    f"connect_ms={connect_ms if connect_ms is not None else '-'} "
                    f"auth_ms={auth_ms if auth_ms is not None else '-'} "
                    f"enumerate_ms=- dump_ms=- total_ms={int((time.monotonic() - started) * 1000)}"
                )
                return _record(
                    is_zookeeper=True,
                    status="auth_required",
                    auth_required=True,
                    provided_credentials_ok=provided_credentials_ok,
                    znode_count=None,
                    znodes=None,
                    znode_details=None,
                    znode_values=None,
                    znodes_truncated=False,
                    query_znode_value=None,
                    query_znode_dump=None,
                    query_znode_dump_error="Access Denied",
                    can_create_znode=None,
                    can_delete_znode=None,
                    znode_capability_error=None,
                    auth_inference_source=auth_inference_source,
                    auth_probe_trace=auth_probe_trace,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    error=auth_error,
                    connect_ms=connect_ms,
                    auth_ms=auth_ms,
                    enumerate_ms=None,
                    dump_ms=None,
                    connect_error=connect_error_detail,
                    auth_error=auth_error_detail,
                    enum_error=enum_error_detail,
                    query_error=query_error_detail,
                    dump_error=dump_error_detail,
                    attempts=attempt + 1,
                    max_attempts=max_attempts,
                )

            if root_err == _ZK_ERR_RETRYABLE_ROOT_QUERY and not bonus_retry_for_root_query_124:
                bonus_retry_for_root_query_124 = True
                last_error = f"root query failed: {_zk_error_name(root_err)}"
                delay = _retry_delay(attempt)
                query_error_detail = _zk_error_name(root_err)
                last_query_error = query_error_detail
                _stage_trace(
                    _STAGE_AUTH_INFERENCE,
                    attempt=attempt + 1,
                    started_at=stage2_started,
                    result="retry",
                    error=last_error,
                )
                _debug_retry_decision(
                    _STAGE_AUTH_INFERENCE,
                    attempt=attempt + 1,
                    max_attempts=max_attempts,
                    delay_s=delay,
                    reason=last_error,
                )
                time.sleep(delay)
                continue

            if root_err != _ZK_ERR_OK:
                query_error_detail = _zk_error_name(root_err)
                _stage_trace(
                    _STAGE_AUTH_INFERENCE,
                    attempt=attempt + 1,
                    started_at=stage2_started,
                    result="fail",
                    error=f"root query failed: {_zk_error_name(root_err)}",
                )
                _debug(
                    f"attempt={attempt + 1}/{max_attempts} result=fail root_err={query_error_detail} "
                    f"connect_ms={connect_ms if connect_ms is not None else '-'} "
                    f"auth_ms={auth_ms if auth_ms is not None else '-'} "
                    f"enumerate_ms=- dump_ms=- total_ms={int((time.monotonic() - started) * 1000)}"
                )
                return _record(
                    is_zookeeper=True,
                    status="fail",
                    auth_required=inferred_auth_required,
                    provided_credentials_ok=provided_credentials_ok,
                    znode_count=None,
                    znodes=None,
                    znode_details=None,
                    znode_values=None,
                    znodes_truncated=False,
                    query_znode_value=None,
                    query_znode_dump=None,
                    query_znode_dump_error=None,
                    can_create_znode=None,
                    can_delete_znode=None,
                    znode_capability_error=None,
                    auth_inference_source=auth_inference_source,
                    auth_probe_trace=auth_probe_trace,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    error=f"root query failed: {_zk_error_name(root_err)}",
                    connect_ms=connect_ms,
                    auth_ms=auth_ms,
                    enumerate_ms=None,
                    dump_ms=None,
                    connect_error=connect_error_detail,
                    auth_error=auth_error_detail,
                    enum_error=enum_error_detail,
                    query_error=query_error_detail,
                    dump_error=dump_error_detail,
                    attempts=attempt + 1,
                    max_attempts=max_attempts,
                )

            stage2_result = "ok"
            if provided_credentials_ok is True:
                stage2_result = "valid_credentials"
            elif invalid_provided_credentials:
                stage2_result = "invalid_credentials_anonymous"
            elif inferred_auth_required is True:
                stage2_result = "auth_required"
            _stage_trace(
                _STAGE_AUTH_INFERENCE,
                attempt=attempt + 1,
                started_at=stage2_started,
                result=stage2_result,
                error=auth_error_detail,
            )

            if not run_deep_checks:
                detect_status = (
                    "valid_credentials"
                    if provided_credentials_ok
                    else "invalid_credentials_anonymous"
                    if invalid_provided_credentials
                    else "open_no_auth"
                )
                _debug(
                    f"attempt={attempt + 1}/{max_attempts} detect-only result={detect_status} "
                    f"connect_ms={connect_ms if connect_ms is not None else '-'} "
                    f"auth_ms={auth_ms if auth_ms is not None else '-'} "
                    f"total_ms={int((time.monotonic() - started) * 1000)}"
                )
                return _record(
                    is_zookeeper=True,
                    status=detect_status,
                    auth_required=inferred_auth_required,
                    provided_credentials_ok=provided_credentials_ok,
                    znode_count=None,
                    znodes=None,
                    znode_details=None,
                    znode_values=None,
                    znodes_truncated=False,
                    query_znode_value=None,
                    query_znode_dump=None,
                    query_znode_dump_error=None,
                    can_create_znode=None,
                    can_delete_znode=None,
                    znode_capability_error=None,
                    auth_inference_source=auth_inference_source,
                    auth_probe_trace=auth_probe_trace,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    error=last_error if not invalid_provided_credentials else (auth_error or "authentication failed"),
                    connect_ms=connect_ms,
                    auth_ms=auth_ms,
                    enumerate_ms=None,
                    dump_ms=None,
                    connect_error=connect_error_detail,
                    auth_error=auth_error_detail,
                    enum_error=enum_error_detail,
                    query_error=query_error_detail,
                    dump_error=dump_error_detail,
                    attempts=attempt + 1,
                    max_attempts=max_attempts,
                )

            noauth_detail_text = "Access Denied"
            can_create_znode: bool | None = None
            can_delete_znode: bool | None = None
            znode_capability_error: str | None = None
            stage3_started = time.monotonic()
            if not invalid_provided_credentials:
                can_create_znode, can_delete_znode, znode_capability_error = _probe_znode_create_delete(
                    client, host, port
                )
            if znode_capability_error:
                if _is_retryable_stage_error(znode_capability_error) and attempt < max_attempts - 1:
                    last_error = znode_capability_error
                    _stage_trace(
                        _STAGE_ACCESS_CAPABILITIES,
                        attempt=attempt + 1,
                        started_at=stage3_started,
                        result="retry",
                        error=znode_capability_error,
                    )
                    delay = _retry_delay(attempt)
                    _debug_retry_decision(
                        _STAGE_ACCESS_CAPABILITIES,
                        attempt=attempt + 1,
                        max_attempts=max_attempts,
                        delay_s=delay,
                        reason=znode_capability_error,
                    )
                    time.sleep(delay)
                    continue
                _stage_trace(
                    _STAGE_ACCESS_CAPABILITIES,
                    attempt=attempt + 1,
                    started_at=stage3_started,
                    result="error",
                    error=znode_capability_error,
                )
            else:
                _stage_trace(
                    _STAGE_ACCESS_CAPABILITIES,
                    attempt=attempt + 1,
                    started_at=stage3_started,
                    result="ok",
                    error=None,
                )

            stage4_started = time.monotonic()
            enum_started = time.monotonic()
            collect_znode_paths = bool(show_znodes or (dump and not query_znode))
            enum_auth_username = normalized_username if provided_credentials_ok else None
            enum_auth_password = normalized_password if provided_credentials_ok else None

            progress_hook: Callable[[dict[str, Any]], None] | None = None
            if debug:

                def _progress(event: dict[str, Any]) -> None:
                    event_type = str(event.get("event") or "")
                    if event_type not in {"enumerate_progress", "enumerate_done"}:
                        return
                    total_count_event = int(event.get("total_count") or 0)
                    queued_event = int(event.get("queued") or 0)
                    listed_count_event = int(event.get("listed_count") or 0)
                    processed_parents_event = int(event.get("processed_parents") or 0)
                    interval_count_event = int(event.get("interval_count") or 0)
                    interval_processed_event = int(event.get("interval_processed") or 0)
                    interval_s_event = float(event.get("interval_s") or 0.0)
                    rate = interval_count_event / max(interval_s_event, 0.001)
                    eta = queued_event / rate if rate > 0 else None
                    process_rate = interval_processed_event / max(interval_s_event, 0.001)
                    process_eta = queued_event / process_rate if process_rate > 0 else None
                    eta_text = f"{eta:.1f}s" if eta is not None else "-"
                    process_eta_text = f"{process_eta:.1f}s" if process_eta is not None else "-"
                    window_text = f"{interval_s_event:.1f}s" if interval_s_event > 0 else "-"
                    if event_type == "enumerate_done":
                        elapsed_event = float(event.get("elapsed_s") or 0.0)
                        _debug(
                            f"enumerate done discovered={total_count_event} listed={listed_count_event} "
                            f"processed={processed_parents_event} queued={queued_event} elapsed={elapsed_event:.1f}s"
                        )
                        return
                    _debug(
                        f"enumerate progress discovered={total_count_event} listed={listed_count_event} "
                        f"processed={processed_parents_event} queued={queued_event} "
                        f"window={window_text} rate={rate:.1f}/s eta={eta_text} "
                        f"process_rate={process_rate:.1f}/s process_eta={process_eta_text}"
                    )

                progress_hook = _progress

            try:
                listed_znodes, total_count, truncated, listed_meta, enum_error = _enumerate_znodes(
                    client,
                    max_znodes,
                    progress_hook,
                    collect_paths=collect_znode_paths,
                    enum_workers=enum_workers,
                    auth_username=enum_auth_username,
                    auth_password=enum_auth_password,
                )
            except TypeError as exc:
                if not is_signature_compat_typeerror(
                    exc, expected_keywords={"collect_paths", "enum_workers", "auth_username", "auth_password"}
                ):
                    raise
                # Backward-safe for patched tests/helpers that may expose legacy signatures.
                try:
                    listed_znodes, total_count, truncated, listed_meta, enum_error = _enumerate_znodes(
                        client,
                        max_znodes,
                        progress_hook,
                        collect_paths=collect_znode_paths,
                    )
                except TypeError as exc:
                    if not is_signature_compat_typeerror(exc, expected_keywords={"collect_paths"}):
                        raise
                    try:
                        listed_znodes, total_count, truncated, listed_meta, enum_error = _enumerate_znodes(
                            client,
                            max_znodes,
                            progress_hook,
                        )
                    except TypeError as exc:
                        if not is_signature_compat_typeerror(
                            exc, expected_keywords={"progress_hook"}, allow_positional_mismatch=True
                        ):
                            raise
                        listed_znodes, total_count, truncated, listed_meta, enum_error = _enumerate_znodes(
                            client,
                            max_znodes,
                        )
            enumerate_ms = int((time.monotonic() - enum_started) * 1000)
            last_enumerate_ms = enumerate_ms
            if enum_error:
                last_error = enum_error
                enum_error_detail = enum_error
                last_enum_error = enum_error_detail
            sorted_znodes: list[str]
            znode_details: list[dict[str, Any]] | None
            if collect_znode_paths:
                sorted_znodes = sorted(listed_znodes)
                znode_details = [_znode_detail_entry(path, listed_meta.get(path)) for path in sorted_znodes]
            else:
                sorted_znodes = []
                znode_details = None

            dump_started = time.monotonic() if (dump or query_znode) else None
            dump_error_codes: set[str] = set()

            znode_values: list[str] | None = None
            if dump and not query_znode:
                znode_values = []
                for path in sorted_znodes:
                    value_bytes, value_err, _value_stat = client.get_data(path)
                    if value_err == _ZK_ERR_OK:
                        znode_values.append(f"{path}:{_format_znode_data(value_bytes)}")
                    elif value_err == _ZK_ERR_NOAUTH:
                        znode_values.append(f"{path}:<{noauth_detail_text}>")
                        dump_error_codes.add("NOAUTH")
                    elif value_err == _ZK_ERR_NONODE:
                        znode_values.append(f"{path}:<not found>")
                        dump_error_codes.add("NONODE")
                    else:
                        znode_values.append(f"{path}:<error:{_zk_error_name(value_err)}>")
                        dump_error_codes.add(_zk_error_name(value_err))

            query_znode_value: str | None = None
            query_znode_dump: str | None = None
            query_znode_dump_error: str | None = None
            if query_znode:
                q_children, q_err, q_stat = client.get_children2(query_znode)
                if q_err == _ZK_ERR_NONODE:
                    query_znode_value = f"{query_znode}:<not found>"
                    query_error_detail = "NONODE"
                    if dump:
                        query_znode_dump_error = "znode not found"
                        dump_error_codes.add("NONODE")
                elif q_err == _ZK_ERR_NOAUTH:
                    query_znode_value = f"{query_znode}:<{noauth_detail_text}>"
                    query_error_detail = "NOAUTH"
                    if dump:
                        query_znode_dump_error = noauth_detail_text
                        dump_error_codes.add("NOAUTH")
                elif q_err == _ZK_ERR_OK:
                    child_count = len(q_children or [])
                    data_length = int((q_stat or {}).get("data_length") or 0)
                    query_znode_value = f"{query_znode} (children:{child_count},bytes:{data_length})"
                    if dump:
                        value_bytes, value_err, _value_stat = client.get_data(query_znode)
                        if value_err == _ZK_ERR_OK:
                            query_znode_dump = _format_znode_data(value_bytes)
                        elif value_err == _ZK_ERR_NONODE:
                            query_znode_dump_error = "znode not found"
                            dump_error_codes.add("NONODE")
                        elif value_err == _ZK_ERR_NOAUTH:
                            query_znode_dump_error = noauth_detail_text
                            dump_error_codes.add("NOAUTH")
                        else:
                            query_znode_dump_error = _zk_error_name(value_err)
                            dump_error_codes.add(_zk_error_name(value_err))
                else:
                    query_znode_value = f"{query_znode}:<error:{_zk_error_name(q_err)}>"
                    query_error_detail = _zk_error_name(q_err)
                    if dump:
                        query_znode_dump_error = _zk_error_name(q_err)
                        dump_error_codes.add(_zk_error_name(q_err))

            if dump_started is not None:
                dump_ms = int((time.monotonic() - dump_started) * 1000)
                last_dump_ms = dump_ms
            if dump_error_codes:
                dump_error_detail = ",".join(sorted(dump_error_codes))
                last_dump_error = dump_error_detail
            if query_error_detail:
                last_query_error = query_error_detail

            if enum_error_detail and _is_retryable_stage_error(enum_error_detail) and attempt < max_attempts - 1:
                last_error = enum_error_detail
                _stage_trace(
                    _STAGE_DATA,
                    attempt=attempt + 1,
                    started_at=stage4_started,
                    result="retry",
                    error=enum_error_detail,
                )
                delay = _retry_delay(attempt)
                _debug_retry_decision(
                    _STAGE_DATA,
                    attempt=attempt + 1,
                    max_attempts=max_attempts,
                    delay_s=delay,
                    reason=enum_error_detail,
                )
                time.sleep(delay)
                continue

            stage4_result = "ok"
            stage4_error_value: str | None = None
            if enum_error_detail:
                stage4_result = "partial"
                stage4_error_value = enum_error_detail
            elif query_error_detail and query_error_detail not in {"NOAUTH", "NONODE"}:
                stage4_result = "partial"
                stage4_error_value = query_error_detail
            elif dump_error_detail and dump_error_detail not in {"NOAUTH", "NONODE"}:
                stage4_result = "partial"
                stage4_error_value = dump_error_detail
            _stage_trace(
                _STAGE_DATA,
                attempt=attempt + 1,
                started_at=stage4_started,
                result=stage4_result,
                error=stage4_error_value,
            )

            root_count = len(root_children or [])
            if total_count == 0 and root_count > 0:
                total_count = root_count

            auth_required_value = inferred_auth_required

            elapsed_ms = int((time.monotonic() - started) * 1000)
            final_status = (
                "valid_credentials"
                if provided_credentials_ok
                else "invalid_credentials_anonymous"
                if invalid_provided_credentials
                else "open_no_auth"
            )
            _debug(
                f"attempt={attempt + 1}/{max_attempts} result={final_status} "
                f"connect_ms={connect_ms if connect_ms is not None else '-'} "
                f"auth_ms={auth_ms if auth_ms is not None else '-'} "
                f"enumerate_ms={enumerate_ms if enumerate_ms is not None else '-'} "
                f"dump_ms={dump_ms if dump_ms is not None else '-'} total_ms={elapsed_ms}"
            )
            return _record(
                is_zookeeper=True,
                status=final_status,
                auth_required=auth_required_value,
                provided_credentials_ok=provided_credentials_ok,
                znode_count=total_count,
                znodes=sorted_znodes,
                znode_details=znode_details,
                znode_values=znode_values,
                znodes_truncated=truncated,
                query_znode_value=query_znode_value,
                query_znode_dump=query_znode_dump,
                query_znode_dump_error=query_znode_dump_error,
                can_create_znode=can_create_znode,
                can_delete_znode=can_delete_znode,
                znode_capability_error=znode_capability_error,
                auth_inference_source=auth_inference_source,
                auth_probe_trace=auth_probe_trace,
                elapsed_ms=elapsed_ms,
                error=last_error if not invalid_provided_credentials else (auth_error or "authentication failed"),
                connect_ms=connect_ms,
                auth_ms=auth_ms,
                enumerate_ms=enumerate_ms,
                dump_ms=dump_ms,
                connect_error=connect_error_detail,
                auth_error=auth_error_detail,
                enum_error=enum_error_detail,
                query_error=query_error_detail,
                dump_error=dump_error_detail,
                attempts=attempt + 1,
                max_attempts=max_attempts,
            )
        except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
            last_error = _friendly_error_from_exception(exc)
            connect_error_detail = last_error
            last_connect_error = connect_error_detail
            last_connect_ms = connect_ms
            last_auth_ms = auth_ms
            last_enumerate_ms = enumerate_ms
            last_dump_ms = dump_ms
            max_attempts = base_attempts + (1 if bonus_retry_for_root_query_124 else 0)
            stage_result = "retry" if attempt < max_attempts - 1 else "fail"
            _stage_trace(
                _STAGE_DETECT_PROTOCOL,
                attempt=attempt + 1,
                started_at=stage1_started,
                result=stage_result,
                error=last_error,
            )
            if attempt >= max_attempts - 1:
                break
            delay = _retry_delay(attempt)
            _debug_retry_decision(
                _STAGE_DETECT_PROTOCOL,
                attempt=attempt + 1,
                max_attempts=max_attempts,
                delay_s=delay,
                reason=last_error,
            )
            time.sleep(delay)
        finally:
            client.close()

    _debug(f"final fail attempts={last_attempts}/{last_max_attempts} error={last_error or 'connection failed'}")
    return _record(
        is_zookeeper=False,
        status="fail",
        auth_required=None,
        provided_credentials_ok=None,
        znode_count=None,
        znodes=None,
        znode_details=None,
        znode_values=None,
        znodes_truncated=False,
        query_znode_value=None,
        query_znode_dump=None,
        query_znode_dump_error=None,
        can_create_znode=None,
        can_delete_znode=None,
        znode_capability_error=None,
        auth_inference_source="not_run",
        auth_probe_trace=[],
        elapsed_ms=None,
        error=last_error or "connection failed",
        connect_ms=last_connect_ms,
        auth_ms=last_auth_ms,
        enumerate_ms=last_enumerate_ms,
        dump_ms=last_dump_ms,
        connect_error=last_connect_error,
        auth_error=last_auth_error,
        enum_error=last_enum_error,
        query_error=last_query_error,
        dump_error=last_dump_error,
        attempts=last_attempts,
        max_attempts=last_max_attempts,
    )


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{'ZOOKEEPER':<12}\t{host}\t{port}\t"


def _with_optional_znodes(record: dict[str, Any], message: str) -> str:
    if bool(record.get("znode_count_unknown")):
        suffix = "unknown partial" if bool(record.get("znode_count_partial")) else "unknown"
        return f"{message} (znodes:{suffix})"
    znode_count = record.get("znode_count")
    if not isinstance(znode_count, int):
        return f"{message} (znodes:-)"
    return f"{message} (znodes:{znode_count})"


def _merge_stage2_record(
    detect_record: dict[str, Any],
    deep_record: dict[str, Any],
    *,
    timeout: float,
    retries: int,
) -> dict[str, Any]:
    merged = dict(detect_record)
    detect_debug_events = detect_record.get("debug_events")
    deep_debug_events = deep_record.get("debug_events")
    merged_debug_events: list[str] = []
    if isinstance(detect_debug_events, list):
        for item in detect_debug_events:
            if isinstance(item, str) and item.strip():
                merged_debug_events.append(item)
    if isinstance(deep_debug_events, list):
        for item in deep_debug_events:
            if isinstance(item, str) and item.strip():
                merged_debug_events.append(item)
    merged["debug_events"] = merged_debug_events
    merged["debug_events_streamed"] = bool(detect_record.get("debug_events_streamed")) or bool(
        deep_record.get("debug_events_streamed")
    )

    stage2_attempts = max(1, retries + 1)
    stage2_fields = (
        "znode_count",
        "znodes",
        "znode_details",
        "znode_values",
        "znodes_truncated",
        "query_znode_value",
        "query_znode_dump",
        "query_znode_dump_error",
        "can_create_znode",
        "can_delete_znode",
        "znode_capability_error",
        "connect_ms",
        "auth_ms",
        "enumerate_ms",
        "dump_ms",
        "elapsed_ms",
        "connect_error",
        "auth_error",
        "enum_error",
        "query_error",
        "dump_error",
        "attempts",
        "max_attempts",
        "stages",
        "stage_failed_at",
        "stage_durations_ms",
        "stage_attempts",
    )
    for field in stage2_fields:
        merged[field] = deep_record.get(field)

    deep_status = str(deep_record.get("status") or "")
    deep_is_zk = bool(deep_record.get("is_zookeeper"))
    deep_success = deep_is_zk and deep_status in {"open_no_auth", "valid_credentials", "invalid_credentials_anonymous"}

    if deep_success:
        enum_error = str(deep_record.get("enum_error") or "").strip()
        stage2_error = str(deep_record.get("stage2_error") or "").strip()
        if not stage2_error:
            stage2_error = enum_error or str(deep_record.get("error") or "").strip()
        partial_hint = bool(deep_record.get("znodes")) or bool(deep_record.get("znode_values"))
        if not partial_hint and isinstance(deep_record.get("znode_count"), int):
            partial_hint = int(deep_record.get("znode_count") or 0) > 0

        merged["znode_count_unknown"] = bool(enum_error)
        merged["znode_count_partial"] = bool(enum_error) and partial_hint
        merged["znode_count_attempt_timeouts"] = (
            [float(timeout)] * stage2_attempts if _is_connection_timeout_error(enum_error) else []
        )
        merged["stage2_error"] = stage2_error or None
        return merged

    stage2_error = str(deep_record.get("error") or "").strip() or "stage2 deep checks failed"
    merged["znode_count"] = None
    merged["znodes"] = detect_record.get("znodes")
    merged["znode_details"] = detect_record.get("znode_details")
    merged["znode_values"] = detect_record.get("znode_values")
    merged["znodes_truncated"] = bool(detect_record.get("znodes_truncated"))
    merged["query_znode_value"] = detect_record.get("query_znode_value")
    merged["query_znode_dump"] = detect_record.get("query_znode_dump")
    merged["query_znode_dump_error"] = detect_record.get("query_znode_dump_error")
    merged["can_create_znode"] = None
    merged["can_delete_znode"] = None
    merged["znode_capability_error"] = None
    merged["znode_count_unknown"] = True
    merged["znode_count_partial"] = bool(merged.get("znodes")) or bool(merged.get("znode_values"))
    merged["znode_count_attempt_timeouts"] = (
        [float(timeout)] * stage2_attempts if _is_connection_timeout_error(stage2_error) else []
    )
    merged["stage2_error"] = stage2_error
    return merged


def _credentials_label(record: dict[str, Any]) -> str:
    username = str(record.get("provided_username") or "user").strip() or "user"
    provided_password = record.get("provided_password")
    password_text = (
        "<empty>" if provided_password == "" else str(provided_password) if provided_password is not None else "<none>"
    )
    return f"{username}:{password_text}"


def _znode_caps_suffix(record: dict[str, Any]) -> str:
    create_cap = record.get("can_create_znode")
    delete_cap = record.get("can_delete_znode")
    create_text = "True" if create_cap is True else "False" if create_cap is False else "unknown"
    delete_text = "True" if delete_cap is True else "False" if delete_cap is False else "unknown"
    return f"(create:{create_text}) (delete:{delete_text})"


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
                "service": "zookeeper",
                "detected": bool(record.get("is_zookeeper")),
                "auth_required": auth_required_value,
                "auth_inference_source": record.get("auth_inference_source"),
                "auth_probe_trace": record.get("auth_probe_trace") or [],
            },
            ensure_ascii=False,
        )

    prefix = _nxc_prefix(record)
    return f"{prefix} [*] ZooKeeper Service (auth required:{auth_required_text})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 72)

    if status == "open_no_auth":
        return _with_optional_znodes(record, f"{prefix} [+] anonymous access {_znode_caps_suffix(record)}")

    if status == "invalid_credentials_anonymous":
        return f"{prefix} [-] {_credentials_label(record)}"

    if status == "valid_credentials":
        return _with_optional_znodes(record, f"{prefix} [+] {_credentials_label(record)} {_znode_caps_suffix(record)}")

    if status == "auth_required":
        if record.get("provided_credentials"):
            return f"{prefix} [-] {_credentials_label(record)}"
        return f"{prefix} [-] authentication required"

    if status == "fail" and record.get("provided_credentials") and err.lower().startswith("authentication failed"):
        return f"{prefix} [-] {_credentials_label(record)}"

    line = f"{prefix} [!] connection failed"
    if err != "-":
        return f"{line} err={err}"
    return line


def _format_znodes_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    show_znodes = bool(record.get("show_znodes"))
    dump = bool(record.get("dump"))
    query_znode = str(record.get("query_znode") or "").strip()
    query_znode_value = record.get("query_znode_value")
    query_znode_dump = record.get("query_znode_dump")
    query_znode_dump_error = str(record.get("query_znode_dump_error") or "").strip()

    znodes_raw = record.get("znodes")
    znode_details_raw = record.get("znode_details")
    znode_values_raw = record.get("znode_values")

    znodes: list[str] = []
    if isinstance(znodes_raw, list):
        znodes = sorted(str(item) for item in znodes_raw)

    znode_details: list[dict[str, Any]] = []
    if isinstance(znode_details_raw, list):
        for item in znode_details_raw:
            if not isinstance(item, dict):
                continue
            znode_details.append(
                {
                    "path": str(item.get("path") or ""),
                    "state": str(item.get("state") or "unknown"),
                    "children": item.get("children"),
                    "bytes": item.get("bytes"),
                    "error": str(item.get("error") or "").strip() or None,
                }
            )
        znode_details = sorted(znode_details, key=lambda item: str(item.get("path") or ""))
    elif znodes:
        znode_details = [
            {"path": path, "state": "unknown", "children": None, "bytes": None, "error": None} for path in znodes
        ]

    znode_values: list[str] = []
    if isinstance(znode_values_raw, list):
        znode_values = [str(item) for item in znode_values_raw]

    znode_count = record.get("znode_count")
    max_znodes = record.get("max_znodes")
    truncated = bool(record.get("znodes_truncated"))
    znode_count_unknown = bool(record.get("znode_count_unknown"))
    znode_count_partial = bool(record.get("znode_count_partial"))
    stage2_error = str(record.get("stage2_error") or "").strip()
    attempt_timeouts_raw = record.get("znode_count_attempt_timeouts")
    attempt_timeouts: list[float] = []
    if isinstance(attempt_timeouts_raw, list):
        for item in attempt_timeouts_raw:
            if isinstance(item, (int, float)):
                attempt_timeouts.append(float(item))
    shown_count = len(znode_details) if znode_details else len(znodes)
    truncation_note = None
    if truncated and isinstance(znode_count, int) and isinstance(max_znodes, int):
        truncation_note = f"showing first {shown_count} of {znode_count} znodes (max_znodes={max_znodes})"
    unknown_note = None
    if znode_count_unknown:
        unknown_note = "znode count unknown"
        if znode_count_partial:
            unknown_note += " (partial)"
        if attempt_timeouts:
            timeout_text = ",".join(f"{value:g}s" for value in attempt_timeouts)
            unknown_note += f" (timeouts={timeout_text})"
        if stage2_error:
            unknown_note += f" reason={stage2_error}"

    if not show_znodes and not dump and not query_znode:
        return []

    if output_format == "json":
        lines: list[str] = []
        if show_znodes and znodes:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "znodes_list",
                        "service": "zookeeper",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "znode_count": record.get("znode_count"),
                        "znodes": znodes,
                        "znodes_shown": shown_count,
                        "znodes_truncated": truncated,
                        "max_znodes": max_znodes,
                        "znode_details": znode_details,
                    },
                    ensure_ascii=False,
                )
            )
        if query_znode:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "znode_detail",
                        "service": "zookeeper",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "znode": query_znode,
                        "value": query_znode_value,
                    },
                    ensure_ascii=False,
                )
            )
        if dump and query_znode:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "znode_dump",
                        "service": "zookeeper",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "znode": query_znode,
                        "data": query_znode_dump,
                        "error": query_znode_dump_error or None,
                    },
                    ensure_ascii=False,
                )
            )
        if dump and not query_znode and znode_values:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "znodes_dump",
                        "service": "zookeeper",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "znode_count": record.get("znode_count"),
                        "znode_values": znode_values,
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    prefix = _nxc_prefix(record)
    lines: list[str] = []
    if show_znodes and znode_details:
        lines.append(f"{prefix} [*] Show Znodes")
        if unknown_note:
            lines.append(f"{prefix} [*] {unknown_note}")
        if truncation_note:
            lines.append(f"{prefix} [*] {truncation_note}")
        for item in znode_details:
            path = str(item.get("path") or "")
            state = str(item.get("state") or "unknown")
            error = str(item.get("error") or "").strip()
            if error:
                lines.append(f"{prefix} {path}:<{error}>")
                continue
            if state == "empty":
                lines.append(f"{prefix} {path}:<empty>")
                continue
            children = item.get("children")
            data_length = item.get("bytes")
            if isinstance(children, int) and isinstance(data_length, int):
                lines.append(f"{prefix} {path} (children:{children},bytes:{data_length})")
            else:
                lines.append(f"{prefix} {path}")
    if query_znode:
        lines.append(f"{prefix} [*] Znode {query_znode}")
        if isinstance(query_znode_value, str):
            lines.append(f"{prefix} {query_znode_value}")
    if dump and query_znode:
        lines.append(f"{prefix} [*] Dump Znode {query_znode}")
        if isinstance(query_znode_dump, str):
            lines.append(f"{prefix} {query_znode_dump}")
        elif query_znode_dump_error:
            lines.append(f"{prefix} [-] {query_znode_dump_error}")
        else:
            lines.append(f"{prefix} <no data>")
    if dump and not query_znode and znode_values:
        lines.append(f"{prefix} [*] Dump Znodes")
        if unknown_note:
            lines.append(f"{prefix} [*] {unknown_note}")
        if truncation_note:
            lines.append(f"{prefix} [*] {truncation_note}")
        for item in znode_values:
            lines.append(f"{prefix} {item}")
    if unknown_note and not znode_details and not znode_values and (show_znodes or dump):
        lines.append(f"{prefix} [*] {unknown_note}")
    return lines


def _render_colored_zookeeper_line(console: Console, line: str) -> bool:
    return render_colored_marker_line(
        console,
        line,
        tag="ZOOKEEPER",
        booleans=(BooleanColorRule("create"), BooleanColorRule("delete")),
        counts=(CountColorRule("znodes", "red"),),
    )


def _emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
    if emit_line is not None:
        emit_line(line)


def _update_debug_stats(debug_stats: dict[str, Any], record: dict[str, Any]) -> None:
    status_counts = debug_stats.setdefault("status_counts", Counter())
    status_counts[str(record.get("status") or "fail")] += 1

    auth_sources = debug_stats.setdefault("auth_sources", Counter())
    auth_sources[str(record.get("auth_inference_source") or "not_run")] += 1

    timing_sums = debug_stats.setdefault("timing_sums", Counter())
    timing_counts = debug_stats.setdefault("timing_counts", Counter())
    timing_max = debug_stats.setdefault("timing_max", Counter())
    for key in ("connect_ms", "auth_ms", "enumerate_ms", "dump_ms", "elapsed_ms"):
        value = record.get(key)
        if isinstance(value, int) and value >= 0:
            timing_sums[key] += value
            timing_counts[key] += 1
            timing_max[key] = max(int(timing_max.get(key, 0)), value)

    error_counts = debug_stats.setdefault("error_counts", Counter())
    for field, label in (
        ("connect_error", "connect"),
        ("auth_error", "auth"),
        ("enum_error", "enumerate"),
        ("query_error", "query"),
        ("dump_error", "dump"),
    ):
        value = str(record.get(field) or "").strip()
        if value:
            error_counts[f"{label}:{value}"] += 1

    fallback_error = str(record.get("error") or "").strip()
    if fallback_error:
        error_counts[f"error:{fallback_error}"] += 1


def audit_zookeeper_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
    username: str | None,
    password: str | None,
    show_znodes: bool,
    dump: bool,
    query_znode: str | None,
    max_znodes: int,
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
    suppress_connection_refused_status_lines: bool = False,
    debug_emit: Callable[[str], None] | None = None,
    debug_stats: dict[str, Any] | None = None,
    enum_workers: int = 3,
    show_progress: bool = False,
    command_progress: Any | None = None,
) -> tuple[int, int, int, int, int]:
    total = 0
    open_no_auth = 0
    valid = 0
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
            else start_audit_progress("ZOOKEEPER", len(indexed_hosts), enabled=show_progress, leave=True)
        )

        def _detect_task(host: str) -> dict[str, Any]:
            return _call_audit_host_with_thread_debug(
                host,
                port,
                timeout,
                retries,
                username,
                password,
                show_znodes,
                dump,
                query_znode,
                max_znodes,
                bool(debug_emit),
                False,
                enum_workers,
                debug_emit,
            )

        def _deep_task(host: str) -> dict[str, Any]:
            return _call_audit_host_with_thread_debug(
                host,
                port,
                timeout,
                retries,
                username,
                password,
                show_znodes,
                dump,
                query_znode,
                max_znodes,
                bool(debug_emit),
                True,
                enum_workers,
                debug_emit,
            )

        def _emit_detect(detect_record: dict[str, Any]) -> None:
            if bool(detect_record.get("is_zookeeper")):
                _emit_line(out_fh, emit_line, _format_detect_record(detect_record, output_format))

        def _deep_gate(detect_record: dict[str, Any]) -> tuple[bool, str]:
            detect_status = str(detect_record.get("status") or "fail")
            if detect_status in {"open_no_auth", "valid_credentials"}:
                return True, f"status={detect_status}"
            return False, f"status={detect_status}"

        pass_result = TwoPassAuditRunner(
            label="ZOOKEEPER",
            workers=workers,
            debug_emit=debug_emit,
            progress=progress,
            detected_name="zookeeper",
        ).run(
            indexed_hosts,
            detect_task=_detect_task,
            deep_task=_deep_task,
            is_detected=lambda record: bool(record.get("is_zookeeper")),
            deep_gate=_deep_gate,
            emit_detect=_emit_detect,
            merge_records=lambda detect_record, deep_record: _merge_stage2_record(
                detect_record,
                deep_record,
                timeout=timeout,
                retries=retries,
            ),
            not_detected_reason="not_zookeeper",
        )

        final_records = pass_result.final_records

        for idx in range(len(hosts)):
            emit_record = final_records[idx]
            emit_status = str(emit_record.get("status") or "fail")
            total += 1

            if emit_status in {"open_no_auth", "invalid_credentials_anonymous"}:
                open_no_auth += 1
            elif emit_status == "valid_credentials":
                valid += 1
            elif emit_status == "auth_required":
                auth_required += 1
            else:
                failed += 1

            if debug_emit is not None and not bool(emit_record.get("debug_events_streamed")):
                for event in emit_record.get("debug_events") or []:
                    if isinstance(event, str) and event.strip():
                        debug_emit(event)
            if debug_stats is not None:
                _update_debug_stats(debug_stats, emit_record)

            suppress_auth_required_status_line = (
                output_format == "txt"
                and bool(emit_record.get("is_zookeeper"))
                and emit_status == "auth_required"
                and not bool(emit_record.get("provided_credentials"))
            )
            suppress_connection_refused_status_line = (
                suppress_connection_refused_status_lines
                and output_format == "txt"
                and _is_suppressed_fail_record(emit_record)
            )
            if not suppress_auth_required_status_line and not suppress_connection_refused_status_line:
                _emit_line(out_fh, emit_line, _format_record(emit_record, output_format))

            if bool(emit_record.get("is_zookeeper")):
                for detail in _format_znodes_detail_records(emit_record, output_format):
                    _emit_line(out_fh, emit_line, detail)

            if logger is not None and not (
                suppress_connection_refused_status_lines and _is_suppressed_fail_record(emit_record)
            ):
                logger.log(
                    "zookeeper",
                    (str(emit_record.get("host") or "-"), int(emit_record.get("port") or port)),
                    phase="audit",
                    status=emit_record.get("status"),
                    auth_required=emit_record.get("auth_required"),
                    provided_credentials_ok=emit_record.get("provided_credentials_ok"),
                    znode_count=emit_record.get("znode_count"),
                    connect_ms=emit_record.get("connect_ms"),
                    auth_ms=emit_record.get("auth_ms"),
                    enumerate_ms=emit_record.get("enumerate_ms"),
                    dump_ms=emit_record.get("dump_ms"),
                    attempts=emit_record.get("attempts"),
                    max_attempts=emit_record.get("max_attempts"),
                    connect_error=emit_record.get("connect_error"),
                    auth_error=emit_record.get("auth_error"),
                    enum_error=emit_record.get("enum_error"),
                    query_error=emit_record.get("query_error"),
                    dump_error=emit_record.get("dump_error"),
                    error=emit_record.get("error"),
                )
    finally:
        if command_progress is None and progress is not None:
            progress.close()
        if out_fh is not None:
            out_fh.close()

    return total, open_no_auth, valid, auth_required, failed


def run_zookeeper_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)
    enum_workers = int(getattr(args, "enum_workers", 3) or 3)

    username = str(args.username).strip() if args.username is not None else None
    if username == "":
        username = None
    password = str(args.password).strip() if args.password is not None else None
    if username is None and password == "":
        password = None
    try:
        credential_file_entries = parse_username_password_credential_file(username, password)
    except ValueError as exc:
        console.error(str(exc))
        return 2
    if credential_file_entries is not None:
        username = credential_file_entries[0].username
        password = credential_file_entries[0].password
    credential_runs = (
        [(entry.username, entry.password) for entry in credential_file_entries]
        if credential_file_entries is not None
        else [(username, password)]
    )

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
        return 2
    if args.max_znodes <= 0:
        console.error("--max-znodes must be > 0")
        return 2
    if enum_workers <= 0:
        console.error("--enum-workers must be > 0")
        return 2
    if credential_file_entries is None and (username is None) != (password is None):
        console.error("--username and --password must be set together")
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
        console.error("zookeeper requires -t/--targets")
        return 2

    stream_to_stdout = not bool(args.output)
    query_znode = _normalize_znode_path(getattr(args, "znode", None))
    show_znodes = bool(args.show_znodes)
    dump = bool(getattr(args, "dump", False))

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith("ZOOKEEPER") and all(token not in line for token in (" [*] ", " [+] ", " [-] ", " [!] ")):
            if console.render_tagged_payload_line(line, "ZOOKEEPER", payload_color="orange"):
                return
            console.plain(line, color="white")
            return
        if _render_colored_zookeeper_line(console, line):
            return
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
        mode_parts = ["count-znodes"]
        if credential_file_entries is not None:
            mode_parts.append(f"credfile={len(credential_file_entries)}")
        elif username is not None and password is not None:
            mode_parts.append("provided-creds")
        if show_znodes:
            mode_parts.append("show-znodes")
        if dump:
            mode_parts.append("dump")
        if query_znode:
            mode_parts.append(f"znode={query_znode}")
        mode = "+".join(mode_parts)
        console.info(
            f"zookeeper audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} max_znodes={args.max_znodes} enum_workers={enum_workers} "
            f"mode={mode} format=txt"
        )
    if args.debug and not stream_to_stdout:
        mode_parts = ["count-znodes"]
        if credential_file_entries is not None:
            mode_parts.append(f"credfile={len(credential_file_entries)}")
        elif username is not None and password is not None:
            mode_parts.append("provided-creds")
        if show_znodes:
            mode_parts.append("show-znodes")
        if dump:
            mode_parts.append("dump")
        if query_znode:
            mode_parts.append(f"znode={query_znode}")
        mode = "+".join(mode_parts)
        console.info(
            f"zookeeper audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} max_znodes={args.max_znodes} enum_workers={enum_workers} "
            f"mode={mode} format={args.output_format} output={args.output}"
        )

    total = 0
    open_no_auth = 0
    valid = 0
    auth_required = 0
    failed = 0
    debug_stats: dict[str, Any] = {}
    hosts_by_port: dict[int, list[str]] = {int(port): list(hosts) for port in ports}
    if credential_file_entries is not None:
        for audit_port in ports:
            hosts_by_port[int(audit_port)] = filter_open_tcp_hosts_for_credential_file(
                hosts,
                int(audit_port),
                timeout=args.timeout,
                workers=args.workers,
            )
            if args.debug:
                emit_debug(
                    f"credential_prefilter port={int(audit_port)} open={len(hosts_by_port[int(audit_port)])}/"
                    f"{len(hosts)}"
                )
    outer_progress = None
    use_single_global_progress = should_use_global_progress(args.output_format, len(ports), len(credential_runs))
    if use_single_global_progress:
        outer_progress = start_command_progress(
            args,
            "ZOOKEEPER",
            progress_total_from_groups(hosts_by_port.values(), len(credential_runs)),
            enabled=True,
            leave=True,
        )
    output_written = False
    try:
        for audit_port in ports:
            audit_hosts = hosts_by_port[int(audit_port)]
            if not audit_hosts:
                continue
            host_batches = [[host] for host in audit_hosts] if credential_file_entries is not None else [audit_hosts]
            for host_batch in host_batches:
                for run_username, run_password in credential_runs:
                    part_total, part_open, part_valid, part_auth, part_failed = audit_zookeeper_targets(
                        hosts=host_batch,
                        port=audit_port,
                        timeout=args.timeout,
                        retries=args.retries,
                        workers=args.workers,
                        username=run_username,
                        password=run_password,
                        show_znodes=show_znodes,
                        dump=dump,
                        query_znode=query_znode,
                        max_znodes=args.max_znodes,
                        output_path=args.output,
                        output_format=args.output_format,
                        emit_line=emit_line,
                        logger=logger if args.debug else None,
                        append_output=output_written,
                        suppress_connection_refused_status_lines=not bool(args.debug),
                        debug_emit=emit_debug if args.debug else None,
                        debug_stats=debug_stats if args.debug else None,
                        enum_workers=enum_workers,
                        show_progress=not use_single_global_progress,
                        command_progress=outer_progress,
                    )
                    total += part_total
                    open_no_auth += part_open
                    valid += part_valid
                    auth_required += part_auth
                    failed += part_failed
                    output_written = True
    except OSError as exc:
        console.error(f"failed to process zookeeper output: {exc}")
        return 2
    finally:
        if outer_progress is not None:
            outer_progress.close()

    if stream_to_stdout:
        if (
            total > 0
            and open_no_auth == 0
            and valid == 0
            and auth_required == 0
            and failed == total
            and args.output_format == "txt"
        ):
            console.warn(
                "all zookeeper targets are unreachable; check host/port, network reachability, and service status"
            )
        if args.debug and args.output_format == "txt":
            console.info(
                f"zookeeper audit complete: total={total} anonymous={open_no_auth} valid={valid} "
                f"auth_required={auth_required} fail={failed}"
            )
            timing_sums: Counter[str] = debug_stats.get("timing_sums", Counter())
            timing_counts: Counter[str] = debug_stats.get("timing_counts", Counter())
            timing_max: Counter[str] = debug_stats.get("timing_max", Counter())
            timing_fragments: list[str] = []
            for key, short in (
                ("connect_ms", "connect"),
                ("auth_ms", "auth"),
                ("enumerate_ms", "enumerate"),
                ("dump_ms", "dump"),
                ("elapsed_ms", "total"),
            ):
                count = int(timing_counts.get(key, 0))
                if count <= 0:
                    continue
                avg_value = int(round(float(timing_sums.get(key, 0)) / float(count)))
                max_value = int(timing_max.get(key, 0))
                timing_fragments.append(f"{short}:avg={avg_value}ms,max={max_value}ms,n={count}")
            if timing_fragments:
                emit_debug("timings summary " + " | ".join(timing_fragments))

            auth_sources: Counter[str] = debug_stats.get("auth_sources", Counter())
            if auth_sources:
                top_sources = ", ".join(f"{name}={count}" for name, count in auth_sources.most_common(5))
                emit_debug(f"auth inference summary {top_sources}")

            error_counts: Counter[str] = debug_stats.get("error_counts", Counter())
            if error_counts:
                top_errors = ", ".join(f"{name}={count}" for name, count in error_counts.most_common(7))
                emit_debug(f"top errors {top_errors}")
        return 0

    if args.debug:
        console.info(
            f"zookeeper audit complete: total={total} anonymous={open_no_auth} valid={valid} "
            f"auth_required={auth_required} fail={failed} "
            f"format={args.output_format} output={args.output}"
        )
        timing_sums = debug_stats.get("timing_sums", Counter())
        timing_counts = debug_stats.get("timing_counts", Counter())
        timing_max = debug_stats.get("timing_max", Counter())
        timing_fragments: list[str] = []
        for key, short in (
            ("connect_ms", "connect"),
            ("auth_ms", "auth"),
            ("enumerate_ms", "enumerate"),
            ("dump_ms", "dump"),
            ("elapsed_ms", "total"),
        ):
            count = int(timing_counts.get(key, 0))
            if count <= 0:
                continue
            avg_value = int(round(float(timing_sums.get(key, 0)) / float(count)))
            max_value = int(timing_max.get(key, 0))
            timing_fragments.append(f"{short}:avg={avg_value}ms,max={max_value}ms,n={count}")
        if timing_fragments:
            emit_debug("timings summary " + " | ".join(timing_fragments))

        auth_sources = debug_stats.get("auth_sources", Counter())
        if auth_sources:
            top_sources = ", ".join(f"{name}={count}" for name, count in auth_sources.most_common(5))
            emit_debug(f"auth inference summary {top_sources}")

        error_counts = debug_stats.get("error_counts", Counter())
        if error_counts:
            top_errors = ", ".join(f"{name}={count}" for name, count in error_counts.most_common(7))
            emit_debug(f"top errors {top_errors}")
    return 0
