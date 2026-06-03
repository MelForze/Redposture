"""gRPC audit stage."""

from __future__ import annotations

import base64
import json
import re
import sys
import threading
import time
from collections.abc import Callable
from typing import Any

from google.protobuf import descriptor_pb2

from ...clients.grpc import (
    _build_auth_header,
    _build_basic_auth_header,
    _compile_proto_files,
    _decode_grpc_frames,
    _decode_grpc_web_frames,
    _dedup_descriptor_bytes,
    _descriptor_bytes_from_protoset,
    _descriptor_bytes_to_pool,
    _encode_grpc_frame,
    _extract_descriptors,
    _find_method_descriptor,
    _generate_openapi_document,
    _grpc_call,
    _grpc_health_payload,
    _grpc_reflection_list_payload,
    _grpc_reflection_symbol_payload,
    _grpc_status_name,
    _grpc_web_call,
    _grpc_web_health_check_call,
    _GrpcCallResult,
    _GrpcWebCallResult,
    _health_check_call,
    _HealthResult,
    _http2_headers_to_map,
    _invoke_unary_method,
    _InvokeResult,
    _load_explicit_descriptor_bytes,
    _metadata_value,
    _open_grpc_socket,
    _open_http_socket,
    _parse_health_message,
    _parse_http1_response,
    _parse_json_payload_source,
    _parse_metadata_items,
    _reflection_file_descriptors_call,
    _reflection_list_services_call,
    _ReflectionDescriptorResult,
    _ReflectionListResult,
    _split_grpc_method_path,
    _write_openapi_document,
)
from ...console import Console
from ...proto import grpc_health_pb2, grpc_reflection_pb2
from ...rendering import RegexColorRule, collect_color_spans, render_colored_marker_line, render_tagged_detail_line
from ...stage_runtime import (
    AuditHookContext,
    AuditRecord,
    _invoke_module_host_stage,
    merge_stage_records,
)
from ...utils import (
    utc_now_iso,
)

__all__ = [
    "descriptor_pb2",
    "grpc_health_pb2",
    "grpc_reflection_pb2",
    "_GrpcCallResult",
    "_GrpcWebCallResult",
    "_HealthResult",
    "_InvokeResult",
    "_ReflectionDescriptorResult",
    "_ReflectionListResult",
    "_build_auth_header",
    "_build_basic_auth_header",
    "_compile_proto_files",
    "_decode_grpc_frames",
    "_decode_grpc_web_frames",
    "_descriptor_bytes_from_protoset",
    "_descriptor_bytes_to_pool",
    "_encode_grpc_frame",
    "_extract_descriptors",
    "_find_method_descriptor",
    "_generate_openapi_document",
    "_grpc_call",
    "_grpc_health_payload",
    "_grpc_reflection_list_payload",
    "_grpc_reflection_symbol_payload",
    "_grpc_status_name",
    "_grpc_web_call",
    "_grpc_web_health_check_call",
    "_health_check_call",
    "_http2_headers_to_map",
    "_invoke_unary_method",
    "_load_explicit_descriptor_bytes",
    "_metadata_value",
    "_open_grpc_socket",
    "_open_http_socket",
    "_parse_health_message",
    "_parse_http1_response",
    "_parse_json_payload_source",
    "_parse_metadata_items",
    "_reflection_file_descriptors_call",
    "_reflection_list_services_call",
    "_split_grpc_method_path",
    "_write_openapi_document",
]

_GRPC_TAG = "GRPC"
_CONNECTION_REFUSED_PREFIX = "connection refused"
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"

_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"

_THREAD_LOCAL_DEBUG_EMIT = threading.local()

_DEFAULT_BASIC_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "admin"),
    ("grpc", "grpc"),
    ("service", "service"),
    ("test", "test"),
    ("user", "password"),
)
_DEFAULT_BEARER_TOKENS: tuple[str, ...] = (
    "admin",
    "token",
    "secret",
    "changeme",
    "grpc",
    "default-token",
)

_GRPC_AUTH_CODES = {7, 16}
_GRPC_OK = 0
_GRPC_UNIMPLEMENTED = 12


def _clip(text: str, width: int = 96) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _get_thread_debug_emitter() -> Callable[[str], None] | None:
    callback = getattr(_THREAD_LOCAL_DEBUG_EMIT, "callback", None)
    if callable(callback):
        return callback
    return None


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


def _is_retryable_stage_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    return text.startswith(_CONNECTION_TIMEOUT_PREFIX) or text.startswith(_CONNECTION_REFUSED_PREFIX)


def _is_suppressed_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail"


def _auth_required_from_grpc_status(grpc_status: int | None) -> bool | None:
    if grpc_status in _GRPC_AUTH_CODES:
        return True
    if grpc_status is None:
        return None
    return False


def _detect_grpc_target(
    host: str,
    port: int,
    *,
    timeout: float,
    preferred_scheme: str | None,
) -> dict[str, Any]:
    scheme_hint = str(preferred_scheme or "").strip().lower()
    if scheme_hint == "http":
        transport_order = [False, True]
    elif scheme_hint == "https":
        transport_order = [True, False]
    else:
        transport_order = [True, False]

    calls: list[_HealthResult | _ReflectionListResult] = []
    transport_errors: list[str] = []
    non_grpc_seen = False

    for use_tls in transport_order:
        health = _health_check_call(host, port, timeout=timeout, use_tls=use_tls, authorization=None, service_name="")
        calls.append(health)
        health_call = health["call"]
        if bool(health_call.get("is_grpc")):
            return {
                "is_grpc": True,
                "protocol_flavor": "grpc",
                "grpc_web_detected": False,
                "transport_mode": "tls" if use_tls else "plaintext",
                "auth_required": _auth_required_from_grpc_status(health.get("grpc_status")),
                "health_supported": health.get("health_supported"),
                "reflection_enabled": None,
                "detect_error": health.get("error"),
                "detect_probe_trace": [
                    {
                        "probe": "health",
                        "scheme": "https" if use_tls else "http",
                        "http_status": health_call.get("http_status"),
                        "grpc_status": health.get("grpc_status"),
                        "error": health.get("error"),
                    }
                ],
            }

        if health_call.get("transport_ok"):
            non_grpc_seen = True
        if health.get("error"):
            transport_errors.append(str(health.get("error")))

        reflection = _reflection_list_services_call(
            host,
            port,
            timeout=timeout,
            use_tls=use_tls,
            authorization=None,
        )
        calls.append(reflection)
        reflection_call = reflection["call"]
        if bool(reflection_call.get("is_grpc")):
            return {
                "is_grpc": True,
                "protocol_flavor": "grpc",
                "grpc_web_detected": False,
                "transport_mode": "tls" if use_tls else "plaintext",
                "auth_required": _auth_required_from_grpc_status(reflection.get("grpc_status")),
                "health_supported": health.get("health_supported"),
                "reflection_enabled": reflection.get("reflection_enabled"),
                "detect_error": reflection.get("error"),
                "detect_probe_trace": [
                    {
                        "probe": "health",
                        "scheme": "https" if use_tls else "http",
                        "http_status": health_call.get("http_status"),
                        "grpc_status": health.get("grpc_status"),
                        "error": health.get("error"),
                    },
                    {
                        "probe": "reflection",
                        "scheme": "https" if use_tls else "http",
                        "http_status": reflection_call.get("http_status"),
                        "grpc_status": reflection.get("grpc_status"),
                        "error": reflection.get("error"),
                    },
                ],
            }

        if reflection_call.get("transport_ok"):
            non_grpc_seen = True
        if reflection.get("error"):
            transport_errors.append(str(reflection.get("error")))

    for use_tls in transport_order:
        web_health = _grpc_web_health_check_call(
            host,
            port,
            timeout=timeout,
            use_tls=use_tls,
            authorization=None,
            service_name="",
        )
        calls.append(web_health)
        web_call = web_health["call"]
        if bool(web_call.get("is_grpc_web")):
            return {
                "is_grpc": True,
                "protocol_flavor": "grpc-web",
                "grpc_web_detected": True,
                "transport_mode": "tls" if use_tls else "plaintext",
                "auth_required": _auth_required_from_grpc_status(web_health.get("grpc_status")),
                "health_supported": web_health.get("health_supported"),
                "reflection_enabled": False,
                "detect_error": web_health.get("error"),
                "detect_probe_trace": [
                    {
                        "probe": "grpc-web-health",
                        "scheme": "https" if use_tls else "http",
                        "http_status": web_call.get("http_status"),
                        "grpc_status": web_health.get("grpc_status"),
                        "error": web_health.get("error"),
                    }
                ],
            }
        if web_call.get("transport_ok"):
            non_grpc_seen = True
        if web_health.get("error"):
            transport_errors.append(str(web_health.get("error")))

    if non_grpc_seen:
        return {
            "is_grpc": False,
            "protocol_flavor": None,
            "grpc_web_detected": False,
            "status": "not_grpc",
            "transport_mode": None,
            "auth_required": None,
            "health_supported": None,
            "reflection_enabled": None,
            "detect_error": "not a gRPC endpoint",
            "detect_probe_trace": [
                {
                    "probe": "health",
                    "scheme": "https" if item.get("call", {}).get("use_tls") else "http",
                    "http_status": item.get("call", {}).get("http_status"),
                    "grpc_status": item.get("grpc_status"),
                    "error": item.get("error"),
                }
                for item in calls
            ],
        }

    error_text = "; ".join(dict.fromkeys(err for err in transport_errors if err.strip())) or "connection failed"
    return {
        "is_grpc": False,
        "protocol_flavor": None,
        "grpc_web_detected": False,
        "status": "fail",
        "transport_mode": None,
        "auth_required": None,
        "health_supported": None,
        "reflection_enabled": None,
        "detect_error": error_text,
        "detect_probe_trace": [
            {
                "probe": "health",
                "scheme": "https" if item.get("call", {}).get("use_tls") else "http",
                "http_status": item.get("call", {}).get("http_status"),
                "grpc_status": item.get("grpc_status"),
                "error": item.get("error"),
            }
            for item in calls
        ],
    }


def _credential_label(entry: dict[str, Any]) -> str:
    auth_type = str(entry.get("type") or "").strip()
    if auth_type == "token":
        return "token"
    if auth_type == "basic":
        username = str(entry.get("username") or "user").strip() or "user"
        password = str(entry.get("password") or "")
        if password == "":
            password = "<empty>"
        return f"{username}:{password}"
    return "credentials"


def _auth_attempt_entries(
    *,
    token: str | None,
    username: str | None,
    password: str | None,
    defcreds: bool,
) -> list[dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def _add_token(value: str, source: str) -> None:
        key = ("token", value, "")
        if key in seen:
            return
        seen.add(key)
        attempts.append({"type": "token", "token": value, "source": source})

    def _add_basic(user: str, pwd: str, source: str) -> None:
        key = ("basic", user, pwd)
        if key in seen:
            return
        seen.add(key)
        attempts.append({"type": "basic", "username": user, "password": pwd, "source": source})

    if token:
        _add_token(token, "provided")
    elif username is not None and password is not None:
        _add_basic(username, password, "provided")

    if defcreds:
        for value in _DEFAULT_BEARER_TOKENS:
            _add_token(value, "defcreds")
        for user, pwd in _DEFAULT_BASIC_CREDENTIALS:
            _add_basic(user, pwd, "defcreds")

    return attempts


def _auth_attempt_success(grpc_status: int | None, is_grpc: bool) -> bool:
    if not is_grpc:
        return False
    if grpc_status in _GRPC_AUTH_CODES:
        return False
    if grpc_status is None:
        return False
    return True


def _try_credentials(
    host: str,
    port: int,
    *,
    timeout: float,
    use_tls: bool,
    protocol_flavor: str,
    candidates: list[dict[str, Any]],
) -> tuple[bool, dict[str, Any] | None, dict[str, Any] | None]:
    last_attempt: dict[str, Any] | None = None
    for candidate in candidates:
        auth_header = _build_auth_header(
            token=str(candidate.get("token") or "") if candidate.get("type") == "token" else None,
            username=str(candidate.get("username") or "") if candidate.get("type") == "basic" else None,
            password=str(candidate.get("password") or "") if candidate.get("type") == "basic" else None,
        )
        if protocol_flavor == "grpc-web":
            health = _grpc_web_health_check_call(
                host,
                port,
                timeout=timeout,
                use_tls=use_tls,
                authorization=auth_header,
                service_name="",
            )
        else:
            health = _health_check_call(
                host,
                port,
                timeout=timeout,
                use_tls=use_tls,
                authorization=auth_header,
                service_name="",
            )
        last_attempt = {
            "candidate": candidate,
            "health": health,
        }
        if _auth_attempt_success(health.get("grpc_status"), bool(health.get("call", {}).get("is_grpc"))):
            return True, candidate, last_attempt

        if protocol_flavor == "grpc-web":
            continue

        reflection = _reflection_list_services_call(
            host,
            port,
            timeout=timeout,
            use_tls=use_tls,
            authorization=auth_header,
        )
        last_attempt = {
            "candidate": candidate,
            "health": health,
            "reflection": reflection,
        }
        if _auth_attempt_success(reflection.get("grpc_status"), bool(reflection.get("call", {}).get("is_grpc"))):
            return True, candidate, last_attempt

    return False, None, last_attempt


def _format_status_label(status: str) -> str:
    if status == "open_no_auth":
        return "anonymous access"
    if status == "valid_credentials":
        return "valid credentials"
    if status == "auth_required":
        return "authentication required"
    if status == "invalid_credentials_anonymous":
        return "invalid credentials (anonymous works)"
    if status == "not_grpc":
        return "not grpc"
    if status == "fail":
        return "fail"
    return status


def _audit_grpc_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    token: str | None,
    username: str | None,
    password: str | None,
    defcreds: bool,
    preferred_scheme: str | None,
    run_deep_checks: bool,
    schema_descriptor_bytes: list[bytes] | None = None,
    invoke_path: str | None = None,
    invoke_request_json: dict[str, Any] | None = None,
    metadata: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    provided_credentials = bool(token or (username is not None and password is not None))
    auth_candidates = _auth_attempt_entries(token=token, username=username, password=password, defcreds=defcreds)

    last_error: str | None = None
    detect_probe_trace: list[dict[str, Any]] = []

    detect_duration_ms = 0
    auth_duration_ms = 0
    capability_duration_ms = 0
    data_duration_ms = 0
    stage_attempts_used = 1

    detect_result: dict[str, Any] = {}

    for attempt in range(attempts):
        stage_attempts_used = attempt + 1
        detect_started = time.monotonic()
        detect_result = _detect_grpc_target(
            host,
            port,
            timeout=timeout,
            preferred_scheme=preferred_scheme,
        )
        detect_duration_ms = int((time.monotonic() - detect_started) * 1000)
        detect_probe_trace = list(detect_result.get("detect_probe_trace") or [])

        if detect_result.get("status") == "fail":
            last_error = str(detect_result.get("detect_error") or "connection failed")
            if attempt >= attempts - 1 or not _is_retryable_stage_error(last_error):
                break
            time.sleep(_retry_delay(attempt))
            continue

        break

    if detect_result.get("status") == "fail":
        return {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "is_grpc": False,
            "transport_mode": None,
            "protocol_flavor": detect_result.get("protocol_flavor"),
            "grpc_web_detected": bool(detect_result.get("grpc_web_detected")),
            "status": "fail",
            "auth_required": None,
            "provided_credentials": provided_credentials,
            "provided_username": username,
            "provided_password": password if username is not None and password is not None else None,
            "provided_credentials_ok": None,
            "auth_used": None,
            "defcreds_used": bool(defcreds),
            "reflection_enabled": None,
            "health_supported": None,
            "services": None,
            "methods": None,
            "descriptors": None,
            "health_checks": None,
            "invoke_result": None,
            "descriptor_protos_b64": None,
            "detect_probe_trace": detect_probe_trace,
            "error": last_error or str(detect_result.get("detect_error") or "connection failed"),
            "stage_detect_ms": detect_duration_ms,
            "stage_auth_ms": auth_duration_ms,
            "stage_capabilities_ms": capability_duration_ms,
            "stage_data_ms": data_duration_ms,
            "stage_attempts_used": stage_attempts_used,
        }

    if not bool(detect_result.get("is_grpc")):
        return {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "is_grpc": False,
            "transport_mode": None,
            "protocol_flavor": detect_result.get("protocol_flavor"),
            "grpc_web_detected": bool(detect_result.get("grpc_web_detected")),
            "status": "not_grpc",
            "auth_required": None,
            "provided_credentials": provided_credentials,
            "provided_username": username,
            "provided_password": password if username is not None and password is not None else None,
            "provided_credentials_ok": None,
            "auth_used": None,
            "defcreds_used": bool(defcreds),
            "reflection_enabled": None,
            "health_supported": None,
            "services": None,
            "methods": None,
            "descriptors": None,
            "health_checks": None,
            "invoke_result": None,
            "descriptor_protos_b64": None,
            "detect_probe_trace": detect_probe_trace,
            "error": str(detect_result.get("detect_error") or "not a gRPC endpoint"),
            "stage_detect_ms": detect_duration_ms,
            "stage_auth_ms": auth_duration_ms,
            "stage_capabilities_ms": capability_duration_ms,
            "stage_data_ms": data_duration_ms,
            "stage_attempts_used": stage_attempts_used,
        }

    transport_mode = str(detect_result.get("transport_mode") or "plaintext")
    protocol_flavor = str(detect_result.get("protocol_flavor") or "grpc")
    use_tls = transport_mode == "tls"

    auth_started = time.monotonic()
    auth_required = detect_result.get("auth_required")
    provided_credentials_ok: bool | None = None
    auth_used: dict[str, Any] | None = None
    auth_error: str | None = None

    should_try_auth = bool(auth_candidates) and (auth_required is not False or provided_credentials)
    if should_try_auth:
        success, matched_candidate, last_attempt = _try_credentials(
            host,
            port,
            timeout=timeout,
            use_tls=use_tls,
            protocol_flavor=protocol_flavor,
            candidates=auth_candidates,
        )
        if success:
            provided_credentials_ok = True
            auth_used = matched_candidate
            auth_required = True if auth_required is not False else False
        else:
            provided_credentials_ok = False if bool(auth_candidates) else None
            if isinstance(last_attempt, dict):
                health = last_attempt.get("health")
                reflection = last_attempt.get("reflection")
                if isinstance(health, dict) and health.get("error"):
                    auth_error = str(health.get("error"))
                if not auth_error and isinstance(reflection, dict) and reflection.get("error"):
                    auth_error = str(reflection.get("error"))
            if auth_required is None and provided_credentials:
                auth_required = True

    auth_duration_ms = int((time.monotonic() - auth_started) * 1000)

    if auth_required is False:
        if provided_credentials and provided_credentials_ok is False:
            status = "invalid_credentials_anonymous"
        elif provided_credentials_ok is True:
            status = "valid_credentials"
        else:
            status = "open_no_auth"
    elif provided_credentials_ok is True:
        status = "valid_credentials"
    else:
        status = "auth_required"

    reflection_enabled = detect_result.get("reflection_enabled")
    health_supported = detect_result.get("health_supported")
    services: list[str] = []
    methods: list[dict[str, Any]] = []
    descriptors: list[dict[str, Any]] = []
    health_checks: list[dict[str, Any]] = []
    descriptor_blobs: list[bytes] = _dedup_descriptor_bytes(list(schema_descriptor_bytes or []))
    invoke_result: dict[str, Any] | None = None

    if run_deep_checks and status in {"open_no_auth", "valid_credentials"}:
        cap_started = time.monotonic()
        auth_header = None
        if isinstance(auth_used, dict):
            auth_header = _build_auth_header(
                token=str(auth_used.get("token") or "") if auth_used.get("type") == "token" else None,
                username=str(auth_used.get("username") or "") if auth_used.get("type") == "basic" else None,
                password=str(auth_used.get("password") or "") if auth_used.get("type") == "basic" else None,
            )

        if protocol_flavor == "grpc-web":
            reflection_enabled = False
        else:
            reflection = _reflection_list_services_call(
                host,
                port,
                timeout=timeout,
                use_tls=use_tls,
                authorization=auth_header,
            )
            reflection_enabled = reflection.get("reflection_enabled")
            services = list(reflection.get("services") or [])

        health_call = _grpc_web_health_check_call if protocol_flavor == "grpc-web" else _health_check_call
        primary_health = health_call(
            host,
            port,
            timeout=timeout,
            use_tls=use_tls,
            authorization=auth_header,
            service_name="",
        )
        health_supported = primary_health.get("health_supported")
        health_checks.append(
            {
                "service": "",
                "grpc_status": primary_health.get("grpc_status"),
                "grpc_status_name": primary_health.get("grpc_status_name"),
                "serving_status": primary_health.get("serving_status"),
                "error": primary_health.get("error"),
            }
        )

        capability_duration_ms = int((time.monotonic() - cap_started) * 1000)

        data_started = time.monotonic()
        if protocol_flavor != "grpc-web" and reflection_enabled is True and services:
            for service_name in services:
                response = _reflection_file_descriptors_call(
                    host,
                    port,
                    timeout=timeout,
                    use_tls=use_tls,
                    authorization=auth_header,
                    symbol=service_name,
                )
                descriptor_blobs.extend(
                    blob for blob in response.get("descriptor_bytes") or [] if isinstance(blob, bytes)
                )

        descriptor_blobs = _dedup_descriptor_bytes(descriptor_blobs)
        methods, descriptors = _extract_descriptors(descriptor_blobs)
        if not services and methods:
            services = sorted({str(method.get("service") or "") for method in methods if method.get("service")})

        if services:
            for service_name in services:
                health_entry = health_call(
                    host,
                    port,
                    timeout=timeout,
                    use_tls=use_tls,
                    authorization=auth_header,
                    service_name=service_name,
                )
                health_checks.append(
                    {
                        "service": service_name,
                        "grpc_status": health_entry.get("grpc_status"),
                        "grpc_status_name": health_entry.get("grpc_status_name"),
                        "serving_status": health_entry.get("serving_status"),
                        "error": health_entry.get("error"),
                    }
                )

        if invoke_path:
            invoke_result = _invoke_unary_method(
                host,
                port,
                timeout=timeout,
                use_tls=use_tls,
                protocol_flavor=protocol_flavor,
                authorization=auth_header,
                metadata=list(metadata or []),
                descriptor_bytes=descriptor_blobs,
                invoke_path=invoke_path,
                request_json=dict(invoke_request_json or {}),
            )

        data_duration_ms = int((time.monotonic() - data_started) * 1000)

    error_parts: list[str] = []
    if detect_result.get("detect_error") and status in {"fail", "not_grpc"}:
        error_parts.append(str(detect_result.get("detect_error")))
    if auth_error and status in {"auth_required", "invalid_credentials_anonymous"}:
        error_parts.append(auth_error)

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_grpc": True,
        "transport_mode": transport_mode,
        "protocol_flavor": protocol_flavor,
        "grpc_web_detected": protocol_flavor == "grpc-web",
        "status": status,
        "auth_required": auth_required,
        "provided_credentials": provided_credentials,
        "provided_username": username,
        "provided_password": password if username is not None and password is not None else None,
        "provided_credentials_ok": provided_credentials_ok,
        "auth_used": auth_used,
        "defcreds_used": bool(defcreds),
        "reflection_enabled": reflection_enabled,
        "health_supported": health_supported,
        "services": services or None,
        "methods": methods or None,
        "descriptors": descriptors or None,
        "health_checks": health_checks or None,
        "invoke_result": invoke_result,
        "descriptor_protos_b64": [
            base64.b64encode(blob).decode("ascii") for blob in _dedup_descriptor_bytes(descriptor_blobs)
        ]
        or None,
        "detect_probe_trace": detect_probe_trace,
        "error": "; ".join(dict.fromkeys(part for part in error_parts if part.strip())) or None,
        "stage_detect_ms": detect_duration_ms,
        "stage_auth_ms": auth_duration_ms,
        "stage_capabilities_ms": capability_duration_ms,
        "stage_data_ms": data_duration_ms,
        "stage_attempts_used": stage_attempts_used,
    }


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{_GRPC_TAG:<8}\t{host}\t{port}\t"


def _auth_required_text(value: Any) -> str:
    if value is True:
        return "True"
    if value is False:
        return "False"
    return "unknown"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    status = str(record.get("status") or "fail")
    if output_format == "json":
        return json.dumps(
            {
                "timestamp": record.get("timestamp"),
                "type": "detect",
                "host": record.get("host"),
                "port": record.get("port"),
                "service": "grpc",
                "detected": bool(record.get("is_grpc")),
                "status": status,
                "auth_required": record.get("auth_required"),
                "transport_mode": record.get("transport_mode"),
                "protocol_flavor": record.get("protocol_flavor"),
                "grpc_web_detected": bool(record.get("grpc_web_detected")),
            },
            ensure_ascii=False,
        )

    prefix = _nxc_prefix(record)
    if status == "fail":
        err = _clip(str(record.get("error") or "-"), 72)
        if err != "-":
            return f"{prefix} [!] connection failed err={err}"
        return f"{prefix} [!] connection failed"
    if status == "not_grpc":
        return f"{prefix} [-] not a gRPC service"

    transport = str(record.get("transport_mode") or "-")
    protocol = str(record.get("protocol_flavor") or "grpc")
    return (
        f"{prefix} [*] gRPC Service (auth required:{_auth_required_text(record.get('auth_required'))}) "
        f"(transport:{transport}) (protocol:{protocol})"
    )


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 72)

    services_count = len(record.get("services") or []) if isinstance(record.get("services"), list) else 0
    methods_count = len(record.get("methods") or []) if isinstance(record.get("methods"), list) else 0
    reflection_enabled = record.get("reflection_enabled")
    health_supported = record.get("health_supported")
    _ = (services_count, methods_count, reflection_enabled, health_supported)

    if status == "open_no_auth":
        return f"{prefix} [+] anonymous access"

    if status == "invalid_credentials_anonymous":
        username = str(record.get("provided_username") or "user").strip() or "user"
        provided_password = record.get("provided_password")
        password_text = "<empty>" if provided_password == "" else str(provided_password or "")
        return f"{prefix} [-] {username}:{password_text}"

    if status == "valid_credentials":
        auth_used = record.get("auth_used")
        if isinstance(auth_used, dict):
            label = _credential_label(auth_used)
        else:
            label = "credentials"
        return f"{prefix} [+] {label}"

    if status == "auth_required":
        if record.get("provided_credentials"):
            username = str(record.get("provided_username") or "user").strip() or "user"
            provided_password = record.get("provided_password")
            password_text = "<empty>" if provided_password == "" else str(provided_password or "")
            base = f"{prefix} [-] {username}:{password_text}"
        else:
            base = f"{prefix} [-] authentication required"
        if err != "-":
            return f"{base} err={err}"
        return base

    if status == "not_grpc":
        return f"{prefix} [-] not a gRPC service"

    line = f"{prefix} [!] connection failed"
    if err != "-":
        return f"{line} err={err}"
    return line


def _format_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if str(record.get("status") or "") not in {"open_no_auth", "valid_credentials"}:
        return []

    services = [str(item).strip() for item in (record.get("services") or []) if str(item).strip()]
    methods_raw = record.get("methods") if isinstance(record.get("methods"), list) else []
    methods = [item for item in methods_raw if isinstance(item, dict)]
    descriptors_raw = record.get("descriptors") if isinstance(record.get("descriptors"), list) else []
    descriptors = [item for item in descriptors_raw if isinstance(item, dict)]
    health_checks_raw = record.get("health_checks") if isinstance(record.get("health_checks"), list) else []
    health_checks = [item for item in health_checks_raw if isinstance(item, dict)]
    invoke_result = record.get("invoke_result") if isinstance(record.get("invoke_result"), dict) else None
    reflection_enabled = record.get("reflection_enabled")
    health_supported = record.get("health_supported")

    if output_format == "json":
        lines: list[str] = []
        lines.append(
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "grpc_reflection_services",
                    "service": "grpc",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "reflection_enabled": record.get("reflection_enabled"),
                    "services": services,
                },
                ensure_ascii=False,
            )
        )
        lines.append(
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "grpc_methods",
                    "service": "grpc",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "methods": methods,
                },
                ensure_ascii=False,
            )
        )
        lines.append(
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "grpc_descriptors",
                    "service": "grpc",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "descriptors": descriptors,
                },
                ensure_ascii=False,
            )
        )
        lines.append(
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "grpc_health_checks",
                    "service": "grpc",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "health_supported": record.get("health_supported"),
                    "checks": health_checks,
                },
                ensure_ascii=False,
            )
        )
        if invoke_result is not None:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "grpc_invoke_result",
                        "service": "grpc",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "result": invoke_result,
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    prefix = _nxc_prefix(record)
    lines: list[str] = []

    lines.append(f"{prefix} [*] Reflection (enabled:{_auth_required_text(reflection_enabled)})")
    if reflection_enabled is True:
        if services:
            lines.append(f"{prefix} [*] {len(services)} Services")
            for service_name in services:
                lines.append(f"{prefix} service={service_name}")
        else:
            lines.append(f"{prefix} <no services>")
    elif reflection_enabled is False:
        lines.append(f"{prefix} reflection disabled/unimplemented")
    else:
        lines.append(f"{prefix} reflection unavailable")

    if methods:
        lines.append(f"{prefix} [*] {len(methods)} Methods")
        for method in methods:
            full_method = str(method.get("full_method") or "")
            input_type = str(method.get("input_type") or "-")
            output_type = str(method.get("output_type") or "-")
            client_streaming = bool(method.get("client_streaming"))
            server_streaming = bool(method.get("server_streaming"))
            lines.append(
                f"{prefix} {full_method} input={input_type} output={output_type} "
                f"client_stream={client_streaming} server_stream={server_streaming}"
            )

    if descriptors:
        lines.append(f"{prefix} [*] {len(descriptors)} Descriptors")
        for descriptor in descriptors:
            file_name = str(descriptor.get("file") or "-")
            package_name = str(descriptor.get("package") or "-")
            service_list = descriptor.get("services") if isinstance(descriptor.get("services"), list) else []
            lines.append(f"{prefix} file={file_name} package={package_name} services={len(service_list)}")

    lines.append(f"{prefix} [*] Health (supported:{_auth_required_text(health_supported)})")
    if health_checks:
        lines.append(f"{prefix} [*] {len(health_checks)} Health Checks")
        for entry in health_checks:
            service_name = str(entry.get("service") or "") or "<overall>"
            serving = str(entry.get("serving_status") or "-")
            grpc_status_name = str(entry.get("grpc_status_name") or "-")
            err = str(entry.get("error") or "").strip()
            line = f"{prefix} service={service_name} grpc={grpc_status_name} status={serving}"
            if err:
                line = f"{line} err={_clip(err, 60)}"
            lines.append(line)
    else:
        lines.append(f"{prefix} <no health data>")

    if invoke_result is not None:
        lines.append(f"{prefix} [*] Invoke")
        invoke_path = str(invoke_result.get("path") or "-")
        status = str(invoke_result.get("status") or "-")
        grpc_status_name = str(invoke_result.get("grpc_status_name") or "-")
        elapsed_ms = invoke_result.get("elapsed_ms")
        line = f"{prefix} method={invoke_path} result={status} grpc={grpc_status_name}"
        if elapsed_ms is not None:
            line = f"{line} elapsed_ms={elapsed_ms}"
        lines.append(line)
        if invoke_result.get("response") is not None:
            response_json = json.dumps(invoke_result.get("response"), ensure_ascii=False, sort_keys=True)
            lines.append(f"{prefix} response={response_json}")
        if invoke_result.get("error"):
            lines.append(f"{prefix} err={_clip(str(invoke_result.get('error')), 120)}")

    return lines


def _grpc_marker_color_spans(payload: str) -> list[tuple[int, int, str]]:
    return collect_color_spans(
        payload,
        literals=(
            ("(auth required:True)", "bright_green"),
            ("(auth required:False)", "red"),
            ("(auth required:unknown)", "yellow"),
            ("(enabled:True)", "red"),
            ("(enabled:False)", "bright_green"),
            ("(enabled:unknown)", "yellow"),
            ("(supported:True)", "bright_green"),
            ("(supported:False)", "yellow"),
            ("(supported:unknown)", "yellow"),
            ("(transport:tls)", "bright_green"),
            ("(transport:plaintext)", "yellow"),
            ("(transport:-)", "yellow"),
            ("(protocol:grpc)", "bright_green"),
            ("(protocol:grpc-web)", "orange"),
            ("anonymous access", "bright_green"),
            ("authentication required", "red"),
        ),
        regexes=(
            RegexColorRule(r"\((services|methods|descriptors|checks):(\d+)\)", "orange", skip_zero_group=2),
            RegexColorRule(r"\bservice=[^\s]+", "orange"),
            RegexColorRule(r"\bfile=[^\s]+", "orange"),
            RegexColorRule(r"\bmethod=/[^\s]+", "orange"),
            RegexColorRule(r"(?<!\S)/[A-Za-z0-9_.]+/[A-Za-z0-9_]+", "orange"),
            RegexColorRule(r"(?<=\bstatus=)SERVING\b", "orange"),
            RegexColorRule(r"(?<=\bgrpc=)OK\b", "orange"),
            RegexColorRule(r"(?<=\bresult=)ok\b", "orange"),
            RegexColorRule(r"(?<=\bstatus=)[A-Z_]+\b", "yellow"),
            RegexColorRule(r"(?<=\bgrpc=)[A-Z_]+\b", "yellow"),
            RegexColorRule(r"(?<=\bresult=)unsupported\b", "yellow"),
            RegexColorRule(r"\berr=[^\s].*", "yellow"),
            RegexColorRule(r"\b(response=\{.*)", "orange"),
            RegexColorRule(r"\bOpenAPI exported\b.*", "orange"),
        ),
    )


def _grpc_detail_color_spans(payload: str) -> list[tuple[int, int, str]]:
    return collect_color_spans(
        payload,
        regexes=(
            RegexColorRule(r"^\s*service=[^\s]+\s+grpc=[A-Z_]+\s+status=[A-Z_]+.*", "orange"),
            RegexColorRule(r"^\s*/[A-Za-z0-9_.]+/[A-Za-z0-9_]+.*", "orange"),
            RegexColorRule(r"^\s*file=[^\s]+.*", "orange"),
            RegexColorRule(r"^\s*method=/[^\s]+.*", "orange"),
            RegexColorRule(r"^\s*response=\{.*", "orange"),
            RegexColorRule(r"^\s*OpenAPI exported\b.*", "orange"),
            RegexColorRule(r"\bservice=[^\s]+", "orange"),
            RegexColorRule(r"\bfile=[^\s]+", "orange"),
            RegexColorRule(r"(?<!\S)/[A-Za-z0-9_.]+/[A-Za-z0-9_]+", "orange"),
            RegexColorRule(r"\bmethod=/[^\s]+", "orange"),
            RegexColorRule(r"\bresponse=\{.*", "orange"),
            RegexColorRule(r"\berr=.*", "yellow"),
            RegexColorRule(r"(?<=\bgrpc=)OK\b", "orange"),
            RegexColorRule(r"(?<=\bstatus=)SERVING\b", "orange"),
            RegexColorRule(r"(?<=\bresult=)ok\b", "orange"),
            RegexColorRule(r"(?<=\bgrpc=)[A-Z_]+\b", "yellow"),
            RegexColorRule(r"(?<=\bstatus=)[A-Z_]+\b", "yellow"),
            RegexColorRule(r"(?<=\bresult=)unsupported\b", "yellow"),
        ),
    )


def _render_colored_grpc_line(console: Console, line: str) -> bool:
    if not line.startswith(_GRPC_TAG):
        return False

    if render_colored_marker_line(
        console,
        line,
        tag=_GRPC_TAG,
        include_auth_required=False,
        extra_spans=lambda _marker, payload: _grpc_marker_color_spans(payload),
    ):
        return True

    if "\t" in line:
        _left, right = line.rsplit("\t", 1)
        if re.search(r"^\s*(service=|file=|/|method=|response=|err=)|\b(status=SERVING|grpc=OK)\b", right):
            return render_tagged_detail_line(console, line, tag=_GRPC_TAG, spans=_grpc_detail_color_spans(right))

    return False


def _call_audit_grpc_host_with_thread_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    token: str | None,
    username: str | None,
    password: str | None,
    defcreds: bool,
    preferred_scheme: str | None,
    debug: bool,
    run_deep_checks: bool,
    schema_descriptor_bytes: list[bytes] | None = None,
    invoke_path: str | None = None,
    invoke_request_json: dict[str, Any] | None = None,
    metadata: list[tuple[str, str]] | None = None,
    debug_emit: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    with _thread_debug_context(debug_emit):
        return _call_audit_grpc_host_with_stage_debug(
            host,
            port,
            timeout,
            retries,
            token=token,
            username=username,
            password=password,
            defcreds=defcreds,
            preferred_scheme=preferred_scheme,
            debug=debug,
            run_deep_checks=run_deep_checks,
            schema_descriptor_bytes=schema_descriptor_bytes,
            invoke_path=invoke_path,
            invoke_request_json=invoke_request_json,
            metadata=metadata,
            debug_emit=debug_emit,
        )


def _thread_debug_context(debug_emit: Callable[[str], None] | None):
    class _Ctx:
        def __enter__(self_inner):
            _THREAD_LOCAL_DEBUG_EMIT.callback = debug_emit

        def __exit__(self_inner, exc_type, exc, tb):
            try:
                del _THREAD_LOCAL_DEBUG_EMIT.callback
            except AttributeError:
                pass

    return _Ctx()


def _call_audit_grpc_host_with_stage_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    token: str | None,
    username: str | None,
    password: str | None,
    defcreds: bool,
    preferred_scheme: str | None,
    debug: bool,
    run_deep_checks: bool,
    schema_descriptor_bytes: list[bytes] | None = None,
    invoke_path: str | None = None,
    invoke_request_json: dict[str, Any] | None = None,
    metadata: list[tuple[str, str]] | None = None,
    debug_emit: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    record = _audit_grpc_host(
        host,
        port,
        timeout,
        retries,
        token=token,
        username=username,
        password=password,
        defcreds=defcreds,
        preferred_scheme=preferred_scheme,
        run_deep_checks=run_deep_checks,
        schema_descriptor_bytes=schema_descriptor_bytes,
        invoke_path=invoke_path,
        invoke_request_json=invoke_request_json,
        metadata=metadata,
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
    attempts = max(1, retries + 1)
    attempts_used = int(result.get("stage_attempts_used") or 1)

    if attempts_used > 1 and status == "fail":
        _debug(
            f"retry_decision stage={_STAGE_DETECT_PROTOCOL} attempt=1/{attempts} "
            f"backoff={_retry_delay(0):.2f}s reason=error"
        )

    stage_entries = [
        {
            "stage_name": _STAGE_DETECT_PROTOCOL,
            "attempt": attempts_used,
            "duration_ms": int(result.get("stage_detect_ms") or 0),
            "result": "ok" if status not in {"fail", "not_grpc"} else ("skip" if status == "not_grpc" else "error"),
            "error": result.get("error") if status == "fail" else None,
        },
        {
            "stage_name": _STAGE_AUTH_INFERENCE,
            "attempt": attempts_used,
            "duration_ms": int(result.get("stage_auth_ms") or 0),
            "result": "ok"
            if status in {"open_no_auth", "valid_credentials", "auth_required", "invalid_credentials_anonymous"}
            else "skip",
            "error": None,
        },
        {
            "stage_name": _STAGE_ACCESS_CAPABILITIES,
            "attempt": 1,
            "duration_ms": int(result.get("stage_capabilities_ms") or 0),
            "result": "ok" if run_deep_checks and status in {"open_no_auth", "valid_credentials"} else "skip",
            "error": None,
        },
        {
            "stage_name": _STAGE_DATA,
            "attempt": 1,
            "duration_ms": int(result.get("stage_data_ms") or 0),
            "result": "ok" if run_deep_checks and status in {"open_no_auth", "valid_credentials"} else "skip",
            "error": None,
        },
    ]

    for stage_entry in stage_entries:
        _debug(
            f"stage_trace stage_name={stage_entry['stage_name']} attempt={stage_entry['attempt']} "
            f"duration_ms={stage_entry['duration_ms']} result={stage_entry['result']} "
            f"error={stage_entry['error'] or '-'}"
        )

    stage_failed_at: str | None = None
    for stage_entry in stage_entries:
        if str(stage_entry.get("result") or "") == "error":
            stage_failed_at = str(stage_entry.get("stage_name") or "")
            break

    stage_durations_ms = {str(item["stage_name"]): int(item["duration_ms"]) for item in stage_entries}
    stage_attempts = {str(item["stage_name"]): int(item["attempt"]) for item in stage_entries}

    total_ms = int((time.monotonic() - started) * 1000)
    _debug(
        f"stage_timing_summary status={status} attempts={attempts_used}/{attempts} "
        f"detect_ms={stage_durations_ms.get(_STAGE_DETECT_PROTOCOL, 0)} "
        f"auth_ms={stage_durations_ms.get(_STAGE_AUTH_INFERENCE, 0)} "
        f"capabilities_ms={stage_durations_ms.get(_STAGE_ACCESS_CAPABILITIES, 0)} "
        f"data_ms={stage_durations_ms.get(_STAGE_DATA, 0)} total_ms={total_ms}"
    )

    result["stages"] = stage_entries
    result["stage_failed_at"] = stage_failed_at
    result["stage_durations_ms"] = stage_durations_ms
    result["stage_attempts"] = stage_attempts
    result["debug_events"] = debug_events
    result["debug_events_streamed"] = bool(debug and debug_emit is not None)
    result["elapsed_ms"] = total_ms
    result["detect_confidence"] = "high" if bool(result.get("is_grpc")) else "low"
    result["transport_mode"] = result.get("transport_mode")
    result["health_supported"] = result.get("health_supported")
    result["reflection_enabled"] = result.get("reflection_enabled")
    return result


def _merge_stage2_record(detect_record: dict[str, Any], deep_record: dict[str, Any]) -> dict[str, Any]:
    return merge_stage_records(detect_record, deep_record)


# Typed runner boundary -----------------------------------------------------


def record_from_mapping(payload: dict[str, Any]) -> AuditRecord:
    """Convert module protocol payloads to the typed runtime model."""

    return AuditRecord.from_mapping(payload, module="grpc", service="grpc")


def _credential_is_anonymous(ctx: AuditHookContext) -> bool:
    return ctx.credential.username is None and ctx.credential.password is None and ctx.credential.token is None


def _run_host_stage(ctx: AuditHookContext, *, run_deep_checks: bool) -> AuditRecord:
    return _invoke_module_host_stage(
        sys.modules[__name__],
        module="grpc",
        ctx=ctx,
        run_deep_checks=run_deep_checks,
    )


def detect(ctx: AuditHookContext) -> AuditRecord:
    return _run_host_stage(ctx, run_deep_checks=False)


def auth(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
    if _credential_is_anonymous(ctx) and not bool(getattr(ctx.args, "defcreds", False)):
        return record
    return _run_host_stage(ctx, run_deep_checks=False)


def capabilities(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
    _ = ctx
    return record


def data(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
    _ = record
    return _run_host_stage(ctx, run_deep_checks=True)
