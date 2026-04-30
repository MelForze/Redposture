"""gRPC audit stage."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from google.protobuf import descriptor_pb2, descriptor_pool, json_format, message_factory
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded, StreamReset, TrailersReceived

from .console import Console
from .logger import AttemptLogger
from .progress import ProgressBar
from .proto import grpc_health_pb2, grpc_reflection_pb2
from .utils import (
    build_scan_execution_groups,
    collect_scan_ports,
    collect_scan_target_specs,
    parse_username_password_credential_file,
    utc_now_iso,
)

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


class _GrpcCallResult(dict):
    """Typed map wrapper for gRPC call results."""


class _ReflectionListResult(dict):
    """Typed map wrapper for reflection list result."""


class _ReflectionDescriptorResult(dict):
    """Typed map wrapper for reflection descriptor result."""


class _HealthResult(dict):
    """Typed map wrapper for health result."""


class _InvokeResult(dict):
    """Typed map wrapper for invoke result."""


class _GrpcWebCallResult(dict):
    """Typed map wrapper for gRPC-Web call results."""


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


def _is_retryable_stage_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    return text.startswith(_CONNECTION_TIMEOUT_PREFIX) or text.startswith(_CONNECTION_REFUSED_PREFIX)


def _is_suppressed_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail"


def _grpc_status_name(code: int | None) -> str:
    names = {
        0: "OK",
        1: "CANCELLED",
        2: "UNKNOWN",
        3: "INVALID_ARGUMENT",
        4: "DEADLINE_EXCEEDED",
        5: "NOT_FOUND",
        6: "ALREADY_EXISTS",
        7: "PERMISSION_DENIED",
        8: "RESOURCE_EXHAUSTED",
        9: "FAILED_PRECONDITION",
        10: "ABORTED",
        11: "OUT_OF_RANGE",
        12: "UNIMPLEMENTED",
        13: "INTERNAL",
        14: "UNAVAILABLE",
        15: "DATA_LOSS",
        16: "UNAUTHENTICATED",
    }
    if code is None:
        return "-"
    return names.get(int(code), f"CODE_{int(code)}")


def _encode_grpc_frame(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(4, "big") + payload


def _decode_grpc_frames(payload: bytes) -> tuple[list[bytes], str | None]:
    messages: list[bytes] = []
    idx = 0
    total = len(payload)
    while idx + 5 <= total:
        compressed_flag = payload[idx]
        size = int.from_bytes(payload[idx + 1 : idx + 5], "big")
        idx += 5
        if idx + size > total:
            return messages, "truncated gRPC frame"
        chunk = payload[idx : idx + size]
        idx += size
        if compressed_flag != 0:
            return messages, "compressed gRPC payload is not supported"
        messages.append(chunk)
    if idx != total:
        return messages, "trailing bytes after gRPC frames"
    return messages, None


def _build_basic_auth_header(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode("utf-8", errors="replace")
    token = base64.b64encode(raw).decode("ascii")
    return f"Basic {token}"


def _build_auth_header(*, token: str | None, username: str | None, password: str | None) -> str | None:
    if token:
        return f"Bearer {token}"
    if username is not None and password is not None:
        return _build_basic_auth_header(username, password)
    return None


def _grpc_health_payload(service_name: str = "") -> bytes:
    request = grpc_health_pb2.HealthCheckRequest(service=service_name)
    return request.SerializeToString()


def _grpc_reflection_list_payload() -> bytes:
    request = grpc_reflection_pb2.ServerReflectionRequest(host="", list_services="*")
    return request.SerializeToString()


def _grpc_reflection_symbol_payload(symbol: str) -> bytes:
    request = grpc_reflection_pb2.ServerReflectionRequest(host="", file_containing_symbol=symbol)
    return request.SerializeToString()


def _parse_health_message(message_bytes: bytes) -> str | None:
    if not message_bytes:
        return None
    try:
        response = grpc_health_pb2.HealthCheckResponse()
        response.ParseFromString(message_bytes)
    except Exception:
        return None
    enum_desc = grpc_health_pb2.HealthCheckResponse.ServingStatus
    try:
        return enum_desc.Name(int(response.status))
    except Exception:
        return str(int(response.status))


def _metadata_value(headers: dict[str, str], trailers: dict[str, str], key: str) -> str | None:
    lower_key = key.lower()
    value = trailers.get(lower_key)
    if value is not None:
        return value
    return headers.get(lower_key)


def _http2_headers_to_map(raw_headers: list[tuple[bytes | str, bytes | str]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for k, v in raw_headers:
        key = k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k)
        val = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
        result[key.lower()] = val
    return result


def _open_grpc_socket(host: str, port: int, timeout: float, *, use_tls: bool) -> socket.socket:
    base_sock = socket.create_connection((host, port), timeout=timeout)
    base_sock.settimeout(timeout)
    if not use_tls:
        return base_sock

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    wrapped = context.wrap_socket(base_sock, server_hostname=host)
    wrapped.settimeout(timeout)
    negotiated = wrapped.selected_alpn_protocol()
    if negotiated and negotiated.lower() != "h2":
        raise OSError(f"tls alpn negotiation failed (expected h2, got {negotiated})")
    return wrapped


def _grpc_call(
    host: str,
    port: int,
    *,
    path: str,
    payload: bytes,
    timeout: float,
    use_tls: bool,
    authorization: str | None,
    metadata: list[tuple[str, str]] | None = None,
) -> _GrpcCallResult:
    started = time.monotonic()
    result: _GrpcCallResult = _GrpcCallResult(
        {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "path": path,
            "use_tls": bool(use_tls),
            "http_status": None,
            "response_headers": {},
            "response_trailers": {},
            "grpc_status": None,
            "grpc_message": None,
            "messages": [],
            "is_grpc": False,
            "transport_ok": False,
            "error": None,
            "elapsed_ms": None,
        }
    )

    sock: socket.socket | None = None
    try:
        sock = _open_grpc_socket(host, port, timeout, use_tls=use_tls)
        result["transport_ok"] = True
        conn = H2Connection()
        conn.initiate_connection()
        pending = conn.data_to_send()
        if pending:
            sock.sendall(pending)

        stream_id = conn.get_next_available_stream_id()
        headers: list[tuple[str, str]] = [
            (":method", "POST"),
            (":scheme", "https" if use_tls else "http"),
            (":authority", f"{host}:{port}"),
            (":path", path),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
            ("user-agent", "RedPosture/1.0"),
        ]
        for key, value in metadata or []:
            headers.append((str(key).lower(), str(value)))
        if authorization:
            headers.append(("authorization", authorization))

        conn.send_headers(stream_id, headers, end_stream=False)
        conn.send_data(stream_id, _encode_grpc_frame(payload), end_stream=True)
        pending = conn.data_to_send()
        if pending:
            sock.sendall(pending)

        response_headers: dict[str, str] = {}
        response_trailers: dict[str, str] = {}
        body = bytearray()
        stream_closed = False

        while not stream_closed:
            chunk = sock.recv(64 * 1024)
            if not chunk:
                break
            events = conn.receive_data(chunk)
            for event in events:
                if isinstance(event, ResponseReceived):
                    response_headers.update(_http2_headers_to_map(list(event.headers)))
                elif isinstance(event, TrailersReceived):
                    response_trailers.update(_http2_headers_to_map(list(event.headers)))
                elif isinstance(event, DataReceived):
                    body.extend(event.data)
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, StreamEnded):
                    stream_closed = True
                elif isinstance(event, StreamReset):
                    result["error"] = f"stream reset by peer (code={int(event.error_code)})"
                    stream_closed = True

            pending = conn.data_to_send()
            if pending:
                sock.sendall(pending)

        result["response_headers"] = response_headers
        result["response_trailers"] = response_trailers

        status_raw = response_headers.get(":status")
        if status_raw is not None:
            try:
                result["http_status"] = int(status_raw)
            except ValueError:
                result["http_status"] = None

        grpc_status_raw = _metadata_value(response_headers, response_trailers, "grpc-status")
        if grpc_status_raw is not None:
            try:
                result["grpc_status"] = int(str(grpc_status_raw).strip())
            except ValueError:
                result["grpc_status"] = None

        grpc_message_raw = _metadata_value(response_headers, response_trailers, "grpc-message")
        if grpc_message_raw is not None:
            result["grpc_message"] = str(grpc_message_raw)

        messages, frame_error = _decode_grpc_frames(bytes(body))
        result["messages"] = messages

        content_type = str(response_headers.get("content-type") or "")
        result["is_grpc"] = (
            ("application/grpc" in content_type.lower())
            or (result["grpc_status"] is not None)
            or (len(messages) > 0 and result.get("http_status") == 200)
        )

        if frame_error and result.get("error") is None:
            result["error"] = frame_error

        if not result["is_grpc"] and result.get("error") is None and result.get("http_status") is None:
            result["error"] = "not a gRPC endpoint"

    except (OSError, TimeoutError, ValueError, ssl.SSLError) as exc:
        result["transport_ok"] = False
        result["error"] = _friendly_error_from_exception(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        result["elapsed_ms"] = int((time.monotonic() - started) * 1000)

    return result


def _open_http_socket(host: str, port: int, timeout: float, *, use_tls: bool) -> socket.socket:
    base_sock = socket.create_connection((host, port), timeout=timeout)
    base_sock.settimeout(timeout)
    if not use_tls:
        return base_sock
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    wrapped = context.wrap_socket(base_sock, server_hostname=host)
    wrapped.settimeout(timeout)
    return wrapped


def _parse_http1_response(raw: bytes) -> tuple[int | None, dict[str, str], bytes, str | None]:
    header_blob, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        return None, {}, raw, "truncated HTTP response"
    header_lines = header_blob.decode("iso-8859-1", errors="replace").split("\r\n")
    status: int | None = None
    if header_lines:
        parts = header_lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    headers: dict[str, str] = {}
    for line in header_lines[1:]:
        key, colon, value = line.partition(":")
        if colon:
            headers[key.strip().lower()] = value.strip()
    return status, headers, body, None


def _decode_grpc_web_frames(payload: bytes) -> tuple[list[bytes], dict[str, str], str | None]:
    messages: list[bytes] = []
    trailers: dict[str, str] = {}
    idx = 0
    total = len(payload)
    while idx + 5 <= total:
        frame_type = payload[idx]
        size = int.from_bytes(payload[idx + 1 : idx + 5], "big")
        idx += 5
        if idx + size > total:
            return messages, trailers, "truncated gRPC-Web frame"
        chunk = payload[idx : idx + size]
        idx += size
        if frame_type == 0:
            messages.append(chunk)
        elif frame_type & 0x80:
            trailer_text = chunk.decode("utf-8", errors="replace")
            for line in re.split(r"\r?\n", trailer_text):
                key, colon, value = line.partition(":")
                if colon:
                    trailers[key.strip().lower()] = value.strip()
        else:
            return messages, trailers, f"unsupported gRPC-Web frame type {frame_type}"
    if idx != total:
        return messages, trailers, "trailing bytes after gRPC-Web frames"
    return messages, trailers, None


def _grpc_web_call(
    host: str,
    port: int,
    *,
    path: str,
    payload: bytes,
    timeout: float,
    use_tls: bool,
    authorization: str | None,
    metadata: list[tuple[str, str]] | None = None,
) -> _GrpcWebCallResult:
    started = time.monotonic()
    result: _GrpcWebCallResult = _GrpcWebCallResult(
        {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "path": path,
            "use_tls": bool(use_tls),
            "http_status": None,
            "response_headers": {},
            "response_trailers": {},
            "grpc_status": None,
            "grpc_message": None,
            "messages": [],
            "is_grpc": False,
            "is_grpc_web": False,
            "transport_ok": False,
            "error": None,
            "elapsed_ms": None,
        }
    )
    sock: socket.socket | None = None
    try:
        sock = _open_http_socket(host, port, timeout, use_tls=use_tls)
        result["transport_ok"] = True
        body = _encode_grpc_frame(payload)
        header_lines = [
            f"POST {path} HTTP/1.1",
            f"Host: {host}:{port}",
            "User-Agent: RedPosture/1.0",
            "Content-Type: application/grpc-web+proto",
            "Accept: application/grpc-web+proto",
            "X-Grpc-Web: 1",
            "Connection: close",
            f"Content-Length: {len(body)}",
        ]
        for key, value in metadata or []:
            header_lines.append(f"{str(key)}: {str(value)}")
        if authorization:
            header_lines.append(f"Authorization: {authorization}")
        request = ("\r\n".join(header_lines) + "\r\n\r\n").encode("ascii", errors="replace") + body
        sock.sendall(request)
        response = bytearray()
        while True:
            chunk = sock.recv(64 * 1024)
            if not chunk:
                break
            response.extend(chunk)

        http_status, response_headers, response_body, parse_error = _parse_http1_response(bytes(response))
        result["http_status"] = http_status
        result["response_headers"] = response_headers
        content_type = str(response_headers.get("content-type") or "")
        messages, trailers, frame_error = _decode_grpc_web_frames(response_body)
        result["messages"] = messages
        result["response_trailers"] = trailers
        result["is_grpc_web"] = "application/grpc-web" in content_type.lower() or "grpc-status" in trailers
        result["is_grpc"] = bool(result["is_grpc_web"])

        grpc_status_raw = trailers.get("grpc-status") or response_headers.get("grpc-status")
        if grpc_status_raw is not None:
            try:
                result["grpc_status"] = int(str(grpc_status_raw).strip())
            except ValueError:
                result["grpc_status"] = None
        grpc_message = trailers.get("grpc-message") or response_headers.get("grpc-message")
        if grpc_message is not None:
            result["grpc_message"] = grpc_message
        if parse_error and result.get("error") is None:
            result["error"] = parse_error
        if frame_error and result.get("error") is None:
            result["error"] = frame_error
        if not result["is_grpc_web"] and result.get("error") is None:
            result["error"] = "not a gRPC-Web endpoint"
    except (OSError, TimeoutError, ValueError, ssl.SSLError) as exc:
        result["transport_ok"] = False
        result["error"] = _friendly_error_from_exception(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return result


def _health_check_call(
    host: str,
    port: int,
    *,
    timeout: float,
    use_tls: bool,
    authorization: str | None,
    service_name: str = "",
) -> _HealthResult:
    call = _grpc_call(
        host,
        port,
        path="/grpc.health.v1.Health/Check",
        payload=_grpc_health_payload(service_name),
        timeout=timeout,
        use_tls=use_tls,
        authorization=authorization,
    )

    grpc_status = call.get("grpc_status")
    messages = call.get("messages") or []
    serving_status = _parse_health_message(messages[0]) if isinstance(messages, list) and messages else None
    health_supported: bool | None
    if grpc_status == _GRPC_UNIMPLEMENTED:
        health_supported = False
    elif grpc_status in _GRPC_AUTH_CODES:
        health_supported = None
    elif call.get("is_grpc"):
        health_supported = True
    else:
        health_supported = None

    return _HealthResult(
        {
            "call": call,
            "grpc_status": grpc_status,
            "grpc_status_name": _grpc_status_name(grpc_status),
            "serving_status": serving_status,
            "health_supported": health_supported,
            "error": call.get("error"),
            "service": service_name,
        }
    )


def _grpc_web_health_check_call(
    host: str,
    port: int,
    *,
    timeout: float,
    use_tls: bool,
    authorization: str | None,
    service_name: str = "",
) -> _HealthResult:
    call = _grpc_web_call(
        host,
        port,
        path="/grpc.health.v1.Health/Check",
        payload=_grpc_health_payload(service_name),
        timeout=timeout,
        use_tls=use_tls,
        authorization=authorization,
    )
    grpc_status = call.get("grpc_status")
    messages = call.get("messages") or []
    serving_status = _parse_health_message(messages[0]) if isinstance(messages, list) and messages else None
    if grpc_status == _GRPC_UNIMPLEMENTED:
        health_supported: bool | None = False
    elif grpc_status in _GRPC_AUTH_CODES:
        health_supported = None
    elif call.get("is_grpc"):
        health_supported = True
    else:
        health_supported = None
    return _HealthResult(
        {
            "call": call,
            "grpc_status": grpc_status,
            "grpc_status_name": _grpc_status_name(grpc_status),
            "serving_status": serving_status,
            "health_supported": health_supported,
            "error": call.get("error"),
            "service": service_name,
        }
    )


def _reflection_list_services_call(
    host: str,
    port: int,
    *,
    timeout: float,
    use_tls: bool,
    authorization: str | None,
) -> _ReflectionListResult:
    call = _grpc_call(
        host,
        port,
        path="/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        payload=_grpc_reflection_list_payload(),
        timeout=timeout,
        use_tls=use_tls,
        authorization=authorization,
    )

    services: list[str] = []
    reflection_enabled: bool | None = None
    error_message: str | None = None

    grpc_status = call.get("grpc_status")
    if grpc_status == _GRPC_OK:
        reflection_enabled = True
    elif grpc_status == _GRPC_UNIMPLEMENTED:
        reflection_enabled = False
    elif grpc_status in _GRPC_AUTH_CODES:
        reflection_enabled = None

    messages = call.get("messages") or []
    if isinstance(messages, list):
        for msg_bytes in messages:
            if not isinstance(msg_bytes, (bytes, bytearray)):
                continue
            try:
                response = grpc_reflection_pb2.ServerReflectionResponse()
                response.ParseFromString(bytes(msg_bytes))
            except Exception:
                continue
            if response.HasField("list_services_response"):
                services.extend(item.name for item in response.list_services_response.service if item.name)
            if response.HasField("error_response") and not error_message:
                error_message = f"{response.error_response.error_code}:{response.error_response.error_message}"

    dedup_services = sorted(dict.fromkeys(str(item).strip() for item in services if str(item).strip()))

    return _ReflectionListResult(
        {
            "call": call,
            "services": dedup_services,
            "reflection_enabled": reflection_enabled,
            "grpc_status": grpc_status,
            "grpc_status_name": _grpc_status_name(grpc_status),
            "error": error_message or call.get("error"),
        }
    )


def _reflection_file_descriptors_call(
    host: str,
    port: int,
    *,
    timeout: float,
    use_tls: bool,
    authorization: str | None,
    symbol: str,
) -> _ReflectionDescriptorResult:
    call = _grpc_call(
        host,
        port,
        path="/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        payload=_grpc_reflection_symbol_payload(symbol),
        timeout=timeout,
        use_tls=use_tls,
        authorization=authorization,
    )

    descriptor_bytes: list[bytes] = []
    error_message: str | None = None

    messages = call.get("messages") or []
    if isinstance(messages, list):
        for msg_bytes in messages:
            if not isinstance(msg_bytes, (bytes, bytearray)):
                continue
            try:
                response = grpc_reflection_pb2.ServerReflectionResponse()
                response.ParseFromString(bytes(msg_bytes))
            except Exception:
                continue
            if response.HasField("file_descriptor_response"):
                descriptor_bytes.extend(
                    bytes(blob)
                    for blob in response.file_descriptor_response.file_descriptor_proto
                    if isinstance(blob, (bytes, bytearray)) and blob
                )
            if response.HasField("error_response") and not error_message:
                error_message = f"{response.error_response.error_code}:{response.error_response.error_message}"

    return _ReflectionDescriptorResult(
        {
            "call": call,
            "symbol": symbol,
            "descriptor_bytes": descriptor_bytes,
            "grpc_status": call.get("grpc_status"),
            "grpc_status_name": _grpc_status_name(call.get("grpc_status")),
            "error": error_message or call.get("error"),
        }
    )


def _extract_descriptors(descriptor_bytes: list[bytes]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    methods: list[dict[str, Any]] = []
    descriptors: list[dict[str, Any]] = []

    seen_descriptors: set[str] = set()
    for blob in descriptor_bytes:
        if not blob:
            continue
        fd = descriptor_pb2.FileDescriptorProto()
        try:
            fd.ParseFromString(blob)
        except Exception:
            continue

        file_name = str(fd.name or "-")
        if file_name in seen_descriptors:
            continue
        seen_descriptors.add(file_name)

        package_name = str(fd.package or "").strip()
        file_entry: dict[str, Any] = {
            "file": file_name,
            "package": package_name or None,
            "services": [],
        }

        for service in fd.service:
            service_name = str(service.name or "").strip()
            if not service_name:
                continue
            full_service = f"{package_name}.{service_name}" if package_name else service_name
            service_entry = {
                "service": full_service,
                "methods": [],
            }
            for method in service.method:
                method_name = str(method.name or "").strip()
                if not method_name:
                    continue
                method_entry = {
                    "service": full_service,
                    "method": method_name,
                    "full_method": f"/{full_service}/{method_name}",
                    "input_type": str(method.input_type or "").lstrip("."),
                    "output_type": str(method.output_type or "").lstrip("."),
                    "client_streaming": bool(method.client_streaming),
                    "server_streaming": bool(method.server_streaming),
                    "file": file_name,
                }
                methods.append(method_entry)
                service_entry["methods"].append(method_entry)

            file_entry["services"].append(service_entry)

        descriptors.append(file_entry)

    dedup_methods: list[dict[str, Any]] = []
    seen_method_keys: set[tuple[str, str]] = set()
    for method in methods:
        key = (str(method.get("service") or ""), str(method.get("method") or ""))
        if key in seen_method_keys:
            continue
        seen_method_keys.add(key)
        dedup_methods.append(method)

    return dedup_methods, descriptors


def _dedup_descriptor_bytes(descriptor_bytes: list[bytes]) -> list[bytes]:
    result: list[bytes] = []
    seen: set[str] = set()
    for blob in descriptor_bytes:
        if not blob:
            continue
        fd = descriptor_pb2.FileDescriptorProto()
        try:
            fd.ParseFromString(blob)
        except Exception:
            continue
        key = str(fd.name or blob.hex())
        if key in seen:
            continue
        seen.add(key)
        result.append(fd.SerializeToString())
    return result


def _descriptor_bytes_to_pool(descriptor_bytes: list[bytes]) -> tuple[descriptor_pool.DescriptorPool, list[str]]:
    pool = descriptor_pool.DescriptorPool()
    pending: list[descriptor_pb2.FileDescriptorProto] = []
    errors: list[str] = []
    seen: set[str] = set()
    for blob in _dedup_descriptor_bytes(descriptor_bytes):
        fd = descriptor_pb2.FileDescriptorProto()
        try:
            fd.ParseFromString(blob)
        except Exception as exc:
            errors.append(f"invalid descriptor: {exc}")
            continue
        if fd.name in seen:
            continue
        seen.add(str(fd.name))
        pending.append(fd)

    while pending:
        next_pending: list[descriptor_pb2.FileDescriptorProto] = []
        progressed = False
        for fd in pending:
            try:
                pool.Add(fd)
                progressed = True
            except Exception as exc:
                error_text = str(exc).lower()
                if any(
                    fragment in error_text
                    for fragment in (
                        "duplicate file name",
                        "duplicate symbol",
                        "already defined",
                    )
                ):
                    progressed = True
                    continue
                next_pending.append(fd)
        if not progressed:
            for fd in next_pending:
                errors.append(f"failed to add descriptor {fd.name or '-'}")
            break
        pending = next_pending
    return pool, errors


def _descriptor_bytes_from_protoset(path: str) -> list[bytes]:
    payload = Path(path).read_bytes()
    descriptor_set = descriptor_pb2.FileDescriptorSet()
    descriptor_set.ParseFromString(payload)
    return [fd.SerializeToString() for fd in descriptor_set.file]


def _compile_proto_files(proto_files: list[str], proto_paths: list[str]) -> list[bytes]:
    all_proto_paths = [str(Path(item).resolve()) for item in proto_paths if str(item).strip()]
    resolved_proto_files = [str(Path(item).resolve()) for item in proto_files]
    for proto_file in resolved_proto_files:
        parent = str(Path(proto_file).parent)
        if parent not in all_proto_paths:
            all_proto_paths.append(parent)

    with tempfile.NamedTemporaryFile(suffix=".protoset", delete=False) as tmp:
        out_path = tmp.name
    try:
        argv = ["grpc_tools.protoc"]
        for include_path in all_proto_paths or [os.getcwd()]:
            argv.append(f"-I{include_path}")
        argv.extend(
            [
                f"--descriptor_set_out={out_path}",
                "--include_imports",
                "--include_source_info",
            ]
        )
        argv.extend(resolved_proto_files)
        try:
            from grpc_tools import protoc  # type: ignore[import-not-found]

            rc = int(protoc.main(argv))
            if rc != 0:
                raise RuntimeError(f"protoc failed with exit code {rc}")
        except ImportError:
            cli_argv = ["protoc", *argv[1:]]
            try:
                completed = subprocess.run(cli_argv, capture_output=True, text=True, check=False)
            except FileNotFoundError as exc:
                raise RuntimeError(
                    "grpcio-tools or protoc is required for --proto; install package dependency grpcio-tools"
                ) from exc
            if completed.returncode != 0:
                err = (completed.stderr or completed.stdout or "").strip()
                raise RuntimeError(f"protoc failed with exit code {completed.returncode}: {err}") from None
        return _descriptor_bytes_from_protoset(out_path)
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _load_explicit_descriptor_bytes(
    proto_files: list[str] | None,
    proto_paths: list[str] | None,
    protoset_files: list[str] | None,
) -> list[bytes]:
    descriptor_bytes: list[bytes] = []
    for protoset in protoset_files or []:
        descriptor_bytes.extend(_descriptor_bytes_from_protoset(protoset))
    if proto_files:
        descriptor_bytes.extend(_compile_proto_files(proto_files, proto_paths or []))
    return _dedup_descriptor_bytes(descriptor_bytes)


def _parse_json_payload_source(value: str | None) -> dict[str, Any]:
    if value is None or str(value).strip() == "":
        return {}
    text = str(value)
    if text.startswith("@"):
        text = Path(text[1:]).read_text(encoding="utf-8")
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("--data must decode to a JSON object")
    return payload


def _parse_metadata_items(values: list[str] | None) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for raw in values or []:
        key, sep, value = str(raw).partition("=")
        key = key.strip().lower()
        if not sep or not key:
            raise ValueError("--meta must use key=value")
        if key.startswith(":"):
            raise ValueError("--meta cannot set HTTP/2 pseudo headers")
        if key in {"content-type", "te", "user-agent", "authorization"}:
            raise ValueError(f"--meta cannot override reserved header {key}")
        result.append((key, value))
    return result


def _split_grpc_method_path(path: str) -> tuple[str, str]:
    text = str(path or "").strip()
    if not text.startswith("/") or text.count("/") != 2:
        raise ValueError("--invoke must use /package.Service/Method")
    _, service_name, method_name = text.split("/")
    if not service_name or not method_name:
        raise ValueError("--invoke must use /package.Service/Method")
    return service_name, method_name


def _find_method_descriptor(pool: descriptor_pool.DescriptorPool, path: str):
    service_name, method_name = _split_grpc_method_path(path)
    service_desc = pool.FindServiceByName(service_name)
    method_desc = service_desc.FindMethodByName(method_name)
    if method_desc is None:
        raise KeyError(f"method not found: {path}")
    return method_desc


def _invoke_unary_method(
    host: str,
    port: int,
    *,
    timeout: float,
    use_tls: bool,
    protocol_flavor: str,
    authorization: str | None,
    metadata: list[tuple[str, str]],
    descriptor_bytes: list[bytes],
    invoke_path: str,
    request_json: dict[str, Any],
) -> _InvokeResult:
    started = time.monotonic()
    result: _InvokeResult = _InvokeResult(
        {
            "path": invoke_path,
            "status": "error",
            "grpc_status": None,
            "grpc_status_name": "-",
            "grpc_message": None,
            "request": request_json,
            "response": None,
            "error": None,
            "elapsed_ms": None,
        }
    )
    try:
        pool, pool_errors = _descriptor_bytes_to_pool(descriptor_bytes)
        if pool_errors:
            result["error"] = "; ".join(pool_errors)
            return result
        method_desc = _find_method_descriptor(pool, invoke_path)
        result["input_type"] = method_desc.input_type.full_name
        result["output_type"] = method_desc.output_type.full_name
        result["client_streaming"] = bool(method_desc.client_streaming)
        result["server_streaming"] = bool(method_desc.server_streaming)
        if bool(method_desc.client_streaming) or bool(method_desc.server_streaming):
            result["status"] = "unsupported"
            result["error"] = "unsupported streaming method"
            return result

        input_cls = message_factory.GetMessageClass(method_desc.input_type)
        request_msg = input_cls()
        json_format.ParseDict(request_json, request_msg)
        payload = request_msg.SerializeToString()
        if protocol_flavor == "grpc-web":
            call = _grpc_web_call(
                host,
                port,
                path=invoke_path,
                payload=payload,
                timeout=timeout,
                use_tls=use_tls,
                authorization=authorization,
                metadata=metadata,
            )
        else:
            call = _grpc_call(
                host,
                port,
                path=invoke_path,
                payload=payload,
                timeout=timeout,
                use_tls=use_tls,
                authorization=authorization,
                metadata=metadata,
            )
        grpc_status = call.get("grpc_status")
        result["grpc_status"] = grpc_status
        result["grpc_status_name"] = _grpc_status_name(grpc_status)
        result["grpc_message"] = call.get("grpc_message")
        result["error"] = call.get("error")
        messages = call.get("messages") or []
        if grpc_status == _GRPC_OK and isinstance(messages, list) and messages:
            output_cls = message_factory.GetMessageClass(method_desc.output_type)
            response_msg = output_cls()
            response_msg.ParseFromString(bytes(messages[0]))
            result["response"] = json_format.MessageToDict(response_msg, preserving_proto_field_name=True)
            result["status"] = "ok"
        elif grpc_status == _GRPC_OK:
            result["response"] = {}
            result["status"] = "ok"
        else:
            result["status"] = "grpc_error"
            if result.get("error") is None:
                result["error"] = call.get("grpc_message") or _grpc_status_name(grpc_status)
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return result


def _json_schema_for_message(
    msg_desc: Any,
    components: dict[str, Any],
    visiting: set[str] | None = None,
) -> dict[str, Any]:
    visiting = visiting or set()
    full_name = str(msg_desc.full_name)
    component_name = full_name.replace(".", "_")
    if component_name in components:
        return {"$ref": f"#/components/schemas/{component_name}"}
    if full_name in visiting:
        return {"$ref": f"#/components/schemas/{component_name}"}
    visiting.add(full_name)
    schema: dict[str, Any] = {"type": "object", "properties": {}}
    components[component_name] = schema
    for field in msg_desc.fields:
        field_schema: dict[str, Any]
        if getattr(field, "message_type", None) is not None:
            field_schema = _json_schema_for_message(field.message_type, components, visiting)
        elif getattr(field, "enum_type", None) is not None:
            field_schema = {"type": "string", "enum": [str(v.name) for v in field.enum_type.values]}
        else:
            field_type = int(field.type)
            if field_type in {1, 2}:  # double, float
                field_schema = {"type": "number"}
            elif field_type in {3, 4, 5, 6, 13, 15, 16, 17, 18}:  # int/uint/fixed/sint
                field_schema = {"type": "integer"}
            elif field_type == 8:
                field_schema = {"type": "boolean"}
            elif field_type == 12:
                field_schema = {"type": "string", "format": "byte"}
            else:
                field_schema = {"type": "string"}
        if getattr(field, "is_repeated", False):
            field_schema = {"type": "array", "items": field_schema}
        schema["properties"][str(field.name)] = field_schema
    visiting.discard(full_name)
    return {"$ref": f"#/components/schemas/{component_name}"}


def _generate_openapi_document(descriptor_bytes: list[bytes]) -> dict[str, Any]:
    pool, errors = _descriptor_bytes_to_pool(descriptor_bytes)
    methods, _descriptors = _extract_descriptors(descriptor_bytes)
    components: dict[str, Any] = {}
    paths: dict[str, Any] = {}
    for method in methods:
        full_method = str(method.get("full_method") or "")
        if not full_method:
            continue
        try:
            method_desc = _find_method_descriptor(pool, full_method)
            request_schema = _json_schema_for_message(method_desc.input_type, components)
            response_schema = _json_schema_for_message(method_desc.output_type, components)
        except Exception:
            request_schema = {"type": "object"}
            response_schema = {"type": "object"}
        paths[full_method] = {
            "post": {
                "operationId": full_method.strip("/").replace("/", "_").replace(".", "_"),
                "summary": full_method,
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": request_schema}},
                },
                "responses": {
                    "200": {
                        "description": "gRPC response represented as JSON",
                        "content": {"application/json": {"schema": response_schema}},
                    }
                },
                "x-grpc-service": method.get("service"),
                "x-grpc-method": method.get("method"),
                "x-grpc-input-type": method.get("input_type"),
                "x-grpc-output-type": method.get("output_type"),
                "x-grpc-streaming": {
                    "client": bool(method.get("client_streaming")),
                    "server": bool(method.get("server_streaming")),
                },
            }
        }
    return {
        "openapi": "3.1.0",
        "info": {"title": "RedPosture gRPC export", "version": "1.0.0"},
        "paths": paths,
        "components": {"schemas": components},
        "x-redposture": {"descriptor_errors": errors},
    }


def _write_openapi_document(path: str, descriptor_bytes: list[bytes]) -> int:
    document = _generate_openapi_document(descriptor_bytes)
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return len(document.get("paths") or {})


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


def _render_colored_grpc_line(console: Console, line: str) -> bool:
    if not line.startswith(_GRPC_TAG):
        return False

    marker_color = {
        "[*]": "cyan",
        "[+]": "bright_green",
        "[-]": "red",
        "[!]": "red",
    }

    for marker in ("[!]", "[-]", "[+]", "[*]"):
        token = f" {marker} "
        if token not in line:
            continue

        left, right = line.split(token, 1)
        tag = _GRPC_TAG
        rest = left[len(tag) :] if left.startswith(tag) else left

        spans: list[tuple[int, int, str]] = []
        for fragment, color in (
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
        ):
            idx = right.find(fragment)
            if idx >= 0:
                spans.append((idx, idx + len(fragment), color))

        for pattern, color in (
            (r"\((services|methods|descriptors|checks):(\d+)\)", "orange"),
            (r"\b(\d+)\s+(Services|Methods|Descriptors|Health Checks)\b", "orange"),
            (r"\bservice=[^\s]+", "orange"),
            (r"\bfile=[^\s]+", "orange"),
            (r"\bmethod=/[^\s]+", "orange"),
            (r"(?<!\S)/[A-Za-z0-9_.]+/[A-Za-z0-9_]+", "orange"),
            (r"(?<=\bstatus=)SERVING\b", "orange"),
            (r"(?<=\bgrpc=)OK\b", "orange"),
            (r"(?<=\bresult=)ok\b", "orange"),
            (r"(?<=\bstatus=)[A-Z_]+\b", "yellow"),
            (r"(?<=\bgrpc=)[A-Z_]+\b", "yellow"),
            (r"(?<=\bresult=)unsupported\b", "yellow"),
            (r"\berr=[^\s].*", "yellow"),
            (r"\b(response=\{.*)", "orange"),
            (r"\bOpenAPI exported\b.*", "orange"),
        ):
            for match in re.finditer(pattern, right):
                number = match.group(match.lastindex) if match.lastindex else None
                if number is not None and str(number).isdigit() and int(number) == 0:
                    continue
                spans.append((match.start(), match.end(), color))

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

    if "\t" in line:
        left, right = line.rsplit("\t", 1)
        if re.search(r"^\s*(service=|file=|/|method=|response=|err=)|\b(status=SERVING|grpc=OK)\b", right):
            tag = _GRPC_TAG
            rest = left[len(tag) :] if left.startswith(tag) else left
            detail_spans: list[tuple[int, int, str]] = []
            for pattern, color in (
                (r"\bservice=[^\s]+", "orange"),
                (r"\bfile=[^\s]+", "orange"),
                (r"(?<!\S)/[A-Za-z0-9_.]+/[A-Za-z0-9_]+", "orange"),
                (r"\bmethod=/[^\s]+", "orange"),
                (r"\bresponse=\{.*", "orange"),
                (r"\berr=.*", "yellow"),
                (r"(?<=\bgrpc=)OK\b", "orange"),
                (r"(?<=\bstatus=)SERVING\b", "orange"),
                (r"(?<=\bresult=)ok\b", "orange"),
                (r"(?<=\bgrpc=)[A-Z_]+\b", "yellow"),
                (r"(?<=\bstatus=)[A-Z_]+\b", "yellow"),
                (r"(?<=\bresult=)unsupported\b", "yellow"),
            ):
                for match in re.finditer(pattern, right):
                    detail_spans.append((match.start(), match.end(), color))
            chunks: list[str] = []
            cursor = 0
            for start, end, color in sorted(detail_spans, key=lambda item: item[0]):
                if start < cursor:
                    continue
                if start > cursor:
                    chunks.append(console._paint(right[cursor:start], "white", sys.stdout))
                chunks.append(console._paint(right[start:end], color, sys.stdout))
                cursor = end
            if cursor < len(right):
                chunks.append(console._paint(right[cursor:], "white", sys.stdout))
            console.plain(
                f"{console._paint(tag, 'blue', sys.stdout)}"
                f"{console._paint(rest, 'white', sys.stdout)}\t"
                f"{''.join(chunks)}"
            )
            return True

    return False


def _emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
    if emit_line is not None:
        emit_line(line)


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
    merged = dict(detect_record)
    merged.update(deep_record)

    debug_events: list[str] = []
    for source in (detect_record.get("debug_events"), deep_record.get("debug_events")):
        if not isinstance(source, list):
            continue
        for item in source:
            if isinstance(item, str) and item.strip():
                debug_events.append(item)
    merged["debug_events"] = debug_events
    merged["debug_events_streamed"] = bool(detect_record.get("debug_events_streamed")) or bool(
        deep_record.get("debug_events_streamed")
    )

    stages: list[dict[str, Any]] = []
    for source in (detect_record.get("stages"), deep_record.get("stages")):
        if isinstance(source, list):
            for entry in source:
                if isinstance(entry, dict):
                    stages.append(dict(entry))
    merged["stages"] = stages

    stage_durations: dict[str, int] = {}
    for source in (detect_record.get("stage_durations_ms"), deep_record.get("stage_durations_ms")):
        if isinstance(source, dict):
            for key, value in source.items():
                stage_durations[str(key)] = int(value or 0)
    merged["stage_durations_ms"] = stage_durations

    stage_attempts: dict[str, int] = {}
    for source in (detect_record.get("stage_attempts"), deep_record.get("stage_attempts")):
        if isinstance(source, dict):
            for key, value in source.items():
                stage_attempts[str(key)] = int(value or 0)
    merged["stage_attempts"] = stage_attempts

    merged["stage_failed_at"] = deep_record.get("stage_failed_at") or detect_record.get("stage_failed_at")
    return merged


def audit_grpc_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
    *,
    token: str | None,
    username: str | None,
    password: str | None,
    defcreds: bool,
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
    suppress_timeout_status_lines: bool = False,
    suppress_connection_refused_status_lines: bool = False,
    preferred_scheme: str | None = None,
    debug_emit: Callable[[str], None] | None = None,
    show_progress: bool = True,
    schema_descriptor_bytes: list[bytes] | None = None,
    invoke_path: str | None = None,
    invoke_request_json: dict[str, Any] | None = None,
    metadata: list[tuple[str, str]] | None = None,
    record_sink: list[dict[str, Any]] | None = None,
) -> tuple[int, int, int, int, int, int]:
    total = 0
    open_no_auth = 0
    valid = 0
    auth_required = 0
    not_grpc = 0
    failed = 0

    out_fh: Any = None
    progress: ProgressBar | None = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, "a" if append_output else "w", encoding="utf-8")

    try:
        indexed_hosts = list(enumerate(hosts))
        detect_records: dict[int, dict[str, Any]] = {}
        deep_records: dict[int, dict[str, Any]] = {}
        progress = ProgressBar(_GRPC_TAG, len(indexed_hosts), enabled=show_progress, leave=True)

        if debug_emit is not None:
            debug_emit(f"pass=1 detect start total={len(indexed_hosts)}")

        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            pass1_future_map = {
                executor.submit(
                    _call_audit_grpc_host_with_thread_debug,
                    host,
                    port,
                    timeout,
                    retries,
                    token=token,
                    username=username,
                    password=password,
                    defcreds=defcreds,
                    preferred_scheme=preferred_scheme,
                    debug=bool(debug_emit),
                    run_deep_checks=False,
                    schema_descriptor_bytes=schema_descriptor_bytes,
                    invoke_path=invoke_path,
                    invoke_request_json=invoke_request_json,
                    metadata=metadata,
                    debug_emit=debug_emit,
                ): idx
                for idx, host in indexed_hosts
            }
            buffered_records: dict[int, dict[str, Any]] = {}
            next_emit_idx = 0
            for future in as_completed(pass1_future_map):
                record_idx = int(pass1_future_map[future])
                buffered_records[record_idx] = future.result()
                progress.advance()
                while next_emit_idx in buffered_records:
                    detect_record = buffered_records.pop(next_emit_idx)
                    detect_records[next_emit_idx] = detect_record
                    detect_status = str(detect_record.get("status") or "fail")
                    suppress_detect_line = (
                        suppress_timeout_status_lines and output_format == "txt" and detect_status == "fail"
                    )
                    if not suppress_detect_line:
                        _emit_line(out_fh, emit_line, _format_detect_record(detect_record, output_format))
                    next_emit_idx += 1

        deep_candidates: list[tuple[int, str]] = []
        detected_count = 0
        for idx, host in indexed_hosts:
            detect_record = detect_records[idx]
            detect_status = str(detect_record.get("status") or "fail")
            if not bool(detect_record.get("is_grpc")):
                if debug_emit is not None:
                    debug_emit(f"{host}:{port} stage2_gate=skip reason=not_grpc")
                continue
            detected_count += 1
            if detect_status in {"open_no_auth", "valid_credentials"}:
                deep_candidates.append((idx, host))
                if debug_emit is not None:
                    debug_emit(f"{host}:{port} stage2_gate=run reason=status={detect_status}")
            elif debug_emit is not None:
                debug_emit(f"{host}:{port} stage2_gate=skip reason=status={detect_status}")

        if debug_emit is not None:
            debug_emit(f"pass=1 detect complete grpc={detected_count} deep_candidates={len(deep_candidates)}")

        progress.set_total(len(indexed_hosts) + len(deep_candidates))
        if debug_emit is not None:
            debug_emit(f"pass=2 deep start total={len(deep_candidates)}")

        if deep_candidates:
            with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
                pass2_future_map = {
                    executor.submit(
                        _call_audit_grpc_host_with_thread_debug,
                        host,
                        port,
                        timeout,
                        retries,
                        token=token,
                        username=username,
                        password=password,
                        defcreds=defcreds,
                        preferred_scheme=preferred_scheme,
                        debug=bool(debug_emit),
                        run_deep_checks=True,
                        schema_descriptor_bytes=schema_descriptor_bytes,
                        invoke_path=invoke_path,
                        invoke_request_json=invoke_request_json,
                        metadata=metadata,
                        debug_emit=debug_emit,
                    ): idx
                    for idx, host in deep_candidates
                }
                for future in as_completed(pass2_future_map):
                    record_idx = int(pass2_future_map[future])
                    deep_records[record_idx] = future.result()
                    progress.advance()

        if debug_emit is not None:
            debug_emit(f"pass=2 deep complete processed={len(deep_records)}")

        final_records: dict[int, dict[str, Any]] = {}
        for idx in range(len(hosts)):
            detect_record = detect_records[idx]
            deep_record = deep_records.get(idx)
            if deep_record is None:
                final_records[idx] = detect_record
            else:
                final_records[idx] = _merge_stage2_record(detect_record, deep_record)

        for idx in range(len(hosts)):
            record = final_records[idx]
            total += 1

            status = str(record.get("status") or "fail")
            if status in {"open_no_auth", "invalid_credentials_anonymous"}:
                open_no_auth += 1
            elif status == "valid_credentials":
                valid += 1
            elif status == "auth_required":
                auth_required += 1
            elif status == "not_grpc":
                not_grpc += 1
            elif status == "fail":
                failed += 1

            if debug_emit is not None and not bool(record.get("debug_events_streamed")):
                for event in record.get("debug_events") or []:
                    if isinstance(event, str) and event.strip():
                        debug_emit(event)

            suppress_status_line = False
            if status == "auth_required":
                suppress_status_line = True
            elif status == "not_grpc":
                suppress_status_line = True
            elif suppress_timeout_status_lines and output_format == "txt" and status == "fail":
                suppress_status_line = True
            elif (
                suppress_connection_refused_status_lines
                and output_format == "txt"
                and status == "fail"
                and _is_connection_refused_fail_record(record)
            ):
                suppress_status_line = True

            if not suppress_status_line:
                _emit_line(out_fh, emit_line, _format_record(record, output_format))

            for detail in _format_detail_records(record, output_format):
                _emit_line(out_fh, emit_line, detail)

            if logger is not None:
                logger.log(
                    "grpc",
                    (str(record.get("host") or "-"), int(record.get("port") or port)),
                    phase="audit",
                    status=record.get("status"),
                    auth_required=record.get("auth_required"),
                    auth_valid=record.get("provided_credentials_ok"),
                    transport_mode=record.get("transport_mode"),
                    reflection_enabled=record.get("reflection_enabled"),
                    health_supported=record.get("health_supported"),
                    services=len(record.get("services") or []) if isinstance(record.get("services"), list) else 0,
                    methods=len(record.get("methods") or []) if isinstance(record.get("methods"), list) else 0,
                    error=record.get("error"),
                )
        if record_sink is not None:
            record_sink.extend(final_records[idx] for idx in range(len(hosts)))
    finally:
        if progress is not None:
            progress.close()
        if out_fh is not None:
            out_fh.close()

    return total, open_no_auth, valid, auth_required, not_grpc, failed


def run_grpc_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
        return 2

    token: str | None = getattr(args, "token", None)
    username: str | None = getattr(args, "username", None)
    password: str | None = getattr(args, "password", None)
    credential_file_entries = None
    if token and (username or password):
        console.warn("--token takes precedence; provided -u/-p are ignored")
        username = None
        password = None
    elif username is not None:
        try:
            credential_file_entries = parse_username_password_credential_file(username, password)
        except ValueError as exc:
            console.error(str(exc))
            return 2
        if credential_file_entries is None and bool(username) != bool(password):
            console.error("-u and -p must be set together")
            return 2
        if credential_file_entries is not None:
            username = credential_file_entries[0].username
            password = credential_file_entries[0].password
    elif bool(username) != bool(password):
        console.error("-u and -p must be set together")
        return 2
    credential_runs = (
        [(entry.username, entry.password) for entry in credential_file_entries]
        if credential_file_entries is not None
        else [(username, password)]
    )

    try:
        metadata = _parse_metadata_items(getattr(args, "meta", None))
        invoke_request_json = (
            _parse_json_payload_source(getattr(args, "data", None)) if getattr(args, "invoke", None) else None
        )
        explicit_descriptor_bytes = _load_explicit_descriptor_bytes(
            getattr(args, "proto", None),
            getattr(args, "proto_path", None),
            getattr(args, "protoset", None),
        )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        console.error(str(exc))
        return 2

    try:
        ports = collect_scan_ports(getattr(args, "ports", None))
    except ValueError as exc:
        console.error(f"failed to parse --ports: {exc}")
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
        console.error("grpc requires -t/--targets")
        return 2

    hosts = list(dict.fromkeys(spec.host for spec in target_specs))
    execution_groups = build_scan_execution_groups(target_specs, ports, include_scheme_in_key=True)

    stream_to_stdout = not bool(args.output)

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if _render_colored_grpc_line(console, line):
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

    if args.debug:
        mode_parts: list[str] = []
        if token:
            mode_parts.append("token")
        if credential_file_entries is not None:
            mode_parts.append(f"credfile={len(credential_file_entries)}")
        if username and password:
            mode_parts.append("basic")
        if args.defcreds:
            mode_parts.append("defcreds")
        mode = ",".join(mode_parts) if mode_parts else "anonymous"
        console.info(
            f"grpc audit started: hosts={len(hosts)} ports={len(execution_groups)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={mode} format={args.output_format}"
        )

    total = 0
    open_no_auth = 0
    valid = 0
    auth_required = 0
    not_grpc = 0
    failed = 0
    records: list[dict[str, Any]] = []

    outer_progress: ProgressBar | None = None
    use_single_global_progress = (
        stream_to_stdout and args.output_format == "txt" and (len(execution_groups) > 1 or len(credential_runs) > 1)
    )
    if use_single_global_progress:
        global_total = sum(len(group.hosts) for group in execution_groups) * len(credential_runs)
        outer_progress = ProgressBar(_GRPC_TAG, global_total, enabled=True, leave=True)

    try:
        for idx, group in enumerate(execution_groups):
            for cred_idx, (run_username, run_password) in enumerate(credential_runs):
                part_total, part_open, part_valid, part_auth, part_not_grpc, part_failed = audit_grpc_targets(
                    hosts=group.hosts,
                    port=group.port,
                    timeout=args.timeout,
                    retries=args.retries,
                    workers=args.workers,
                    token=token,
                    username=run_username,
                    password=run_password,
                    defcreds=bool(args.defcreds) if credential_file_entries is None else False,
                    output_path=args.output,
                    output_format=args.output_format,
                    emit_line=emit_line,
                    logger=logger if args.debug else None,
                    append_output=idx > 0 or cred_idx > 0,
                    suppress_timeout_status_lines=not bool(args.debug),
                    suppress_connection_refused_status_lines=not bool(args.debug),
                    preferred_scheme=group.scheme_hint,
                    debug_emit=emit_debug if args.debug else None,
                    show_progress=not use_single_global_progress,
                    schema_descriptor_bytes=explicit_descriptor_bytes,
                    invoke_path=getattr(args, "invoke", None),
                    invoke_request_json=invoke_request_json,
                    metadata=metadata,
                    record_sink=records,
                )
                total += part_total
                open_no_auth += part_open
                valid += part_valid
                auth_required += part_auth
                not_grpc += part_not_grpc
                failed += part_failed
                if outer_progress is not None:
                    outer_progress.advance(part_total)
    except OSError as exc:
        console.error(f"failed to process grpc output: {exc}")
        return 2
    finally:
        if outer_progress is not None:
            outer_progress.close()

    if getattr(args, "openapi", None):
        try:
            openapi_descriptor_bytes = list(explicit_descriptor_bytes)
            for record in records:
                for encoded in record.get("descriptor_protos_b64") or []:
                    if isinstance(encoded, str) and encoded.strip():
                        openapi_descriptor_bytes.append(base64.b64decode(encoded))
            operations = _write_openapi_document(str(args.openapi), _dedup_descriptor_bytes(openapi_descriptor_bytes))
        except (OSError, ValueError, RuntimeError, binascii.Error) as exc:
            console.error(f"failed to export OpenAPI: {exc}")
            return 2
        line = f"{_GRPC_TAG:<8}\t-\t-\t [+] OpenAPI exported path={args.openapi} operations={operations}"
        if args.output_format == "json":
            print(
                json.dumps(
                    {
                        "type": "grpc_openapi_export",
                        "path": str(args.openapi),
                        "operations": operations,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
        elif _render_colored_grpc_line(console, line):
            pass
        else:
            console.plain(line)

    if stream_to_stdout and total > 0 and open_no_auth == 0 and valid == 0 and auth_required == 0 and failed == total:
        if args.output_format == "txt":
            console.warn("all grpc targets are unreachable; check host/port, network reachability, and service status")

    if args.debug:
        console.info(
            f"grpc audit complete: total={total} anonymous={open_no_auth} valid={valid} "
            f"auth_required={auth_required} not_grpc={not_grpc} fail={failed}"
        )

    return 0
