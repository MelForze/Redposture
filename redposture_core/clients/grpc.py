"""gRPC protocol client helpers."""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from google.protobuf import descriptor_pb2, descriptor_pool, json_format, message_factory
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded, StreamReset, TrailersReceived

from redposture_core.proto import grpc_health_pb2, grpc_reflection_pb2
from redposture_core.utils import utc_now_iso

_GRPC_AUTH_CODES = {7, 16}
_GRPC_OK = 0
_GRPC_UNIMPLEMENTED = 12


def _friendly_error_text(value: str) -> str:
    from ..utils import friendly_error_text

    return friendly_error_text(value)


def _friendly_error_from_exception(exc: BaseException) -> str:
    from ..utils import friendly_error_from_exception

    return friendly_error_from_exception(exc)


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
    try:
        wrapped = context.wrap_socket(base_sock, server_hostname=host)
    except BaseException:
        base_sock.close()
        raise
    try:
        wrapped.settimeout(timeout)
        negotiated = wrapped.selected_alpn_protocol()
        if negotiated and negotiated.lower() != "h2":
            raise OSError(f"tls alpn negotiation failed (expected h2, got {negotiated})")
        return wrapped
    except BaseException:
        wrapped.close()
        raise


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
    try:
        wrapped = context.wrap_socket(base_sock, server_hostname=host)
    except BaseException:
        base_sock.close()
        raise
    try:
        wrapped.settimeout(timeout)
    except BaseException:
        wrapped.close()
        raise
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
            service_entry: dict[str, Any] = {
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
            from grpc_tools import protoc

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
        call: _GrpcCallResult | _GrpcWebCallResult
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
