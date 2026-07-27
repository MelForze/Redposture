"""gRPC protocol client helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from google.protobuf import descriptor_pb2, descriptor_pool, json_format, message_factory
from google.protobuf.message import DecodeError
from h2.connection import H2Connection
from h2.events import ConnectionTerminated, DataReceived, ResponseReceived, StreamEnded, StreamReset, TrailersReceived

from redposture_core.proto import grpc_health_pb2, grpc_reflection_pb2
from redposture_core.utils import utc_now_iso

_GRPC_AUTH_CODES = {7, 16}
_GRPC_OK = 0
_GRPC_UNIMPLEMENTED = 12
_GRPC_METADATA_KEY_RE = re.compile(r"[0-9a-z!#$%&'*+\-.^_`|~]+", re.ASCII)
_GRPC_RESERVED_METADATA_KEYS = {"authorization", "content-type", "te", "user-agent"}
_GRPC_REFLECTION_PATHS = (
    ("v1", "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"),
    ("v1alpha", "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"),
)


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


class _ReflectionCapabilityResult(dict):
    """Typed map wrapper for a reflection capability probe."""


class _ReflectionDescriptorResult(dict):
    """Typed map wrapper for reflection descriptor result."""


class _HealthResult(dict):
    """Typed map wrapper for health result."""


class _InvokeResult(dict):
    """Typed map wrapper for invoke result."""


class _GrpcWebCallResult(dict):
    """Typed map wrapper for gRPC-Web call results."""


def _grpc_authority(host: str, port: int) -> str:
    """Return an RFC 3986 authority, including brackets for IPv6 literals."""

    text = str(host).strip()
    if text.startswith("[") and text.endswith("]"):
        literal = text
    elif ":" in text:
        literal = f"[{text}]"
    else:
        literal = text
    return f"{literal}:{int(port)}"


def _canonical_binary_metadata_value(value: str) -> str:
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("binary gRPC metadata must be base64 encoded ASCII") from exc
    if any(char in value for char in "\r\n"):
        raise ValueError("gRPC metadata values cannot contain CR or LF")
    if len(value) % 4 == 1:
        raise ValueError("binary gRPC metadata must contain valid base64")
    padded = value + ("=" * (-len(value) % 4))
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("binary gRPC metadata must contain valid base64") from exc
    return base64.b64encode(decoded).decode("ascii")


def _normalize_metadata(
    metadata: Sequence[tuple[str, str | bytes]] | None,
    *,
    reject_reserved: bool = True,
) -> list[tuple[str, str]]:
    """Validate gRPC metadata and normalize binary values for HTTP headers."""

    result: list[tuple[str, str]] = []
    for raw_key, raw_value in metadata or []:
        raw_key_text = str(raw_key)
        if "\r" in raw_key_text or "\n" in raw_key_text:
            raise ValueError("gRPC metadata keys cannot contain CR or LF")
        key = raw_key_text.strip().lower()
        if not key:
            raise ValueError("gRPC metadata keys cannot be empty")
        if key.startswith(":"):
            raise ValueError("gRPC metadata cannot set HTTP/2 pseudo headers")
        if _GRPC_METADATA_KEY_RE.fullmatch(key) is None:
            raise ValueError(f"invalid gRPC metadata key {key!r}")
        if reject_reserved and key in _GRPC_RESERVED_METADATA_KEYS:
            raise ValueError(f"gRPC metadata cannot override reserved header {key}")

        if key.endswith("-bin"):
            if isinstance(raw_value, bytes):
                value = base64.b64encode(raw_value).decode("ascii")
            else:
                value = _canonical_binary_metadata_value(str(raw_value))
        else:
            if isinstance(raw_value, bytes):
                raise ValueError(f"non-binary gRPC metadata {key!r} cannot contain bytes")
            value = str(raw_value)
            if "\r" in value or "\n" in value:
                raise ValueError("gRPC metadata values cannot contain CR or LF")
            try:
                encoded_value = value.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ValueError(f"non-binary gRPC metadata {key!r} must contain printable ASCII") from exc
            if any(char < 0x20 or char > 0x7E for char in encoded_value):
                raise ValueError(f"non-binary gRPC metadata {key!r} must contain printable ASCII")
        result.append((key, value))
    return result


def _normalize_authorization(authorization: str | None) -> str | None:
    """Validate the reserved authorization metadata before HTTP serialization."""

    if authorization is None or authorization == "":
        return None
    value = str(authorization)
    if "\r" in value or "\n" in value:
        raise ValueError("gRPC authorization metadata cannot contain CR or LF")
    try:
        encoded_value = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("gRPC authorization metadata must contain printable ASCII") from exc
    if any(char < 0x20 or char > 0x7E for char in encoded_value):
        raise ValueError("gRPC authorization metadata must contain printable ASCII")
    return value


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


def _new_grpc_call_result(host: str, port: int, path: str, use_tls: bool) -> _GrpcCallResult:
    return _GrpcCallResult(
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


def _finish_grpc_call_result(
    result: _GrpcCallResult,
    response_headers: dict[str, str],
    response_trailers: dict[str, str],
    body: bytes,
) -> None:
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

    messages, frame_error = _decode_grpc_frames(body)
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


class _GrpcH2Session:
    """A reusable, sequential HTTP/2 connection for calls to one gRPC target."""

    def __init__(self, host: str, port: int, *, timeout: float, use_tls: bool) -> None:
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.use_tls = bool(use_tls)
        self._sock: socket.socket | None = None
        self._conn: H2Connection | None = None
        self._closed = False
        self._lock = threading.RLock()
        self._reflection_version: str | None = None

    def __enter__(self) -> _GrpcH2Session:
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        self.close()

    def _drop_connection(self) -> None:
        sock = self._sock
        self._sock = None
        self._conn = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def _ensure_connection(self, timeout: float) -> tuple[socket.socket, H2Connection]:
        if self._closed:
            raise OSError("gRPC HTTP/2 session is closed")
        if self._sock is not None and self._conn is not None:
            self._sock.settimeout(timeout)
            return self._sock, self._conn

        sock = _open_grpc_socket(self.host, self.port, timeout, use_tls=self.use_tls)
        conn = H2Connection()
        try:
            conn.initiate_connection()
            pending = conn.data_to_send()
            if pending:
                sock.sendall(pending)
        except BaseException:
            sock.close()
            raise
        self._sock = sock
        self._conn = conn
        return sock, conn

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._sock is not None and self._conn is not None:
                close_connection = getattr(self._conn, "close_connection", None)
                if callable(close_connection):
                    try:
                        close_connection()
                        pending = self._conn.data_to_send()
                        if pending:
                            self._sock.sendall(pending)
                    except (OSError, ssl.SSLError):
                        pass
            self._drop_connection()

    def call(
        self,
        *,
        path: str,
        payload: bytes,
        timeout: float | None = None,
        authorization: str | None,
        metadata: Sequence[tuple[str, str | bytes]] | None = None,
    ) -> _GrpcCallResult:
        started = time.monotonic()
        result = _new_grpc_call_result(self.host, self.port, path, self.use_tls)
        call_timeout = self.timeout if timeout is None else float(timeout)
        try:
            normalized_metadata = _normalize_metadata(metadata)
            normalized_authorization = _normalize_authorization(authorization)
        except ValueError as exc:
            result["error"] = str(exc)
            result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            return result

        with self._lock:
            response_headers: dict[str, str] = {}
            response_trailers: dict[str, str] = {}
            body = bytearray()
            connection_terminated = False
            try:
                sock, conn = self._ensure_connection(call_timeout)
                result["transport_ok"] = True
                stream_id = conn.get_next_available_stream_id()
                headers: list[tuple[str, str]] = [
                    (":method", "POST"),
                    (":scheme", "https" if self.use_tls else "http"),
                    (":authority", _grpc_authority(self.host, self.port)),
                    (":path", path),
                    ("content-type", "application/grpc"),
                    ("te", "trailers"),
                    ("user-agent", "RedPosture/1.0"),
                ]
                headers.extend(normalized_metadata)
                if normalized_authorization:
                    headers.append(("authorization", normalized_authorization))

                conn.send_headers(stream_id, headers, end_stream=False)
                conn.send_data(stream_id, _encode_grpc_frame(payload), end_stream=True)
                pending = conn.data_to_send()
                if pending:
                    sock.sendall(pending)

                stream_closed = False
                while not stream_closed and not connection_terminated:
                    chunk = sock.recv(64 * 1024)
                    if not chunk:
                        result["error"] = "connection closed before gRPC stream ended"
                        connection_terminated = True
                        break
                    events = conn.receive_data(chunk)
                    for event in events:
                        event_stream_id = getattr(event, "stream_id", stream_id)
                        if isinstance(event, DataReceived):
                            conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                            if event_stream_id == stream_id:
                                body.extend(event.data)
                        elif isinstance(event, ResponseReceived) and event_stream_id == stream_id:
                            response_headers.update(_http2_headers_to_map(list(event.headers)))
                        elif isinstance(event, TrailersReceived) and event_stream_id == stream_id:
                            response_trailers.update(_http2_headers_to_map(list(event.headers)))
                        elif isinstance(event, StreamEnded) and event_stream_id == stream_id:
                            stream_closed = True
                        elif isinstance(event, StreamReset) and event_stream_id == stream_id:
                            result["error"] = f"stream reset by peer (code={int(event.error_code)})"
                            stream_closed = True
                        elif isinstance(event, ConnectionTerminated):
                            connection_terminated = True
                            if not stream_closed and result.get("error") is None:
                                result["error"] = f"HTTP/2 connection terminated (code={event.error_code})"

                    pending = conn.data_to_send()
                    if pending:
                        sock.sendall(pending)

                _finish_grpc_call_result(result, response_headers, response_trailers, bytes(body))
                if connection_terminated:
                    self._drop_connection()
            except (OSError, TimeoutError, ValueError, ssl.SSLError) as exc:
                result["transport_ok"] = False
                result["error"] = _friendly_error_from_exception(exc)
                self._drop_connection()
            finally:
                result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        return result


def _grpc_call(
    host: str,
    port: int,
    *,
    path: str,
    payload: bytes,
    timeout: float,
    use_tls: bool,
    authorization: str | None,
    metadata: Sequence[tuple[str, str | bytes]] | None = None,
    session: _GrpcH2Session | None = None,
) -> _GrpcCallResult:
    if session is not None:
        if (session.host, session.port, session.use_tls) != (host, int(port), bool(use_tls)):
            raise ValueError("gRPC HTTP/2 session target or transport does not match the call")
        return session.call(
            path=path,
            payload=payload,
            timeout=timeout,
            authorization=authorization,
            metadata=metadata,
        )
    with _GrpcH2Session(host, port, timeout=timeout, use_tls=use_tls) as owned_session:
        return owned_session.call(
            path=path,
            payload=payload,
            timeout=timeout,
            authorization=authorization,
            metadata=metadata,
        )


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
    metadata: Sequence[tuple[str, str | bytes]] | None = None,
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
        normalized_metadata = _normalize_metadata(metadata)
        normalized_authorization = _normalize_authorization(authorization)
        sock = _open_http_socket(host, port, timeout, use_tls=use_tls)
        result["transport_ok"] = True
        body = _encode_grpc_frame(payload)
        header_lines = [
            f"POST {path} HTTP/1.1",
            f"Host: {_grpc_authority(host, port)}",
            "User-Agent: RedPosture/1.0",
            "Content-Type: application/grpc-web+proto",
            "Accept: application/grpc-web+proto",
            "X-Grpc-Web: 1",
            "Connection: close",
            f"Content-Length: {len(body)}",
        ]
        for key, value in normalized_metadata:
            header_lines.append(f"{key}: {value}")
        if normalized_authorization:
            header_lines.append(f"Authorization: {normalized_authorization}")
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
    session: _GrpcH2Session | None = None,
) -> _HealthResult:
    call = _grpc_call(
        host,
        port,
        path="/grpc.health.v1.Health/Check",
        payload=_grpc_health_payload(service_name),
        timeout=timeout,
        use_tls=use_tls,
        authorization=authorization,
        session=session,
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


def _reflection_call_with_fallback(
    host: str,
    port: int,
    *,
    payload: bytes,
    timeout: float,
    use_tls: bool,
    authorization: str | None,
    session: _GrpcH2Session | None = None,
) -> tuple[_GrpcCallResult, str]:
    """Prefer stable Reflection v1 and retry v1alpha only when v1 is unavailable."""

    paths: Sequence[tuple[str, str]] = _GRPC_REFLECTION_PATHS
    if session is not None and session._reflection_version == "v1alpha":
        paths = (_GRPC_REFLECTION_PATHS[1],)

    last_call: _GrpcCallResult | None = None
    for version, path in paths:
        call = _grpc_call(
            host,
            port,
            path=path,
            payload=payload,
            timeout=timeout,
            use_tls=use_tls,
            authorization=authorization,
            session=session,
        )
        last_call = call
        grpc_status = call.get("grpc_status")
        # A conforming gRPC server reports UNIMPLEMENTED for the unknown v1
        # method. Some HTTP-aware proxies instead terminate routing with a
        # plain 404 before the request reaches gRPC, which proves the v1 path
        # is unavailable just as clearly and should retain the v1alpha
        # compatibility fallback.
        version_unavailable = grpc_status == _GRPC_UNIMPLEMENTED or (
            grpc_status is None and call.get("http_status") == 404
        )
        if not version_unavailable or version == "v1alpha":
            if session is not None:
                session._reflection_version = version
            return call, version
    # Both entries are static and the loop always returns on v1alpha.
    assert last_call is not None
    return last_call, "v1alpha"


def _reflection_list_services_call(
    host: str,
    port: int,
    *,
    timeout: float,
    use_tls: bool,
    authorization: str | None,
    session: _GrpcH2Session | None = None,
) -> _ReflectionListResult:
    call, reflection_version = _reflection_call_with_fallback(
        host,
        port,
        payload=_grpc_reflection_list_payload(),
        timeout=timeout,
        use_tls=use_tls,
        authorization=authorization,
        session=session,
    )

    services: list[str] = []
    reflection_enabled: bool | None = None
    embedded_code: int | None = None
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
            if response.HasField("error_response"):
                embedded_code = int(response.error_response.error_code)
                if not error_message:
                    error_message = f"{embedded_code}:{response.error_response.error_message}"

    if embedded_code == _GRPC_UNIMPLEMENTED:
        reflection_enabled = False
    elif embedded_code in _GRPC_AUTH_CODES:
        reflection_enabled = None

    dedup_services = sorted(dict.fromkeys(str(item).strip() for item in services if str(item).strip()))

    return _ReflectionListResult(
        {
            "call": call,
            "services": dedup_services,
            "reflection_enabled": reflection_enabled,
            "reflection_version": reflection_version,
            "grpc_status": grpc_status,
            "grpc_status_name": _grpc_status_name(grpc_status),
            "embedded_error_code": embedded_code,
            "error": error_message or call.get("error"),
        }
    )


def _reflection_capability_call(
    host: str,
    port: int,
    *,
    timeout: float,
    use_tls: bool,
    authorization: str | None,
    session: _GrpcH2Session | None = None,
) -> _ReflectionCapabilityResult:
    """Check Reflection without requesting the server's service inventory."""

    probe_symbol = "redposture.probe.__ReflectionCapabilityProbe__"
    call, reflection_version = _reflection_call_with_fallback(
        host,
        port,
        payload=_grpc_reflection_symbol_payload(probe_symbol),
        timeout=timeout,
        use_tls=use_tls,
        authorization=authorization,
        session=session,
    )

    grpc_status = call.get("grpc_status")
    reflection_enabled: bool | None = None
    embedded_code: int | None = None
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
                reflection_enabled = True
            if response.HasField("error_response"):
                embedded_code = int(response.error_response.error_code)
                if not error_message:
                    error_message = f"{embedded_code}:{response.error_response.error_message}"

    effective_code = embedded_code if embedded_code is not None else grpc_status
    if effective_code == _GRPC_UNIMPLEMENTED:
        reflection_enabled = False
    elif effective_code in _GRPC_AUTH_CODES:
        reflection_enabled = None
    elif grpc_status == _GRPC_OK:
        # NOT_FOUND for the deliberately absent symbol proves that the
        # Reflection method handled the request without disclosing inventory.
        reflection_enabled = True

    return _ReflectionCapabilityResult(
        {
            "call": call,
            "reflection_enabled": reflection_enabled,
            "reflection_version": reflection_version,
            "grpc_status": grpc_status,
            "grpc_status_name": _grpc_status_name(grpc_status),
            "embedded_error_code": embedded_code,
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
    session: _GrpcH2Session | None = None,
) -> _ReflectionDescriptorResult:
    call, reflection_version = _reflection_call_with_fallback(
        host,
        port,
        payload=_grpc_reflection_symbol_payload(symbol),
        timeout=timeout,
        use_tls=use_tls,
        authorization=authorization,
        session=session,
    )

    descriptor_bytes: list[bytes] = []
    embedded_code: int | None = None
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
            if response.HasField("error_response"):
                embedded_code = int(response.error_response.error_code)
                if not error_message:
                    error_message = f"{embedded_code}:{response.error_response.error_message}"

    return _ReflectionDescriptorResult(
        {
            "call": call,
            "symbol": symbol,
            "descriptor_bytes": descriptor_bytes,
            "reflection_version": reflection_version,
            "grpc_status": call.get("grpc_status"),
            "grpc_status_name": _grpc_status_name(call.get("grpc_status")),
            "embedded_error_code": embedded_code,
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
    # Keep this shared helper deterministic too: explicit schemas and invoke
    # paths use it before OpenAPI generation gets a chance to inspect inputs.
    return _analyze_descriptor_bytes(descriptor_bytes)[0]


def _normalized_descriptor_bytes(fd: descriptor_pb2.FileDescriptorProto) -> bytes:
    """Serialize schema-relevant descriptor content for stable comparison."""

    normalized = descriptor_pb2.FileDescriptorProto()
    normalized.CopyFrom(fd)
    # Source locations differ between Reflection and --proto builds but do not
    # change protobuf symbols or their wire/JSON schema.
    normalized.ClearField("source_code_info")
    return normalized.SerializeToString(deterministic=True)


def _analyze_descriptor_bytes(
    descriptor_bytes: list[bytes],
    *,
    select_conflicts: bool = True,
) -> tuple[list[bytes], list[str], list[dict[str, Any]]]:
    """Validate and deterministically select one schema per descriptor file."""

    variants_by_name: dict[str, dict[str, tuple[bytes, int, str]]] = {}
    invalid_errors: set[str] = set()
    for blob in descriptor_bytes:
        raw = bytes(blob)
        raw_digest = hashlib.sha256(raw).hexdigest()
        if not raw:
            invalid_errors.add(f"invalid descriptor sha256={raw_digest}: empty payload")
            continue
        fd = descriptor_pb2.FileDescriptorProto()
        try:
            fd.ParseFromString(raw)
        except Exception:
            invalid_errors.add(f"invalid descriptor sha256={raw_digest}: malformed FileDescriptorProto")
            continue
        if not fd.name:
            invalid_errors.add(f"invalid descriptor sha256={raw_digest}: missing file name")
            continue

        canonical = fd.SerializeToString(deterministic=True)
        normalized = _normalized_descriptor_bytes(fd)
        schema_digest = hashlib.sha256(normalized).hexdigest()
        wire_digest = hashlib.sha256(canonical).hexdigest()
        name = str(fd.name)
        variants = variants_by_name.setdefault(name, {})
        current = variants.get(schema_digest)
        # Multiple payloads that differ only in source information are the
        # same schema. Pick their canonical bytes deterministically as well.
        if current is None or wire_digest < current[2]:
            variants[schema_digest] = (canonical, len(normalized), wire_digest)

    selected: list[tuple[str, str, bytes]] = []
    conflicts: list[dict[str, Any]] = []
    for name, variants in sorted(variants_by_name.items()):
        selected_digest = min(variants)
        selected_digests = [selected_digest] if select_conflicts else sorted(variants)
        selected.extend((name, digest, variants[digest][0]) for digest in selected_digests)
        if len(variants) < 2:
            continue
        conflicts.append(
            {
                "file": name,
                "variants": [{"sha256": digest, "size": variants[digest][1]} for digest in sorted(variants)],
                "selected_sha256": selected_digest,
                "selection_policy": "lowest_normalized_sha256",
            }
        )

    return [blob for _name, _digest, blob in selected], sorted(invalid_errors), conflicts


def _descriptor_conflicts(descriptor_bytes: list[bytes]) -> list[dict[str, Any]]:
    """Describe same-name descriptor variants that cannot share one protobuf pool."""

    return _analyze_descriptor_bytes(descriptor_bytes)[2]


def _descriptor_defined_symbols(fd: descriptor_pb2.FileDescriptorProto) -> list[tuple[str, str]]:
    symbols: list[tuple[str, str]] = []

    def _qualified(prefix: str, name: str) -> str:
        return f"{prefix}.{name}" if prefix else name

    def _walk_message(message: descriptor_pb2.DescriptorProto, prefix: str) -> None:
        full_name = _qualified(prefix, str(message.name))
        if message.name:
            symbols.append((full_name, "message"))
        for enum in message.enum_type:
            if enum.name:
                symbols.append((_qualified(full_name, str(enum.name)), "enum"))
        for nested in message.nested_type:
            _walk_message(nested, full_name)

    package = str(fd.package or "")
    for message in fd.message_type:
        _walk_message(message, package)
    for enum in fd.enum_type:
        if enum.name:
            symbols.append((_qualified(package, str(enum.name)), "enum"))
    for service in fd.service:
        if service.name:
            symbols.append((_qualified(package, str(service.name)), "service"))
    return symbols


def _descriptor_symbol_conflicts(descriptor_bytes: list[bytes]) -> list[dict[str, Any]]:
    definitions: dict[str, dict[str, set[str]]] = {}
    for blob in descriptor_bytes:
        fd = descriptor_pb2.FileDescriptorProto()
        try:
            fd.ParseFromString(blob)
        except Exception:
            continue
        file_name = str(fd.name or "<unnamed>")
        for symbol, kind in _descriptor_defined_symbols(fd):
            definitions.setdefault(symbol, {}).setdefault(kind, set()).add(file_name)

    conflicts: list[dict[str, Any]] = []
    for symbol, kind_files in sorted(definitions.items()):
        files = sorted({file_name for names in kind_files.values() for file_name in names})
        if len(files) < 2:
            continue
        conflicts.append(
            {
                "symbol": symbol,
                "kinds": sorted(kind_files),
                "files": files,
            }
        )
    return conflicts


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
    try:
        descriptor_set.ParseFromString(payload)
    except DecodeError as exc:
        raise ValueError(f"invalid protoset {path!r}: {exc}") from exc
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
    variants, errors, _conflicts = _analyze_descriptor_bytes(descriptor_bytes, select_conflicts=False)
    if errors:
        raise ValueError("invalid explicit protobuf descriptor: " + "; ".join(errors))
    return variants


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
        raw_key, sep, value = str(raw).partition("=")
        if "\r" in raw_key or "\n" in raw_key:
            raise ValueError("gRPC metadata keys cannot contain CR or LF")
        key = raw_key
        key = key.strip().lower()
        if not sep or not key:
            raise ValueError("--meta must use key=value")
        if key.startswith(":"):
            raise ValueError("--meta cannot set HTTP/2 pseudo headers")
        if _GRPC_METADATA_KEY_RE.fullmatch(key) is None:
            raise ValueError(f"--meta contains invalid metadata key {key!r}")
        if key in _GRPC_RESERVED_METADATA_KEYS:
            raise ValueError(f"--meta cannot override reserved header {key}")
        result.extend(_normalize_metadata([(key, value)]))
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
    session: _GrpcH2Session | None = None,
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
    if metadata:
        result["metadata"] = [{"key": key, "value": value} for key, value in metadata]
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
                session=session,
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


_SIGNED_64_TYPES = {
    descriptor_pb2.FieldDescriptorProto.TYPE_INT64,
    descriptor_pb2.FieldDescriptorProto.TYPE_SFIXED64,
    descriptor_pb2.FieldDescriptorProto.TYPE_SINT64,
}
_UNSIGNED_64_TYPES = {
    descriptor_pb2.FieldDescriptorProto.TYPE_UINT64,
    descriptor_pb2.FieldDescriptorProto.TYPE_FIXED64,
}
_SIGNED_32_TYPES = {
    descriptor_pb2.FieldDescriptorProto.TYPE_INT32,
    descriptor_pb2.FieldDescriptorProto.TYPE_SFIXED32,
    descriptor_pb2.FieldDescriptorProto.TYPE_SINT32,
}
_UNSIGNED_32_TYPES = {
    descriptor_pb2.FieldDescriptorProto.TYPE_UINT32,
    descriptor_pb2.FieldDescriptorProto.TYPE_FIXED32,
}
_PROTOBUF_WRAPPER_TYPES: dict[str, dict[str, Any]] = {
    "google.protobuf.DoubleValue": {
        "oneOf": [
            {"type": "number", "format": "double"},
            {"type": "string", "enum": ["NaN", "Infinity", "-Infinity"]},
            {"type": "null"},
        ]
    },
    "google.protobuf.FloatValue": {
        "oneOf": [
            {"type": "number", "format": "float"},
            {"type": "string", "enum": ["NaN", "Infinity", "-Infinity"]},
            {"type": "null"},
        ]
    },
    "google.protobuf.Int64Value": {
        "type": ["string", "null"],
        "pattern": r"^-?[0-9]+$",
        "x-protobuf-type": "int64",
    },
    "google.protobuf.UInt64Value": {
        "type": ["string", "null"],
        "pattern": r"^[0-9]+$",
        "x-protobuf-type": "uint64",
    },
    "google.protobuf.Int32Value": {
        "type": ["integer", "null"],
        "format": "int32",
        "minimum": -(2**31),
        "maximum": 2**31 - 1,
    },
    "google.protobuf.UInt32Value": {
        "type": ["integer", "null"],
        "format": "int64",
        "minimum": 0,
        "maximum": 2**32 - 1,
        "x-protobuf-type": "uint32",
    },
    "google.protobuf.BoolValue": {"type": ["boolean", "null"]},
    "google.protobuf.StringValue": {"type": ["string", "null"]},
    "google.protobuf.BytesValue": {
        "type": ["string", "null"],
        "format": "byte",
        "contentEncoding": "base64",
    },
}


def _protobuf_type_name(field_type: int) -> str:
    try:
        name = descriptor_pb2.FieldDescriptorProto.Type.Name(field_type)
    except ValueError:
        return str(field_type)
    return str(name).removeprefix("TYPE_").lower()


def _protobuf_scalar_schema(field_type: int) -> dict[str, Any]:
    if field_type == descriptor_pb2.FieldDescriptorProto.TYPE_DOUBLE:
        return {
            "oneOf": [
                {"type": "number", "format": "double"},
                {"type": "string", "enum": ["NaN", "Infinity", "-Infinity"]},
            ]
        }
    if field_type == descriptor_pb2.FieldDescriptorProto.TYPE_FLOAT:
        return {
            "oneOf": [
                {"type": "number", "format": "float"},
                {"type": "string", "enum": ["NaN", "Infinity", "-Infinity"]},
            ]
        }
    if field_type in _SIGNED_64_TYPES:
        return {"type": "string", "pattern": r"^-?[0-9]+$", "x-protobuf-type": "int64"}
    if field_type in _UNSIGNED_64_TYPES:
        return {"type": "string", "pattern": r"^[0-9]+$", "x-protobuf-type": "uint64"}
    if field_type in _SIGNED_32_TYPES:
        return {"type": "integer", "format": "int32", "minimum": -(2**31), "maximum": 2**31 - 1}
    if field_type in _UNSIGNED_32_TYPES:
        return {
            "type": "integer",
            "format": "int64",
            "minimum": 0,
            "maximum": 2**32 - 1,
            "x-protobuf-type": "uint32",
        }
    if field_type == descriptor_pb2.FieldDescriptorProto.TYPE_BOOL:
        return {"type": "boolean"}
    if field_type == descriptor_pb2.FieldDescriptorProto.TYPE_BYTES:
        return {"type": "string", "format": "byte", "contentEncoding": "base64"}
    return {"type": "string"}


def _protobuf_map_key_schema(field_type: int) -> dict[str, Any] | None:
    if field_type in _SIGNED_32_TYPES | _SIGNED_64_TYPES:
        return {"pattern": r"^-?[0-9]+$"}
    if field_type in _UNSIGNED_32_TYPES | _UNSIGNED_64_TYPES:
        return {"pattern": r"^[0-9]+$"}
    if field_type == descriptor_pb2.FieldDescriptorProto.TYPE_BOOL:
        return {"enum": ["false", "true"]}
    return None


def _proto3_optional_field_numbers(msg_desc: Any) -> set[int]:
    """Recover proto3 optional markers hidden by the upb runtime descriptor API."""

    file_proto = descriptor_pb2.FileDescriptorProto()
    try:
        file_proto.ParseFromString(bytes(msg_desc.file.serialized_pb))
    except Exception:
        return set()

    names: list[str] = []
    current = msg_desc
    while current is not None:
        names.append(str(current.name))
        current = getattr(current, "containing_type", None)
    names.reverse()

    messages = file_proto.message_type
    message_proto: Any = None
    for name in names:
        message_proto = next((item for item in messages if item.name == name), None)
        if message_proto is None:
            return set()
        messages = message_proto.nested_type
    return {int(field.number) for field in message_proto.field if field.proto3_optional}


def _well_known_message_schema(
    msg_desc: Any,
    components: dict[str, Any],
    visiting: set[str],
) -> dict[str, Any] | None:
    full_name = str(msg_desc.full_name)

    def _related_message_ref(name: str) -> dict[str, Any]:
        related = msg_desc.file.pool.FindMessageTypeByName(name)
        return _json_schema_for_message(related, components, visiting)

    wrapper_schema = _PROTOBUF_WRAPPER_TYPES.get(full_name)
    if wrapper_schema is not None:
        return {**wrapper_schema, "x-protobuf-well-known-type": full_name}
    if full_name == "google.protobuf.Timestamp":
        return {"type": "string", "format": "date-time", "x-protobuf-well-known-type": full_name}
    if full_name == "google.protobuf.Duration":
        return {
            "type": "string",
            "pattern": r"^-?(?:[0-9]+)(?:\.[0-9]{1,9})?s$",
            "x-protobuf-well-known-type": full_name,
        }
    if full_name == "google.protobuf.FieldMask":
        return {"type": "string", "x-protobuf-well-known-type": full_name}
    if full_name == "google.protobuf.Empty":
        return {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
            "x-protobuf-well-known-type": full_name,
        }
    if full_name == "google.protobuf.Any":
        return {
            "type": "object",
            "properties": {"@type": {"type": "string"}},
            "required": ["@type"],
            "additionalProperties": True,
            "x-protobuf-well-known-type": full_name,
        }
    if full_name == "google.protobuf.Struct":
        return {
            "type": "object",
            "additionalProperties": _related_message_ref("google.protobuf.Value"),
            "x-protobuf-well-known-type": full_name,
        }
    if full_name == "google.protobuf.Value":
        return {
            "oneOf": [
                {"type": "null"},
                {"type": "number"},
                {"type": "string"},
                {"type": "boolean"},
                _related_message_ref("google.protobuf.Struct"),
                _related_message_ref("google.protobuf.ListValue"),
            ],
            "x-protobuf-well-known-type": full_name,
        }
    if full_name == "google.protobuf.ListValue":
        return {
            "type": "array",
            "items": _related_message_ref("google.protobuf.Value"),
            "x-protobuf-well-known-type": full_name,
        }
    return None


def _json_schema_for_field(field: Any, components: dict[str, Any], visiting: set[str]) -> dict[str, Any]:
    message_type = getattr(field, "message_type", None)
    if message_type is not None:
        if bool(message_type.GetOptions().map_entry):
            value_field = message_type.fields_by_name["value"]
            key_field = message_type.fields_by_name["key"]
            value_schema = _json_schema_for_field(value_field, components, visiting)
            map_schema: dict[str, Any] = {
                "type": "object",
                "additionalProperties": value_schema,
                "x-protobuf-map-key-type": _protobuf_type_name(int(key_field.type)),
            }
            key_schema = _protobuf_map_key_schema(int(key_field.type))
            if key_schema is not None:
                map_schema["propertyNames"] = key_schema
            return map_schema
        return _json_schema_for_message(message_type, components, visiting)

    enum_type = getattr(field, "enum_type", None)
    if enum_type is not None:
        if str(enum_type.full_name) == "google.protobuf.NullValue":
            return {"type": "null"}
        return {"type": "string", "enum": [str(value.name) for value in enum_type.values]}
    return _protobuf_scalar_schema(int(field.type))


def _json_schema_for_message(
    msg_desc: Any,
    components: dict[str, Any],
    visiting: set[str] | None = None,
) -> dict[str, Any]:
    visiting = visiting if visiting is not None else set()
    full_name = str(msg_desc.full_name)
    # Protobuf full names are valid OpenAPI component keys.  Keeping the dots
    # also avoids collisions such as ``a.b_c.Request`` vs ``a_b.c.Request``
    # that occur when every separator is flattened to an underscore.
    component_name = full_name
    component_ref = {"$ref": f"#/components/schemas/{component_name}"}
    if component_name in components or full_name in visiting:
        return component_ref

    visiting.add(full_name)
    components[component_name] = {}
    well_known_schema = _well_known_message_schema(msg_desc, components, visiting)
    if well_known_schema is not None:
        components[component_name].update(well_known_schema)
        visiting.discard(full_name)
        return component_ref

    schema = components[component_name]
    schema.update({"type": "object", "properties": {}})
    proto3_optional_numbers = _proto3_optional_field_numbers(msg_desc)
    required_fields: list[str] = []
    oneof_fields: dict[str, list[str]] = {}

    for field in msg_desc.fields:
        field_schema = _json_schema_for_field(field, components, visiting)
        is_map = bool(getattr(field, "message_type", None) is not None and field.message_type.GetOptions().map_entry)
        if getattr(field, "is_repeated", False) and not is_map:
            field_schema = {"type": "array", "items": field_schema}

        json_name = str(getattr(field, "json_name", None) or field.name)
        proto_name = str(field.name)
        if json_name != proto_name:
            field_schema["x-protobuf-field-name"] = proto_name
        if int(field.number) in proto3_optional_numbers:
            field_schema["x-protobuf-optional"] = True
        elif getattr(field, "containing_oneof", None) is not None:
            oneof_name = str(field.containing_oneof.name)
            field_schema["x-protobuf-oneof"] = oneof_name
            oneof_fields.setdefault(oneof_name, []).append(json_name)
        if bool(getattr(field, "is_required", False)):
            required_fields.append(json_name)
        schema["properties"][json_name] = field_schema

    if required_fields:
        schema["required"] = required_fields
    if oneof_fields:
        schema["x-protobuf-oneofs"] = oneof_fields
        constraints: list[dict[str, Any]] = []
        for field_names in oneof_fields.values():
            required_variants = [{"required": [field_name]} for field_name in field_names]
            constraints.append(
                {
                    "oneOf": [
                        {"not": {"anyOf": required_variants}},
                        *required_variants,
                    ]
                }
            )
        if len(constraints) == 1:
            schema.update(constraints[0])
        else:
            schema["allOf"] = constraints

    visiting.discard(full_name)
    return component_ref


def _openapi_operation_id(full_method: str, *, disambiguate: bool = False) -> str:
    service_name, method_name = _split_grpc_method_path(full_method)
    legacy_id = full_method.strip("/").replace("/", "_").replace(".", "_")
    if not disambiguate:
        return legacy_id
    # Length prefixes make the separator unambiguous even when protobuf
    # identifiers themselves contain underscores or package separators.
    return f"{legacy_id}__grpc_{len(service_name)}_{service_name}_{len(method_name)}_{method_name}"


def _generate_openapi_document(
    descriptor_bytes: list[bytes],
    *,
    descriptor_targets: dict[str, bool] | None = None,
    server_urls: list[str] | None = None,
) -> dict[str, Any]:
    unique_descriptor_bytes, input_errors, descriptor_conflicts = _analyze_descriptor_bytes(descriptor_bytes)
    symbol_conflicts = _descriptor_symbol_conflicts(unique_descriptor_bytes)
    pool, pool_errors = _descriptor_bytes_to_pool(unique_descriptor_bytes)
    symbol_errors = [
        f"duplicate protobuf symbol {item['symbol']} ({'/'.join(item['kinds'])}) in files: {', '.join(item['files'])}"
        for item in symbol_conflicts
    ]
    errors = sorted(dict.fromkeys([*input_errors, *pool_errors, *symbol_errors]))
    methods, _descriptors = _extract_descriptors(unique_descriptor_bytes)
    operation_id_counts: dict[str, int] = {}
    for method in methods:
        full_method = str(method.get("full_method") or "")
        if not full_method:
            continue
        legacy_operation_id = _openapi_operation_id(full_method)
        operation_id_counts[legacy_operation_id] = operation_id_counts.get(legacy_operation_id, 0) + 1
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
                "operationId": _openapi_operation_id(
                    full_method,
                    disambiguate=operation_id_counts[_openapi_operation_id(full_method)] > 1,
                ),
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
    targets = dict(sorted((descriptor_targets or {}).items()))
    targets_without_descriptors = [target for target, obtained in targets.items() if not obtained]
    descriptor_metadata: dict[str, Any] = {
        "descriptors_obtained": bool(unique_descriptor_bytes),
        "descriptor_count": len(unique_descriptor_bytes),
        "descriptor_errors": errors,
    }
    if targets:
        descriptor_metadata["descriptor_targets"] = targets
        descriptor_metadata["targets_without_descriptors"] = targets_without_descriptors
    if descriptor_conflicts:
        descriptor_metadata["descriptor_conflicts"] = descriptor_conflicts
    if symbol_conflicts:
        descriptor_metadata["descriptor_symbol_conflicts"] = symbol_conflicts

    document: dict[str, Any] = {
        "openapi": "3.1.0",
        "info": {"title": "RedPosture gRPC export", "version": "1.0.0"},
        "paths": paths,
        "components": {"schemas": components},
        "x-redposture": descriptor_metadata,
    }
    normalized_server_urls = sorted(
        {item.strip() for item in (server_urls or []) if isinstance(item, str) and item.strip()}
    )
    if normalized_server_urls:
        document["servers"] = [{"url": url} for url in normalized_server_urls]
    return document


def _write_openapi_document(
    path: str,
    descriptor_bytes: list[bytes],
    *,
    descriptor_targets: dict[str, bool] | None = None,
    server_urls: list[str] | None = None,
) -> int:
    document = _generate_openapi_document(
        descriptor_bytes,
        descriptor_targets=descriptor_targets,
        server_urls=server_urls,
    )
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return len(document.get("paths") or {})
