"""Kubernetes API audit stage."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any

from ...clients.http_api import (
    HttpApiClient,
    HttpClientConfig,
    build_http_target_url,
    format_http_authority,
    join_http_target_path,
)
from ...console import Console
from ...rendering import CountColorRule, render_colored_marker_line, render_tagged_detail_line
from ...utils import (
    is_signature_compat_typeerror,
    utc_now_iso,
)

_KUBE_TAG = "KUBEAPI"
_KUBE_LIST_PAGE_LIMIT = 500
_KUBE_MAX_LIST_PAGES = 40
_KUBE_DETECT_RESPONSE_CAP = 256 * 1024
_KUBE_AUTH_RESPONSE_CAP = 256 * 1024
_KUBE_DATA_RESPONSE_CAP = 10 * 1024 * 1024
_KUBE_WS_READ_TIMEOUT = 3.0
_KUBE_WS_HANDSHAKE_TIMEOUT = 5.0
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_CONNECTION_REFUSED_PREFIX = "connection refused"

_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"


@dataclass
class KubeApiLifecycleState:
    use_https: bool = True
    insecure: bool = False
    tls_auto_insecure: bool = False
    ca_file: str | None = None
    anonymous_namespaces: list[str] | None = None
    anonymous_namespaces_error: str | None = None
    access_namespaces: list[str] | None = None
    access_namespaces_error: str | None = None
    token: str | None = None
    username: str | None = None
    password: str | None = None
    deep_record: dict[str, Any] | None = None
    http_clients: dict[tuple[bool, bool, str | None, int], HttpApiClient] = dataclass_field(default_factory=dict)

    def http_client(self, *, response_size_cap: int) -> HttpApiClient:
        key = (self.use_https, self.insecure, self.ca_file, int(response_size_cap))
        client = self.http_clients.get(key)
        if client is None:
            client = HttpApiClient(
                HttpClientConfig(
                    insecure=bool(self.use_https and self.insecure),
                    ca_file=self.ca_file if self.use_https and self.ca_file else None,
                    response_size_cap=int(response_size_cap),
                )
            )
            self.http_clients[key] = client
        return client


_THREAD_LOCAL_DEBUG_EMIT = threading.local()


def _clip(text: str, width: int = 72) -> str:
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
    from ...utils import friendly_error_text

    return friendly_error_text(value, tls_hint="try --insecure or --ca-file")


def _friendly_error_from_exception(exc: BaseException) -> str:
    from ...utils import friendly_error_from_exception

    return friendly_error_from_exception(exc, tls_hint="try --insecure or --ca-file")


def _is_connection_timeout_fail_record(record: dict[str, Any]) -> bool:
    if str(record.get("status") or "") != "fail":
        return False
    error_text = str(record.get("error") or "").strip().lower()
    return bool(error_text) and (
        error_text.startswith(_CONNECTION_TIMEOUT_PREFIX) or error_text.startswith(_CONNECTION_REFUSED_PREFIX)
    )


def _is_tls_verify_error(value: str | None) -> bool:
    text = str(value or "").strip().lower()
    return "tls verification failed" in text or "self signed certificate" in text or "certificate verify failed" in text


def _ssl_context(*, use_https: bool, insecure: bool, ca_file: str | None) -> ssl.SSLContext | None:
    if not use_https:
        return None
    cafile = (ca_file or "").strip() or None
    if insecure:
        ctx = ssl._create_unverified_context()
        return ctx
    return ssl.create_default_context(cafile=cafile)


def _basic_auth_value(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _kube_api_headers(token: str | None, username: str | None, password: str | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        return headers
    if username is not None or password is not None:
        headers["Authorization"] = _basic_auth_value(username or "", password or "")
    return headers


def _http_request(
    host: str,
    port: int,
    method: str,
    path: str,
    timeout: float,
    *,
    use_https: bool,
    insecure: bool,
    ca_file: str | None,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    client: HttpApiClient | None = None,
    response_size_cap: int = _KUBE_DATA_RESPONSE_CAP,
) -> tuple[int, bytes, dict[str, str], str | None]:
    scheme = "https" if use_https else "http"
    url = build_http_target_url(host, port, path, default_scheme=scheme)
    request_headers = {
        "User-Agent": "RedPosture/1.0",
        "Accept": "application/json",
    }
    if headers:
        request_headers.update(headers)
    request_client = client or HttpApiClient(
        HttpClientConfig(
            timeout=timeout,
            insecure=bool(use_https and insecure),
            ca_file=ca_file if use_https and ca_file else None,
            response_size_cap=int(response_size_cap),
        )
    )
    response = request_client.request(method, url, headers=request_headers, body=body, timeout=timeout)
    if response.error:
        return 0, b"", {}, _friendly_error_text(response.error)
    if response.truncated:
        return (
            int(response.status),
            b"",
            {str(k).lower(): str(v) for k, v in response.headers.items()},
            f"response exceeds {int(response_size_cap)} byte limit",
        )
    return int(response.status), response.body, {str(k).lower(): str(v) for k, v in response.headers.items()}, None


def _json_loads_bytes(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8", errors="replace"))


def _api_get_json(
    host: str,
    port: int,
    path: str,
    timeout: float,
    *,
    use_https: bool,
    insecure: bool,
    ca_file: str | None,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    client: HttpApiClient | None = None,
    response_size_cap: int = _KUBE_DATA_RESPONSE_CAP,
) -> tuple[int, Any, dict[str, str], str | None]:
    status, payload, headers, error = _http_request(
        host,
        port,
        "GET",
        path,
        timeout,
        use_https=use_https,
        insecure=insecure,
        ca_file=ca_file,
        headers=_kube_api_headers(token, username, password),
        client=client,
        response_size_cap=response_size_cap,
    )
    if error:
        return status, None, headers, error
    if not payload:
        return status, None, headers, None
    try:
        return status, _json_loads_bytes(payload), headers, None
    except json.JSONDecodeError:
        return status, None, headers, None


_PRODUCTION_API_GET_JSON = _api_get_json


def _state_http_client_or_none(
    state: KubeApiLifecycleState,
    *,
    response_size_cap: int,
) -> HttpApiClient | None:
    # Unit adapters and compatibility integrations may replace the transport
    # hook entirely. Avoid constructing an unused SSL context in that case.
    if _api_get_json is not _PRODUCTION_API_GET_JSON:
        return None
    return state.http_client(response_size_cap=response_size_cap)


def _recv_exact(sock: socket.socket, size: int, buffer: bytearray | None = None) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    if buffer:
        take = min(remaining, len(buffer))
        chunks.append(bytes(buffer[:take]))
        del buffer[:take]
        remaining -= take
    while remaining > 0:
        part = sock.recv(remaining)
        if not part:
            raise ConnectionError("unexpected EOF")
        chunks.append(part)
        remaining -= len(part)
    return b"".join(chunks)


def _ws_recv_frame_details(sock: socket.socket, buffer: bytearray | None = None) -> tuple[bool, int, bytes]:
    header = _recv_exact(sock, 2, buffer)
    b0 = header[0]
    b1 = header[1]
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    if length == 126:
        length = int.from_bytes(_recv_exact(sock, 2, buffer), "big")
    elif length == 127:
        length = int.from_bytes(_recv_exact(sock, 8, buffer), "big")
    mask_key = _recv_exact(sock, 4, buffer) if masked else b""
    payload = _recv_exact(sock, length, buffer) if length else b""
    if masked and payload:
        payload = bytes(byte ^ mask_key[idx % 4] for idx, byte in enumerate(payload))
    return fin, opcode, payload


def _ws_recv_frame(sock: socket.socket) -> tuple[int, bytes]:
    _fin, opcode, payload = _ws_recv_frame_details(sock)
    return opcode, payload


def _ws_send_control(sock: socket.socket, opcode: int, payload: bytes = b"") -> None:
    if len(payload) > 125:
        raise ValueError("websocket control payload is too large")
    mask_key = os.urandom(4)
    masked_payload = bytes(byte ^ mask_key[idx % 4] for idx, byte in enumerate(payload))
    frame = bytearray((0x80 | (opcode & 0x0F), 0x80 | len(payload)))
    frame.extend(mask_key)
    frame.extend(masked_payload)
    sock.sendall(bytes(frame))


def _ws_send_close(sock: socket.socket) -> None:
    try:
        _ws_send_control(sock, 0x8)
    except OSError:
        return


def _kube_exec_status_from_error_channel(raw: str) -> tuple[int | None, str | None, bool | None]:
    text = (raw or "").strip()
    if not text:
        return None, None, None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None, text, None
    if not isinstance(payload, dict):
        return None, text, None
    status_value = str(payload.get("status") or "").strip()
    if status_value.lower() == "success":
        return 0, None, True
    message = str(payload.get("message") or "").strip() or None
    details = payload.get("details")
    if isinstance(details, dict):
        causes = details.get("causes")
        if isinstance(causes, list):
            for item in causes:
                if not isinstance(item, dict):
                    continue
                if str(item.get("reason") or "").lower() != "exitcode":
                    continue
                value = str(item.get("message") or "").strip()
                if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
                    return int(value), message, False
    return None, message, False


def _kube_exec_ws(
    host: str,
    port: int,
    namespace: str,
    pod: str,
    command: str,
    timeout: float,
    *,
    use_https: bool,
    insecure: bool,
    ca_file: str | None,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "namespace": namespace,
        "pod": pod,
        "command": command,
        "ok": False,
        "stdout": "",
        "stderr": "",
        "error": None,
        "exit_code": None,
    }

    query: list[tuple[str, str]] = [
        ("command", "/bin/sh"),
        ("command", "-c"),
        ("command", command),
        ("stdin", "0"),
        ("stdout", "1"),
        ("stderr", "1"),
        ("tty", "0"),
    ]
    exec_path = (
        f"/api/v1/namespaces/{urllib.parse.quote(namespace, safe='')}/pods/{urllib.parse.quote(pod, safe='')}/exec"
        f"?{urllib.parse.urlencode(query, doseq=True)}"
    )
    headers = _kube_api_headers(token, username, password)
    sec_key = base64.b64encode(os.urandom(16)).decode("ascii")
    request_headers = {
        "Host": format_http_authority(host, port),
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": sec_key,
        "Sec-WebSocket-Protocol": "v4.channel.k8s.io",
        "User-Agent": "RedPosture/1.0",
    }
    request_headers.update(headers)

    sock: socket.socket | None = None
    try:
        raw_sock = socket.create_connection((host, port), timeout=min(max(timeout, 0.1), _KUBE_WS_HANDSHAKE_TIMEOUT))
        raw_sock.settimeout(min(max(timeout, 0.1), _KUBE_WS_HANDSHAKE_TIMEOUT))
        # Track raw_sock immediately so the `finally` closes it even if TLS wrap
        # (or ctx init) fails — otherwise the descriptor leaks on every failed
        # handshake (fd exhaustion over a large scan).
        sock = raw_sock
        if use_https:
            ctx = _ssl_context(use_https=True, insecure=insecure, ca_file=ca_file)
            if ctx is None:
                raise ValueError("failed to initialize TLS context")
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)

        request_exec_path = join_http_target_path(exec_path)
        req_lines = [f"GET {request_exec_path} HTTP/1.1"] + [f"{k}: {v}" for k, v in request_headers.items()] + ["", ""]
        sock.sendall("\r\n".join(req_lines).encode("utf-8"))

        response_buf = bytearray()
        while b"\r\n\r\n" not in response_buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("websocket handshake failed: unexpected EOF")
            response_buf.extend(chunk)
            if len(response_buf) > 65536:
                raise ConnectionError("websocket handshake failed: headers too large")
        header_bytes, remaining = bytes(response_buf).split(b"\r\n\r\n", 1)
        header_lines = header_bytes.decode("iso-8859-1", errors="replace").split("\r\n")
        if not header_lines:
            raise ConnectionError("websocket handshake failed: empty response")
        status_line = header_lines[0]
        try:
            status_code = int(status_line.split()[1])
        except Exception as exc:  # pragma: no cover - malformed response defensive path
            raise ConnectionError(f"websocket handshake failed: {status_line}") from exc
        header_map: dict[str, str] = {}
        for line in header_lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            header_map[key.strip().lower()] = value.strip()
        if status_code != 101:
            body_text = remaining.decode("utf-8", errors="replace").strip()
            if not body_text:
                body_text = f"status={status_code}"
            result["error"] = f"exec websocket handshake failed: {body_text}"
            return result
        expected_accept = base64.b64encode(
            hashlib.sha1((sec_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        ).decode("ascii")
        if header_map.get("sec-websocket-accept") != expected_accept:
            result["error"] = "exec websocket handshake failed: invalid server accept"
            return result
        if (
            "upgrade" not in header_map.get("connection", "").lower()
            or header_map.get("upgrade", "").lower() != "websocket"
        ):
            result["error"] = "exec websocket handshake failed: invalid upgrade headers"
            return result

        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        error_parts: list[str] = []
        exit_code: int | None = None
        terminal_status_seen = False
        timed_out = False
        frame_buffer = bytearray(remaining)
        fragmented_opcode: int | None = None
        fragmented_payload = bytearray()

        def _consume_message(payload: bytes) -> None:
            nonlocal exit_code, terminal_status_seen
            if not payload:
                return
            channel = payload[0]
            data_bytes = payload[1:]
            text = data_bytes.decode("utf-8", errors="replace")
            if channel == 1:
                stdout_parts.append(text)
            elif channel == 2:
                stderr_parts.append(text)
            elif channel == 3:
                parsed_exit, parsed_msg, parsed_success = _kube_exec_status_from_error_channel(text)
                if parsed_success is not None:
                    terminal_status_seen = True
                if parsed_exit is not None:
                    exit_code = parsed_exit
                elif parsed_success is True:
                    exit_code = 0
                if parsed_success is True:
                    return
                if parsed_msg:
                    error_parts.append(parsed_msg)
                elif text.strip():
                    error_parts.append(text)

        # Consume websocket stream until close or timeout.
        sock.settimeout(max(timeout, _KUBE_WS_READ_TIMEOUT))
        while True:
            try:
                fin, opcode, payload = _ws_recv_frame_details(sock, frame_buffer)
            except TimeoutError:
                timed_out = True
                break
            if opcode == 0x8:  # close
                break
            if opcode == 0x9:  # ping
                _ws_send_control(sock, 0xA, payload)
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode == 0x0:
                if fragmented_opcode is None:
                    error_parts.append("unexpected websocket continuation frame")
                    break
                fragmented_payload.extend(payload)
                if fin:
                    _consume_message(bytes(fragmented_payload))
                    fragmented_opcode = None
                    fragmented_payload.clear()
                continue
            if opcode not in {0x1, 0x2}:
                continue
            if fragmented_opcode is not None:
                error_parts.append("interleaved websocket fragmented messages")
                break
            if fin:
                _consume_message(payload)
            else:
                fragmented_opcode = opcode
                fragmented_payload.extend(payload)

        result["stdout"] = "".join(stdout_parts)
        result["stderr"] = "".join(stderr_parts)
        if exit_code is not None:
            result["exit_code"] = exit_code
        error_text = " ".join(part.strip() for part in error_parts if part.strip()).strip()
        if fragmented_opcode is not None and not error_text:
            error_text = "exec websocket closed with an incomplete fragmented message"
        if not terminal_status_seen and not error_text:
            error_text = (
                "exec websocket timed out before terminal status"
                if timed_out
                else "exec websocket closed before terminal status"
            )
        if error_text:
            result["error"] = _clip(error_text, 200)
        result["ok"] = terminal_status_seen and exit_code == 0 and not bool(result["error"])
        return result
    except (OSError, ssl.SSLError, ValueError, ConnectionError) as exc:
        result["error"] = _friendly_error_from_exception(exc)
        return result
    finally:
        if sock is not None:
            try:
                _ws_send_close(sock)
            except Exception:
                pass
            try:
                sock.close()
            except OSError:
                pass


def _kube_status_message(status: int, payload: Any) -> str | None:
    if isinstance(payload, dict):
        raw = payload.get("message")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        reason = payload.get("reason")
        if isinstance(reason, str) and reason.strip():
            return reason.strip()
        kind = payload.get("kind")
        if isinstance(kind, str) and kind == "Status":
            code = payload.get("code")
            if isinstance(code, int):
                return f"kubernetes status code={code}"
    if status in {401, 403}:
        return "authentication required"
    if status == 404:
        return "endpoint not found"
    return None


_KUBE_GIT_VERSION_RE = re.compile(r"^v(?P<major>\d+)\.(?P<minor>\d+)\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def _looks_like_kube_version_info(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    git_version = payload.get("gitVersion")
    major = payload.get("major")
    minor = payload.get("minor")
    if not isinstance(git_version, str) or not isinstance(major, (str, int)) or not isinstance(minor, (str, int)):
        return False
    match = _KUBE_GIT_VERSION_RE.fullmatch(git_version.strip())
    if match is None:
        return False
    major_text = str(major).strip()
    minor_text = str(minor).strip().removesuffix("+")
    return major_text == match.group("major") and minor_text == match.group("minor")


def _looks_like_kube_api_versions(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("kind") != "APIVersions" or payload.get("apiVersion") != "v1":
        return False
    versions = payload.get("versions")
    return isinstance(versions, list) and "v1" in versions


def _looks_like_kube_auth_status(status: int, payload: Any) -> bool:
    if status not in {401, 403} or not isinstance(payload, dict):
        return False
    expected_reason = "Unauthorized" if status == 401 else "Forbidden"
    return (
        payload.get("kind") == "Status"
        and payload.get("apiVersion") == "v1"
        and payload.get("status") == "Failure"
        and payload.get("reason") == expected_reason
        and payload.get("code") == status
    )


def _looks_like_kube_api_payload(payload: Any) -> bool:
    """Return only strong, endpoint-independent Kubernetes payload shapes."""

    return _looks_like_kube_version_info(payload) or _looks_like_kube_api_versions(payload)


def _kube_version_text(version_payload: Any) -> str | None:
    if not isinstance(version_payload, dict):
        return None
    for key in ("gitVersion", "git_version"):
        raw = version_payload.get(key)
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    major = version_payload.get("major")
    minor = version_payload.get("minor")
    if isinstance(major, str) and isinstance(minor, str) and major.strip() and minor.strip():
        return f"v{major.strip()}.{minor.strip()}"
    return None


def _normalize_namespace_filters(values: list[str] | None) -> list[str]:
    if not values:
        return []
    items: list[str] = []
    seen: set[str] = set()
    for raw in values:
        for part in str(raw).split(","):
            token = part.strip()
            if not token:
                continue
            key = token.lower()
            if key in seen:
                continue
            seen.add(key)
            items.append(token)
    return items


def _parse_pod_selector(value: str | None) -> tuple[str | None, str | None]:
    raw = str(value or "").strip()
    if not raw:
        return None, None
    if "/" in raw:
        left, right = raw.split("/", 1)
        namespace = left.strip() or None
        pod = right.strip() or None
        return namespace, pod
    return None, raw


def _resolve_exec_pod_target(
    pod_selector: str | None,
    namespace_filters: list[str],
    enumerated_pods: list[dict[str, Any]] | None,
) -> tuple[str | None, str | None, str | None]:
    namespace_hint, pod_name = _parse_pod_selector(pod_selector)
    if not pod_name:
        return None, None, "missing --pod"
    if namespace_hint:
        return namespace_hint, pod_name, None
    if len(namespace_filters) == 1:
        return namespace_filters[0], pod_name, None
    if not isinstance(enumerated_pods, list):
        return None, None, "pod namespace is ambiguous; use --namespace or --pod <namespace/pod>"
    matches = []
    for item in enumerated_pods:
        if not isinstance(item, dict):
            continue
        if str(item.get("name") or "").strip() != pod_name:
            continue
        ns = str(item.get("namespace") or "").strip()
        if ns:
            matches.append(ns)
    unique_matches = sorted(set(matches))
    if len(unique_matches) == 1:
        return unique_matches[0], pod_name, None
    if len(unique_matches) > 1:
        return None, None, f"multiple pods named '{pod_name}' found in namespaces: {','.join(unique_matches)}"
    return None, None, f"pod '{pod_name}' not found"


def _kube_list_path(base_path: str, *, limit: int, continue_token: str | None) -> str:
    params = {"limit": str(limit)}
    if continue_token:
        params["continue"] = continue_token
    return f"{base_path}?{urllib.parse.urlencode(params)}"


def _kube_list_items(
    host: str,
    port: int,
    base_path: str,
    timeout: float,
    *,
    use_https: bool,
    insecure: bool,
    ca_file: str | None,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    limit: int = _KUBE_LIST_PAGE_LIMIT,
    max_pages: int | None = None,
    client: HttpApiClient | None = None,
    response_size_cap: int = _KUBE_DATA_RESPONSE_CAP,
) -> tuple[list[dict[str, Any]] | None, int, str | None]:
    items: list[dict[str, Any]] = []
    continue_token: str | None = None
    last_status = 0
    effective_max_pages = _KUBE_MAX_LIST_PAGES if max_pages is None else max_pages
    for _page in range(max(1, int(effective_max_pages))):
        path = _kube_list_path(base_path, limit=limit, continue_token=continue_token)
        request_kwargs: dict[str, Any] = {
            "use_https": use_https,
            "insecure": insecure,
            "ca_file": ca_file,
            "token": token,
            "username": username,
            "password": password,
        }
        if client is not None:
            request_kwargs["client"] = client
        if response_size_cap != _KUBE_DATA_RESPONSE_CAP:
            request_kwargs["response_size_cap"] = response_size_cap
        status, payload, _headers, error = _api_get_json(host, port, path, timeout, **request_kwargs)
        last_status = status
        if error:
            return (items if items else None), status, f"partial: {error}" if items else error
        if status != 200:
            error_text = _kube_status_message(status, payload) or f"unexpected status={status}"
            return (items if items else None), status, f"partial: {error_text}" if items else error_text
        if not isinstance(payload, dict):
            error_text = "invalid kubernetes list response"
            return (items if items else None), status, f"partial: {error_text}" if items else error_text
        raw_items = payload.get("items")
        if not isinstance(raw_items, list):
            error_text = "invalid kubernetes list items payload"
            return (items if items else None), status, f"partial: {error_text}" if items else error_text
        for item in raw_items:
            if isinstance(item, dict):
                items.append(item)
        metadata = payload.get("metadata")
        next_token = None
        if isinstance(metadata, dict):
            raw_continue = metadata.get("continue")
            if isinstance(raw_continue, str) and raw_continue.strip():
                next_token = raw_continue.strip()
        if not next_token:
            return items, status, None
        continue_token = next_token
    return items, last_status, "partial: pagination limit exceeded"


def _metadata_name(item: dict[str, Any]) -> str:
    metadata = item.get("metadata")
    if not isinstance(metadata, dict):
        return "-"
    raw = metadata.get("name")
    return str(raw).strip() or "-"


def _metadata_namespace(item: dict[str, Any]) -> str:
    metadata = item.get("metadata")
    if not isinstance(metadata, dict):
        return "-"
    raw = metadata.get("namespace")
    return str(raw).strip() or "-"


def _decode_secret_data_value(raw_value: Any) -> str:
    if not isinstance(raw_value, str):
        return ""
    padded = raw_value + ("=" * (-len(raw_value) % 4))
    try:
        decoded = base64.b64decode(padded, validate=False)
    except Exception:
        return "<invalid-base64>"
    if not decoded:
        return "<empty>"
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return f"<binary:{len(decoded)}B>"
    safe = text.replace("\n", "\\n")
    if any(ord(ch) < 32 and ch not in "\t\r\n" for ch in text):
        return f"<binary-text:{len(decoded)}B>"
    return safe


def _list_namespaces(
    host: str,
    port: int,
    timeout: float,
    *,
    use_https: bool,
    insecure: bool,
    ca_file: str | None,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    client: HttpApiClient | None = None,
    limit: int = _KUBE_LIST_PAGE_LIMIT,
    max_pages: int | None = None,
    response_size_cap: int = _KUBE_DATA_RESPONSE_CAP,
) -> tuple[list[str] | None, int, str | None]:
    items, status, error = _kube_list_items(
        host,
        port,
        "/api/v1/namespaces",
        timeout,
        use_https=use_https,
        insecure=insecure,
        ca_file=ca_file,
        token=token,
        username=username,
        password=password,
        client=client,
        limit=limit,
        max_pages=max_pages,
        response_size_cap=response_size_cap,
    )
    if items is None:
        return None, status, error
    out = sorted({_metadata_name(item) for item in items if _metadata_name(item) != "-"})
    return out, status, error


def _probe_namespace_access(
    host: str,
    port: int,
    timeout: float,
    *,
    use_https: bool,
    insecure: bool,
    ca_file: str | None,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    client: HttpApiClient | None = None,
) -> tuple[bool | None, int, str | None]:
    """Check namespace-list access with exactly one bounded response page."""

    namespaces, status, error = _list_namespaces(
        host,
        port,
        timeout,
        use_https=use_https,
        insecure=insecure,
        ca_file=ca_file,
        token=token,
        username=username,
        password=password,
        client=client,
        limit=1,
        max_pages=1,
        response_size_cap=_KUBE_AUTH_RESPONSE_CAP,
    )
    if namespaces is not None:
        # A continuation token is expected here: this probe intentionally reads
        # only one item to classify access and is not a truncated data request.
        return True, status, None
    if status in {401, 403}:
        return False, status, error
    return None, status, error


def _list_pods(
    host: str,
    port: int,
    timeout: float,
    *,
    use_https: bool,
    insecure: bool,
    ca_file: str | None,
    namespaces: list[str],
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    client: HttpApiClient | None = None,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    results: list[dict[str, Any]] = []
    if namespaces:
        target_namespaces = namespaces
    else:
        target_namespaces = []

    if not target_namespaces:
        items, _status, error = _kube_list_items(
            host,
            port,
            "/api/v1/pods",
            timeout,
            use_https=use_https,
            insecure=insecure,
            ca_file=ca_file,
            token=token,
            username=username,
            password=password,
            client=client,
        )
        if items is None:
            return None, error
        partial_errors: list[str] = [error] if error else []
        for item in items:
            spec = item.get("spec")
            status_obj = item.get("status")
            phase = "-"
            if isinstance(status_obj, dict):
                raw_phase = status_obj.get("phase")
                if isinstance(raw_phase, str) and raw_phase.strip():
                    phase = raw_phase.strip()
            containers = 0
            if isinstance(spec, dict):
                raw_containers = spec.get("containers")
                if isinstance(raw_containers, list):
                    containers = sum(1 for entry in raw_containers if isinstance(entry, dict))
            results.append(
                {
                    "namespace": _metadata_namespace(item),
                    "name": _metadata_name(item),
                    "phase": phase,
                    "containers": containers,
                }
            )
    else:
        partial_errors = []
        for namespace in target_namespaces:
            encoded_ns = urllib.parse.quote(namespace, safe="")
            items, _status, error = _kube_list_items(
                host,
                port,
                f"/api/v1/namespaces/{encoded_ns}/pods",
                timeout,
                use_https=use_https,
                insecure=insecure,
                ca_file=ca_file,
                token=token,
                username=username,
                password=password,
                client=client,
            )
            if items is None:
                error_text = f"{namespace}: {error}" if error else f"{namespace}: request failed"
                if results:
                    partial_errors.append(f"partial: {error_text}")
                    break
                return None, error_text
            if error:
                partial_errors.append(f"{namespace}: {error}")
            for item in items:
                spec = item.get("spec")
                status_obj = item.get("status")
                phase = "-"
                if isinstance(status_obj, dict):
                    raw_phase = status_obj.get("phase")
                    if isinstance(raw_phase, str) and raw_phase.strip():
                        phase = raw_phase.strip()
                containers = 0
                if isinstance(spec, dict):
                    raw_containers = spec.get("containers")
                    if isinstance(raw_containers, list):
                        containers = sum(1 for entry in raw_containers if isinstance(entry, dict))
                results.append(
                    {
                        "namespace": namespace,
                        "name": _metadata_name(item),
                        "phase": phase,
                        "containers": containers,
                    }
                )
    results.sort(key=lambda item: (str(item.get("namespace") or ""), str(item.get("name") or "")))
    return results, "; ".join(partial_errors) or None


def _list_secrets(
    host: str,
    port: int,
    timeout: float,
    *,
    use_https: bool,
    insecure: bool,
    ca_file: str | None,
    namespaces: list[str],
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    client: HttpApiClient | None = None,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    results: list[dict[str, Any]] = []
    if not namespaces:
        items, _status, error = _kube_list_items(
            host,
            port,
            "/api/v1/secrets",
            timeout,
            use_https=use_https,
            insecure=insecure,
            ca_file=ca_file,
            token=token,
            username=username,
            password=password,
            client=client,
        )
        if items is None:
            return None, error
        partial_errors: list[str] = [error] if error else []
        iter_items: list[tuple[str | None, dict[str, Any]]] = [(None, item) for item in items]
    else:
        per_ns_items: list[tuple[str | None, dict[str, Any]]] = []
        partial_errors = []
        for namespace in namespaces:
            encoded_ns = urllib.parse.quote(namespace, safe="")
            items, _status, error = _kube_list_items(
                host,
                port,
                f"/api/v1/namespaces/{encoded_ns}/secrets",
                timeout,
                use_https=use_https,
                insecure=insecure,
                ca_file=ca_file,
                token=token,
                username=username,
                password=password,
                client=client,
            )
            if items is None:
                error_text = f"{namespace}: {error}" if error else f"{namespace}: request failed"
                if per_ns_items:
                    partial_errors.append(f"partial: {error_text}")
                    break
                return None, error_text
            if error:
                partial_errors.append(f"{namespace}: {error}")
            per_ns_items.extend((namespace, item) for item in items)
        iter_items = per_ns_items

    for forced_ns, item in iter_items:
        data_map = item.get("data")
        decoded_data: dict[str, str] = {}
        if isinstance(data_map, dict):
            for key in sorted(data_map.keys()):
                decoded_data[str(key)] = _decode_secret_data_value(data_map.get(key))
        results.append(
            {
                "namespace": forced_ns or _metadata_namespace(item),
                "name": _metadata_name(item),
                "type": str(item.get("type") or "-"),
                "data": decoded_data,
            }
        )
    results.sort(key=lambda item: (str(item.get("namespace") or ""), str(item.get("name") or "")))
    return results, "; ".join(partial_errors) or None


def _auth_label(token: str | None, username: str | None, password: str | None) -> str:
    if token:
        return "token auth"
    if username is not None or password is not None:
        return f"{username or ''}:{password or ''}"
    return "anonymous access"


def _call_audit_kubeapi_host_with_thread_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    use_https: bool,
    insecure: bool,
    ca_file: str | None,
    token: str | None,
    username: str | None,
    password: str | None,
    show_namespaces: bool,
    show_pods: bool,
    show_secrets: bool,
    namespace_filters: list[str],
    exec_pod: str | None,
    exec_command: str | None,
    debug: bool,
    run_deep_checks: bool,
    debug_emit: Callable[[str], None] | None,
) -> dict[str, Any]:
    def _invoke() -> dict[str, Any]:
        try:
            return _audit_kubeapi_host(
                host,
                port,
                timeout,
                retries,
                use_https=use_https,
                insecure=insecure,
                ca_file=ca_file,
                token=token,
                username=username,
                password=password,
                show_namespaces=show_namespaces,
                show_pods=show_pods,
                show_secrets=show_secrets,
                namespace_filters=namespace_filters,
                exec_pod=exec_pod,
                exec_command=exec_command,
                debug=debug,
                run_deep_checks=run_deep_checks,
            )
        except TypeError as exc:
            if not is_signature_compat_typeerror(exc, expected_keywords={"debug", "run_deep_checks"}):
                raise
            return _audit_kubeapi_host(
                host,
                port,
                timeout,
                retries,
                use_https=use_https,
                insecure=insecure,
                ca_file=ca_file,
                token=token,
                username=username,
                password=password,
                show_namespaces=show_namespaces,
                show_pods=show_pods,
                show_secrets=show_secrets,
                namespace_filters=namespace_filters,
                exec_pod=exec_pod,
                exec_command=exec_command,
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


def _audit_kubeapi_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    use_https: bool,
    insecure: bool,
    ca_file: str | None,
    token: str | None,
    username: str | None,
    password: str | None,
    show_namespaces: bool,
    show_pods: bool,
    show_secrets: bool,
    namespace_filters: list[str],
    exec_pod: str | None,
    exec_command: str | None,
    debug: bool = False,
    run_deep_checks: bool = True,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    debug_events: list[str] = []
    stages: list[dict[str, Any]] = []
    stage_durations_ms: dict[str, int] = {}
    stage_attempts: dict[str, int] = {}
    stage_failed_at: str | None = None
    debug_events_streamed = False

    def _debug(message: str) -> None:
        nonlocal debug_events_streamed
        if not debug:
            return
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

    def _emit_stage_timing_summary(*, status: str, attempts_done: int, max_attempts: int) -> None:
        def _duration(stage_name: str) -> str:
            raw = stage_durations_ms.get(stage_name)
            if isinstance(raw, int):
                return f"{raw}ms"
            return "-"

        def _attempt_count(stage_name: str) -> int:
            raw = stage_attempts.get(stage_name)
            return int(raw) if isinstance(raw, int) else 0

        _debug(
            f"stage_timing_summary status={status} attempts={attempts_done}/{max_attempts} "
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

    def _record(payload: dict[str, Any], *, attempts_done: int, max_attempts: int) -> dict[str, Any]:
        if debug:
            _emit_stage_timing_summary(
                status=str(payload.get("status") or "fail"),
                attempts_done=attempts_done,
                max_attempts=max_attempts,
            )
        record = dict(payload)
        record["attempts"] = int(attempts_done)
        record["max_attempts"] = int(max_attempts)
        record["stages"] = list(stages)
        record["stage_failed_at"] = stage_failed_at
        record["stage_durations_ms"] = dict(stage_durations_ms)
        record["stage_attempts"] = dict(stage_attempts)
        record["debug_events"] = list(debug_events) if debug else []
        record["debug_events_streamed"] = bool(debug_events_streamed)
        return record

    for attempt in range(attempts):
        started = time.monotonic()
        _debug(f"attempt={attempt + 1}/{attempts} start timeout={timeout}s")
        stage1_started = time.monotonic()
        try:
            effective_insecure = bool(insecure)
            tls_auto_insecure = False
            version_status, version_payload, _vh, version_error = _api_get_json(
                host,
                port,
                "/version",
                timeout,
                use_https=use_https,
                insecure=effective_insecure,
                ca_file=ca_file,
            )
            api_status, api_payload, _ah, api_error = _api_get_json(
                host,
                port,
                "/api",
                timeout,
                use_https=use_https,
                insecure=effective_insecure,
                ca_file=ca_file,
            )
            if (
                use_https
                and not effective_insecure
                and (_is_tls_verify_error(version_error) or _is_tls_verify_error(api_error))
            ):
                effective_insecure = True
                tls_auto_insecure = True
                version_status, version_payload, _vh, version_error = _api_get_json(
                    host,
                    port,
                    "/version",
                    timeout,
                    use_https=use_https,
                    insecure=effective_insecure,
                    ca_file=ca_file,
                )
                api_status, api_payload, _ah, api_error = _api_get_json(
                    host,
                    port,
                    "/api",
                    timeout,
                    use_https=use_https,
                    insecure=effective_insecure,
                    ca_file=ca_file,
                )

            version_confirmed = version_status == 200 and _looks_like_kube_version_info(version_payload)
            api_confirmed = api_status == 200 and _looks_like_kube_api_versions(api_payload)
            auth_status_confirmed = (
                api_status == version_status
                and _looks_like_kube_auth_status(version_status, version_payload)
                and _looks_like_kube_auth_status(api_status, api_payload)
            )
            version_text = _kube_version_text(version_payload) if version_confirmed else None
            is_kubeapi = version_confirmed or api_confirmed or auth_status_confirmed

            if not is_kubeapi:
                if version_error and api_error:
                    raise ValueError(version_error if version_error == api_error else f"{version_error}; {api_error}")
                _stage_trace(
                    _STAGE_DETECT_PROTOCOL,
                    attempt=attempt + 1,
                    started_at=stage1_started,
                    result="not_kubeapi",
                    error=None,
                )
                return _record(
                    {
                        "timestamp": utc_now_iso(),
                        "host": host,
                        "port": port,
                        "https": use_https,
                        "insecure_effective": effective_insecure,
                        "tls_auto_insecure": tls_auto_insecure,
                        "is_kubeapi": False,
                        "status": "not_kubeapi",
                        "version": version_text,
                        "auth_required": None,
                        "auth_mode": None,
                        "auth_valid": None,
                        "namespace_filters": list(namespace_filters),
                        "show_namespaces": show_namespaces,
                        "show_pods": show_pods,
                        "show_secrets": show_secrets,
                        "exec_pod": exec_pod,
                        "exec_command": exec_command,
                        "exec_result": None,
                        "namespaces": [],
                        "pods": [],
                        "secrets": [],
                        "namespaces_error": None,
                        "pods_error": None,
                        "secrets_error": None,
                        "error": None,
                        "elapsed_ms": int((time.monotonic() - started) * 1000),
                        "can_list_namespaces": None,
                        "can_list_pods": None,
                        "can_list_secrets": None,
                        "can_exec_pod": None,
                    },
                    attempts_done=attempt + 1,
                    max_attempts=attempts,
                )
            _stage_trace(
                _STAGE_DETECT_PROTOCOL,
                attempt=attempt + 1,
                started_at=stage1_started,
                result="ok",
                error=None,
            )

            # Determine whether unauthenticated namespace listing is allowed.
            stage2_started = time.monotonic()
            unauth_ns_items, unauth_ns_status, unauth_ns_error = _list_namespaces(
                host,
                port,
                timeout,
                use_https=use_https,
                insecure=effective_insecure,
                ca_file=ca_file,
            )
            auth_required: bool | None
            if unauth_ns_items is not None:
                auth_required = False
            elif unauth_ns_status in {401, 403}:
                auth_required = True
            else:
                auth_required = None

            token_clean = (token or "").strip() or None
            username_value = username if username is not None else None
            password_value = password if password is not None else None
            auth_mode = "none"
            if token_clean:
                auth_mode = "token"
            elif username_value is not None or password_value is not None:
                auth_mode = "basic"

            auth_valid: bool | None = None
            auth_error: str | None = None
            access_namespaces: list[str] | None = None
            namespaces_error: str | None = None

            if auth_mode == "none":
                access_namespaces = unauth_ns_items if unauth_ns_items is not None else None
                namespaces_error = unauth_ns_error
            else:
                access_namespaces, auth_ns_status, auth_ns_error = _list_namespaces(
                    host,
                    port,
                    timeout,
                    use_https=use_https,
                    insecure=effective_insecure,
                    ca_file=ca_file,
                    token=token_clean,
                    username=username_value,
                    password=password_value,
                )
                if access_namespaces is not None:
                    auth_valid = True
                elif auth_ns_status in {401, 403}:
                    auth_valid = False
                    auth_error = auth_ns_error or "authentication failed"
                else:
                    auth_valid = None
                    auth_error = auth_ns_error
                namespaces_error = auth_ns_error

            if auth_mode == "none":
                if auth_required is False:
                    status = "open_no_auth"
                elif auth_required is True:
                    status = "auth_required"
                else:
                    status = "detected"
            else:
                if auth_valid is True:
                    status = "auth_valid"
                elif auth_valid is False:
                    status = "auth_failed"
                else:
                    status = "detected"

            can_list_namespaces: bool | None = None
            if auth_mode == "none":
                if auth_required is False:
                    can_list_namespaces = True
                elif auth_required is True:
                    can_list_namespaces = False
            else:
                if auth_valid is True:
                    can_list_namespaces = True
                elif auth_valid is False:
                    can_list_namespaces = False

            _stage_trace(
                _STAGE_AUTH_INFERENCE,
                attempt=attempt + 1,
                started_at=stage2_started,
                result=status,
                error=auth_error,
            )

            base_record = {
                "timestamp": utc_now_iso(),
                "host": host,
                "port": port,
                "https": use_https,
                "insecure_effective": effective_insecure,
                "tls_auto_insecure": tls_auto_insecure,
                "is_kubeapi": True,
                "status": status,
                "version": version_text,
                "auth_required": auth_required,
                "auth_mode": auth_mode,
                "auth_valid": auth_valid,
                "auth_error": auth_error,
                "namespace_filters": list(namespace_filters),
                "show_namespaces": show_namespaces,
                "show_pods": show_pods,
                "show_secrets": show_secrets,
                "exec_pod": exec_pod,
                "exec_command": exec_command,
                "exec_result": None,
                "namespaces": [],
                "pods": [],
                "secrets": [],
                "namespaces_error": namespaces_error,
                "pods_error": None,
                "secrets_error": None,
                "error": None,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "can_list_namespaces": can_list_namespaces,
                "can_list_pods": None,
                "can_list_secrets": None,
                "can_exec_pod": None,
            }

            if not run_deep_checks:
                _debug(f"attempt={attempt + 1}/{attempts} detect-only result={status}")
                return _record(base_record, attempts_done=attempt + 1, max_attempts=attempts)

            if status not in {"open_no_auth", "auth_valid"}:
                _debug(f"stage2_gate=skip reason=status={status}")
                return _record(base_record, attempts_done=attempt + 1, max_attempts=attempts)

            _debug(f"stage2_gate=run reason=status={status}")
            stage3_started = time.monotonic()
            _stage_trace(
                _STAGE_ACCESS_CAPABILITIES,
                attempt=attempt + 1,
                started_at=stage3_started,
                result="ok",
                error=None,
            )

            namespaces_out: list[str] = []
            pods_out: list[dict[str, Any]] = []
            secrets_out: list[dict[str, Any]] = []
            exec_out: dict[str, Any] | None = None
            pods_error: str | None = None
            secrets_error: str | None = None
            can_list_pods: bool | None = None
            can_list_secrets: bool | None = None
            can_exec_pod: bool | None = None

            list_token = token_clean if auth_mode == "token" and auth_valid is True else None
            list_user = username_value if auth_mode == "basic" and auth_valid is True else None
            list_pass = password_value if auth_mode == "basic" and auth_valid is True else None

            can_list = (auth_mode == "none" and auth_required is False) or (auth_valid is True)
            stage4_started = time.monotonic()
            if can_list:
                if show_namespaces and access_namespaces is not None:
                    namespaces_out = list(access_namespaces)
                elif show_namespaces:
                    ns_items, _ns_status, ns_error = _list_namespaces(
                        host,
                        port,
                        timeout,
                        use_https=use_https,
                        insecure=effective_insecure,
                        ca_file=ca_file,
                        token=list_token,
                        username=list_user,
                        password=list_pass,
                    )
                    if ns_items is not None:
                        namespaces_out = ns_items
                        namespaces_error = ns_error
                    else:
                        namespaces_error = ns_error

                if show_pods:
                    pods_items, pods_error = _list_pods(
                        host,
                        port,
                        timeout,
                        use_https=use_https,
                        insecure=effective_insecure,
                        ca_file=ca_file,
                        namespaces=namespace_filters,
                        token=list_token,
                        username=list_user,
                        password=list_pass,
                    )
                    if pods_items is not None:
                        pods_out = pods_items
                        can_list_pods = True
                    else:
                        can_list_pods = False

                if show_secrets:
                    secret_items, secrets_error = _list_secrets(
                        host,
                        port,
                        timeout,
                        use_https=use_https,
                        insecure=effective_insecure,
                        ca_file=ca_file,
                        namespaces=namespace_filters,
                        token=list_token,
                        username=list_user,
                        password=list_pass,
                    )
                    if secret_items is not None:
                        secrets_out = secret_items
                        can_list_secrets = True
                    else:
                        can_list_secrets = False

                if exec_pod and exec_command:
                    pods_for_resolution = pods_out if pods_out else None
                    if pods_for_resolution is None and not namespace_filters:
                        pods_items, pods_lookup_error = _list_pods(
                            host,
                            port,
                            timeout,
                            use_https=use_https,
                            insecure=effective_insecure,
                            ca_file=ca_file,
                            namespaces=[],
                            token=list_token,
                            username=list_user,
                            password=list_pass,
                        )
                        if pods_items is not None:
                            pods_for_resolution = pods_items
                        else:
                            exec_out = {
                                "namespace": None,
                                "pod": str(exec_pod),
                                "command": str(exec_command),
                                "ok": False,
                                "stdout": "",
                                "stderr": "",
                                "error": f"pod lookup failed: {pods_lookup_error or 'request failed'}",
                                "exit_code": None,
                            }
                    if exec_out is None:
                        resolved_ns, resolved_pod, resolve_error = _resolve_exec_pod_target(
                            exec_pod,
                            namespace_filters,
                            pods_for_resolution,
                        )
                        if resolve_error:
                            exec_out = {
                                "namespace": None,
                                "pod": str(exec_pod),
                                "command": str(exec_command),
                                "ok": False,
                                "stdout": "",
                                "stderr": "",
                                "error": resolve_error,
                                "exit_code": None,
                            }
                        else:
                            exec_out = _kube_exec_ws(
                                host,
                                port,
                                resolved_ns or "",
                                resolved_pod or "",
                                str(exec_command),
                                timeout,
                                use_https=use_https,
                                insecure=effective_insecure,
                                ca_file=ca_file,
                                token=list_token,
                                username=list_user,
                                password=list_pass,
                            )
                    if isinstance(exec_out, dict):
                        if bool(exec_out.get("ok")):
                            can_exec_pod = True
                        else:
                            exec_error_text = str(exec_out.get("error") or "").lower()
                            if any(
                                token_text in exec_error_text
                                for token_text in (
                                    "forbidden",
                                    "access denied",
                                    "unauthorized",
                                    "not allowed",
                                    "exec unavailable",
                                )
                            ):
                                can_exec_pod = False
                elif exec_pod or exec_command:
                    exec_out = {
                        "namespace": None,
                        "pod": str(exec_pod or ""),
                        "command": str(exec_command or ""),
                        "ok": False,
                        "stdout": "",
                        "stderr": "",
                        "error": "use --pod together with -X/--exec-command",
                        "exit_code": None,
                    }
                    can_exec_pod = False
            elif exec_pod or exec_command:
                exec_out = {
                    "namespace": None,
                    "pod": str(exec_pod or ""),
                    "command": str(exec_command or ""),
                    "ok": False,
                    "stdout": "",
                    "stderr": "",
                    "error": "exec unavailable without successful API access",
                    "exit_code": None,
                }
                can_exec_pod = False

            data_error = "; ".join(
                str(item)
                for item in (
                    namespaces_error,
                    pods_error,
                    secrets_error,
                    str(exec_out.get("error") or "").strip() if isinstance(exec_out, dict) else None,
                )
                if str(item or "").strip()
            )
            data_requested = bool(show_namespaces or show_pods or show_secrets or exec_pod or exec_command)
            _stage_trace(
                _STAGE_DATA,
                attempt=attempt + 1,
                started_at=stage4_started,
                result="error" if data_error else "ok" if data_requested else "skipped",
                error=data_error or None,
            )

            final_record = dict(base_record)
            final_record.update(
                {
                    "exec_result": exec_out,
                    "namespaces": namespaces_out,
                    "pods": pods_out,
                    "secrets": secrets_out,
                    "namespaces_error": namespaces_error,
                    "pods_error": pods_error,
                    "secrets_error": secrets_error,
                    "can_list_pods": can_list_pods,
                    "can_list_secrets": can_list_secrets,
                    "can_exec_pod": can_exec_pod,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": None,
                }
            )
            _debug(
                f"attempt={attempt + 1}/{attempts} result={status} total_ms={int((time.monotonic() - started) * 1000)}"
            )
            return _record(final_record, attempts_done=attempt + 1, max_attempts=attempts)
        except (OSError, ValueError, ConnectionError) as exc:
            last_error = str(exc)
            if attempt < attempts - 1:
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
                    max_attempts=attempts,
                    delay_s=delay,
                    reason=last_error,
                )
                time.sleep(delay)
                continue
            _stage_trace(
                _STAGE_DETECT_PROTOCOL,
                attempt=attempt + 1,
                started_at=stage1_started,
                result="fail",
                error=last_error,
            )
            if attempt >= attempts - 1:
                break
    return _record(
        {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "https": use_https,
            "insecure_effective": bool(insecure),
            "tls_auto_insecure": False,
            "is_kubeapi": False,
            "status": "fail",
            "version": None,
            "auth_required": None,
            "auth_mode": None,
            "auth_valid": None,
            "auth_error": None,
            "namespace_filters": list(namespace_filters),
            "show_namespaces": show_namespaces,
            "show_pods": show_pods,
            "show_secrets": show_secrets,
            "exec_pod": exec_pod,
            "exec_command": exec_command,
            "exec_result": None,
            "namespaces": [],
            "pods": [],
            "secrets": [],
            "namespaces_error": None,
            "pods_error": None,
            "secrets_error": None,
            "error": _friendly_error_text(last_error or "connection failed"),
            "elapsed_ms": None,
            "can_list_namespaces": None,
            "can_list_pods": None,
            "can_list_secrets": None,
            "can_exec_pod": None,
        },
        attempts_done=attempts,
        max_attempts=attempts,
    )


def _merge_stage2_record(detect_record: dict[str, Any], deep_record: dict[str, Any]) -> dict[str, Any]:
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

    deep_fields = (
        "status",
        "version",
        "auth_required",
        "auth_mode",
        "auth_valid",
        "auth_error",
        "exec_result",
        "namespaces",
        "pods",
        "secrets",
        "namespaces_error",
        "pods_error",
        "secrets_error",
        "elapsed_ms",
        "error",
        "can_list_namespaces",
        "can_list_pods",
        "can_list_secrets",
        "can_exec_pod",
        "attempts",
        "max_attempts",
        "stages",
        "stage_failed_at",
        "stage_durations_ms",
        "stage_attempts",
    )
    for field in deep_fields:
        merged[field] = deep_record.get(field)
    return merged


def _kxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{_KUBE_TAG:<8}\t{host}\t{port}\t"


def _bool_text(value: bool | None) -> str:
    if value is True:
        return "True"
    if value is False:
        return "False"
    return "unknown"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    prefix = _kxc_prefix(record)
    status = str(record.get("status") or "fail")
    if status == "fail":
        err = _clip(str(record.get("error") or "connection failed"), 96)
        return f"{prefix} [!] connection failed err={err}"
    if status == "not_kubeapi":
        return f"{prefix} [-] not a Kubernetes API"

    version_text = str(record.get("version") or "-")
    auth_required_text = _bool_text(record.get("auth_required"))
    return f"{prefix} [*] Kubernetes API (auth required:{auth_required_text}) (version:{version_text})"


def _status_summary_line(record: dict[str, Any]) -> str | None:
    status = str(record.get("status") or "fail")
    if status in {"fail", "not_kubeapi"}:
        return None
    auth_mode = str(record.get("auth_mode") or "none")
    auth_valid = record.get("auth_valid")
    auth_error = str(record.get("auth_error") or "").strip()
    username = None
    password = None
    if auth_mode == "basic":
        # Not persisted in record intentionally; summary body is generic for JSON outputs.
        username = str(record.get("_username_display") or "")
        password = str(record.get("_password_display") or "")

    counts: list[str] = []
    if bool(record.get("show_namespaces")):
        counts.append(f"(namespaces:{len(record.get('namespaces') or [])})")
    if bool(record.get("show_pods")):
        counts.append(f"(pods:{len(record.get('pods') or [])})")
    if bool(record.get("show_secrets")):
        counts.append(f"(secrets:{len(record.get('secrets') or [])})")
    counts_text = f" {' '.join(counts)}" if counts else ""

    if auth_mode == "none":
        auth_required = record.get("auth_required")
        if auth_required is True:
            # The detect line already renders ``auth required:True``. Repeating
            # the same state as a negative result adds noise and can be
            # mistaken for a second failed check.
            return None
        if auth_required is False:
            return None
        return "[*] detected"

    if auth_valid is True:
        if auth_mode == "token":
            return f"[+] token auth{counts_text}"
        cred_display = f"{username or ''}:{password or ''}" if (username or password) else "basic auth"
        return f"[+] {cred_display}{counts_text}"
    if auth_valid is False:
        if auth_mode == "token":
            body = "[-] token auth failed"
        else:
            cred_display = f"{username or ''}:{password or ''}" if (username or password) else "basic auth"
            body = f"[-] {cred_display} auth failed"
        if auth_error:
            body += f" err={_clip(auth_error, 80)}"
        return body
    body = "[*] authentication check unavailable"
    if auth_error:
        body += f" err={_clip(auth_error, 80)}"
    return body


def _format_detail_records(record: dict[str, Any], output_format: str, *, debug: bool = False) -> list[str]:
    if output_format == "json":
        return []
    status = str(record.get("status") or "fail")
    if status in {"fail", "not_kubeapi"}:
        return []
    access_blocked = status in {"auth_required", "auth_failed"}
    if access_blocked and not debug:
        return []

    prefix = _kxc_prefix(record)
    lines: list[str] = []

    if bool(record.get("show_namespaces")):
        namespaces = record.get("namespaces")
        err = str(record.get("namespaces_error") or "").strip()
        lines.append(f"{prefix} [*] Namespaces")
        if isinstance(namespaces, list) and namespaces:
            for item in namespaces:
                lines.append(f"{prefix} {str(item)}")
        elif err:
            lines.append(f"{prefix} [-] namespaces unavailable: {_clip(err, 96)}")
        else:
            lines.append(f"{prefix} <no namespaces>")

    if bool(record.get("show_pods")) and not access_blocked:
        pods = record.get("pods")
        err = str(record.get("pods_error") or "").strip()
        filters = record.get("namespace_filters")
        ns_scope = ",".join(str(item) for item in filters) if isinstance(filters, list) and filters else "all"
        lines.append(f"{prefix} [*] Pods (namespace:{ns_scope})")
        if isinstance(pods, list) and pods:
            for item in pods:
                if not isinstance(item, dict):
                    continue
                ns = str(item.get("namespace") or "-")
                name = str(item.get("name") or "-")
                phase = str(item.get("phase") or "-")
                containers = int(item.get("containers") or 0)
                lines.append(f"{prefix} {ns}/{name} (phase:{phase}) (containers:{containers})")
        elif err:
            lines.append(f"{prefix} [-] pods unavailable: {_clip(err, 96)}")
        else:
            lines.append(f"{prefix} <no pods>")

    if bool(record.get("show_secrets")) and not access_blocked:
        secrets = record.get("secrets")
        err = str(record.get("secrets_error") or "").strip()
        filters = record.get("namespace_filters")
        ns_scope = ",".join(str(item) for item in filters) if isinstance(filters, list) and filters else "all"
        lines.append(f"{prefix} [*] Secrets (namespace:{ns_scope})")
        if isinstance(secrets, list) and secrets:
            for item in secrets:
                if not isinstance(item, dict):
                    continue
                ns = str(item.get("namespace") or "-")
                name = str(item.get("name") or "-")
                secret_type = str(item.get("type") or "-")
                data = item.get("data")
                key_count = len(data) if isinstance(data, dict) else 0
                lines.append(f"{prefix} {ns}/{name} (type:{secret_type}) (keys:{key_count})")
                if isinstance(data, dict):
                    for key in sorted(data.keys()):
                        lines.append(f"{prefix} {key}:{str(data.get(key) or '')}")
        elif err:
            lines.append(f"{prefix} [-] secrets unavailable: {_clip(err, 96)}")
        else:
            lines.append(f"{prefix} <no secrets>")

    exec_result = record.get("exec_result") if not access_blocked else None
    if isinstance(exec_result, dict):
        exec_ns = str(exec_result.get("namespace") or "").strip()
        exec_pod = str(exec_result.get("pod") or "").strip() or str(record.get("exec_pod") or "").strip() or "-"
        exec_target = f"{exec_ns}/{exec_pod}" if exec_ns else exec_pod
        command_text = str(exec_result.get("command") or record.get("exec_command") or "").strip()
        lines.append(f"{prefix} [*] Exec Pod {exec_target}")
        if command_text:
            lines.append(f"{prefix} [*] Command: {command_text}")
        ok = bool(exec_result.get("ok"))
        error_text = str(exec_result.get("error") or "").strip()
        exit_code = exec_result.get("exit_code")
        if ok:
            tail = ""
            if isinstance(exit_code, int):
                tail = f" (exit:{exit_code})"
            lines.append(f"{prefix} [+] exec succeeded{tail}")
        else:
            tail = ""
            if isinstance(exit_code, int):
                tail = f" (exit:{exit_code})"
            if error_text:
                lines.append(f"{prefix} [-] exec failed{tail} err={_clip(error_text, 120)}")
            else:
                lines.append(f"{prefix} [-] exec failed{tail}")

        stdout_text = str(exec_result.get("stdout") or "")
        stderr_text = str(exec_result.get("stderr") or "")
        if stdout_text:
            lines.append(f"{prefix} [*] STDOUT")
            for line in stdout_text.splitlines():
                lines.append(f"{prefix} {line}")
        if stderr_text:
            lines.append(f"{prefix} [*] STDERR")
            for line in stderr_text.splitlines():
                lines.append(f"{prefix} {line}")
        if not stdout_text and not stderr_text:
            lines.append(f"{prefix} <no exec output>")

    return lines


def _render_colored_kubeapi_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(
        console,
        line,
        tag=_KUBE_TAG,
        counts=(
            CountColorRule("secrets", "red"),
            CountColorRule("pods", "orange"),
            CountColorRule("namespaces", "orange"),
            CountColorRule("keys", "red"),
        ),
    ):
        return True
    if line.startswith(_KUBE_TAG) and "\t" in line:
        return render_tagged_detail_line(console, line, tag=_KUBE_TAG, default_color="orange")
    return False


def _lifecycle_get_json_with_retries(
    ctx: Any,
    state: KubeApiLifecycleState,
    path: str,
    *,
    response_size_cap: int,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> tuple[int, Any, dict[str, str], str | None]:
    attempts = max(1, int(getattr(ctx.args, "retries", 0) or 0) + 1)
    timeout = float(getattr(ctx.args, "timeout", 5.0))
    last_result: tuple[int, Any, dict[str, str], str | None] = (0, None, {}, "request failed")
    attempt = 0
    while attempt < attempts:
        client = _state_http_client_or_none(state, response_size_cap=response_size_cap)
        last_result = _api_get_json(
            str(ctx.host),
            int(ctx.port),
            path,
            timeout,
            use_https=state.use_https,
            insecure=state.insecure,
            ca_file=state.ca_file,
            token=token,
            username=username,
            password=password,
            response_size_cap=response_size_cap,
            **({"client": client} if client is not None else {}),
        )
        error = last_result[3]
        if error and state.use_https and not state.insecure and _is_tls_verify_error(error):
            state.insecure = True
            state.tls_auto_insecure = True
            # TLS fallback retries this endpoint immediately and does not
            # consume the caller's network retry budget.
            continue
        if not error:
            return last_result
        attempt += 1
        if attempt < attempts:
            time.sleep(_retry_delay(attempt - 1))
    return last_result


def detect_kubeapi(ctx: Any, options: dict[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, KubeApiLifecycleState):
        raise TypeError("kubeapi lifecycle state is unavailable")
    target_scheme = str(ctx.target.scheme or "").lower() if ctx.target is not None else ""
    state.use_https = (
        target_scheme == "https" if target_scheme in {"http", "https"} else bool(getattr(ctx.args, "https", True))
    )
    state.insecure = bool(getattr(ctx.args, "insecure", False))
    state.ca_file = getattr(ctx.args, "ca_file", None) or getattr(ctx.args, "tls_ca", None)
    started = time.monotonic()
    version_status, version_payload, _headers, version_error = _lifecycle_get_json_with_retries(
        ctx,
        state,
        "/version",
        response_size_cap=_KUBE_DETECT_RESPONSE_CAP,
    )
    version_confirmed = version_status == 200 and _looks_like_kube_version_info(version_payload)
    version_auth_status = _looks_like_kube_auth_status(version_status, version_payload)
    api_status = 0
    api_payload: Any = None
    api_error: str | None = None
    if not version_confirmed:
        # A transport failure on /version applies to the same authority and is
        # retried in place. Do not double the unreachable-target budget by
        # blindly issuing /api as well.
        if version_error:
            return {
                "timestamp": utc_now_iso(),
                "host": str(ctx.host),
                "port": int(ctx.port),
                "https": state.use_https,
                "insecure_effective": state.insecure,
                "tls_auto_insecure": state.tls_auto_insecure,
                "is_kubeapi": False,
                "status": "fail",
                "version": None,
                "auth_required": None,
                "error": version_error,
            }
        api_status, api_payload, _headers, api_error = _lifecycle_get_json_with_retries(
            ctx,
            state,
            "/api",
            response_size_cap=_KUBE_DETECT_RESPONSE_CAP,
        )

    api_confirmed = api_status == 200 and _looks_like_kube_api_versions(api_payload)
    auth_status_confirmed = (
        version_auth_status and api_status == version_status and _looks_like_kube_auth_status(api_status, api_payload)
    )
    is_kubeapi = version_confirmed or api_confirmed or auth_status_confirmed
    version = _kube_version_text(version_payload) if version_confirmed else None
    if not is_kubeapi:
        last_error = api_error
        return {
            "timestamp": utc_now_iso(),
            "host": str(ctx.host),
            "port": int(ctx.port),
            "https": state.use_https,
            "insecure_effective": state.insecure,
            "tls_auto_insecure": state.tls_auto_insecure,
            "is_kubeapi": False,
            "status": "fail" if last_error else "not_kubeapi",
            "version": version,
            "auth_required": None,
            "error": last_error,
        }

    namespace_access: bool | None
    ns_status: int
    ns_error: str | None
    if auth_status_confirmed:
        namespace_access, ns_status, ns_error = (
            False,
            version_status,
            _kube_status_message(version_status, version_payload),
        )
    else:
        namespace_access, ns_status, ns_error = _probe_namespace_access(
            str(ctx.host),
            int(ctx.port),
            float(getattr(ctx.args, "timeout", 5.0)),
            use_https=state.use_https,
            insecure=state.insecure,
            ca_file=state.ca_file,
            client=_state_http_client_or_none(state, response_size_cap=_KUBE_AUTH_RESPONSE_CAP),
        )
    namespaces: list[str] | None = [] if namespace_access is True else None
    state.anonymous_namespaces = namespaces
    state.anonymous_namespaces_error = ns_error
    state.access_namespaces = namespaces
    state.access_namespaces_error = ns_error
    auth_required = False if namespace_access is True else True if namespace_access is False else None
    return {
        "timestamp": utc_now_iso(),
        "host": str(ctx.host),
        "port": int(ctx.port),
        "https": state.use_https,
        "insecure_effective": state.insecure,
        "tls_auto_insecure": state.tls_auto_insecure,
        "is_kubeapi": True,
        "status": "open_no_auth" if auth_required is False else "auth_required" if auth_required else "detected",
        "version": version,
        "auth_required": auth_required,
        "auth_mode": "none",
        "auth_valid": None,
        "auth_error": None,
        "namespace_filters": list(options["namespace_filters"]),
        "show_namespaces": bool(options["show_namespaces"]),
        "show_pods": bool(options["show_pods"]),
        "show_secrets": bool(options["show_secrets"]),
        "exec_pod": options["exec_pod"],
        "exec_command": options["exec_command"],
        "exec_result": None,
        "namespaces": [],
        "pods": [],
        "secrets": [],
        "namespaces_error": ns_error,
        "pods_error": None,
        "secrets_error": None,
        "can_list_namespaces": namespace_access,
        "can_list_pods": None,
        "can_list_secrets": None,
        "can_exec_pod": None,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "error": None,
    }


def authenticate_kubeapi(ctx: Any, detect_record: Any, _options: dict[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, KubeApiLifecycleState):
        raise TypeError("kubeapi lifecycle state is unavailable")
    record = dict(detect_record.to_dict() if hasattr(detect_record, "to_dict") else detect_record)
    credential = ctx.credential
    if credential.token is None and credential.username is None and credential.password is None:
        return record
    namespace_access, status, error = _probe_namespace_access(
        str(ctx.host),
        int(ctx.port),
        float(getattr(ctx.args, "timeout", 5.0)),
        use_https=state.use_https,
        insecure=state.insecure,
        ca_file=state.ca_file,
        token=credential.token,
        username=credential.username,
        password=credential.password,
        client=_state_http_client_or_none(state, response_size_cap=_KUBE_AUTH_RESPONSE_CAP),
    )
    # Kubernetes deliberately distinguishes unauthenticated (401) from an
    # authenticated principal that lacks this cluster-wide capability (403).
    # Namespace-scoped service-account tokens must not be rejected solely
    # because they cannot list every namespace.
    # A Kubernetes bearer token can be valid while being forbidden from the
    # cluster-wide namespaces collection.  Do not apply that inference to
    # Basic credentials: a generic 403 does not prove that pair was accepted.
    anonymous_open = state.anonymous_namespaces is not None
    # A 403 can prove that a bearer token was authenticated only when the
    # anonymous baseline itself was not usable. If anonymous access is open,
    # the same forbidden response cannot distinguish an accepted token from an
    # ignored/invalid one and must not be promoted to auth_valid.
    ok = namespace_access is True or (status == 403 and credential.token is not None and not anonymous_open)
    if ok:
        state.access_namespaces = [] if namespace_access is True else None
        state.access_namespaces_error = error
        state.token, state.username, state.password = credential.token, credential.username, credential.password
    record.update(
        {
            "timestamp": utc_now_iso(),
            "status": "auth_valid" if ok else "invalid_credentials_anonymous" if anonymous_open else "auth_failed",
            "auth_mode": "token" if credential.token else "basic",
            "auth_valid": bool(ok),
            "auth_error": (
                "credential accepted but cluster-wide namespace listing is forbidden"
                if ok and namespace_access is not True and status == 403
                else None
                if ok
                else error or f"authentication failed status={status}"
            ),
            "namespaces_error": error,
            "can_list_namespaces": namespace_access is True,
        }
    )
    return record


def collect_kubeapi_data(ctx: Any, source_record: Any, options: dict[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, KubeApiLifecycleState):
        raise TypeError("kubeapi lifecycle state is unavailable")
    if state.deep_record is not None:
        return state.deep_record
    record = dict(source_record.to_dict() if hasattr(source_record, "to_dict") else source_record)
    token, username, password = state.token, state.username, state.password
    if str(record.get("status") or "") == "invalid_credentials_anonymous":
        token = username = password = None
        state.access_namespaces = state.anonymous_namespaces
    needs_http_data = bool(options["show_namespaces"] or options["show_pods"] or options["show_secrets"])
    data_client = (
        _state_http_client_or_none(state, response_size_cap=_KUBE_DATA_RESPONSE_CAP) if needs_http_data else None
    )
    namespaces_out: list[str] = []
    namespaces_error = state.access_namespaces_error
    if options["show_namespaces"]:
        full_namespaces, _namespace_status, namespaces_error = _list_namespaces(
            str(ctx.host),
            int(ctx.port),
            float(getattr(ctx.args, "timeout", 5.0)),
            use_https=state.use_https,
            insecure=state.insecure,
            ca_file=state.ca_file,
            token=token,
            username=username,
            password=password,
            client=data_client,
        )
        namespaces_out = list(full_namespaces or [])
    pods_out: list[dict[str, Any]] = []
    secrets_out: list[dict[str, Any]] = []
    pods_error: str | None = None
    secrets_error: str | None = None
    if options["show_pods"] or (options["exec_pod"] and not options["namespace_filters"]):
        pods, pods_error = _list_pods(
            str(ctx.host),
            int(ctx.port),
            float(getattr(ctx.args, "timeout", 5.0)),
            use_https=state.use_https,
            insecure=state.insecure,
            ca_file=state.ca_file,
            namespaces=list(options["namespace_filters"]),
            token=token,
            username=username,
            password=password,
            client=data_client,
        )
        if pods is None and not pods_error:
            pods_error = "pods request failed"
        pods_out = list(pods or [])
    if options["show_secrets"]:
        secrets, secrets_error = _list_secrets(
            str(ctx.host),
            int(ctx.port),
            float(getattr(ctx.args, "timeout", 5.0)),
            use_https=state.use_https,
            insecure=state.insecure,
            ca_file=state.ca_file,
            namespaces=list(options["namespace_filters"]),
            token=token,
            username=username,
            password=password,
            client=data_client,
        )
        if secrets is None and not secrets_error:
            secrets_error = "secrets request failed"
        secrets_out = list(secrets or [])
    exec_result: dict[str, Any] | None = None
    if options["exec_pod"] and options["exec_command"]:
        resolved_ns, resolved_pod, resolve_error = _resolve_exec_pod_target(
            options["exec_pod"],
            list(options["namespace_filters"]),
            pods_out or None,
        )
        if resolve_error:
            exec_result = {
                "namespace": None,
                "pod": options["exec_pod"],
                "command": options["exec_command"],
                "ok": False,
                "stdout": "",
                "stderr": "",
                "error": resolve_error,
                "exit_code": None,
            }
        else:
            exec_result = _kube_exec_ws(
                str(ctx.host),
                int(ctx.port),
                resolved_ns or "",
                resolved_pod or "",
                str(options["exec_command"]),
                float(getattr(ctx.args, "timeout", 5.0)),
                use_https=state.use_https,
                insecure=state.insecure,
                ca_file=state.ca_file,
                token=token,
                username=username,
                password=password,
            )
    record.update(
        {
            "namespaces": namespaces_out,
            "pods": pods_out if options["show_pods"] else [],
            "secrets": secrets_out,
            "exec_result": exec_result,
            "namespaces_error": namespaces_error,
            "pods_error": pods_error,
            "secrets_error": secrets_error,
            "can_list_pods": None if not options["show_pods"] else pods_error is None,
            "can_list_secrets": None if not options["show_secrets"] else secrets_error is None,
            "can_exec_pod": None if exec_result is None else bool(exec_result.get("ok")),
        }
    )
    state.deep_record = record
    return record


# Typed runner boundary -----------------------------------------------------
host_stage = _call_audit_kubeapi_host_with_thread_debug
