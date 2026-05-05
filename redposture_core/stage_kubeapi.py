"""Kubernetes API audit stage."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .console import Console
from .logger import AttemptLogger
from .progress import ProgressBar
from .utils import (
    build_scan_execution_groups,
    collect_scan_ports,
    collect_scan_target_specs,
    filter_open_tcp_hosts_for_credential_file,
    is_signature_compat_typeerror,
    parse_username_password_credential_file,
    utc_now_iso,
)

_KUBE_TAG = "KUBEAPI"
_KUBE_LIST_PAGE_LIMIT = 500
_KUBE_MAX_LIST_PAGES = 40
_KUBE_WS_READ_TIMEOUT = 3.0
_KUBE_WS_HANDSHAKE_TIMEOUT = 5.0
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_CONNECTION_REFUSED_PREFIX = "connection refused"

_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
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
    text = (value or "").strip()
    if not text:
        return "connection failed"
    if text.startswith("<urlopen error ") and text.endswith(">"):
        text = text[len("<urlopen error ") : -1].strip()
    lower = text.lower()
    if "certificate verify failed" in lower or "self signed certificate" in lower:
        return "tls verification failed (try --insecure or --ca-file)"
    if "wrong version number" in lower or "ssl" in lower and "http request" in lower:
        return "tls/http protocol mismatch"
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
    if isinstance(exc, TimeoutError):
        return "connection timeout"
    return _friendly_error_text(str(exc))


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
) -> tuple[int, bytes, dict[str, str], str | None]:
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}{path}"
    request_headers = {
        "User-Agent": "RedPosture/1.0",
        "Accept": "application/json",
    }
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, data=body, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
            context=_ssl_context(use_https=use_https, insecure=insecure, ca_file=ca_file),
        ) as response:
            status = int(response.status)
            payload = response.read()
            response_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
            return status, payload, response_headers, None
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        response_headers = {str(k).lower(): str(v) for k, v in exc.headers.items()}
        return int(exc.code), payload, response_headers, None
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        return 0, b"", {}, _friendly_error_from_exception(exc)


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
    )
    if error:
        return status, None, headers, error
    if not payload:
        return status, None, headers, None
    try:
        return status, _json_loads_bytes(payload), headers, None
    except json.JSONDecodeError:
        return status, None, headers, None


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        part = sock.recv(remaining)
        if not part:
            raise ConnectionError("unexpected EOF")
        chunks.append(part)
        remaining -= len(part)
    return b"".join(chunks)


def _ws_recv_frame(sock: socket.socket) -> tuple[int, bytes]:
    header = _recv_exact(sock, 2)
    b0 = header[0]
    b1 = header[1]
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    if length == 126:
        length = int.from_bytes(_recv_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(_recv_exact(sock, 8), "big")
    mask_key = _recv_exact(sock, 4) if masked else b""
    payload = _recv_exact(sock, length) if length else b""
    if masked and payload:
        payload = bytes(byte ^ mask_key[idx % 4] for idx, byte in enumerate(payload))
    return opcode, payload


def _ws_send_close(sock: socket.socket) -> None:
    payload = b""
    mask_key = os.urandom(4)
    masked_payload = payload
    frame = bytearray()
    frame.append(0x88)  # FIN + close opcode
    frame.append(0x80 | len(masked_payload))
    frame.extend(mask_key)
    frame.extend(masked_payload)
    try:
        sock.sendall(bytes(frame))
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
        "Host": f"{host}:{port}",
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
        if use_https:
            ctx = _ssl_context(use_https=True, insecure=insecure, ca_file=ca_file)
            if ctx is None:
                raise ValueError("failed to initialize TLS context")
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        req_lines = [f"GET {exec_path} HTTP/1.1"] + [f"{k}: {v}" for k, v in request_headers.items()] + ["", ""]
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

        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        error_parts: list[str] = []
        exit_code: int | None = None

        # Consume websocket stream until close or timeout.
        sock.settimeout(max(timeout, _KUBE_WS_READ_TIMEOUT))
        while True:
            try:
                opcode, payload = _ws_recv_frame(sock)
            except TimeoutError:
                break
            if opcode == 0x8:  # close
                break
            if opcode == 0x9:  # ping
                # Ignore pings; close soon after command completes.
                continue
            if opcode not in {0x1, 0x2} or not payload:
                continue
            channel = payload[0]
            data_bytes = payload[1:]
            text = data_bytes.decode("utf-8", errors="replace")
            if channel == 1:
                stdout_parts.append(text)
            elif channel == 2:
                stderr_parts.append(text)
            elif channel == 3:
                parsed_exit, parsed_msg, parsed_success = _kube_exec_status_from_error_channel(text)
                if parsed_exit is not None:
                    exit_code = parsed_exit
                if parsed_success is True:
                    continue
                if parsed_msg:
                    error_parts.append(parsed_msg)
                elif text.strip():
                    error_parts.append(text)

        result["stdout"] = "".join(stdout_parts)
        result["stderr"] = "".join(stderr_parts)
        if exit_code is not None:
            result["exit_code"] = exit_code
        error_text = " ".join(part.strip() for part in error_parts if part.strip()).strip()
        if error_text:
            result["error"] = _clip(error_text, 200)
        # K8s exec often reports success via channel 3 status payload with no exit code.
        result["ok"] = (exit_code in {None, 0}) and not bool(result["error"])
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


def _looks_like_kube_api_payload(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if isinstance(payload.get("gitVersion"), str):
        return True
    kind = payload.get("kind")
    if isinstance(kind, str) and kind in {"APIVersions", "APIGroupList", "Status", "NamespaceList"}:
        return True
    versions = payload.get("versions")
    if isinstance(versions, list) and any(isinstance(item, str) for item in versions):
        return True
    api_version = payload.get("apiVersion")
    if isinstance(api_version, str) and api_version.startswith("v1"):
        return True
    return False


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
) -> tuple[list[dict[str, Any]] | None, int, str | None]:
    items: list[dict[str, Any]] = []
    continue_token: str | None = None
    last_status = 0
    for _page in range(_KUBE_MAX_LIST_PAGES):
        path = _kube_list_path(base_path, limit=limit, continue_token=continue_token)
        status, payload, _headers, error = _api_get_json(
            host,
            port,
            path,
            timeout,
            use_https=use_https,
            insecure=insecure,
            ca_file=ca_file,
            token=token,
            username=username,
            password=password,
        )
        last_status = status
        if error:
            return None, status, error
        if status != 200:
            return None, status, _kube_status_message(status, payload) or f"unexpected status={status}"
        if not isinstance(payload, dict):
            return None, status, "invalid kubernetes list response"
        raw_items = payload.get("items")
        if not isinstance(raw_items, list):
            return None, status, "invalid kubernetes list items payload"
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
    return items, last_status, "pagination limit exceeded"


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
    )
    if items is None:
        return None, status, error
    out = sorted({_metadata_name(item) for item in items if _metadata_name(item) != "-"})
    return out, status, None


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
        )
        if items is None:
            return None, error
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
            )
            if items is None:
                return None, f"{namespace}: {error}" if error else f"{namespace}: request failed"
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
    return results, None


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
        )
        if items is None:
            return None, error
        iter_items = [(None, item) for item in items]
    else:
        per_ns_items: list[tuple[str | None, dict[str, Any]]] = []
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
            )
            if items is None:
                return None, f"{namespace}: {error}" if error else f"{namespace}: request failed"
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
    return results, None


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

            version_text = _kube_version_text(version_payload)
            is_kubeapi = (
                bool(version_text)
                or _looks_like_kube_api_payload(api_payload)
                or _looks_like_kube_api_payload(version_payload)
            )
            if not is_kubeapi and version_status in {401, 403} and _looks_like_kube_api_payload(version_payload):
                is_kubeapi = True
            if not is_kubeapi and api_status in {401, 403} and _looks_like_kube_api_payload(api_payload):
                is_kubeapi = True

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
                item
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

    auth_required_text = _bool_text(record.get("auth_required"))
    version_text = str(record.get("version") or "-")
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
            return "[-] authentication required"
        if auth_required is False:
            return f"[+] anonymous access{counts_text}"
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


def _format_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format == "json":
        return []
    status = str(record.get("status") or "fail")
    if status in {"fail", "not_kubeapi"}:
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

    if bool(record.get("show_pods")):
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

    if bool(record.get("show_secrets")):
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

    exec_result = record.get("exec_result")
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
    if not line.startswith(_KUBE_TAG):
        return False

    marker_color = {"[*]": "cyan", "[+]": "bright_green", "[-]": "red", "[!]": "red"}
    for marker in ("[!]", "[-]", "[+]", "[*]"):
        token = f" {marker} "
        if token not in line:
            continue
        left, right = line.split(token, 1)
        tag = _KUBE_TAG
        rest = left[len(tag) :] if left.startswith(tag) else left

        spans: list[tuple[int, int, str]] = []
        for fragment, color in (
            ("(auth required:True)", "bright_green"),
            ("(auth required:False)", "red"),
            ("(auth required:unknown)", "yellow"),
        ):
            idx = right.find(fragment)
            if idx >= 0:
                spans.append((idx, idx + len(fragment), color))

        for pattern, color in (
            (r"\(secrets:(\d+)\)", "red"),
            (r"\(pods:(\d+)\)", "orange"),
            (r"\(namespaces:(\d+)\)", "orange"),
            (r"\(keys:(\d+)\)", "red"),
        ):
            match = re.search(pattern, right)
            if match and match.group(1).isdigit() and int(match.group(1)) > 0:
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

        rendered = (
            f"{console._paint(tag, 'blue', sys.stdout)}"
            f"{console._paint(rest, 'white', sys.stdout)} "
            f"{console._paint(marker, marker_color.get(marker, 'white'), sys.stdout)} "
            f"{right_colored}"
        )
        console.plain(rendered)
        return True
    return False


def _emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
    if emit_line is not None:
        emit_line(line)


def audit_kubeapi_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
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
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
    suppress_timeout_status_lines: bool = False,
    debug_emit: Callable[[str], None] | None = None,
    show_progress: bool = True,
) -> tuple[int, int, int]:
    total = 0
    detected = 0
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
        progress = ProgressBar("KUBEAPI", len(indexed_hosts), enabled=show_progress, leave=True)

        if debug_emit is not None:
            debug_emit(f"pass=1 detect start total={len(indexed_hosts)}")

        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            pass1_future_map = {
                executor.submit(
                    _call_audit_kubeapi_host_with_thread_debug,
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
                    debug=bool(debug_emit),
                    run_deep_checks=False,
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
                    if output_format == "txt":
                        suppress_timeout_detect_line = (
                            suppress_timeout_status_lines
                            and output_format == "txt"
                            and str(detect_record.get("status") or "") == "fail"
                        )
                        if not suppress_timeout_detect_line:
                            record_for_output = dict(detect_record)
                            if username is not None or password is not None:
                                record_for_output["_username_display"] = username or ""
                                record_for_output["_password_display"] = password or ""
                            _emit_line(out_fh, emit_line, _format_detect_record(record_for_output, output_format))
                    next_emit_idx += 1

        deep_candidates: list[tuple[int, str]] = []
        detected_total = 0
        for idx, host in indexed_hosts:
            detect_record = detect_records[idx]
            detect_status = str(detect_record.get("status") or "fail")
            if not bool(detect_record.get("is_kubeapi")):
                if debug_emit is not None:
                    debug_emit(f"{host}:{port} stage2_gate=skip reason=not_kubeapi")
                continue
            detected_total += 1
            if detect_status in {"open_no_auth", "auth_valid"}:
                deep_candidates.append((idx, host))
                if debug_emit is not None:
                    debug_emit(f"{host}:{port} stage2_gate=run reason=status={detect_status}")
            elif debug_emit is not None:
                debug_emit(f"{host}:{port} stage2_gate=skip reason=status={detect_status}")

        if debug_emit is not None:
            debug_emit(f"pass=1 detect complete kubeapi={detected_total} deep_candidates={len(deep_candidates)}")

        progress.set_total(len(indexed_hosts) + len(deep_candidates))
        if debug_emit is not None:
            debug_emit(f"pass=2 deep start total={len(deep_candidates)}")

        if deep_candidates:
            with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
                pass2_future_map = {
                    executor.submit(
                        _call_audit_kubeapi_host_with_thread_debug,
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
                        debug=bool(debug_emit),
                        run_deep_checks=True,
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
            if bool(record.get("is_kubeapi")):
                detected += 1
            if str(record.get("status") or "fail") == "fail":
                failed += 1

            if debug_emit is not None and not bool(record.get("debug_events_streamed")):
                for event in record.get("debug_events") or []:
                    if isinstance(event, str) and event.strip():
                        debug_emit(event)

            # Add masked/basic display only for text summary formatting.
            record_for_output = dict(record)
            if username is not None or password is not None:
                record_for_output["_username_display"] = username or ""
                record_for_output["_password_display"] = password or ""

            if output_format != "txt":
                _emit_line(out_fh, emit_line, _format_detect_record(record_for_output, output_format))

            if output_format == "txt":
                suppress_timeout_detect_line = (
                    suppress_timeout_status_lines
                    and output_format == "txt"
                    and str(record_for_output.get("status") or "") == "fail"
                )
                status_line = _status_summary_line(record_for_output)
                suppress_auth_required_status_line = (
                    bool(record_for_output.get("is_kubeapi"))
                    and str(record_for_output.get("status") or "") == "auth_required"
                )
                if status_line and not suppress_auth_required_status_line and not suppress_timeout_detect_line:
                    _emit_line(out_fh, emit_line, f"{_kxc_prefix(record_for_output)} {status_line}")
                for detail in _format_detail_records(record_for_output, output_format):
                    _emit_line(out_fh, emit_line, detail)

            if logger is not None:
                logger.log(
                    "kubeapi",
                    (str(record.get("host") or "-"), int(record.get("port") or port)),
                    phase="audit",
                    status=record.get("status"),
                    auth_required=record.get("auth_required"),
                    auth_mode=record.get("auth_mode"),
                    auth_valid=record.get("auth_valid"),
                    version=record.get("version"),
                    namespaces=len(record.get("namespaces") or []),
                    pods=len(record.get("pods") or []),
                    secrets=len(record.get("secrets") or []),
                    exec_ok=bool((record.get("exec_result") or {}).get("ok"))
                    if isinstance(record.get("exec_result"), dict)
                    else None,
                    error=record.get("error"),
                )
    finally:
        if progress is not None:
            progress.close()
        if out_fh is not None:
            out_fh.close()

    return total, detected, failed


def run_kubeapi_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
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
        console.error("kubeapi requires -t/--targets")
        return 2
    hosts = list(dict.fromkeys(spec.host for spec in target_specs))
    execution_groups = build_scan_execution_groups(target_specs, ports, include_scheme_in_key=True)

    namespace_filters = _normalize_namespace_filters(getattr(args, "namespace", None))
    token = (getattr(args, "token", None) or "").strip() or None
    username = getattr(args, "username", None)
    password = getattr(args, "password", None)
    credential_file_entries = None
    if token and (username is not None or password is not None):
        console.warn("--token is set; Basic auth credentials are ignored")
        username = None
        password = None
    elif username is not None:
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

    show_namespaces = bool(getattr(args, "namespaces", False))
    show_pods = bool(getattr(args, "pods", False))
    show_secrets = bool(getattr(args, "secrets", False))
    exec_pod = (getattr(args, "pod", None) or "").strip() or None
    exec_command = (getattr(args, "exec_command", None) or "").strip() or None

    stream_to_stdout = not bool(args.output)

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith(_KUBE_TAG) and all(token_ not in line for token_ in (" [*] ", " [+] ", " [-] ", " [!] ")):
            if console.render_tagged_payload_line(line, _KUBE_TAG, payload_color="orange"):
                return
            console.plain(line, color="white")
            return
        if _render_colored_kubeapi_line(console, line):
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

    if args.debug and args.output_format == "txt":
        target_auth = (
            "token"
            if token
            else f"credfile={len(credential_file_entries)}"
            if credential_file_entries is not None
            else ("basic" if (username is not None or password is not None) else "none")
        )
        console.info(
            f"kubeapi audit started: hosts={len(hosts)} ports={len(execution_groups)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} https={args.https} insecure={args.insecure} "
            f"auth={target_auth} format=txt"
        )
    if args.debug and not stream_to_stdout and args.output_format != "txt":
        console.info(
            f"kubeapi audit started: hosts={len(hosts)} ports={len(execution_groups)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} format={args.output_format} output={args.output}"
        )

    total = 0
    detected = 0
    failed = 0
    group_hosts_by_idx: dict[int, list[str]] = {idx: list(group.hosts) for idx, group in enumerate(execution_groups)}
    if credential_file_entries is not None:
        for idx, group in enumerate(execution_groups):
            group_hosts_by_idx[idx] = filter_open_tcp_hosts_for_credential_file(
                list(group.hosts),
                int(group.port),
                timeout=args.timeout,
                workers=args.workers,
                enabled=not bool(getattr(args, "proxy", None)),
            )
            if args.debug:
                emit_debug(
                    f"credential_prefilter port={int(group.port)} open={len(group_hosts_by_idx[idx])}/"
                    f"{len(group.hosts)}"
                )
    outer_progress: ProgressBar | None = None
    use_single_global_progress = (
        stream_to_stdout and args.output_format == "txt" and (len(execution_groups) > 1 or len(credential_runs) > 1)
    )
    if use_single_global_progress:
        global_total = sum(len(group_hosts_by_idx[idx]) for idx, _group in enumerate(execution_groups)) * len(
            credential_runs
        )
        outer_progress = ProgressBar(_KUBE_TAG, global_total, enabled=True, leave=True)
    output_written = False
    try:
        for idx, group in enumerate(execution_groups):
            audit_hosts = group_hosts_by_idx[idx]
            if not audit_hosts:
                continue
            group_use_https = bool(args.https)
            if group.scheme_hint in {"http", "https"}:
                group_use_https = group.scheme_hint == "https"
            host_batches = [[host] for host in audit_hosts] if credential_file_entries is not None else [audit_hosts]
            for host_batch in host_batches:
                for run_username, run_password in credential_runs:
                    part_total, part_detected, part_failed = audit_kubeapi_targets(
                        hosts=host_batch,
                        port=group.port,
                        timeout=args.timeout,
                        retries=args.retries,
                        workers=args.workers,
                        use_https=group_use_https,
                        insecure=bool(args.insecure),
                        ca_file=getattr(args, "ca_file", None),
                        token=token,
                        username=run_username,
                        password=run_password,
                        show_namespaces=show_namespaces,
                        show_pods=show_pods,
                        show_secrets=show_secrets,
                        namespace_filters=namespace_filters,
                        exec_pod=exec_pod,
                        exec_command=exec_command,
                        output_path=args.output,
                        output_format=args.output_format,
                        emit_line=emit_line,
                        logger=logger if args.debug else None,
                        append_output=output_written,
                        suppress_timeout_status_lines=not bool(args.debug),
                        debug_emit=emit_debug if args.debug else None,
                        show_progress=not use_single_global_progress,
                    )
                    total += part_total
                    detected += part_detected
                    failed += part_failed
                    if outer_progress is not None:
                        outer_progress.advance(part_total)
                    output_written = True
    except OSError as exc:
        console.error(f"failed to process kubeapi output: {exc}")
        return 2
    finally:
        if outer_progress is not None:
            outer_progress.close()

    if stream_to_stdout and total > 0 and detected == 0 and failed == total and args.output_format == "txt":
        console.warn("all kubeapi targets are unreachable; check host/port, TLS mode, and network reachability")

    if args.debug:
        console.info(f"kubeapi audit complete: total={total} detected={detected} fail={failed}")
    return 0
