"""Proxmox API audit stage."""

from __future__ import annotations

import argparse
import base64
import binascii
import http.client
import ipaddress
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
from dataclasses import dataclass
from typing import Any

from .console import Console
from .logger import AttemptLogger
from .utils import collect_scan_ports, collect_scan_targets, utc_now_iso

_PROXMOX_API_PREFIX = "/api2/json"
_CONNECTION_REFUSED_PREFIX = "connection refused"
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_MAX_HTTP_BODY_BYTES = 262_144
_MAX_FINDINGS_PER_TARGET = 200
_MAX_FINDINGS_PER_ENDPOINT = 40

_SENSITIVE_KEY_TOKENS = (
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "accesskey",
    "secret_key",
    "secretkey",
    "private_key",
    "privatekey",
    "client_secret",
    "clientsecret",
    "credential",
)

_NON_SECRET_KEY_TOKENS = {
    # Proxmox non-secret operational fields that may look sensitive by name.
    "csrfpreventiontoken",
    "tokenid",
    "nodeid",
    "userid",
    "username",
    "vmid",
    "volid",
    "upid",
    "clustername",
    "ticketid",
}

_NON_SECRET_LITERALS = {
    "",
    "-",
    "<empty>",
    "<none>",
    "none",
    "null",
    "n/a",
    "na",
    "true",
    "false",
    "enabled",
    "disabled",
}

_TEXT_SECRET_RE = re.compile(
    r"(?i)([A-Za-z_][A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|credential))\s*[:=]\s*(?:\"([^\"]{1,512})\"|'([^']{1,512})'|([^\s,;{}\[\]\"']{1,512}))"
)
_URL_BASIC_AUTH_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:([^@\s/]+)@")
_AUTH_BASIC_RE = re.compile(r"(?i)\bauthorization\s*[:=]\s*basic\s+[A-Za-z0-9+/=]{8,}")
_AUTH_BEARER_RE = re.compile(r"(?i)\bauthorization\s*[:=]\s*bearer\s+[A-Za-z0-9._~+/-]{10,}")
_URI_WITH_AUTH_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]{1,128}:[^@\s/]{4,256}@[^ \t\r\n\"'<>]{1,512}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_OPAQUE_TOKEN_RE = re.compile(
    r"\b(?:glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|ya29\.[A-Za-z0-9._-]{20,}|[A-Fa-f0-9]{32,64})\b"
)
_BASE64_TEXT_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
_PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PERMISSION_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*\.[A-Za-z][A-Za-z0-9_.-]*$")


@dataclass(frozen=True)
class _ProxyConfig:
    scheme: str
    host: str
    port: int
    username: str | None
    password: str | None
    raw_url: str


def _clip(text: str, width: int = 90) -> str:
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
    if "certificate verify failed" in lower or "self signed certificate" in lower:
        return "tls verification failed (try --insecure)"
    if "wrong version number" in lower or ("ssl" in lower and "http request" in lower):
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
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "connection timeout"
    return _friendly_error_text(str(exc))


def _is_connection_refused_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text.startswith(_CONNECTION_REFUSED_PREFIX)


def _is_connection_timeout_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and text.startswith(_CONNECTION_TIMEOUT_PREFIX)


def _is_suppressed_fail_record(record: dict[str, Any]) -> bool:
    if str(record.get("status") or "") != "fail":
        return False
    err = record.get("error")
    return _is_connection_refused_error(err) or _is_connection_timeout_error(err)


def _ssl_context(*, use_https: bool, insecure: bool) -> ssl.SSLContext | None:
    if not use_https:
        return None
    if insecure:
        return ssl._create_unverified_context()
    return ssl.create_default_context()


def _parse_proxy_config(raw_proxy: str | None) -> tuple[_ProxyConfig | None, str | None]:
    value = str(raw_proxy or "").strip()
    if not value:
        return None, None

    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return None, "invalid --proxy URL"

    scheme = str(parsed.scheme or "").lower().strip()
    if not scheme:
        return None, "proxy URL must include scheme (http:// or socks5://)"
    if scheme not in {"http", "https", "socks5", "socks5h"}:
        return None, "unsupported proxy scheme (supported: http, https, socks5, socks5h)"

    host = str(parsed.hostname or "").strip()
    if not host:
        return None, "proxy URL must include host"

    try:
        port = int(parsed.port or 0)
    except ValueError:
        return None, "proxy URL has invalid port"
    if port < 1 or port > 65535:
        return None, "proxy URL port must be in range 1..65535"

    username = urllib.parse.unquote(parsed.username) if parsed.username is not None else None
    password = urllib.parse.unquote(parsed.password) if parsed.password is not None else None
    return _ProxyConfig(
        scheme=scheme,
        host=host,
        port=port,
        username=username,
        password=password,
        raw_url=value,
    ), None


def _auth_header_value(pve_api_token: str) -> str:
    token = str(pve_api_token or "").strip()
    if token.lower().startswith("pveapitoken="):
        return token
    return f"PVEAPIToken={token}"


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data += chunk
    return data


def _socks5_open_tunnel(
    proxy: _ProxyConfig, target_host: str, target_port: int, timeout: float
) -> tuple[socket.socket, str | None]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((proxy.host, proxy.port))

        methods = [0x00]
        if proxy.username is not None:
            methods.append(0x02)
        sock.sendall(bytes([0x05, len(methods), *methods]))
        hello = _recv_exact(sock, 2)
        if hello[0] != 0x05 or hello[1] == 0xFF:
            return sock, "socks5 proxy authentication method negotiation failed"

        if hello[1] == 0x02:
            username = str(proxy.username or "")
            password = str(proxy.password or "")
            user_raw = username.encode("utf-8", errors="replace")
            pass_raw = password.encode("utf-8", errors="replace")
            if len(user_raw) > 255 or len(pass_raw) > 255:
                return sock, "socks5 credentials are too long"
            sock.sendall(bytes([0x01, len(user_raw)]) + user_raw + bytes([len(pass_raw)]) + pass_raw)
            auth_reply = _recv_exact(sock, 2)
            if auth_reply[1] != 0x00:
                return sock, "socks5 proxy authentication failed"

        use_remote_dns = proxy.scheme == "socks5h"
        atyp: int
        addr_payload: bytes
        if use_remote_dns:
            host_raw = target_host.encode("idna", errors="ignore")
            if not host_raw or len(host_raw) > 255:
                return sock, "invalid target host for socks5h proxy"
            atyp = 0x03
            addr_payload = bytes([len(host_raw)]) + host_raw
        else:
            try:
                ip = ipaddress.ip_address(target_host)
                if ip.version == 4:
                    atyp = 0x01
                else:
                    atyp = 0x04
                addr_payload = ip.packed
            except ValueError:
                host_raw = target_host.encode("idna", errors="ignore")
                if not host_raw or len(host_raw) > 255:
                    return sock, "invalid target host for socks5 proxy"
                atyp = 0x03
                addr_payload = bytes([len(host_raw)]) + host_raw

        req = bytes([0x05, 0x01, 0x00, atyp]) + addr_payload + int(target_port).to_bytes(2, "big")
        sock.sendall(req)

        reply_head = _recv_exact(sock, 4)
        if reply_head[0] != 0x05:
            return sock, "socks5 proxy returned invalid response"
        rep = reply_head[1]
        if rep != 0x00:
            return sock, f"socks5 proxy connect failed (code={rep})"

        rep_atyp = reply_head[3]
        if rep_atyp == 0x01:
            _recv_exact(sock, 4)
        elif rep_atyp == 0x04:
            _recv_exact(sock, 16)
        elif rep_atyp == 0x03:
            domain_len = _recv_exact(sock, 1)[0]
            _recv_exact(sock, domain_len)
        else:
            return sock, "socks5 proxy returned invalid address type"
        _recv_exact(sock, 2)
        return sock, None
    except (OSError, ValueError, ConnectionError) as exc:
        return sock, _friendly_error_from_exception(exc)


def _read_http_response_from_socket(sock: socket.socket) -> tuple[int, bytes, dict[str, str], str | None]:
    try:
        response = http.client.HTTPResponse(sock)
        response.begin()
        status = int(response.status)
        payload = response.read(_MAX_HTTP_BODY_BYTES)
        headers = {str(k).lower(): str(v) for k, v in response.getheaders()}
        return status, payload, headers, None
    except (OSError, ValueError, http.client.HTTPException) as exc:
        return 0, b"", {}, _friendly_error_from_exception(exc)


def _request_via_socks_proxy(
    host: str,
    port: int,
    path: str,
    timeout: float,
    *,
    pve_api_token: str,
    use_https: bool,
    insecure: bool,
    proxy: _ProxyConfig,
) -> tuple[int, bytes, dict[str, str], str | None]:
    sock: socket.socket | None = None
    transport_sock: socket.socket | ssl.SSLSocket | None = None
    try:
        sock, connect_error = _socks5_open_tunnel(proxy, host, port, timeout)
        if connect_error:
            return 0, b"", {}, connect_error
        transport_sock = sock
        if use_https:
            ctx = _ssl_context(use_https=True, insecure=insecure)
            if ctx is None:
                return 0, b"", {}, "internal tls context error"
            transport_sock = ctx.wrap_socket(sock, server_hostname=host)
            transport_sock.settimeout(timeout)

        request_path = f"{_PROXMOX_API_PREFIX}{path}"
        host_header = f"{host}:{port}"
        headers = [
            f"GET {request_path} HTTP/1.1",
            f"Host: {host_header}",
            "User-Agent: RedPosture/1.0",
            "Accept: application/json,text/plain,*/*",
            f"Authorization: {_auth_header_value(pve_api_token)}",
            "Connection: close",
            "",
            "",
        ]
        transport_sock.sendall("\r\n".join(headers).encode("utf-8", errors="replace"))
        return _read_http_response_from_socket(transport_sock)
    except (ssl.SSLError, OSError, ValueError) as exc:
        return 0, b"", {}, _friendly_error_from_exception(exc)
    finally:
        if transport_sock is not None and transport_sock is not sock:
            try:
                transport_sock.close()
            except OSError:
                pass
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _request_via_http_proxy(
    host: str,
    port: int,
    path: str,
    timeout: float,
    *,
    pve_api_token: str,
    use_https: bool,
    insecure: bool,
    proxy: _ProxyConfig,
) -> tuple[int, bytes, dict[str, str], str | None]:
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}{_PROXMOX_API_PREFIX}{path}"
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": "RedPosture/1.0",
            "Accept": "application/json,text/plain,*/*",
            "Authorization": _auth_header_value(pve_api_token),
        },
    )

    handlers: list[Any] = [urllib.request.ProxyHandler({"http": proxy.raw_url, "https": proxy.raw_url})]
    if use_https:
        handlers.append(urllib.request.HTTPSHandler(context=_ssl_context(use_https=True, insecure=insecure)))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(response.status)
            payload = response.read(_MAX_HTTP_BODY_BYTES)
            response_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
            return status, payload, response_headers, None
    except urllib.error.HTTPError as exc:
        payload = exc.read(_MAX_HTTP_BODY_BYTES)
        response_headers = {str(k).lower(): str(v) for k, v in exc.headers.items()}
        return int(exc.code), payload, response_headers, None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, ssl.SSLError) as exc:
        return 0, b"", {}, _friendly_error_from_exception(exc)


def _proxmox_request_once(
    host: str,
    port: int,
    path: str,
    timeout: float,
    *,
    pve_api_token: str,
    use_https: bool,
    insecure: bool,
    proxy: _ProxyConfig | None,
) -> tuple[int, bytes, dict[str, str], str | None]:
    if proxy is not None:
        if proxy.scheme in {"http", "https"}:
            return _request_via_http_proxy(
                host,
                port,
                path,
                timeout,
                pve_api_token=pve_api_token,
                use_https=use_https,
                insecure=insecure,
                proxy=proxy,
            )
        if proxy.scheme in {"socks5", "socks5h"}:
            return _request_via_socks_proxy(
                host,
                port,
                path,
                timeout,
                pve_api_token=pve_api_token,
                use_https=use_https,
                insecure=insecure,
                proxy=proxy,
            )
        return 0, b"", {}, "unsupported proxy scheme"

    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}{_PROXMOX_API_PREFIX}{path}"
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": "RedPosture/1.0",
            "Accept": "application/json,text/plain,*/*",
            "Authorization": _auth_header_value(pve_api_token),
        },
    )
    handlers: list[Any] = []
    if use_https:
        handlers.append(urllib.request.HTTPSHandler(context=_ssl_context(use_https=True, insecure=insecure)))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(response.status)
            payload = response.read(_MAX_HTTP_BODY_BYTES)
            response_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
            return status, payload, response_headers, None
    except urllib.error.HTTPError as exc:
        payload = exc.read(_MAX_HTTP_BODY_BYTES)
        response_headers = {str(k).lower(): str(v) for k, v in exc.headers.items()}
        return int(exc.code), payload, response_headers, None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, ssl.SSLError) as exc:
        return 0, b"", {}, _friendly_error_from_exception(exc)


def _proxmox_request(
    host: str,
    port: int,
    path: str,
    timeout: float,
    retries: int,
    *,
    pve_api_token: str,
    use_https: bool,
    insecure: bool,
    proxy: _ProxyConfig | None,
) -> tuple[int, bytes, dict[str, str], str | None]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    for attempt in range(attempts):
        status, payload, response_headers, error = _proxmox_request_once(
            host,
            port,
            path,
            timeout,
            pve_api_token=pve_api_token,
            use_https=use_https,
            insecure=insecure,
            proxy=proxy,
        )
        if error is None:
            return status, payload, response_headers, None
        last_error = error
        if attempt >= attempts - 1:
            break
        time.sleep(_retry_delay(attempt))
    return 0, b"", {}, last_error or "connection failed"


def _decode_body_text(payload: bytes) -> str:
    return payload.decode("utf-8", errors="replace")


def _parse_json_payload(payload: bytes) -> Any | None:
    try:
        return json.loads(_decode_body_text(payload))
    except json.JSONDecodeError:
        return None


def _extract_error_message(payload: bytes) -> str | None:
    parsed = _parse_json_payload(payload)
    if isinstance(parsed, dict):
        for key in ("errors", "error", "message"):
            value = parsed.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, dict):
                parts: list[str] = []
                for item in value.values():
                    text = str(item or "").strip()
                    if text:
                        parts.append(text)
                if parts:
                    return "; ".join(parts)
        data = parsed.get("data")
        if isinstance(data, str) and data.strip():
            return data.strip()
    text = _decode_body_text(payload).strip()
    return text or None


def _is_invalid_token_message(value: str | None) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    needles = (
        "invalid token",
        "invalid api token",
        "authentication failed",
        "invalid pve ticket",
        "no such token",
        "token not found",
    )
    return any(needle in text for needle in needles)


def _is_permission_denied_message(value: str | None) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    needles = (
        "permission check failed",
        "insufficient privileges",
        "insufficient permission",
        "not enough permissions",
        "access denied",
        "forbidden",
    )
    return any(needle in text for needle in needles)


def _classify_auth_failure(status: int, error_message: str | None) -> str:
    if _is_permission_denied_message(error_message):
        return "insufficient_privileges"
    if status == 401:
        return "auth_failed"
    if _is_invalid_token_message(error_message):
        return "auth_failed"
    if status == 403:
        return "insufficient_privileges"
    return "auth_failed"


def _unwrap_api_data(payload: Any) -> Any:
    if isinstance(payload, dict) and "data" in payload:
        return payload.get("data")
    return payload


def _collect_nodes(payload: bytes) -> list[str]:
    parsed = _parse_json_payload(payload)
    data = _unwrap_api_data(parsed)
    if not isinstance(data, list):
        return []
    nodes: list[str] = []
    seen: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        node = str(item.get("node") or "").strip()
        if not node or node in seen:
            continue
        seen.add(node)
        nodes.append(node)
    return nodes


def _collect_vmids(payload: bytes) -> list[str]:
    parsed = _parse_json_payload(payload)
    data = _unwrap_api_data(parsed)
    if not isinstance(data, list):
        return []
    vmids: list[str] = []
    seen: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        vmid = str(item.get("vmid") or "").strip()
        if not vmid or vmid in seen:
            continue
        seen.add(vmid)
        vmids.append(vmid)
    return vmids


def _collect_storage_ids(payload: bytes) -> list[str]:
    parsed = _parse_json_payload(payload)
    data = _unwrap_api_data(parsed)
    if not isinstance(data, list):
        return []
    storage_ids: list[str] = []
    seen: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        storage_id = str(item.get("storage") or "").strip()
        if not storage_id or storage_id in seen:
            continue
        seen.add(storage_id)
        storage_ids.append(storage_id)
    return storage_ids


def _collect_volids(payload: bytes) -> list[str]:
    parsed = _parse_json_payload(payload)
    data = _unwrap_api_data(parsed)
    if not isinstance(data, list):
        return []
    volids: list[str] = []
    seen: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        volid = str(item.get("volid") or "").strip()
        if not volid or volid in seen:
            continue
        seen.add(volid)
        volids.append(volid)
    return volids


def _collect_user_ids(payload: bytes) -> list[str]:
    parsed = _parse_json_payload(payload)
    data = _unwrap_api_data(parsed)
    if not isinstance(data, list):
        return []
    user_ids: list[str] = []
    seen: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        user_id = str(item.get("userid") or item.get("user") or "").strip()
        if not user_id or user_id in seen:
            continue
        seen.add(user_id)
        user_ids.append(user_id)
    return user_ids


def _collect_permission_tokens(value: Any, sink: set[str]) -> None:
    if isinstance(value, dict):
        for key, inner in value.items():
            key_text = str(key or "").strip()
            if _PERMISSION_TOKEN_RE.fullmatch(key_text):
                if isinstance(inner, bool):
                    if inner:
                        sink.add(key_text)
                elif isinstance(inner, int):
                    if inner != 0:
                        sink.add(key_text)
                else:
                    sink.add(key_text)
            _collect_permission_tokens(inner, sink)
        return
    if isinstance(value, list):
        for item in value:
            _collect_permission_tokens(item, sink)
        return
    if isinstance(value, str):
        candidate = value.strip()
        if _PERMISSION_TOKEN_RE.fullmatch(candidate):
            sink.add(candidate)


def _has_any_permission(permission_tokens: set[str], required: tuple[str, ...]) -> bool:
    for token in required:
        if token in permission_tokens:
            return True
    return False


def _derive_permission_caps(permission_tokens: set[str]) -> dict[str, bool]:
    return {
        "adduser": _has_any_permission(
            permission_tokens,
            ("User.Modify", "Permissions.Modify", "Realm.AllocateUser"),
        ),
        "read": _has_any_permission(
            permission_tokens,
            (
                "Sys.Audit",
                "Sys.Syslog",
                "VM.Audit",
                "Datastore.Audit",
                "Pool.Audit",
                "SDN.Audit",
            ),
        ),
        "modify": _has_any_permission(
            permission_tokens,
            (
                "VM.Config.Options",
                "VM.Config.CPU",
                "VM.Config.Disk",
                "VM.Config.Network",
                "VM.PowerMgmt",
                "Datastore.Allocate",
                "Datastore.AllocateSpace",
                "SDN.Use",
            ),
        ),
        "backup": _has_any_permission(
            permission_tokens,
            ("VM.Backup", "Datastore.AllocateSpace", "Datastore.Allocate"),
        ),
    }


def _cap_text(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "unknown"


def _caps_suffix(record: dict[str, Any]) -> str:
    return " ".join(
        (
            f"(adduser:{_cap_text(record.get('cap_adduser'))})",
            f"(modify:{_cap_text(record.get('cap_modify'))})",
            f"(backup:{_cap_text(record.get('cap_backup'))})",
            f"(read:{_cap_text(record.get('cap_read'))})",
        )
    )


def _normalize_key_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _key_is_non_secret(key: str) -> bool:
    normalized = _normalize_key_token(key)
    if not normalized:
        return False
    return normalized in _NON_SECRET_KEY_TOKENS


def _clean_value_text(value: Any) -> str:
    text = str(value if value is not None else "").strip()
    while text and text[-1] in ",;)}]>":
        text = text[:-1].strip()
    while text and text[0] in "({[<":
        text = text[1:].strip()
    if len(text) >= 2 and (
        (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'"))
    ):
        text = text[1:-1].strip()
    return text


def _value_looks_secret(value: Any) -> bool:
    text = _clean_value_text(value)
    if not text:
        return False
    if text.lower() in _NON_SECRET_LITERALS:
        return False
    if set(text) <= {"*", "x", "X", "."} and len(text) >= 3:
        return False
    if len(text) < 4:
        return False
    return True


def _key_looks_sensitive(key: str) -> bool:
    if _key_is_non_secret(key):
        return False
    normalized = _normalize_key_token(key)
    if not normalized:
        return False
    return any(token in normalized for token in _SENSITIVE_KEY_TOKENS)


def _decode_base64_text(value: str) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if len(raw) < 20 or len(raw) > 4096:
        return None
    if not _BASE64_TEXT_RE.fullmatch(raw):
        return None

    padded = raw + ("=" * ((4 - (len(raw) % 4)) % 4))
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (ValueError, binascii.Error):
        return None
    if not decoded:
        return None
    if len(decoded) > 8192:
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.strip():
        return None
    printable_ratio = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t") / max(1, len(text))
    if printable_ratio < 0.90:
        return None
    return text


def _looks_like_cloud_init_secret_blob(value: str) -> bool:
    text = str(value or "")
    lower = text.lower()
    if "#cloud-config" not in lower:
        return False
    needles = ("chpasswd:", "password:", "plain_text_passwd", "passwd:", "ssh_authorized_keys:")
    return any(needle in lower for needle in needles)


def _add_finding(
    findings: list[dict[str, str]],
    seen: set[tuple[str, str, str, str]],
    *,
    endpoint: str,
    reason: str,
    path: str,
    sample: str,
) -> None:
    if len(findings) >= _MAX_FINDINGS_PER_TARGET:
        return
    sample_text = _clip(_clean_value_text(sample), 100)
    key = (endpoint, reason, path, sample_text)
    if key in seen:
        return
    seen.add(key)
    findings.append(
        {
            "endpoint": endpoint,
            "reason": reason,
            "path": path,
            "sample": sample_text,
        }
    )


def _collect_text_findings(
    text: str,
    endpoint: str,
    findings: list[dict[str, str]],
    seen: set[tuple[str, str, str, str]],
    *,
    path: str,
    limit: int,
    depth: int = 0,
) -> None:
    added = 0
    for match in _TEXT_SECRET_RE.finditer(text):
        if added >= limit:
            break
        key = str(match.group(1) or "")
        value_raw = match.group(2) or match.group(3) or match.group(4) or ""
        value = _clean_value_text(value_raw)
        if not _key_looks_sensitive(key) or not _value_looks_secret(value):
            continue
        _add_finding(
            findings,
            seen,
            endpoint=endpoint,
            reason=f"text_{key.lower()}",
            path=path,
            sample=f"{key}={value}",
        )
        added += 1

    uri_auth_match = _URI_WITH_AUTH_RE.search(text)
    if uri_auth_match:
        _add_finding(
            findings,
            seen,
            endpoint=endpoint,
            reason="uri_with_auth",
            path=path,
            sample=str(uri_auth_match.group(0) or ""),
        )
    url_basic_match = _URL_BASIC_AUTH_RE.search(text)
    if url_basic_match:
        _add_finding(
            findings,
            seen,
            endpoint=endpoint,
            reason="url_basic_auth",
            path=path,
            sample=str(url_basic_match.group(0) or ""),
        )
    auth_basic_match = _AUTH_BASIC_RE.search(text)
    if auth_basic_match:
        _add_finding(
            findings,
            seen,
            endpoint=endpoint,
            reason="authorization_basic",
            path=path,
            sample=str(auth_basic_match.group(0) or ""),
        )
    auth_bearer_match = _AUTH_BEARER_RE.search(text)
    if auth_bearer_match:
        _add_finding(
            findings,
            seen,
            endpoint=endpoint,
            reason="authorization_bearer",
            path=path,
            sample=str(auth_bearer_match.group(0) or ""),
        )
    jwt_match = _JWT_RE.search(text)
    if jwt_match:
        _add_finding(findings, seen, endpoint=endpoint, reason="jwt_token", path=path, sample=str(jwt_match.group(0) or ""))
    opaque_match = _OPAQUE_TOKEN_RE.search(text)
    if opaque_match:
        _add_finding(
            findings,
            seen,
            endpoint=endpoint,
            reason="opaque_token",
            path=path,
            sample=str(opaque_match.group(0) or ""),
        )
    if _looks_like_cloud_init_secret_blob(text):
        _add_finding(findings, seen, endpoint=endpoint, reason="cloud_init_blob", path=path, sample=text)
    pem_match = _PEM_PRIVATE_KEY_RE.search(text)
    if pem_match:
        _add_finding(
            findings,
            seen,
            endpoint=endpoint,
            reason="private_key_pem",
            path=path,
            sample=str(pem_match.group(0) or ""),
        )

    if depth >= 1:
        return
    for match in _BASE64_TEXT_RE.finditer(text):
        candidate = str(match.group(0) or "")
        decoded_text = _decode_base64_text(candidate)
        if not decoded_text:
            continue
        _collect_text_findings(
            decoded_text,
            endpoint,
            findings,
            seen,
            path=f"{path}.base64",
            limit=max(4, limit // 2),
            depth=depth + 1,
        )


def _collect_json_findings(
    payload: Any,
    endpoint: str,
    findings: list[dict[str, str]],
    seen: set[tuple[str, str, str, str]],
    *,
    path: str = "$",
) -> None:
    if len(findings) >= _MAX_FINDINGS_PER_TARGET:
        return

    if isinstance(payload, dict):
        for key, value in payload.items():
            key_text = str(key)
            sub_path = f"{path}.{key_text}"
            if _key_looks_sensitive(key_text) and _value_looks_secret(value):
                _add_finding(
                    findings,
                    seen,
                    endpoint=endpoint,
                    reason=f"json_{key_text.lower()}",
                    path=sub_path,
                    sample=str(value),
                )

            if isinstance(value, str):
                _collect_text_findings(
                    value,
                    endpoint,
                    findings,
                    seen,
                    path=sub_path,
                    limit=_MAX_FINDINGS_PER_ENDPOINT,
                )
            _collect_json_findings(value, endpoint, findings, seen, path=sub_path)
        return

    if isinstance(payload, list):
        for idx, value in enumerate(payload):
            sub_path = f"{path}[{idx}]"
            if isinstance(value, str):
                _collect_text_findings(
                    value,
                    endpoint,
                    findings,
                    seen,
                    path=sub_path,
                    limit=_MAX_FINDINGS_PER_ENDPOINT,
                )
            _collect_json_findings(value, endpoint, findings, seen, path=sub_path)


def _scan_endpoint_payload(
    endpoint: str,
    payload: bytes,
    findings: list[dict[str, str]],
    seen: set[tuple[str, str, str, str]],
) -> None:
    text = _decode_body_text(payload)
    _collect_text_findings(
        text,
        endpoint,
        findings,
        seen,
        path="$text",
        limit=_MAX_FINDINGS_PER_ENDPOINT,
    )

    parsed = _parse_json_payload(payload)
    if parsed is None:
        return
    data = _unwrap_api_data(parsed)
    _collect_json_findings(data, endpoint, findings, seen)


def _audit_proxmox_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    pve_api_token: str,
    use_https: bool,
    insecure: bool,
    proxy: _ProxyConfig | None,
    *,
    discover_creds: bool = False,
    show_nodes: bool = False,
    show_users: bool = False,
    on_status_ready: Callable[[dict[str, Any]], None] | None = None,
    on_discovered_url: Callable[[str], None] | None = None,
    on_credential_finding: Callable[[dict[str, str]], None] | None = None,
) -> dict[str, Any]:
    endpoint_results: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    findings_seen: set[tuple[str, str, str, str]] = set()
    stream_started = False
    streamed_url_count = 0
    streamed_finding_count = 0

    def flush_stream_buffers() -> None:
        nonlocal streamed_url_count, streamed_finding_count
        if not stream_started:
            return
        if discover_creds and on_discovered_url is not None:
            while streamed_url_count < len(endpoint_results):
                item = endpoint_results[streamed_url_count]
                streamed_url_count += 1
                path = str(item.get("path") or "").strip()
                if path.startswith("/"):
                    on_discovered_url(path)
        if discover_creds and on_credential_finding is not None:
            while streamed_finding_count < len(findings):
                finding = findings[streamed_finding_count]
                streamed_finding_count += 1
                if isinstance(finding, dict):
                    on_credential_finding(finding)

    def fetch(path: str) -> tuple[int, bytes, str | None]:
        status, payload, _headers, error = _proxmox_request(
            host,
            port,
            path,
            timeout,
            retries,
            pve_api_token=pve_api_token,
            use_https=use_https,
            insecure=insecure,
            proxy=proxy,
        )
        endpoint_results.append(
            {
                "path": path,
                "status": status,
                "error": error,
            }
        )
        if discover_creds and status == 200 and payload and len(findings) < _MAX_FINDINGS_PER_TARGET:
            _scan_endpoint_payload(path, payload, findings, findings_seen)
        flush_stream_buffers()
        return status, payload, error

    started = time.monotonic()
    access_status, access_payload, access_error = fetch("/access")
    if access_error:
        result = {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "is_proxmox": False,
            "status": "fail",
            "discover_creds": discover_creds,
            "use_https": use_https,
            "show_nodes": show_nodes,
            "nodes": None,
            "nodes_error": None,
            "show_users": show_users,
            "users": None,
            "users_error": None,
            "cap_adduser": None,
            "cap_read": None,
            "cap_modify": None,
            "cap_backup": None,
            "checked_endpoints": len(endpoint_results),
            "successful_endpoints": 0,
            "findings": findings,
            "credential_hits": len(findings),
            "endpoint_results": endpoint_results,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": access_error,
        }
        if on_status_ready is not None:
            on_status_ready(result)
        return result

    if access_status in {401, 403}:
        access_error_text = _extract_error_message(access_payload)
        auth_status = _classify_auth_failure(access_status, access_error_text)

        permissions_status, permissions_payload, permissions_error = fetch("/access/permissions?path=/")
        if permissions_error:
            cap_adduser: bool | None = None
            cap_read: bool | None = None
            cap_modify: bool | None = None
            cap_backup: bool | None = None
        elif permissions_status != 200:
            cap_adduser = None
            cap_read = None
            cap_modify = None
            cap_backup = None
        else:
            permission_tokens: set[str] = set()
            _collect_permission_tokens(_unwrap_api_data(_parse_json_payload(permissions_payload)), permission_tokens)
            caps = _derive_permission_caps(permission_tokens)
            cap_adduser = caps["adduser"]
            cap_read = caps["read"]
            cap_modify = caps["modify"]
            cap_backup = caps["backup"]

        users: list[str] | None = None
        users_error: str | None = None
        if show_users:
            users_status, users_payload, users_fetch_error = fetch("/access/users")
            if users_fetch_error:
                users_error = users_fetch_error
            elif users_status != 200:
                users_error = f"unexpected HTTP {users_status} from /access/users"
            else:
                users = _collect_user_ids(users_payload)

        result = {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "is_proxmox": True,
            "status": auth_status,
            "discover_creds": discover_creds,
            "use_https": use_https,
            "show_nodes": show_nodes,
            "nodes": None,
            "nodes_error": access_error_text or ("authentication failed" if auth_status == "auth_failed" else "permission denied"),
            "show_users": show_users,
            "users": users,
            "users_error": users_error,
            "cap_adduser": cap_adduser,
            "cap_read": cap_read,
            "cap_modify": cap_modify,
            "cap_backup": cap_backup,
            "checked_endpoints": len(endpoint_results),
            "successful_endpoints": 0,
            "findings": findings,
            "credential_hits": len(findings),
            "endpoint_results": endpoint_results,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": access_error_text or ("authentication failed" if auth_status == "auth_failed" else "insufficient privileges"),
        }
        if on_status_ready is not None:
            on_status_ready(result)
        return result

    if access_status != 200:
        result = {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "is_proxmox": bool(access_status),
            "status": "fail",
            "discover_creds": discover_creds,
            "use_https": use_https,
            "show_nodes": show_nodes,
            "nodes": None,
            "nodes_error": None,
            "show_users": show_users,
            "users": None,
            "users_error": None,
            "cap_adduser": None,
            "cap_read": None,
            "cap_modify": None,
            "cap_backup": None,
            "checked_endpoints": len(endpoint_results),
            "successful_endpoints": 0,
            "findings": findings,
            "credential_hits": len(findings),
            "endpoint_results": endpoint_results,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": f"unexpected HTTP {access_status} from /access",
        }
        if on_status_ready is not None:
            on_status_ready(result)
        return result

    permissions_status, permissions_payload, permissions_error = fetch("/access/permissions?path=/")
    if permissions_error:
        cap_adduser: bool | None = None
        cap_read: bool | None = None
        cap_modify: bool | None = None
        cap_backup: bool | None = None
    elif permissions_status != 200:
        cap_adduser = None
        cap_read = None
        cap_modify = None
        cap_backup = None
    else:
        permission_tokens: set[str] = set()
        _collect_permission_tokens(_unwrap_api_data(_parse_json_payload(permissions_payload)), permission_tokens)
        caps = _derive_permission_caps(permission_tokens)
        cap_adduser = caps["adduser"]
        cap_read = caps["read"]
        cap_modify = caps["modify"]
        cap_backup = caps["backup"]

    users: list[str] | None = None
    users_error: str | None = None
    if show_users:
        users_status, users_payload, users_fetch_error = fetch("/access/users")
        if users_fetch_error:
            users_error = users_fetch_error
        elif users_status != 200:
            users_error = f"unexpected HTTP {users_status} from /access/users"
        else:
            users = _collect_user_ids(users_payload)
    else:
        users = None
        users_error = None

    status_preview = {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_proxmox": True,
        "status": "token_ok",
        "cap_adduser": cap_adduser,
        "cap_read": cap_read,
        "cap_modify": cap_modify,
        "cap_backup": cap_backup,
        "error": None,
    }
    if on_status_ready is not None:
        on_status_ready(status_preview)
    stream_started = True
    flush_stream_buffers()

    discover_creds_crawl = discover_creds and (cap_read is not False or cap_modify is not False or cap_backup is not False)

    nodes: list[str] = []
    nodes_error: str | None = None
    if show_nodes or discover_creds_crawl:
        nodes_status, nodes_payload, nodes_fetch_error = fetch("/nodes")
        if nodes_fetch_error:
            nodes_error = nodes_fetch_error
        elif nodes_status == 200:
            nodes = _collect_nodes(nodes_payload)
        elif nodes_status in {401, 403}:
            nodes_error = _extract_error_message(nodes_payload) or "permission denied"
        else:
            nodes_error = f"unexpected HTTP {nodes_status} from /nodes"

    if discover_creds_crawl:
        for node in nodes:
            if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                break
            node_id = urllib.parse.quote(node, safe="")
            fetch(f"/nodes/{node_id}/syslog")
            if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                break
            fetch(f"/nodes/{node_id}/report")
            if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                break
            fetch(f"/nodes/{node_id}/tasks")
            if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                break

            qemu_status, qemu_payload, _qemu_error = fetch(f"/nodes/{node_id}/qemu")
            if qemu_status == 200:
                for vmid in _collect_vmids(qemu_payload):
                    if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                        break
                    vmid_id = urllib.parse.quote(vmid, safe="")
                    fetch(f"/nodes/{node_id}/qemu/{vmid_id}/config")

            lxc_status, lxc_payload, _lxc_error = fetch(f"/nodes/{node_id}/lxc")
            if lxc_status == 200:
                for vmid in _collect_vmids(lxc_payload):
                    if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                        break
                    vmid_id = urllib.parse.quote(vmid, safe="")
                    fetch(f"/nodes/{node_id}/lxc/{vmid_id}/config")

            storages_status, storages_payload, _storages_error = fetch(f"/nodes/{node_id}/storage")
            if storages_status == 200:
                for storage_id in _collect_storage_ids(storages_payload):
                    if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                        break
                    storage_q = urllib.parse.quote(storage_id, safe="")
                    base_path = f"/nodes/{node_id}/storage/{storage_q}"
                    content_status, content_payload, _content_error = fetch(f"{base_path}/content")
                    backup_status, backup_payload, _backup_error = fetch(f"{base_path}/content?content=backup")

                    volids: list[str] = []
                    if content_status == 200:
                        volids.extend(_collect_volids(content_payload))
                    if backup_status == 200:
                        volids.extend(_collect_volids(backup_payload))

                    seen_volids: set[str] = set()
                    for volid in volids:
                        if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                            break
                        if volid in seen_volids:
                            continue
                        seen_volids.add(volid)
                        volid_q = urllib.parse.quote(volid, safe="")
                        fetch(f"{base_path}/content/{volid_q}")
                        if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                            break
                        query = urllib.parse.urlencode({"volumeid": volid})
                        fetch(f"{base_path}/download?{query}")

        if len(findings) < _MAX_FINDINGS_PER_TARGET:
            fetch("/sdn")
        if len(findings) < _MAX_FINDINGS_PER_TARGET:
            fetch("/cluster/backup")

    successful_endpoints = sum(1 for item in endpoint_results if int(item.get("status") or 0) == 200)
    result = {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_proxmox": True,
        "status": "token_ok",
        "discover_creds": discover_creds,
        "use_https": use_https,
        "show_nodes": show_nodes,
        "nodes": nodes if show_nodes else None,
        "nodes_error": nodes_error,
        "show_users": show_users,
        "users": users,
        "users_error": users_error,
        "cap_adduser": cap_adduser,
        "cap_read": cap_read,
        "cap_modify": cap_modify,
        "cap_backup": cap_backup,
        "checked_endpoints": len(endpoint_results),
        "successful_endpoints": successful_endpoints,
        "findings": findings,
        "credential_hits": len(findings),
        "endpoint_results": endpoint_results,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "error": None,
    }
    return result


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{'PROXMOX':<8}\t{host}\t{port}\t"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(
            {
                "timestamp": record.get("timestamp"),
                "type": "detect",
                "host": record.get("host"),
                "port": record.get("port"),
                "service": "proxmox",
                "detected": bool(record.get("is_proxmox")),
            },
            ensure_ascii=False,
        )
    return f"{_nxc_prefix(record)} [*] Proxmox API"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    prefix = _nxc_prefix(record)
    status = str(record.get("status") or "fail")
    if status == "token_ok":
        return f"{prefix} [+] token accepted {_caps_suffix(record)}"
    if status == "insufficient_privileges":
        return f"{prefix} [-] token valid but insufficient privileges {_caps_suffix(record)}"
    if status == "auth_failed":
        return f"{prefix} [-] invalid pve api token"
    err = _clip(str(record.get("error") or "connection failed"), 90)
    return f"{prefix} [!] connection failed err={err}"


def _format_findings_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    findings = record.get("findings")
    if not isinstance(findings, list) or not findings:
        return []

    if output_format == "json":
        lines: list[str] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "credential_hit",
                        "service": "proxmox",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "endpoint": finding.get("endpoint"),
                        "reason": finding.get("reason"),
                        "path": finding.get("path"),
                        "sample": finding.get("sample"),
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    prefix = _nxc_prefix(record)
    lines: list[str] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        reason = _clip(str(finding.get("reason") or "-"), 80)
        path = _clip(str(finding.get("path") or "-"), 100)
        sample = _clip(str(finding.get("sample") or "-"), 100)
        lines.append(f"{prefix} [!] credential candidate reason={reason} path={path} sample={sample}")
    return lines


def _format_single_finding_detail_line(record: dict[str, Any], finding: dict[str, Any]) -> str:
    prefix = _nxc_prefix(record)
    reason = _clip(str(finding.get("reason") or "-"), 80)
    path = _clip(str(finding.get("path") or "-"), 100)
    sample = _clip(str(finding.get("sample") or "-"), 100)
    return f"{prefix} [!] credential candidate reason={reason} path={path} sample={sample}"


def _format_discovered_urls_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []
    if not bool(record.get("discover_creds")):
        return []

    endpoint_results = record.get("endpoint_results")
    if not isinstance(endpoint_results, list):
        return []

    host = str(record.get("host") or "").strip()
    port_text = str(record.get("port") or "").strip()
    if not host or not port_text:
        return []
    scheme = "https" if bool(record.get("use_https")) else "http"

    urls: list[str] = []
    seen_urls: set[str] = set()
    for item in endpoint_results:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").strip()
        if not path.startswith("/"):
            continue
        url = f"{scheme}://{host}:{port_text}{_PROXMOX_API_PREFIX}{path}"
        if url in seen_urls:
            continue
        seen_urls.add(url)
        urls.append(url)

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Discovered Credentials"]
    if not urls:
        lines.append(f"{prefix} [*] Discovered URL")
        lines.append(f"{prefix} [*] <none>")
        return lines
    lines.append(f"{prefix} [*] Discovered URL")
    for url in urls:
        lines.append(f"{prefix} [*] {url}")
    return lines


def _format_nodes_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if not bool(record.get("show_nodes")):
        return []

    nodes = record.get("nodes")
    nodes_error = record.get("nodes_error")

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "nodes_dump",
                    "service": "proxmox",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "nodes": [str(item) for item in nodes] if isinstance(nodes, list) else [],
                    "error": str(nodes_error) if nodes_error else None,
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Nodes"]
    if nodes_error:
        lines.append(f"{prefix} <error:{_clip(str(nodes_error), 120)}>")
        return lines
    if isinstance(nodes, list) and nodes:
        for node in nodes:
            lines.append(f"{prefix} {str(node)}")
        return lines
    lines.append(f"{prefix} <no nodes>")
    return lines


def _format_users_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if not bool(record.get("show_users")):
        return []

    users = record.get("users")
    users_error = record.get("users_error")

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "users_dump",
                    "service": "proxmox",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "users": [str(item) for item in users] if isinstance(users, list) else [],
                    "error": str(users_error) if users_error else None,
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Users"]
    if users_error:
        lines.append(f"{prefix} <error:{_clip(str(users_error), 120)}>")
        return lines
    if isinstance(users, list) and users:
        for user in users:
            lines.append(f"{prefix} {str(user)}")
        return lines
    lines.append(f"{prefix} <no users>")
    return lines


def _render_colored_proxmox_line(console: Console, line: str) -> bool:
    if not line.startswith("PROXMOX"):
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
        tag = "PROXMOX"
        rest = left[len(tag) :] if left.startswith(tag) else left

        if marker == "[!]" and right.startswith("credential candidate "):
            right_colored = console._paint(right, "orange", sys.stdout)
        else:
            spans: list[tuple[int, int, str]] = []
            for cap_name in ("adduser", "modify", "backup", "read"):
                cap_match = re.search(rf"\({cap_name}:(true|false|unknown)\)", right)
                if not cap_match:
                    continue
                value = cap_match.group(1)
                if value == "true":
                    cap_color = "red"
                elif value == "false":
                    cap_color = "bright_green"
                else:
                    cap_color = "yellow"
                spans.append((cap_match.start(), cap_match.end(), cap_color))

            if spans:
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
            else:
                right_colored = console._paint(right, "white", sys.stdout)

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


def _stream_proxmox_discovered_url(
    *,
    out_fh: Any,
    emit_line: Callable[[str], None] | None,
    lock: threading.Lock,
    headers_seen: set[tuple[str, int]],
    urls_seen: set[tuple[str, int, str]],
    host: str,
    port: int,
    use_https: bool,
    path: str,
) -> None:
    if not path.startswith("/"):
        return
    with lock:
        record = {"host": host, "port": port, "use_https": use_https}
        header_key = (host, port)
        if header_key not in headers_seen:
            _emit_line(out_fh, emit_line, f"{_nxc_prefix(record)} [*] Discovered Credentials")
            _emit_line(out_fh, emit_line, f"{_nxc_prefix(record)} [*] Discovered URL")
            headers_seen.add(header_key)

        url_key = (host, port, path)
        if url_key in urls_seen:
            return
        urls_seen.add(url_key)
        scheme = "https" if use_https else "http"
        url = f"{scheme}://{host}:{port}{_PROXMOX_API_PREFIX}{path}"
        _emit_line(out_fh, emit_line, f"{_nxc_prefix(record)} [*] {url}")


def _stream_proxmox_finding(
    *,
    out_fh: Any,
    emit_line: Callable[[str], None] | None,
    lock: threading.Lock,
    findings_seen: set[tuple[str, int, str, str, str, str]],
    host: str,
    port: int,
    finding: dict[str, Any],
) -> None:
    endpoint = str(finding.get("endpoint") or "").strip()
    reason = str(finding.get("reason") or "").strip()
    path = str(finding.get("path") or "").strip()
    sample = str(finding.get("sample") or "").strip()
    finding_key = (host, port, endpoint, reason, path, sample)
    with lock:
        if finding_key in findings_seen:
            return
        findings_seen.add(finding_key)
        line = _format_single_finding_detail_line({"host": host, "port": port}, finding)
        _emit_line(out_fh, emit_line, line)


def _stream_proxmox_status(
    *,
    out_fh: Any,
    emit_line: Callable[[str], None] | None,
    lock: threading.Lock,
    status_emitted: set[tuple[str, int]],
    record: dict[str, Any],
    output_format: str,
    suppress_fail_status_lines: bool,
) -> None:
    host = str(record.get("host") or "-")
    port = int(record.get("port") or 0)
    key = (host, port)
    with lock:
        if key in status_emitted:
            return
        if bool(record.get("is_proxmox")):
            _emit_line(out_fh, emit_line, _format_detect_record(record, output_format))
        suppress_status = suppress_fail_status_lines and output_format == "txt" and _is_suppressed_fail_record(record)
        if not suppress_status:
            _emit_line(out_fh, emit_line, _format_record(record, output_format))
        status_emitted.add(key)


def audit_proxmox_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
    pve_api_token: str,
    use_https: bool,
    insecure: bool,
    proxy: _ProxyConfig | None,
    discover_creds: bool,
    show_nodes: bool,
    show_users: bool,
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
    suppress_fail_status_lines: bool = False,
) -> tuple[int, int, int, int, int, int]:
    total = 0
    token_ok = 0
    insufficient = 0
    auth_failed = 0
    fail = 0
    credential_hits = 0

    out_fh: Any = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, "a" if append_output else "w", encoding="utf-8")
    output_lock = threading.Lock()
    stream_discovery = bool(discover_creds and output_format == "txt" and emit_line is not None)
    streamed_headers: set[tuple[str, int]] = set()
    streamed_urls: set[tuple[str, int, str]] = set()
    streamed_findings: set[tuple[str, int, str, str, str, str]] = set()
    streamed_statuses: set[tuple[str, int]] = set()

    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            future_map = {
                executor.submit(
                    _audit_proxmox_host,
                    host,
                    port,
                    timeout,
                    retries,
                    pve_api_token,
                    use_https,
                    insecure,
                    proxy,
                    discover_creds=discover_creds,
                    show_nodes=show_nodes,
                    show_users=show_users,
                    on_discovered_url=(
                        (
                            lambda path, _host=host: _stream_proxmox_discovered_url(
                                out_fh=out_fh,
                                emit_line=emit_line,
                                lock=output_lock,
                                headers_seen=streamed_headers,
                                urls_seen=streamed_urls,
                                host=_host,
                                port=port,
                                use_https=use_https,
                                path=path,
                            )
                        )
                        if stream_discovery
                        else None
                    ),
                    on_status_ready=(
                        (
                            lambda status_record: _stream_proxmox_status(
                                out_fh=out_fh,
                                emit_line=emit_line,
                                lock=output_lock,
                                status_emitted=streamed_statuses,
                                record=status_record,
                                output_format=output_format,
                                suppress_fail_status_lines=suppress_fail_status_lines,
                            )
                        )
                        if stream_discovery
                        else None
                    ),
                    on_credential_finding=(
                        (
                            lambda finding, _host=host: _stream_proxmox_finding(
                                out_fh=out_fh,
                                emit_line=emit_line,
                                lock=output_lock,
                                findings_seen=streamed_findings,
                                host=_host,
                                port=port,
                                finding=finding,
                            )
                        )
                        if stream_discovery
                        else None
                    ),
                ): host
                for host in hosts
            }

            for future in as_completed(future_map):
                record = future.result()
                total += 1

                status = str(record.get("status") or "fail")
                if status == "token_ok":
                    token_ok += 1
                elif status == "insufficient_privileges":
                    insufficient += 1
                elif status == "auth_failed":
                    auth_failed += 1
                else:
                    fail += 1
                credential_hits += int(record.get("credential_hits") or 0)

                with output_lock:
                    host_key = (str(record.get("host") or "-"), int(record.get("port") or port))
                    if host_key not in streamed_statuses:
                        if bool(record.get("is_proxmox")):
                            _emit_line(out_fh, emit_line, _format_detect_record(record, output_format))
                        suppress_status = (
                            suppress_fail_status_lines and output_format == "txt" and _is_suppressed_fail_record(record)
                        )
                        if not suppress_status:
                            _emit_line(out_fh, emit_line, _format_record(record, output_format))
                    if not stream_discovery:
                        for detail_line in _format_discovered_urls_detail_records(record, output_format):
                            _emit_line(out_fh, emit_line, detail_line)
                    for detail_line in _format_nodes_detail_records(record, output_format):
                        _emit_line(out_fh, emit_line, detail_line)
                    for detail_line in _format_users_detail_records(record, output_format):
                        _emit_line(out_fh, emit_line, detail_line)
                    if not stream_discovery:
                        for detail_line in _format_findings_detail_records(record, output_format):
                            _emit_line(out_fh, emit_line, detail_line)

                if logger is not None:
                    logger.log(
                        "proxmox",
                        (str(record.get("host") or "-"), int(record.get("port") or port)),
                        phase="audit",
                        status=record.get("status"),
                        checked_endpoints=record.get("checked_endpoints"),
                        successful_endpoints=record.get("successful_endpoints"),
                        cap_adduser=record.get("cap_adduser"),
                        cap_read=record.get("cap_read"),
                        cap_modify=record.get("cap_modify"),
                        cap_backup=record.get("cap_backup"),
                        credential_hits=record.get("credential_hits"),
                        error=record.get("error"),
                    )

    finally:
        if out_fh is not None:
            out_fh.close()

    return total, token_ok, insufficient, auth_failed, fail, credential_hits


def run_proxmox_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
        return 2

    pve_api_token = str(getattr(args, "pve_api_token", "") or "").strip()
    if not pve_api_token:
        console.error("--pveapitoken is required")
        return 2
    proxy, proxy_error = _parse_proxy_config(getattr(args, "proxy", None))
    if proxy_error:
        console.error(f"failed to parse --proxy: {proxy_error}")
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
        console.error("proxmox requires -t/--targets")
        return 2

    stream_to_stdout = not bool(args.output)
    discover_creds = bool(getattr(args, "discover_creds", False))
    show_nodes = bool(getattr(args, "show_nodes", False))
    show_users = bool(getattr(args, "show_users", False))

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith("PROXMOX") and all(token not in line for token in (" [*] ", " [+] ", " [-] ", " [!] ")):
            if console.render_tagged_payload_line(line, "PROXMOX", payload_color="orange"):
                return
            console.plain(line, color="white")
            return
        if _render_colored_proxmox_line(console, line):
            return
        if line.startswith("PROXMOX"):
            console.plain(line)
            return
        if args.debug:
            console.plain(line)

    if args.debug and args.output_format == "txt":
        destination = "stdout" if stream_to_stdout else str(args.output)
        proxy_mode = "none" if proxy is None else f"{proxy.scheme}://{proxy.host}:{proxy.port}"
        console.info(
            f"proxmox audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} https={bool(args.https)} insecure={bool(args.insecure)} "
            f"discover_creds={discover_creds} nodes={show_nodes} users={show_users} proxy={proxy_mode} output={destination}"
        )

    total = 0
    token_ok = 0
    insufficient = 0
    auth_failed = 0
    failed = 0
    credential_hits = 0
    try:
        for idx, audit_port in enumerate(ports):
            part_total, part_ok, part_insufficient, part_auth_failed, part_failed, part_hits = audit_proxmox_targets(
                hosts=hosts,
                port=audit_port,
                timeout=args.timeout,
                retries=args.retries,
                workers=args.workers,
                pve_api_token=pve_api_token,
                use_https=bool(args.https),
                insecure=bool(args.insecure),
                proxy=proxy,
                discover_creds=discover_creds,
                show_nodes=show_nodes,
                show_users=show_users,
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                logger=logger if args.debug else None,
                append_output=idx > 0,
                suppress_fail_status_lines=False,
            )
            total += part_total
            token_ok += part_ok
            insufficient += part_insufficient
            auth_failed += part_auth_failed
            failed += part_failed
            credential_hits += part_hits
    except OSError as exc:
        console.error(f"failed to process proxmox output: {exc}")
        return 2

    if args.debug and args.output_format == "txt":
        console.info(
            f"proxmox audit complete: total={total} token_ok={token_ok} insufficient={insufficient} "
            f"auth_failed={auth_failed} fail={failed} credential_hits={credential_hits}"
        )
    return 0
