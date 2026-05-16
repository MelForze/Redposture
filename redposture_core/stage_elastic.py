"""Elasticsearch audit stage."""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections.abc import Callable
from typing import Any

from .console import Console
from .logger import AttemptLogger
from .rendering import BooleanColorRule, render_colored_marker_line
from .stage_runtime import (
    LineOutputSink,
    TwoPassAuditRunner,
    progress_total_from_groups,
    should_use_global_progress,
    start_audit_progress,
    start_command_progress,
)
from .utils import (
    build_scan_execution_groups,
    collect_scan_ports,
    collect_scan_target_specs,
    filter_open_tcp_hosts_for_credential_file,
    is_signature_compat_typeerror,
    parse_username_password_credential_file,
    utc_now_iso,
)

_ELASTIC_TAG = "ELASTIC"
_DISCOVER_QUERY_SIZE = 10000
_DISCOVER_MAX_PRINT_PER_INDEX = 200
_DETECT_EXTENDED_TIMEOUT = 2.5
_DETECT_CONFIRM_PATHS = (
    "/_cluster/health",
    "/_nodes?filter_path=nodes.*.version",
    "/_cat/health",
    "/_security/_authenticate",
)

_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_THREAD_LOCAL_DEBUG_EMIT = threading.local()
_VERSION_NUMBER_RE = re.compile(r'"number"\s*:\s*"([0-9]+(?:\.[0-9]+){1,3}(?:[-+][^"]+)?)"')
_VERSION_STRING_RE = re.compile(r'"version"\s*:\s*"([0-9]+(?:\.[0-9]+){1,3}(?:[-+][^"]+)?)"')

_DISCOVER_KEYWORDS = (
    "password",
    "secret",
    "key",
    "token",
    "api_key",
    "api_token",
    "service_token",
    "jwt",
    "private_key",
    "AKIA",
    "ASIA",
    "aws_access_key_id",
    "aws_secret_access_key",
    "ssh",
    "rdp",
    "aws_",
    "gcp",
    "gcp_",
    "google_api_key",
    "service_account",
    "azure_client_secret",
    "azure_storage_key",
    "azure",
    "azure_",
    "-----BEGIN",
    "PRIVATE KEY",
    "email",
    "user",
    "pass",
    "credential",
    "kibana",
    "elastic",
    "logstash",
    "beats",
    ".kibana",
    ".security",
    ".monitoring",
    ".logstash",
    ".apm",
)

_COMMON_ENDPOINT_PROBES = (
    "/_cat/aliases",
    "/_cat/templates",
    "/_cat/tasks",
    "/_ingest/pipeline",
    "/_remote/info",
)
_ELASTIC_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("elastic", "changeme"),
    ("elastic", "elastic"),
    ("elastic", "password"),
)


def _clip(text: str, width: int = 96) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _build_credential_runs(
    username: str | None,
    password: str | None,
    defcreds: bool,
) -> list[tuple[str | None, str | None]]:
    runs: list[tuple[str | None, str | None]] = []
    seen: set[tuple[str | None, str | None]] = set()
    if username is not None and password is not None:
        pair = (username, password)
        runs.append(pair)
        seen.add(pair)
    if defcreds:
        for user, secret in _ELASTIC_DEFAULT_CREDENTIALS:
            pair = (user, secret)
            if pair in seen:
                continue
            runs.append(pair)
            seen.add(pair)
    return runs or [(username, password)]


def _get_thread_debug_emitter() -> Callable[[str], None] | None:
    callback = getattr(_THREAD_LOCAL_DEBUG_EMIT, "callback", None)
    if callable(callback):
        return callback
    return None


def _header_lookup(headers: dict[str, str], name: str) -> str | None:
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            return str(value)
    return None


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


def _is_tls_or_protocol_error(error_text: str) -> bool:
    lower = str(error_text or "").lower()
    if not lower:
        return False
    tokens = (
        "ssl",
        "tls",
        "wrong version number",
        "unknown protocol",
        "http request",
        "certificate verify failed",
        "handshake",
    )
    return any(token in lower for token in tokens)


def _build_ssl_context(insecure: bool, ca_file: str | None) -> ssl.SSLContext:
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca_file:
        return ssl.create_default_context(cafile=ca_file)
    return ssl.create_default_context()


def _elastic_headers(
    *,
    username: str | None,
    password: str | None,
    api_token: str | None,
    include_json: bool = False,
) -> dict[str, str]:
    headers = {
        "User-Agent": "RedPosture/1.0",
    }
    if include_json:
        headers["Content-Type"] = "application/json; charset=utf-8"
    if api_token:
        headers["Authorization"] = f"ApiKey {api_token}"
        return headers
    if username is not None and password is not None:
        raw = f"{username}:{password}".encode("utf-8", errors="replace")
        token = base64.b64encode(raw).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    return headers


def _elastic_request(
    host: str,
    port: int,
    path: str,
    timeout: float,
    *,
    use_https: bool,
    insecure: bool,
    ca_file: str | None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> tuple[int, bytes, dict[str, str], str | None]:
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}{path}"
    req_headers = {"User-Agent": "RedPosture/1.0"}
    if headers:
        req_headers.update(headers)
    request = urllib.request.Request(url, data=data, method=method, headers=req_headers)

    context = None
    if use_https:
        context = _build_ssl_context(insecure, ca_file)

    handlers: list[urllib.request.BaseHandler] = []
    if use_https:
        handlers.append(urllib.request.HTTPSHandler(context=context))

    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(response.status)
            payload = response.read()
            response_headers = {str(key): str(value) for key, value in response.headers.items()}
            return status, payload, response_headers, None
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        response_headers = {str(key): str(value) for key, value in exc.headers.items()}
        return int(exc.code), payload, response_headers, None
    except Exception as exc:
        return 0, b"", {}, _friendly_error_from_exception(exc)


def _request_with_tls_fallback(
    host: str,
    port: int,
    path: str,
    timeout: float,
    *,
    ca_file: str | None,
    preferred_scheme: str = "https",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> tuple[int, bytes, dict[str, str], str | None, str, bool, bool]:
    normalized_scheme = str(preferred_scheme or "").strip().lower()
    if normalized_scheme not in {"http", "https"}:
        normalized_scheme = "https"
    first_use_https = normalized_scheme == "https"
    second_use_https = not first_use_https
    first_scheme = "https" if first_use_https else "http"
    second_scheme = "http" if first_use_https else "https"

    status, payload, response_headers, error = _elastic_request(
        host,
        port,
        path,
        timeout,
        use_https=first_use_https,
        insecure=first_use_https,
        ca_file=ca_file if first_use_https else None,
        method=method,
        headers=headers,
        data=data,
    )
    if status > 0:
        return status, payload, response_headers, error, first_scheme, first_use_https, not first_use_https

    fallback_status, fallback_payload, fallback_headers, fallback_error = _elastic_request(
        host,
        port,
        path,
        timeout,
        use_https=second_use_https,
        insecure=second_use_https,
        ca_file=ca_file if second_use_https else None,
        method=method,
        headers=headers,
        data=data,
    )
    if fallback_status > 0:
        return (
            fallback_status,
            fallback_payload,
            fallback_headers,
            fallback_error,
            second_scheme,
            second_use_https,
            not second_use_https,
        )

    first_error = str(error or "").strip() or "connection failed"
    second_error = str(fallback_error or "").strip() or "connection failed"
    combined_error = f"{first_scheme}={first_error}; {second_scheme}={second_error}"
    return (
        fallback_status,
        fallback_payload,
        fallback_headers,
        combined_error,
        second_scheme,
        second_use_https,
        not second_use_https,
    )


def _load_json_dict(payload: bytes) -> dict[str, Any] | None:
    try:
        parsed = json.loads(payload.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _load_json_dict_loose(payload: bytes, headers: dict[str, str] | None = None) -> dict[str, Any] | None:
    direct = _load_json_dict(payload)
    if isinstance(direct, dict):
        return direct

    encoding = str(_header_lookup(headers or {}, "Content-Encoding") or "").strip().lower()
    if "gzip" in encoding or (len(payload) >= 2 and payload[:2] == b"\x1f\x8b"):
        try:
            unpacked = gzip.decompress(payload)
        except (OSError, EOFError):
            unpacked = b""
        if unpacked:
            parsed = _load_json_dict(unpacked)
            if isinstance(parsed, dict):
                return parsed
            payload = unpacked
    elif "deflate" in encoding:
        unpacked = b""
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                unpacked = zlib.decompress(payload, wbits)
            except zlib.error:
                continue
            if unpacked:
                break
        if unpacked:
            parsed = _load_json_dict(unpacked)
            if isinstance(parsed, dict):
                return parsed
            payload = unpacked

    text = payload.decode("utf-8", errors="replace").lstrip("\ufeff").strip()
    if not text:
        return None

    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None

    candidate = text[start : end + 1]
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict):
        return parsed
    return None


def _load_json_list(payload: bytes) -> list[Any] | None:
    try:
        parsed = json.loads(payload.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, list):
        return None
    return parsed


def _looks_like_elastic_root(status: int, payload: bytes, headers: dict[str, str]) -> tuple[bool, str | None]:
    product_header = _header_lookup(headers, "X-Elastic-Product")
    if isinstance(product_header, str) and product_header.strip().lower() == "elasticsearch":
        body_dict = _load_json_dict_loose(payload, headers)
        if isinstance(body_dict, dict):
            version = body_dict.get("version")
            if isinstance(version, dict):
                number = version.get("number")
                if isinstance(number, str) and number.strip():
                    return True, number.strip()
        return True, None

    if status not in {200, 401, 403}:
        return False, None

    body_dict = _load_json_dict_loose(payload, headers)
    if not isinstance(body_dict, dict):
        return False, None

    has_markers = any(name in body_dict for name in ("tagline", "cluster_name", "version", "name"))
    if not has_markers:
        return False, None

    version = body_dict.get("version")
    if isinstance(version, dict):
        number = version.get("number")
        if isinstance(number, str) and number.strip():
            return True, number.strip()

    return True, None


def _extract_version_from_body_dict(body: dict[str, Any]) -> str | None:
    version = body.get("version")
    if not isinstance(version, dict):
        return None
    number = version.get("number")
    if isinstance(number, str) and number.strip():
        return number.strip()
    return None


def _extract_version_from_nodes_body(body: dict[str, Any]) -> str | None:
    nodes_raw = body.get("nodes")
    if not isinstance(nodes_raw, dict):
        return None
    for node_data in nodes_raw.values():
        if not isinstance(node_data, dict):
            continue
        raw = node_data.get("version")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    return None


def _extract_version_hint(payload: bytes, headers: dict[str, str] | None = None) -> str | None:
    body = _load_json_dict_loose(payload, headers)
    if isinstance(body, dict):
        version = _extract_version_from_body_dict(body)
        if isinstance(version, str) and version.strip():
            return version.strip()
        node_version = _extract_version_from_nodes_body(body)
        if isinstance(node_version, str) and node_version.strip():
            return node_version.strip()

    text = payload.decode("utf-8", errors="replace")
    match = _VERSION_NUMBER_RE.search(text)
    if match:
        return str(match.group(1)).strip()
    match = _VERSION_STRING_RE.search(text)
    if match:
        return str(match.group(1)).strip()
    return None


def _detect_opensearch_marker(headers: dict[str, str], body: dict[str, Any] | None) -> str | None:
    product_header = _header_lookup(headers, "X-Elastic-Product")
    if isinstance(product_header, str) and "opensearch" in product_header.strip().lower():
        return "vendor_opensearch_header"

    server_header = _header_lookup(headers, "Server")
    if isinstance(server_header, str) and "opensearch" in server_header.strip().lower():
        return "vendor_opensearch_server"

    if not isinstance(body, dict):
        return None

    tagline = str(body.get("tagline") or "").strip().lower()
    if "opensearch" in tagline:
        return "vendor_opensearch_tagline"

    distribution = str(body.get("distribution") or "").strip().lower()
    if "opensearch" in distribution:
        return "vendor_opensearch_distribution"

    version = body.get("version")
    if not isinstance(version, dict):
        return None
    version_distribution = str(version.get("distribution") or "").strip().lower()
    if "opensearch" in version_distribution:
        return "vendor_opensearch_version_distribution"
    build_flavor = str(version.get("build_flavor") or "").strip().lower()
    if "opensearch" in build_flavor:
        return "vendor_opensearch_build_flavor"
    return None


def _is_elastic_auth_error_payload(body: dict[str, Any]) -> bool:
    error_obj = body.get("error")
    if isinstance(error_obj, dict):
        error_type = str(error_obj.get("type") or "").strip().lower()
        reason = str(error_obj.get("reason") or "").strip().lower()
        if error_type == "security_exception" and (
            "missing authentication credentials" in reason
            or "unable to authenticate user" in reason
            or "authentication" in reason
        ):
            return True
    elif isinstance(error_obj, str):
        if "missing authentication credentials" in error_obj.lower():
            return True
    return False


def _looks_like_non_json_gateway_payload(payload: bytes, headers: dict[str, str]) -> bool:
    content_type = str(_header_lookup(headers, "Content-Type") or "").strip().lower()
    if "application/json" in content_type:
        return False

    text = payload.decode("utf-8", errors="replace").strip().lower()
    if not text:
        return False
    if text.startswith("{") or text.startswith("["):
        return False
    if "you know, for search" in text:
        return False

    html_markers = ("<!doctype html", "<html", "<head", "<body")
    proxy_markers = ("nginx", "reverse proxy", "bad gateway", "gateway timeout", "access denied")
    if "text/html" in content_type:
        return True
    if any(text.startswith(marker) for marker in html_markers):
        return True
    if any(marker in text[:300] for marker in proxy_markers):
        return True
    return False


def _classify_detect_probe(
    path: str,
    status: int,
    payload: bytes,
    headers: dict[str, str],
    error: str | None,
) -> dict[str, Any]:
    signals: list[str] = []
    kind = "neutral"
    version: str | None = None

    if error:
        return {"signal_kind": kind, "signals": signals, "version": version}

    body = _load_json_dict_loose(payload, headers)
    opensearch_marker = _detect_opensearch_marker(headers, body)
    if opensearch_marker:
        return {"signal_kind": "hard_negative", "signals": [opensearch_marker], "version": version}

    product_header = _header_lookup(headers, "X-Elastic-Product")
    if isinstance(product_header, str) and product_header.strip().lower() == "elasticsearch":
        signals.append("header_x_elastic_product")
        kind = "hard_positive"

    if isinstance(body, dict):
        version = _extract_version_from_body_dict(body)

        if path == "/":
            tagline = str(body.get("tagline") or "").strip()
            if tagline == "You Know, for Search":
                if "root_tagline" not in signals:
                    signals.append("root_tagline")
                kind = "hard_positive"
            if version and (body.get("cluster_name") is not None or body.get("name") is not None):
                if "root_version_shape" not in signals:
                    signals.append("root_version_shape")
                kind = "hard_positive"
            if status in {401, 403} and _is_elastic_auth_error_payload(body):
                if "security_exception_missing_auth" not in signals:
                    signals.append("security_exception_missing_auth")
                kind = "hard_positive"

            soft_fields = 0
            for field in ("cluster_name", "cluster_uuid", "name"):
                value = body.get(field)
                if isinstance(value, str) and value.strip():
                    soft_fields += 1
            if version:
                soft_fields += 1
            if kind != "hard_positive" and soft_fields >= 2:
                signals.append("root_partial_shape")
                kind = "soft_positive"

        elif path.startswith("/_nodes"):
            nodes_raw = body.get("nodes")
            if isinstance(nodes_raw, dict) and nodes_raw:
                has_node_version = any(
                    isinstance(node_data, dict)
                    and isinstance(node_data.get("version"), str)
                    and str(node_data.get("version")).strip()
                    for node_data in nodes_raw.values()
                )
                if has_node_version:
                    signals.append("nodes_version_shape")
                    version = _extract_version_from_nodes_body(body)
                    kind = "hard_positive"
                elif kind != "hard_positive":
                    signals.append("nodes_partial_shape")
                    kind = "soft_positive"

        elif path == "/_cluster/health":
            cluster_name = body.get("cluster_name")
            cluster_status = body.get("status")
            if (
                kind != "hard_positive"
                and isinstance(cluster_name, str)
                and cluster_name.strip()
                and isinstance(cluster_status, str)
                and cluster_status.strip()
            ):
                signals.append("cluster_health_shape")
                kind = "soft_positive"

        elif path == "/_security/_authenticate":
            if status in {401, 403} and _is_elastic_auth_error_payload(body):
                signals.append("security_exception_missing_auth")
                kind = "hard_positive"
            elif kind != "hard_positive":
                username = body.get("username")
                if isinstance(username, str) and username.strip():
                    signals.append("authenticate_username_shape")
                    kind = "soft_positive"

    elif path == "/_cat/health":
        text = payload.decode("utf-8", errors="replace").strip().lower()
        if status == 200 and "cluster" in text and "status" in text:
            signals.append("cat_health_text_shape")
            kind = "soft_positive"

    if path == "/" and kind == "neutral" and _looks_like_non_json_gateway_payload(payload, headers):
        signals.append("root_non_json_payload")
        kind = "hard_negative"

    return {"signal_kind": kind, "signals": signals, "version": version}


def _request_detect_probe(
    host: str,
    port: int,
    path: str,
    timeout: float,
    *,
    preferred_scheme: str,
    ca_file: str | None,
) -> tuple[int, bytes, dict[str, str], str | None, str]:
    use_https = preferred_scheme == "https"
    status, payload, headers, error = _elastic_request(
        host,
        port,
        path,
        timeout,
        use_https=use_https,
        insecure=use_https,
        ca_file=ca_file if use_https else None,
    )
    if status > 0:
        return status, payload, headers, error, preferred_scheme

    fallback_scheme = "http" if preferred_scheme == "https" else "https"
    fallback_https = fallback_scheme == "https"
    fallback_status, fallback_payload, fallback_headers, fallback_error = _elastic_request(
        host,
        port,
        path,
        timeout,
        use_https=fallback_https,
        insecure=fallback_https,
        ca_file=ca_file if fallback_https else None,
    )
    if fallback_status > 0:
        return fallback_status, fallback_payload, fallback_headers, fallback_error, fallback_scheme

    primary_error = str(error or "").strip() or "connection failed"
    secondary_error = str(fallback_error or "").strip() or "connection failed"
    combined = f"{preferred_scheme}={primary_error}; {fallback_scheme}={secondary_error}"
    return fallback_status, fallback_payload, fallback_headers, combined, fallback_scheme


def _resolve_server_version_without_auth(
    host: str,
    port: int,
    timeout: float,
    *,
    preferred_scheme: str,
    ca_file: str | None,
) -> tuple[str | None, str | None]:
    probe_timeout = max(float(timeout), _DETECT_EXTENDED_TIMEOUT)
    attempts = 2
    scheme = preferred_scheme
    last_error: str | None = None

    root_status, root_payload, root_headers, root_error, root_scheme, _root_insecure, _root_plain = (
        _request_with_tls_fallback(
            host,
            port,
            "/",
            probe_timeout,
            ca_file=ca_file,
        )
    )
    if root_status > 0:
        root_version = _extract_version_hint(root_payload, root_headers)
        if root_version:
            return root_version, None
    elif root_error:
        last_error = str(root_error).strip() or last_error
    scheme = root_scheme

    for attempt in range(attempts):
        for path in ("/", "/_nodes?filter_path=nodes.*.version", "/_cat/nodes?format=json&h=version"):
            status, payload, headers, error, used_scheme = _request_detect_probe(
                host,
                port,
                path,
                probe_timeout,
                preferred_scheme=scheme,
                ca_file=ca_file,
            )
            scheme = used_scheme
            if status > 0:
                version = _extract_version_hint(payload, headers)
                if version:
                    return version, None
            elif error:
                last_error = str(error).strip() or last_error
        if attempt < attempts - 1:
            time.sleep(_retry_delay(attempt))
    return None, last_error


def _evaluate_detect_decision(probes: list[dict[str, Any]]) -> dict[str, Any]:
    hard_positive = [probe for probe in probes if str(probe.get("signal_kind")) == "hard_positive"]
    soft_positive = [probe for probe in probes if str(probe.get("signal_kind")) == "soft_positive"]
    hard_negative = [probe for probe in probes if str(probe.get("signal_kind")) == "hard_negative"]

    soft_paths = {str(probe.get("path") or "") for probe in soft_positive if str(probe.get("path") or "").strip()}

    signals: list[str] = []
    for probe in probes:
        probe_signals = probe.get("signals")
        if not isinstance(probe_signals, list):
            continue
        for signal in probe_signals:
            signal_text = str(signal).strip()
            if signal_text and signal_text not in signals:
                signals.append(signal_text)

    if hard_positive:
        detected = True
        confidence = "high" if not hard_negative else "medium"
    elif len(soft_paths) >= 2 and not hard_negative:
        detected = True
        confidence = "medium"
    elif hard_negative and not soft_positive:
        detected = False
        confidence = "low"
    else:
        detected = True
        confidence = "low"

    primary_probe: dict[str, Any] | None = None
    if hard_positive:
        primary_probe = hard_positive[0]
    elif soft_positive:
        primary_probe = soft_positive[0]
    elif probes:
        primary_probe = probes[0]

    version: str | None = None
    for probe in hard_positive + soft_positive + probes:
        probe_version = probe.get("version")
        if isinstance(probe_version, str) and probe_version.strip():
            version = probe_version.strip()
            break

    return {
        "detected": detected,
        "confidence": confidence,
        "signals": signals,
        "primary_probe": primary_probe,
        "has_hard_negative": bool(hard_negative),
        "has_positive": bool(hard_positive or soft_positive),
        "version": version,
    }


def _normalize_access_level(
    *,
    can_read: bool | None,
    can_write: bool | None,
    can_manage: bool | None,
    can_manage_security: bool | None,
) -> str:
    if None in {can_read, can_write, can_manage, can_manage_security}:
        return "unknown"
    if bool(can_write) or bool(can_manage) or bool(can_manage_security):
        return "more_than_read"
    if bool(can_read):
        return "read_only"
    return "unknown"


def _extract_discover_total(total_raw: Any) -> int:
    if isinstance(total_raw, int):
        return int(total_raw)
    if isinstance(total_raw, dict):
        value = total_raw.get("value")
        if isinstance(value, int):
            return int(value)
    return 0


def _build_discover_query_string() -> str:
    tokens: list[str] = []
    seen: set[str] = set()
    for keyword in _DISCOVER_KEYWORDS:
        clean = str(keyword).strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        if re.search(r"[^A-Za-z0-9_.*-]", clean):
            escaped = clean.replace("\\", "\\\\").replace('"', '\\"')
            tokens.append(f'"{escaped}"')
        else:
            tokens.append(clean)
    return " OR ".join(tokens)


def _extract_cat_endpoints(payload: bytes) -> list[str]:
    text = payload.decode("utf-8", errors="replace")
    endpoints: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = re.search(r"(/_cat/[A-Za-z0-9_./-]+)", line)
        if not match:
            continue
        endpoint = match.group(1)
        if endpoint in seen:
            continue
        seen.add(endpoint)
        endpoints.append(endpoint)
    return endpoints


def _extract_cat_plugins(payload: bytes) -> list[dict[str, str]]:
    parsed = _load_json_list(payload)
    plugins: list[dict[str, str]] = []
    if isinstance(parsed, list):
        for item in parsed:
            if not isinstance(item, dict):
                continue
            plugins.append(
                {
                    "node": str(item.get("name") or "-"),
                    "component": str(item.get("component") or "-"),
                    "version": str(item.get("version") or "-"),
                    "description": str(item.get("description") or "-"),
                }
            )
        return plugins

    text = payload.decode("utf-8", errors="replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        node = parts[0]
        component = parts[1]
        version = parts[2]
        description = parts[3] if len(parts) > 3 else "-"
        plugins.append(
            {
                "node": str(node or "-"),
                "component": str(component or "-"),
                "version": str(version or "-"),
                "description": str(description or "-"),
            }
        )
    return plugins


def _extract_version_from_nodes_payload(payload: bytes) -> str | None:
    parsed = _load_json_dict(payload)
    if parsed is None:
        return None
    nodes_raw = parsed.get("nodes")
    if not isinstance(nodes_raw, dict):
        return None
    for node_data in nodes_raw.values():
        if not isinstance(node_data, dict):
            continue
        raw = node_data.get("version")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    return None


def _resolve_server_version_with_auth(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
) -> tuple[str | None, str | None]:
    status, payload, headers, error = _elastic_request(
        host,
        port,
        "/",
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        headers=auth_headers,
    )
    if error:
        return None, error
    if status == 200:
        _is_elastic, version = _looks_like_elastic_root(status, payload, headers)
        if isinstance(version, str) and version.strip():
            return version.strip(), None
    elif status not in {401, 403}:
        return None, f"status={status}"

    node_status, nodes_payload, _nodes_headers, nodes_error = _elastic_request(
        host,
        port,
        "/_nodes?filter_path=nodes.*.version",
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        headers=auth_headers,
    )
    if nodes_error:
        return None, nodes_error
    if node_status in {401, 403}:
        return None, "Access Denied"
    if node_status != 200:
        return None, f"nodes status={node_status}"
    version = _extract_version_from_nodes_payload(nodes_payload)
    if version:
        return version, None
    return None, "version unavailable"


def _verify_api_key_probe(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
) -> tuple[str, str | None]:
    status, payload, _headers, error = _elastic_request(
        host,
        port,
        "/_security/api_key?size=1",
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        headers=auth_headers,
    )
    if error:
        return "error", error
    if status == 200:
        parsed = _load_json_dict(payload)
        if parsed is None:
            return "error", "invalid api key payload"
        return "ok", None
    if status in {401, 403}:
        return "denied", "Access Denied"
    return "error", f"status={status}"


def _probe_endpoint_status(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
    endpoint: str,
) -> tuple[int, str | None]:
    status, _payload, _headers, error = _elastic_request(
        host,
        port,
        endpoint,
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        headers=auth_headers,
    )
    return status, error


def _fetch_cat_endpoints(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
) -> tuple[list[str] | None, str | None, list[dict[str, Any]]]:
    diagnostics: list[dict[str, Any]] = []
    discovered: set[str] = set()
    had_cat_success = False
    had_cat_denied = False
    cat_errors: list[str] = []

    for path in ("/_cat?help", "/_cat/"):
        status, payload, _headers, error = _elastic_request(
            host,
            port,
            path,
            timeout,
            use_https=scheme == "https",
            insecure=insecure,
            ca_file=ca_file,
            headers=auth_headers,
        )
        diagnostics.append(
            {
                "endpoint": path,
                "status": int(status),
                "error": error,
            }
        )
        if error:
            cat_errors.append(str(error))
            continue
        if status in {401, 403}:
            had_cat_denied = True
            continue
        if status != 200:
            cat_errors.append(f"{path} status={status}")
            continue
        had_cat_success = True
        for endpoint in _extract_cat_endpoints(payload):
            discovered.add(endpoint)

    for endpoint in _COMMON_ENDPOINT_PROBES:
        discovered.add(endpoint)

    available: set[str] = set()
    for endpoint in sorted(discovered):
        status, error = _probe_endpoint_status(
            host,
            port,
            timeout,
            scheme=scheme,
            insecure=insecure,
            ca_file=ca_file,
            auth_headers=auth_headers,
            endpoint=endpoint,
        )
        diagnostics.append(
            {
                "endpoint": endpoint,
                "status": int(status),
                "error": error,
            }
        )
        if error:
            continue
        if 200 <= int(status) < 300:
            available.add(endpoint)

    if available:
        return sorted(available), None, diagnostics
    if had_cat_denied and not had_cat_success:
        return [], "Access Denied", diagnostics
    if cat_errors and not had_cat_success:
        return [], cat_errors[0], diagnostics
    return [], None, diagnostics


def _fetch_cat_plugins(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
) -> tuple[list[dict[str, str]] | None, str | None]:
    status, payload, _headers, error = _elastic_request(
        host,
        port,
        "/_cat/plugins?format=json",
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        headers=auth_headers,
    )
    if error:
        return None, error
    if status in {401, 403}:
        return None, "Access Denied"
    if status != 200:
        return None, f"status={status}"
    plugins = _extract_cat_plugins(payload)
    return plugins, None


def _fetch_cluster_data(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]] | None, str | None]:
    health_status, health_payload, _health_headers, health_error = _elastic_request(
        host,
        port,
        "/_cluster/health",
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        headers=auth_headers,
    )
    if health_error:
        return None, None, health_error
    if health_status in {401, 403}:
        return None, None, "Access Denied"
    if health_status != 200:
        return None, None, f"cluster health status={health_status}"

    health = _load_json_dict(health_payload)
    if health is None:
        return None, None, "invalid cluster health payload"

    nodes_status, nodes_payload, _nodes_headers, nodes_error = _elastic_request(
        host,
        port,
        "/_nodes?filter_path=nodes.*.name,nodes.*.roles,nodes.*.ip,nodes.*.host",
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        headers=auth_headers,
    )
    if nodes_error:
        return health, None, nodes_error
    if nodes_status in {401, 403}:
        return health, None, "Access Denied"
    if nodes_status != 200:
        return health, None, f"nodes status={nodes_status}"

    nodes_dict = _load_json_dict(nodes_payload)
    if nodes_dict is None:
        return health, None, "invalid nodes payload"

    raw_nodes = nodes_dict.get("nodes")
    parsed_nodes: list[dict[str, Any]] = []
    if isinstance(raw_nodes, dict):
        for node_id, node_data in raw_nodes.items():
            if not isinstance(node_data, dict):
                continue
            roles = node_data.get("roles")
            role_list = [str(role) for role in roles if isinstance(role, str)] if isinstance(roles, list) else []
            parsed_nodes.append(
                {
                    "id": str(node_id),
                    "name": str(node_data.get("name") or "-"),
                    "ip": str(node_data.get("ip") or "-"),
                    "host": str(node_data.get("host") or "-"),
                    "roles": role_list,
                }
            )

    parsed_nodes.sort(key=lambda item: str(item.get("name") or ""))
    return health, parsed_nodes, None


def _normalize_setting_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value).strip()


def _is_truthy_setting(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _is_false_setting(value: str) -> bool:
    return value.strip().lower() in {"0", "false", "no", "off", "disabled"}


def _is_wildcard_origin(value: str) -> bool:
    lower = value.strip().strip('"').strip("'").lower()
    if lower in {"*", "http://*", "https://*", ".*"}:
        return True
    return "*" in lower


def _is_world_bind(value: str) -> bool:
    normalized = value.strip().strip('"').strip("'").lower()
    if normalized in {"0.0.0.0", "::", "*", "_global_"}:
        return True
    parts = [part.strip() for part in normalized.split(",") if part.strip()]
    if not parts:
        return False
    return any(part in {"0.0.0.0", "::", "*", "_global_"} for part in parts)


def _flatten_mapping(prefix: str, value: Any, out: dict[str, str]) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_text = str(key)
            next_prefix = f"{prefix}.{key_text}" if prefix else key_text
            _flatten_mapping(next_prefix, nested, out)
        return
    out[prefix] = _normalize_setting_value(value)


def _collect_cluster_flat_settings(payload: dict[str, Any]) -> dict[str, str]:
    flat: dict[str, str] = {}
    for section in ("persistent", "transient", "defaults"):
        section_value = payload.get(section)
        if isinstance(section_value, dict):
            _flatten_mapping("", section_value, flat)
    return flat


def _collect_nodes_flat_settings(payload: dict[str, Any]) -> dict[str, str]:
    flat: dict[str, str] = {}
    nodes = payload.get("nodes")
    if not isinstance(nodes, dict):
        return flat
    for node_data in nodes.values():
        if not isinstance(node_data, dict):
            continue
        settings = node_data.get("settings")
        if not isinstance(settings, dict):
            continue
        _flatten_mapping("", settings, flat)
    return flat


def _merge_settings_values(*maps: dict[str, str]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for mapping in maps:
        for key, value in mapping.items():
            clean = _normalize_setting_value(value)
            if not clean:
                continue
            current = merged.setdefault(key, [])
            if clean not in current:
                current.append(clean)
    return merged


def _build_misconfig_findings(values_by_key: dict[str, list[str]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    def add(key: str, value: str, reason: str) -> None:
        entry = {
            "key": key,
            "value": value,
            "reason": reason,
        }
        if entry not in findings:
            findings.append(entry)

    for key, values in values_by_key.items():
        for value in values:
            if key == "xpack.security.enabled" and _is_false_setting(value):
                add(key, value, "security is disabled")
            if key == "xpack.security.http.ssl.enabled" and _is_false_setting(value):
                add(key, value, "http tls is disabled")
            if key in {"http.bind_host", "network.host"} and _is_world_bind(value):
                add(key, value, "service is bound to all interfaces")
            if key in {"script.allowed_types", "script.allowed_contexts"} and (
                "inline" in value.lower() or value.strip() in {"*", "all"}
            ):
                add(key, value, "script execution appears permissive")
            if key == "script.inline" and _is_truthy_setting(value):
                add(key, value, "inline script execution is enabled")

    cors_enabled = any(_is_truthy_setting(value) for value in values_by_key.get("http.cors.enabled", []))
    cors_origins = values_by_key.get("http.cors.allow-origin", [])
    if cors_enabled:
        for value in cors_origins:
            if _is_wildcard_origin(value):
                add("http.cors.allow-origin", value, "cors allows wildcard origins")

    return findings


def _fetch_cluster_misconfig_findings(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
) -> tuple[list[dict[str, str]] | None, str | None]:
    cluster_status, cluster_payload, _cluster_headers, cluster_error = _elastic_request(
        host,
        port,
        "/_cluster/settings?include_defaults=true&flat_settings=true",
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        headers=auth_headers,
    )
    if cluster_error:
        return None, cluster_error
    if cluster_status in {401, 403}:
        return None, "Access Denied"
    if cluster_status != 200:
        return None, f"cluster settings status={cluster_status}"
    cluster_parsed = _load_json_dict(cluster_payload)
    if cluster_parsed is None:
        return None, "invalid cluster settings payload"

    nodes_status, nodes_payload, _nodes_headers, nodes_error = _elastic_request(
        host,
        port,
        "/_nodes/settings?flat_settings=true",
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        headers=auth_headers,
    )
    if nodes_error:
        return None, nodes_error
    if nodes_status in {401, 403}:
        return None, "Access Denied"
    if nodes_status != 200:
        return None, f"nodes settings status={nodes_status}"
    nodes_parsed = _load_json_dict(nodes_payload)
    if nodes_parsed is None:
        return None, "invalid nodes settings payload"

    values_by_key = _merge_settings_values(
        _collect_cluster_flat_settings(cluster_parsed),
        _collect_nodes_flat_settings(nodes_parsed),
    )
    findings = _build_misconfig_findings(values_by_key)
    return findings, None


def _fetch_security_users(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
) -> tuple[list[dict[str, Any]] | None, str | None]:
    status, payload, _headers, error = _elastic_request(
        host,
        port,
        "/_security/user",
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        headers=auth_headers,
    )
    if error:
        return None, error
    if status in {401, 403}:
        return None, "Access Denied"
    if status != 200:
        return None, f"status={status}"

    body = _load_json_dict(payload)
    if body is None:
        return None, "invalid users payload"

    users: list[dict[str, Any]] = []
    for username, meta in body.items():
        if not isinstance(meta, dict):
            continue
        roles = meta.get("roles")
        users.append(
            {
                "username": str(username),
                "roles": [str(role) for role in roles if isinstance(role, str)] if isinstance(roles, list) else [],
                "enabled": bool(meta.get("enabled")) if meta.get("enabled") is not None else None,
                "full_name": str(meta.get("full_name") or ""),
            }
        )
    users.sort(key=lambda item: str(item.get("username") or ""))
    return users, None


def _check_privileges(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
) -> tuple[bool | None, bool | None, bool | None, bool | None, str | None]:
    body = {
        "cluster": ["monitor", "manage", "manage_security"],
        "index": [
            {
                "names": ["*"],
                "privileges": ["read", "view_index_metadata", "write", "create_index"],
            }
        ],
    }
    headers = dict(auth_headers)
    headers["Content-Type"] = "application/json; charset=utf-8"
    status, payload, _resp_headers, error = _elastic_request(
        host,
        port,
        "/_security/user/_has_privileges",
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        method="POST",
        headers=headers,
        data=json.dumps(body).encode("utf-8"),
    )
    if error:
        return None, None, None, None, error
    if status in {401, 403}:
        return None, None, None, None, "Access Denied"
    if status != 200:
        return None, None, None, None, f"status={status}"

    parsed = _load_json_dict(payload)
    if parsed is None:
        return None, None, None, None, "invalid privileges payload"

    cluster_map = parsed.get("cluster")
    can_manage = None
    can_manage_security = None
    can_read = None
    can_write = None

    if isinstance(cluster_map, dict):
        if isinstance(cluster_map.get("manage"), bool):
            can_manage = bool(cluster_map.get("manage"))
        if isinstance(cluster_map.get("manage_security"), bool):
            can_manage_security = bool(cluster_map.get("manage_security"))

    index_map = parsed.get("index")
    if isinstance(index_map, dict):
        read_values: list[bool] = []
        write_values: list[bool] = []
        for _index_name, permissions in index_map.items():
            if not isinstance(permissions, dict):
                continue
            read_hit = permissions.get("read")
            view_hit = permissions.get("view_index_metadata")
            write_hit = permissions.get("write")
            create_hit = permissions.get("create_index")
            if isinstance(read_hit, bool) or isinstance(view_hit, bool):
                read_values.append(bool(read_hit) or bool(view_hit))
            if isinstance(write_hit, bool) or isinstance(create_hit, bool):
                write_values.append(bool(write_hit) or bool(create_hit))
        if read_values:
            can_read = any(read_values)
        if write_values:
            can_write = any(write_values)

    return can_read, can_write, can_manage, can_manage_security, None


def _list_index_names(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
) -> tuple[list[str] | None, str | None]:
    status, payload, _headers, error = _elastic_request(
        host,
        port,
        "/_cat/indices?format=json&expand_wildcards=all&h=index",
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        headers=auth_headers,
    )
    if error:
        return None, error
    if status in {401, 403}:
        return None, "Access Denied"
    if status != 200:
        return None, f"status={status}"

    payload_list = _load_json_list(payload)
    if payload_list is None:
        return None, "invalid indices payload"

    indices: list[str] = []
    seen: set[str] = set()
    for item in payload_list:
        if not isinstance(item, dict):
            continue
        name = str(item.get("index") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        indices.append(name)
    indices.sort()
    return indices, None


def _search_index(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
    index_name: str,
    query_string: str,
) -> tuple[int, list[dict[str, Any]] | None, str | None]:
    path = f"/{urllib.parse.quote(index_name, safe='')}/_search?size={_DISCOVER_QUERY_SIZE}&expand_wildcards=all"
    body = {
        "size": _DISCOVER_QUERY_SIZE,
        "query": {
            "simple_query_string": {
                "query": query_string,
                "fields": ["*"],
                "default_operator": "OR",
                "analyze_wildcard": True,
                "lenient": True,
            }
        },
    }
    headers = dict(auth_headers)
    headers["Content-Type"] = "application/json; charset=utf-8"

    status, payload, _headers, error = _elastic_request(
        host,
        port,
        path,
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        method="POST",
        headers=headers,
        data=json.dumps(body).encode("utf-8"),
    )
    if error:
        return 0, None, error
    if status in {401, 403}:
        return 0, None, "Access Denied"
    if status != 200:
        return 0, None, f"status={status}"

    parsed = _load_json_dict(payload)
    if parsed is None:
        return 0, None, "invalid search payload"

    hits_obj = parsed.get("hits")
    if not isinstance(hits_obj, dict):
        return 0, None, "invalid search hits payload"

    total_hits = _extract_discover_total(hits_obj.get("total"))

    raw_hits = hits_obj.get("hits")
    parsed_hits: list[dict[str, Any]] = []
    if isinstance(raw_hits, list):
        for item in raw_hits:
            if not isinstance(item, dict):
                continue
            source = item.get("_source")
            if not isinstance(source, dict):
                continue
            parsed_hits.append(
                {
                    "id": str(item.get("_id") or ""),
                    "source": source,
                }
            )

    return total_hits, parsed_hits, None


def _collect_discover_results(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
) -> tuple[list[dict[str, Any]] | None, str | None]:
    indices, indices_error = _list_index_names(
        host,
        port,
        timeout,
        scheme=scheme,
        insecure=insecure,
        ca_file=ca_file,
        auth_headers=auth_headers,
    )
    if indices is None:
        return None, indices_error or "failed to list indices"

    query_string = _build_discover_query_string()
    results: list[dict[str, Any]] = []

    for index_name in indices:
        total_hits, hits, search_error = _search_index(
            host,
            port,
            timeout,
            scheme=scheme,
            insecure=insecure,
            ca_file=ca_file,
            auth_headers=auth_headers,
            index_name=index_name,
            query_string=query_string,
        )
        if search_error:
            results.append(
                {
                    "index": index_name,
                    "total_hits": 0,
                    "shown_hits": 0,
                    "truncated": False,
                    "hits": [],
                    "error": search_error,
                }
            )
            continue

        shown = list(hits or [])[:_DISCOVER_MAX_PRINT_PER_INDEX]
        results.append(
            {
                "index": index_name,
                "total_hits": int(total_hits),
                "shown_hits": len(shown),
                "truncated": int(total_hits) > len(shown),
                "hits": shown,
                "error": None,
            }
        )

    return results, None


def _verify_authenticate(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
) -> tuple[bool | None, str | None, str | None]:
    status, payload, _headers, error = _elastic_request(
        host,
        port,
        "/_security/_authenticate",
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        headers=auth_headers,
    )
    if error:
        return None, error, None
    if status == 200:
        body = _load_json_dict(payload)
        username = None
        if isinstance(body, dict):
            raw_user = body.get("username")
            if isinstance(raw_user, str) and raw_user.strip():
                username = raw_user.strip()
        return True, None, username
    if status in {401, 403}:
        return False, "authentication failed", None
    return None, f"status={status}", None


def _call_audit_elastic_host_with_thread_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    api_token: str | None,
    ca_file: str | None,
    show_endpoints: bool,
    show_plugins: bool,
    show_cluster: bool,
    show_users: bool,
    discover: bool,
    preferred_scheme: str | None,
    debug: bool,
    run_deep_checks: bool,
    debug_emit: Callable[[str], None] | None,
) -> dict[str, Any]:
    def _invoke() -> dict[str, Any]:
        try:
            return _audit_elastic_host(
                host,
                port,
                timeout,
                retries,
                username,
                password,
                api_token,
                ca_file,
                show_endpoints,
                show_plugins,
                show_cluster,
                show_users,
                discover,
                preferred_scheme=preferred_scheme,
                debug=debug,
                run_deep_checks=run_deep_checks,
            )
        except TypeError as exc:
            if not is_signature_compat_typeerror(exc, expected_keywords={"debug", "run_deep_checks"}):
                raise
            return _audit_elastic_host(
                host,
                port,
                timeout,
                retries,
                username,
                password,
                api_token,
                ca_file,
                show_endpoints,
                show_plugins,
                show_cluster,
                show_users,
                discover,
                preferred_scheme=preferred_scheme,
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


def _audit_elastic_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    api_token: str | None,
    ca_file: str | None,
    show_endpoints: bool,
    show_plugins: bool,
    show_cluster: bool,
    show_users: bool,
    discover: bool,
    preferred_scheme: str | None = None,
    debug: bool = False,
    run_deep_checks: bool = True,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None

    provided_credentials = bool(username is not None and password is not None)
    provided_token = bool(api_token)
    auth_provided = provided_token or provided_credentials
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
                status=str(payload.get("status") or "fail"), attempts_done=attempts_done, max_attempts=max_attempts
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
        status, payload, root_headers, error, scheme, effective_insecure, tls_auto_plain = _request_with_tls_fallback(
            host,
            port,
            "/",
            timeout,
            ca_file=ca_file,
            preferred_scheme=str(preferred_scheme or "https"),
        )
        if error and status <= 0:
            last_error = error
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

        root_detection = _classify_detect_probe("/", status, payload, root_headers, error)
        root_detection_version = root_detection.get("version")
        if not isinstance(root_detection_version, str) or not root_detection_version.strip():
            root_detection["version"] = _extract_version_hint(payload, root_headers)
        if (
            scheme == "https"
            and status > 0
            and str(root_detection.get("signal_kind") or "neutral") in {"neutral", "hard_negative"}
        ):
            plain_status, plain_payload, plain_headers, plain_error = _elastic_request(
                host,
                port,
                "/",
                timeout,
                use_https=False,
                insecure=False,
                ca_file=None,
            )
            if plain_status > 0:
                plain_detection = _classify_detect_probe("/", plain_status, plain_payload, plain_headers, plain_error)
                plain_detection_version = plain_detection.get("version")
                if not isinstance(plain_detection_version, str) or not plain_detection_version.strip():
                    plain_detection["version"] = _extract_version_hint(plain_payload, plain_headers)
                if str(plain_detection.get("signal_kind") or "neutral") in {"hard_positive", "soft_positive"}:
                    status = plain_status
                    payload = plain_payload
                    root_headers = plain_headers
                    error = plain_error
                    scheme = "http"
                    effective_insecure = False
                    tls_auto_plain = True
                    root_detection = plain_detection
        detect_probes: list[dict[str, Any]] = [
            {
                "path": "/",
                "status": int(status),
                "scheme": scheme,
                "error": error,
                "signal_kind": str(root_detection.get("signal_kind") or "neutral"),
                "signals": list(root_detection.get("signals") or []),
                "version": root_detection.get("version"),
                "payload": payload,
                "headers": root_headers,
                "insecure_effective": effective_insecure,
                "tls_auto_plain": tls_auto_plain,
                "pass": "base",
            }
        ]
        root_probe_status = int(status)
        root_probe_scheme = scheme

        preferred_scheme = scheme
        for probe_path in _DETECT_CONFIRM_PATHS:
            probe_status, probe_payload, probe_headers, probe_error, probe_scheme = _request_detect_probe(
                host,
                port,
                probe_path,
                timeout,
                preferred_scheme=preferred_scheme,
                ca_file=ca_file,
            )
            probe_detection = _classify_detect_probe(
                probe_path, probe_status, probe_payload, probe_headers, probe_error
            )
            probe_detection_version = probe_detection.get("version")
            if not isinstance(probe_detection_version, str) or not probe_detection_version.strip():
                probe_detection["version"] = _extract_version_hint(probe_payload, probe_headers)
            detect_probes.append(
                {
                    "path": probe_path,
                    "status": int(probe_status),
                    "scheme": probe_scheme,
                    "error": probe_error,
                    "signal_kind": str(probe_detection.get("signal_kind") or "neutral"),
                    "signals": list(probe_detection.get("signals") or []),
                    "version": probe_detection.get("version"),
                    "payload": probe_payload,
                    "headers": probe_headers,
                    "insecure_effective": probe_scheme == "https",
                    "tls_auto_plain": probe_scheme == "http" and preferred_scheme == "https",
                    "pass": "base",
                }
            )
            if probe_status > 0:
                preferred_scheme = probe_scheme

        detect_decision = _evaluate_detect_decision(detect_probes)
        if str(detect_decision.get("confidence") or "low") == "low":
            extended_timeout = max(float(timeout), _DETECT_EXTENDED_TIMEOUT)
            for probe_path in _DETECT_CONFIRM_PATHS:
                probe_status, probe_payload, probe_headers, probe_error, probe_scheme = _request_detect_probe(
                    host,
                    port,
                    probe_path,
                    extended_timeout,
                    preferred_scheme=preferred_scheme,
                    ca_file=ca_file,
                )
                probe_detection = _classify_detect_probe(
                    probe_path, probe_status, probe_payload, probe_headers, probe_error
                )
                probe_detection_version = probe_detection.get("version")
                if not isinstance(probe_detection_version, str) or not probe_detection_version.strip():
                    probe_detection["version"] = _extract_version_hint(probe_payload, probe_headers)
                detect_probes.append(
                    {
                        "path": probe_path,
                        "status": int(probe_status),
                        "scheme": probe_scheme,
                        "error": probe_error,
                        "signal_kind": str(probe_detection.get("signal_kind") or "neutral"),
                        "signals": list(probe_detection.get("signals") or []),
                        "version": probe_detection.get("version"),
                        "payload": probe_payload,
                        "headers": probe_headers,
                        "insecure_effective": probe_scheme == "https",
                        "tls_auto_plain": probe_scheme == "http" and preferred_scheme == "https",
                        "pass": "extended",
                    }
                )
                if probe_status > 0:
                    preferred_scheme = probe_scheme
            detect_decision = _evaluate_detect_decision(detect_probes)

        detect_confidence = str(detect_decision.get("confidence") or "low")
        detect_signals = [str(item) for item in (detect_decision.get("signals") or []) if str(item).strip()]
        detect_probe_trace = [
            {
                "path": str(probe.get("path") or "-"),
                "status": int(probe.get("status") or 0),
                "scheme": str(probe.get("scheme") or "-"),
            }
            for probe in detect_probes
        ]

        is_elastic = bool(detect_decision.get("detected"))
        version_raw = detect_decision.get("version")
        version = str(version_raw).strip() if isinstance(version_raw, str) and version_raw.strip() else None

        primary_probe = detect_decision.get("primary_probe")
        if isinstance(primary_probe, dict):
            status = int(primary_probe.get("status") or status)
            probe_payload = primary_probe.get("payload")
            if isinstance(probe_payload, (bytes, bytearray)):
                payload = bytes(probe_payload)
            probe_headers = primary_probe.get("headers")
            if isinstance(probe_headers, dict):
                root_headers = {str(key): str(value) for key, value in probe_headers.items()}
            probe_error = primary_probe.get("error")
            if isinstance(probe_error, str):
                error = probe_error
            scheme = str(primary_probe.get("scheme") or scheme)
            primary_insecure = primary_probe.get("insecure_effective")
            if isinstance(primary_insecure, bool):
                effective_insecure = primary_insecure
            tls_auto_plain = bool(primary_probe.get("tls_auto_plain"))

        if not is_elastic:
            _stage_trace(
                _STAGE_DETECT_PROTOCOL,
                attempt=attempt + 1,
                started_at=stage1_started,
                result="not_elastic",
                error=None,
            )
            _debug(
                f"attempt={attempt + 1}/{attempts} result=not_elastic total_ms={int((time.monotonic() - started) * 1000)}"
            )
            return _record(
                {
                    "timestamp": utc_now_iso(),
                    "host": host,
                    "port": port,
                    "is_elastic": False,
                    "status": "not_elastic",
                    "auth_required": None,
                    "server_version": None,
                    "provided_credentials": provided_credentials,
                    "provided_username": username,
                    "provided_password": password if provided_credentials else None,
                    "provided_token": provided_token,
                    "api_token": api_token if provided_token else None,
                    "api_key_probe_status": "not_run",
                    "api_key_probe_error": None,
                    "effective_username": None,
                    "auth_valid": None,
                    "show_endpoints": show_endpoints,
                    "show_plugins": show_plugins,
                    "show_cluster": show_cluster,
                    "show_users": show_users,
                    "discover": discover,
                    "cat_endpoints": None,
                    "endpoint_diagnostics": None,
                    "cat_plugins": None,
                    "cluster_health": None,
                    "cluster_nodes": None,
                    "misconfig_findings": None,
                    "misconfig_error": None,
                    "users": None,
                    "discover_results": None,
                    "can_read": None,
                    "can_write": None,
                    "can_manage": None,
                    "can_manage_security": None,
                    "access_level": "unknown",
                    "rights_error": None,
                    "endpoints_error": None,
                    "plugins_error": None,
                    "cluster_error": None,
                    "users_error": None,
                    "discover_error": None,
                    "scheme": scheme,
                    "insecure_effective": effective_insecure,
                    "tls_auto_plain": tls_auto_plain,
                    "detect_confidence": detect_confidence,
                    "detect_signals": detect_signals,
                    "detect_probe_trace": detect_probe_trace,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": None,
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

        stage2_started = time.monotonic()
        auth_required: bool | None
        positive_probe_statuses = [
            int(probe.get("status") or 0)
            for probe in detect_probes
            if str(probe.get("signal_kind") or "neutral") in {"hard_positive", "soft_positive"}
        ]
        if root_probe_status in {401, 403}:
            auth_required = True
        elif root_probe_status == 200:
            auth_required = False
        elif 200 in positive_probe_statuses:
            auth_required = False
        elif any(item in {401, 403} for item in positive_probe_statuses):
            auth_required = True
        elif status in {401, 403}:
            auth_required = True
        elif status == 200:
            auth_required = False
        else:
            auth_required = None

        auth_headers = _elastic_headers(username=username, password=password, api_token=api_token)

        auth_valid: bool | None = None
        effective_username: str | None = None
        auth_error: str | None = None
        if auth_provided:
            auth_valid, auth_error, effective_username = _verify_authenticate(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=auth_headers,
            )

        api_key_probe_status = "not_run"
        api_key_probe_error: str | None = None
        if provided_token:
            api_key_probe_status, api_key_probe_error = _verify_api_key_probe(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=auth_headers,
            )

        if auth_valid is True:
            service_status = "valid_credentials"
        elif auth_required is False and auth_provided and auth_valid is False:
            service_status = "invalid_credentials_anonymous"
        elif auth_required is False:
            service_status = "open_no_auth"
        elif auth_required is True:
            service_status = "auth_required"
        else:
            service_status = "unknown_auth"

        if not version and auth_valid is True:
            resolved_version, version_error = _resolve_server_version_with_auth(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=auth_headers,
            )
            if resolved_version:
                version = resolved_version
            elif version_error:
                auth_error = (
                    f"{auth_error}; version probe: {version_error}" if auth_error else f"version probe: {version_error}"
                )

        if not version:
            detected_version, _ = _resolve_server_version_without_auth(
                host,
                port,
                timeout,
                preferred_scheme=root_probe_scheme,
                ca_file=ca_file,
            )
            if detected_version:
                version = detected_version

        _stage_trace(
            _STAGE_AUTH_INFERENCE,
            attempt=attempt + 1,
            started_at=stage2_started,
            result=service_status,
            error=auth_error,
        )

        base_record = {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "is_elastic": True,
            "status": service_status,
            "auth_required": auth_required,
            "server_version": version,
            "provided_credentials": provided_credentials,
            "provided_username": username,
            "provided_password": password if provided_credentials else None,
            "provided_token": provided_token,
            "api_token": api_token if provided_token else None,
            "api_key_probe_status": "not_run",
            "api_key_probe_error": None,
            "effective_username": effective_username,
            "auth_valid": auth_valid,
            "show_endpoints": show_endpoints,
            "show_plugins": show_plugins,
            "show_cluster": show_cluster,
            "show_users": show_users,
            "discover": discover,
            "cat_endpoints": None,
            "endpoint_diagnostics": None,
            "cat_plugins": None,
            "cluster_health": None,
            "cluster_nodes": None,
            "misconfig_findings": None,
            "misconfig_error": None,
            "users": None,
            "discover_results": None,
            "can_read": None,
            "can_write": None,
            "can_manage": None,
            "can_manage_security": None,
            "access_level": "unknown",
            "rights_error": None,
            "endpoints_error": None,
            "plugins_error": None,
            "cluster_error": None,
            "users_error": None,
            "discover_error": None,
            "scheme": scheme,
            "insecure_effective": effective_insecure,
            "tls_auto_plain": tls_auto_plain,
            "detect_confidence": detect_confidence,
            "detect_signals": detect_signals,
            "detect_probe_trace": detect_probe_trace,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": None,
        }

        if not run_deep_checks:
            _debug(
                f"attempt={attempt + 1}/{attempts} detect-only result={service_status} "
                f"total_ms={int((time.monotonic() - started) * 1000)}"
            )
            return _record(base_record, attempts_done=attempt + 1, max_attempts=attempts)

        if service_status not in {"open_no_auth", "valid_credentials"}:
            _debug(f"stage2_gate=skip reason=status={service_status}")
            return _record(base_record, attempts_done=attempt + 1, max_attempts=attempts)

        _debug(f"stage2_gate=run reason=status={service_status}")
        stage3_started = time.monotonic()
        can_read: bool | None = None
        can_write: bool | None = None
        can_manage: bool | None = None
        can_manage_security: bool | None = None
        rights_error: str | None = None
        access_level = "unknown"
        api_key_probe_status = "not_run"
        api_key_probe_error: str | None = None
        if auth_provided:
            can_read, can_write, can_manage, can_manage_security, rights_error = _check_privileges(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=auth_headers,
            )
            access_level = _normalize_access_level(
                can_read=can_read,
                can_write=can_write,
                can_manage=can_manage,
                can_manage_security=can_manage_security,
            )
            if provided_token:
                api_key_probe_status, api_key_probe_error = _verify_api_key_probe(
                    host,
                    port,
                    timeout,
                    scheme=scheme,
                    insecure=effective_insecure,
                    ca_file=ca_file,
                    auth_headers=auth_headers,
                )
            stage3_error = "; ".join(item for item in (rights_error, api_key_probe_error) if str(item or "").strip())
            _stage_trace(
                _STAGE_ACCESS_CAPABILITIES,
                attempt=attempt + 1,
                started_at=stage3_started,
                result="error" if stage3_error else "ok",
                error=stage3_error or None,
            )
        else:
            _stage_trace(
                _STAGE_ACCESS_CAPABILITIES,
                attempt=attempt + 1,
                started_at=stage3_started,
                result="skipped",
                error="no auth provided",
            )

        stage4_started = time.monotonic()
        cat_endpoints: list[str] | None = None
        endpoints_error: str | None = None
        endpoint_diagnostics: list[dict[str, Any]] | None = None
        cat_plugins: list[dict[str, str]] | None = None
        plugins_error: str | None = None
        cluster_health: dict[str, Any] | None = None
        cluster_nodes: list[dict[str, Any]] | None = None
        cluster_error: str | None = None
        misconfig_findings: list[dict[str, str]] | None = None
        misconfig_error: str | None = None
        users: list[dict[str, Any]] | None = None
        users_error: str | None = None
        discover_results: list[dict[str, Any]] | None = None
        discover_error: str | None = None
        if show_endpoints:
            cat_endpoints, endpoints_error, endpoint_diagnostics = _fetch_cat_endpoints(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=auth_headers,
            )
        if show_plugins:
            cat_plugins, plugins_error = _fetch_cat_plugins(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=auth_headers,
            )
        if show_cluster:
            cluster_health, cluster_nodes, cluster_error = _fetch_cluster_data(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=auth_headers,
            )
            misconfig_findings, misconfig_error = _fetch_cluster_misconfig_findings(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=auth_headers,
            )
        if show_users:
            users, users_error = _fetch_security_users(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=auth_headers,
            )
        if discover:
            discover_results, discover_error = _collect_discover_results(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=auth_headers,
            )
        stage4_error = "; ".join(
            item
            for item in (endpoints_error, plugins_error, cluster_error, misconfig_error, users_error, discover_error)
            if str(item or "").strip()
        )
        stage4_requested = bool(show_endpoints or show_plugins or show_cluster or show_users or discover)
        _stage_trace(
            _STAGE_DATA,
            attempt=attempt + 1,
            started_at=stage4_started,
            result="error" if stage4_error else "ok" if stage4_requested else "skipped",
            error=stage4_error or None,
        )

        errors: list[str] = []
        for value in (
            error,
            auth_error,
            rights_error,
            api_key_probe_error,
            endpoints_error,
            plugins_error,
            cluster_error,
            misconfig_error,
            users_error,
            discover_error,
        ):
            clean = str(value or "").strip()
            if clean and clean not in errors:
                errors.append(clean)

        final_record = dict(base_record)
        final_record.update(
            {
                "api_key_probe_status": api_key_probe_status,
                "api_key_probe_error": api_key_probe_error,
                "cat_endpoints": cat_endpoints,
                "endpoint_diagnostics": endpoint_diagnostics,
                "cat_plugins": cat_plugins,
                "cluster_health": cluster_health,
                "cluster_nodes": cluster_nodes,
                "misconfig_findings": misconfig_findings,
                "misconfig_error": misconfig_error,
                "users": users,
                "discover_results": discover_results,
                "can_read": can_read,
                "can_write": can_write,
                "can_manage": can_manage,
                "can_manage_security": can_manage_security,
                "access_level": access_level,
                "rights_error": rights_error,
                "endpoints_error": endpoints_error,
                "plugins_error": plugins_error,
                "cluster_error": cluster_error,
                "users_error": users_error,
                "discover_error": discover_error,
                "error": "; ".join(errors) if errors else None,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
        )
        _debug(
            f"attempt={attempt + 1}/{attempts} result={service_status} "
            f"total_ms={int((time.monotonic() - started) * 1000)}"
        )
        return _record(final_record, attempts_done=attempt + 1, max_attempts=attempts)

    _debug(f"final fail attempts={attempts}/{attempts} error={_friendly_error_text(last_error or 'connection failed')}")
    return _record(
        {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "is_elastic": False,
            "status": "fail",
            "auth_required": None,
            "server_version": None,
            "provided_credentials": provided_credentials,
            "provided_username": username,
            "provided_password": password if provided_credentials else None,
            "provided_token": provided_token,
            "api_token": api_token if provided_token else None,
            "api_key_probe_status": "not_run",
            "api_key_probe_error": None,
            "effective_username": None,
            "auth_valid": None,
            "show_endpoints": show_endpoints,
            "show_plugins": show_plugins,
            "show_cluster": show_cluster,
            "show_users": show_users,
            "discover": discover,
            "cat_endpoints": None,
            "endpoint_diagnostics": None,
            "cat_plugins": None,
            "cluster_health": None,
            "cluster_nodes": None,
            "misconfig_findings": None,
            "misconfig_error": None,
            "users": None,
            "discover_results": None,
            "can_read": None,
            "can_write": None,
            "can_manage": None,
            "can_manage_security": None,
            "access_level": "unknown",
            "rights_error": None,
            "endpoints_error": None,
            "plugins_error": None,
            "cluster_error": None,
            "users_error": None,
            "discover_error": None,
            "scheme": None,
            "insecure_effective": None,
            "tls_auto_plain": None,
            "detect_confidence": None,
            "detect_signals": [],
            "detect_probe_trace": [],
            "elapsed_ms": None,
            "error": _friendly_error_text(last_error or "connection failed"),
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
        "auth_required",
        "server_version",
        "api_key_probe_status",
        "api_key_probe_error",
        "effective_username",
        "auth_valid",
        "cat_endpoints",
        "endpoint_diagnostics",
        "cat_plugins",
        "cluster_health",
        "cluster_nodes",
        "misconfig_findings",
        "misconfig_error",
        "users",
        "discover_results",
        "can_read",
        "can_write",
        "can_manage",
        "can_manage_security",
        "access_level",
        "rights_error",
        "endpoints_error",
        "plugins_error",
        "cluster_error",
        "users_error",
        "discover_error",
        "scheme",
        "insecure_effective",
        "tls_auto_plain",
        "elapsed_ms",
        "error",
        "attempts",
        "max_attempts",
        "stages",
        "stage_failed_at",
        "stage_durations_ms",
        "stage_attempts",
    )
    for field in deep_fields:
        merged[field] = deep_record.get(field)

    deep_status = str(deep_record.get("status") or "")
    if deep_status in {"open_no_auth", "valid_credentials", "invalid_credentials_anonymous"}:
        return merged
    return merged


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{_ELASTIC_TAG:<8}\t{host}\t{port}\t"


def _bool_text(value: bool | None) -> str:
    if value is True:
        return "True"
    if value is False:
        return "False"
    return "unknown"


def _caps_suffix(record: dict[str, Any]) -> str:
    if not bool(record.get("provided_credentials") or record.get("provided_token")):
        return ""
    can_read = _bool_text(record.get("can_read"))
    can_write = _bool_text(record.get("can_write"))
    can_manage = _bool_text(record.get("can_manage"))
    can_manage_security = _bool_text(record.get("can_manage_security"))
    return f" (read:{can_read}) (write:{can_write}) (manage:{can_manage}) (manage_security:{can_manage_security})"


def _counts_suffix(record: dict[str, Any]) -> str:
    _ = record
    return ""


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(
            {
                "timestamp": record.get("timestamp"),
                "type": "detect",
                "service": "elastic",
                "host": record.get("host"),
                "port": record.get("port"),
                "detected": bool(record.get("is_elastic")),
                "auth_required": record.get("auth_required"),
                "version": record.get("server_version"),
                "scheme": record.get("scheme"),
                "detect_confidence": record.get("detect_confidence"),
                "detect_signals": record.get("detect_signals") or [],
                "detect_probe_trace": record.get("detect_probe_trace") or [],
            },
            ensure_ascii=False,
        )

    prefix = _nxc_prefix(record)
    status = str(record.get("status") or "fail")
    if status == "fail":
        err = _clip(str(record.get("error") or "connection failed"), 96)
        return f"{prefix} [!] connection failed err={err}"
    if status == "not_elastic":
        return f"{prefix} [-] not an Elasticsearch API"

    auth_required_text = _bool_text(record.get("auth_required"))
    version_text = str(record.get("server_version") or "-")
    return f"{prefix} [*] Elasticsearch API (auth required:{auth_required_text}) (version:{version_text})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        payload = dict(record)
        payload.pop("provided_password", None)
        payload.pop("api_token", None)
        return json.dumps(payload, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 96)
    counts = _counts_suffix(record)
    caps = _caps_suffix(record)

    if status == "open_no_auth":
        return f"{prefix} [+] anonymous access{counts}"

    if status == "invalid_credentials_anonymous":
        return f"{prefix} [-] credentials invalid (anonymous access){counts}"

    if status == "valid_credentials":
        if bool(record.get("provided_token")):
            return f"{prefix} [+] apikey auth{counts}{caps}"
        username = str(record.get("provided_username") or record.get("effective_username") or "elastic")
        provided_password = record.get("provided_password")
        password_text = (
            "<empty>"
            if provided_password == ""
            else str(provided_password)
            if provided_password is not None
            else "<none>"
        )
        return f"{prefix} [+] {username}:{password_text}{counts}{caps}"

    if status == "auth_required":
        if bool(record.get("provided_credentials") or record.get("provided_token")):
            return f"{prefix} [-] authentication required (credentials invalid){counts}{caps}"
        return f"{prefix} [-] authentication required{counts}"

    if status == "unknown_auth":
        line = f"{prefix} [!] auth status unknown{counts}{caps}"
        if err != "-":
            return f"{line} err={err}"
        return line

    if status == "not_elastic":
        return f"{prefix} [-] not an Elasticsearch API"

    line = f"{prefix} [!] connection failed"
    return f"{line} err={err}" if err != "-" else line


def _format_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    status = str(record.get("status") or "fail")
    if status in {"fail", "not_elastic"}:
        return []

    prefix = _nxc_prefix(record)

    if output_format == "json":
        lines: list[str] = []
        if bool(record.get("show_endpoints")):
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "endpoints_dump",
                        "service": "elastic",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "endpoints": record.get("cat_endpoints") or [],
                        "diagnostics": record.get("endpoint_diagnostics") or [],
                        "error": record.get("endpoints_error"),
                    },
                    ensure_ascii=False,
                )
            )
        if bool(record.get("show_plugins")):
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "plugins_dump",
                        "service": "elastic",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "plugins": record.get("cat_plugins") or [],
                        "error": record.get("plugins_error"),
                    },
                    ensure_ascii=False,
                )
            )
        if bool(record.get("show_cluster")):
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "cluster_dump",
                        "service": "elastic",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "cluster_health": record.get("cluster_health"),
                        "cluster_nodes": record.get("cluster_nodes") or [],
                        "error": record.get("cluster_error"),
                    },
                    ensure_ascii=False,
                )
            )
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "misconfig_dump",
                        "service": "elastic",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "findings": record.get("misconfig_findings") or [],
                        "error": record.get("misconfig_error"),
                    },
                    ensure_ascii=False,
                )
            )
        if bool(record.get("show_users")):
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "users_dump",
                        "service": "elastic",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "users": record.get("users") or [],
                        "error": record.get("users_error"),
                    },
                    ensure_ascii=False,
                )
            )
        if bool(record.get("discover")):
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "discover_dump",
                        "service": "elastic",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "results": record.get("discover_results") or [],
                        "query_size": _DISCOVER_QUERY_SIZE,
                        "max_print_per_index": _DISCOVER_MAX_PRINT_PER_INDEX,
                        "error": record.get("discover_error"),
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    lines: list[str] = []

    if bool(record.get("show_endpoints")):
        endpoints = record.get("cat_endpoints")
        endpoint_count = len(endpoints) if isinstance(endpoints, list) else 0
        lines.append(f"{prefix} [*] {endpoint_count} Endpoints")
        endpoints_error = str(record.get("endpoints_error") or "").strip()
        if isinstance(endpoints, list) and endpoints:
            for endpoint in endpoints:
                lines.append(f"{prefix} {str(endpoint)}")
        elif endpoints_error:
            lines.append(f"{prefix} [-] endpoints unavailable: {_clip(endpoints_error, 120)}")
        else:
            lines.append(f"{prefix} <no endpoints>")

    if bool(record.get("show_plugins")):
        plugins = record.get("cat_plugins")
        plugin_count = len(plugins) if isinstance(plugins, list) else 0
        lines.append(f"{prefix} [*] {plugin_count} Plugins")
        plugins_error = str(record.get("plugins_error") or "").strip()
        if isinstance(plugins, list) and plugins:
            for item in plugins:
                if not isinstance(item, dict):
                    continue
                node = str(item.get("node") or "-")
                component = str(item.get("component") or "-")
                version = str(item.get("version") or "-")
                description = _clip(str(item.get("description") or "-"), 120)
                lines.append(f"{prefix} node={node} component={component} version={version} description={description}")
        elif plugins_error:
            lines.append(f"{prefix} [-] plugins unavailable: {_clip(plugins_error, 120)}")
        else:
            lines.append(f"{prefix} <no plugins>")

    if bool(record.get("show_cluster")):
        lines.append(f"{prefix} [*] Cluster")
        cluster_health = record.get("cluster_health")
        cluster_nodes = record.get("cluster_nodes")
        cluster_error = str(record.get("cluster_error") or "").strip()
        if isinstance(cluster_health, dict):
            cluster_name = str(cluster_health.get("cluster_name") or "-")
            cluster_status = str(cluster_health.get("status") or "-")
            number_of_nodes = cluster_health.get("number_of_nodes")
            number_of_data_nodes = cluster_health.get("number_of_data_nodes")
            lines.append(
                f"{prefix} cluster={cluster_name} status={cluster_status} nodes={number_of_nodes} data_nodes={number_of_data_nodes}"
            )
        if isinstance(cluster_nodes, list) and cluster_nodes:
            lines.append(f"{prefix} [*] {len(cluster_nodes)} Cluster Nodes")
            for node in cluster_nodes:
                if not isinstance(node, dict):
                    continue
                node_name = str(node.get("name") or "-")
                node_ip = str(node.get("ip") or "-")
                node_host = str(node.get("host") or "-")
                roles_raw = node.get("roles")
                roles_text = (
                    ",".join(str(role) for role in roles_raw) if isinstance(roles_raw, list) and roles_raw else "-"
                )
                lines.append(f"{prefix} name={node_name} ip={node_ip} host={node_host} roles={roles_text}")
        elif cluster_error:
            lines.append(f"{prefix} [-] cluster unavailable: {_clip(cluster_error, 120)}")
        elif not isinstance(cluster_health, dict):
            lines.append(f"{prefix} <no cluster data>")

        lines.append(f"{prefix} [*] Misconfig Findings")
        misconfigs = record.get("misconfig_findings")
        misconfig_error = str(record.get("misconfig_error") or "").strip()
        if isinstance(misconfigs, list) and misconfigs:
            for finding in misconfigs:
                if not isinstance(finding, dict):
                    continue
                key = str(finding.get("key") or "-")
                value = _clip(str(finding.get("value") or "-"), 80)
                reason = _clip(str(finding.get("reason") or "-"), 120)
                lines.append(f"{prefix} key={key} value={value} reason={reason}")
        elif misconfig_error:
            lines.append(f"{prefix} [-] misconfig unavailable: {_clip(misconfig_error, 120)}")
        else:
            lines.append(f"{prefix} <no misconfig findings>")

    if bool(record.get("show_users")):
        users = record.get("users")
        user_count = len(users) if isinstance(users, list) else 0
        lines.append(f"{prefix} [*] {user_count} Users")
        users_error = str(record.get("users_error") or "").strip()
        if isinstance(users, list) and users:
            for item in users:
                if not isinstance(item, dict):
                    continue
                username = str(item.get("username") or "-")
                roles = item.get("roles")
                roles_text = ",".join(str(role) for role in roles) if isinstance(roles, list) and roles else "-"
                enabled = item.get("enabled")
                enabled_text = "True" if enabled is True else "False" if enabled is False else "unknown"
                full_name = str(item.get("full_name") or "")
                suffix = f" full_name={full_name}" if full_name else ""
                lines.append(f"{prefix} user={username} roles={roles_text} enabled={enabled_text}{suffix}")
        elif users_error:
            lines.append(f"{prefix} [-] users unavailable: {_clip(users_error, 120)}")
        else:
            lines.append(f"{prefix} <no users>")

    if bool(record.get("discover")):
        discover_results = record.get("discover_results")
        total_hits = 0
        if isinstance(discover_results, list):
            for item in discover_results:
                if not isinstance(item, dict):
                    continue
                total_hits += int(item.get("total_hits") or 0)
        lines.append(f"{prefix} [*] {total_hits} Discover Hits")
        discover_error = str(record.get("discover_error") or "").strip()
        if isinstance(discover_results, list) and discover_results:
            for item in discover_results:
                if not isinstance(item, dict):
                    continue
                index_name = str(item.get("index") or "-")
                total_hits = int(item.get("total_hits") or 0)
                shown_hits = int(item.get("shown_hits") or 0)
                lines.append(f"{prefix} index={index_name} hits={total_hits} shown={shown_hits}")
                item_error = str(item.get("error") or "").strip()
                if item_error:
                    lines.append(f"{prefix} [-] discover error: {_clip(item_error, 120)}")
                    continue
                if bool(item.get("truncated")):
                    lines.append(
                        f"{prefix} showing first {shown_hits} of {total_hits} hits (max_per_index={_DISCOVER_MAX_PRINT_PER_INDEX})"
                    )
                hits = item.get("hits")
                if isinstance(hits, list):
                    for hit in hits:
                        if not isinstance(hit, dict):
                            continue
                        source = hit.get("source")
                        if not isinstance(source, dict):
                            continue
                        lines.append(f"{prefix} {json.dumps(source, ensure_ascii=False)}")
        elif discover_error:
            lines.append(f"{prefix} [-] discover unavailable: {_clip(discover_error, 120)}")
        else:
            lines.append(f"{prefix} <no discover hits>")

    return lines


def _render_colored_elastic_line(console: Console, line: str) -> bool:
    return render_colored_marker_line(
        console,
        line,
        tag=_ELASTIC_TAG,
        booleans=(
            BooleanColorRule("read"),
            BooleanColorRule("write"),
            BooleanColorRule("manage"),
            BooleanColorRule("manage_security"),
        ),
    )


def _emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
    if emit_line is not None:
        emit_line(line)


def _is_connection_timeout_fail_record(record: dict[str, Any]) -> bool:
    if str(record.get("status") or "") != "fail":
        return False
    error_text = str(record.get("error") or "").strip().lower()
    return bool(error_text) and (
        error_text.startswith("connection timeout")
        or error_text.startswith("connection refused")
        or "timed out" in error_text
    )


def audit_elastic_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
    *,
    username: str | None,
    password: str | None,
    api_token: str | None,
    ca_file: str | None,
    show_endpoints: bool,
    show_plugins: bool,
    show_cluster: bool,
    show_users: bool,
    discover: bool,
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
    suppress_timeout_status_lines: bool = False,
    preferred_scheme: str | None = None,
    debug_emit: Callable[[str], None] | None = None,
    show_progress: bool = False,
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
        progress = start_audit_progress(_ELASTIC_TAG, len(indexed_hosts), enabled=show_progress, leave=True)

        def _detect_task(host: str) -> dict[str, Any]:
            return _call_audit_elastic_host_with_thread_debug(
                host,
                port,
                timeout,
                retries,
                username,
                password,
                api_token,
                ca_file,
                show_endpoints,
                show_plugins,
                show_cluster,
                show_users,
                discover,
                preferred_scheme,
                bool(debug_emit),
                False,
                debug_emit,
            )

        def _deep_task(host: str) -> dict[str, Any]:
            return _call_audit_elastic_host_with_thread_debug(
                host,
                port,
                timeout,
                retries,
                username,
                password,
                api_token,
                ca_file,
                show_endpoints,
                show_plugins,
                show_cluster,
                show_users,
                discover,
                preferred_scheme,
                bool(debug_emit),
                True,
                debug_emit,
            )

        def _emit_detect(detect_record: dict[str, Any]) -> None:
            detect_status = str(detect_record.get("status") or "fail")
            suppress_timeout_detect_line = (
                suppress_timeout_status_lines and output_format == "txt" and detect_status == "fail"
            )
            if not suppress_timeout_detect_line:
                _emit_line(out_fh, emit_line, _format_detect_record(detect_record, output_format))

        def _deep_gate(detect_record: dict[str, Any]) -> tuple[bool, str]:
            detect_status = str(detect_record.get("status") or "fail")
            if detect_status in {"open_no_auth", "valid_credentials"}:
                return True, f"status={detect_status}"
            return False, f"status={detect_status}"

        pass_result = TwoPassAuditRunner(
            label=_ELASTIC_TAG,
            workers=workers,
            debug_emit=debug_emit,
            progress=progress,
            detected_name="elastic",
        ).run(
            indexed_hosts,
            detect_task=_detect_task,
            deep_task=_deep_task,
            is_detected=lambda record: bool(record.get("is_elastic")),
            deep_gate=_deep_gate,
            emit_detect=_emit_detect,
            merge_records=_merge_stage2_record,
            not_detected_reason="not_elastic",
        )

        final_records = pass_result.final_records

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
            elif status == "fail":
                failed += 1

            if debug_emit is not None and not bool(record.get("debug_events_streamed")):
                for event in record.get("debug_events") or []:
                    if isinstance(event, str) and event.strip():
                        debug_emit(event)

            suppress_timeout_detect_line = suppress_timeout_status_lines and output_format == "txt" and status == "fail"
            suppress_auth_required_status_line = bool(record.get("is_elastic")) and status == "auth_required"
            if not suppress_auth_required_status_line and not suppress_timeout_detect_line:
                _emit_line(out_fh, emit_line, _format_record(record, output_format))

            for detail in _format_detail_records(record, output_format):
                _emit_line(out_fh, emit_line, detail)

            if logger is not None:
                logger.log(
                    "elastic",
                    (str(record.get("host") or "-"), int(record.get("port") or port)),
                    phase="audit",
                    status=record.get("status"),
                    auth_required=record.get("auth_required"),
                    auth_valid=record.get("auth_valid"),
                    version=record.get("server_version"),
                    detect_confidence=record.get("detect_confidence"),
                    access_level=record.get("access_level"),
                    endpoints=len(record.get("cat_endpoints") or [])
                    if isinstance(record.get("cat_endpoints"), list)
                    else 0,
                    plugins=len(record.get("cat_plugins") or []) if isinstance(record.get("cat_plugins"), list) else 0,
                    misconfig_findings=len(record.get("misconfig_findings") or [])
                    if isinstance(record.get("misconfig_findings"), list)
                    else 0,
                    api_key_probe_status=record.get("api_key_probe_status"),
                    users=len(record.get("users") or []) if isinstance(record.get("users"), list) else 0,
                    discover_rows=(
                        sum(
                            int(item.get("shown_hits") or 0)
                            for item in (record.get("discover_results") or [])
                            if isinstance(item, dict)
                        )
                        if isinstance(record.get("discover_results"), list)
                        else 0
                    ),
                    error=record.get("error"),
                )
    finally:
        if progress is not None:
            progress.close()
        if out_fh is not None:
            out_fh.close()

    return total, open_no_auth, valid, auth_required, failed


def run_elastic_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
        return 2
    credential_file_entries = None
    if not str(getattr(args, "apitoken", "") or "").strip():
        try:
            credential_file_entries = parse_username_password_credential_file(args.username, args.password)
        except ValueError as exc:
            console.error(str(exc))
            return 2
        if credential_file_entries is None and bool(args.username) != bool(args.password):
            console.error("-u and -p must be set together")
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
        console.error("elastic requires -t/--targets")
        return 2
    hosts = list(dict.fromkeys(spec.host for spec in target_specs))
    execution_groups = build_scan_execution_groups(target_specs, ports, include_scheme_in_key=True)

    api_token = str(getattr(args, "apitoken", "") or "").strip() or None
    username = getattr(args, "username", None)
    password = getattr(args, "password", None)
    if api_token and (username is not None or password is not None):
        console.warn("--apitoken is set; basic credentials are ignored")
        username = None
        password = None
    defcreds = bool(getattr(args, "defcreds", False))
    credential_runs = (
        [(entry.username, entry.password) for entry in credential_file_entries]
        if credential_file_entries is not None
        else _build_credential_runs(username, password, defcreds if api_token is None else False)
    )

    show_endpoints = bool(getattr(args, "endpoints", False))
    show_plugins = bool(getattr(args, "plugins", False))
    show_cluster = bool(getattr(args, "cluster", False))
    show_users = bool(getattr(args, "user", False))
    discover = bool(getattr(args, "discover", False))

    stream_to_stdout = not bool(args.output)

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith(_ELASTIC_TAG) and all(token not in line for token in (" [*] ", " [+] ", " [-] ", " [!] ")):
            if console.render_tagged_payload_line(line, _ELASTIC_TAG, payload_color="orange"):
                return
            console.plain(line, color="white")
            return
        if _render_colored_elastic_line(console, line):
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

    if args.debug:
        mode_parts: list[str] = []
        if api_token:
            mode_parts.append("apikey")
        elif credential_file_entries is not None:
            mode_parts.append(f"credfile={len(credential_file_entries)}")
        elif username and password:
            mode_parts.append("basic")
        elif defcreds and api_token is None:
            mode_parts.append("defcreds")
        else:
            mode_parts.append("anonymous")
        if show_endpoints:
            mode_parts.append("endpoints")
        if show_plugins:
            mode_parts.append("plugins")
        if show_cluster:
            mode_parts.append("cluster")
        if show_users:
            mode_parts.append("users")
        if discover:
            mode_parts.append("discover")
        mode = ",".join(mode_parts)
        output_part = "format=txt" if stream_to_stdout else f"format={args.output_format} output={args.output}"
        console.info(
            f"elastic audit started: hosts={len(hosts)} ports={len(execution_groups)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={mode} {output_part}"
        )

    total = 0
    open_no_auth = 0
    valid = 0
    auth_required = 0
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
    outer_progress = None
    use_single_global_progress = (
        args.output_format == "txt" and credential_file_entries is not None
    ) or should_use_global_progress(
        args.output_format,
        len(execution_groups),
        len(credential_runs) if credential_file_entries is None else 1,
    )
    if use_single_global_progress:
        global_total = progress_total_from_groups(
            group_hosts_by_idx.values(), 1 if credential_file_entries is not None else len(credential_runs)
        )
        outer_progress = start_command_progress(args, _ELASTIC_TAG, global_total, enabled=True, leave=True)

    output_written = False
    output_sink = LineOutputSink(args.output, emit_line)

    def run_elastic_capture(
        host: str,
        run_username: str | None,
        run_password: str | None,
        group_port: int,
        group_scheme_hint: str | None,
        *,
        include_data: bool,
    ) -> tuple[list[str], tuple[int, int, int, int, int]]:
        lines: list[str] = []
        counts = audit_elastic_targets(
            hosts=[host],
            port=group_port,
            timeout=args.timeout,
            retries=args.retries,
            workers=args.workers,
            username=run_username,
            password=run_password,
            api_token=api_token,
            ca_file=getattr(args, "ca_file", None),
            show_endpoints=show_endpoints and include_data,
            show_plugins=show_plugins and include_data,
            show_cluster=show_cluster and include_data,
            show_users=show_users and include_data,
            discover=discover and include_data,
            output_path=None,
            output_format=args.output_format,
            emit_line=lines.append,
            logger=logger if args.debug else None,
            append_output=False,
            suppress_timeout_status_lines=not bool(args.debug),
            preferred_scheme=group_scheme_hint,
            debug_emit=emit_debug if args.debug else None,
            show_progress=False,
        )
        return lines, counts

    try:
        if credential_file_entries is not None:
            for idx, group in enumerate(execution_groups):
                audit_hosts = group_hosts_by_idx[idx]
                if not audit_hosts:
                    continue
                for host in audit_hosts:
                    selected_lines, selected_counts = run_elastic_capture(
                        host, None, None, int(group.port), group.scheme_hint, include_data=False
                    )
                    selected_username: str | None = None
                    selected_password: str | None = None
                    base_total, base_open, base_valid, base_auth, base_failed = selected_counts

                    if base_open == 0 and base_valid == 0 and base_auth > 0:
                        for run_username, run_password in credential_runs:
                            _attempt_lines, attempt_counts = run_elastic_capture(
                                host,
                                run_username,
                                run_password,
                                int(group.port),
                                group.scheme_hint,
                                include_data=False,
                            )
                            _attempt_total, attempt_open, attempt_valid, _attempt_auth, _attempt_failed = attempt_counts
                            if attempt_open > 0 or attempt_valid > 0:
                                selected_username = run_username
                                selected_password = run_password
                                break
                    elif base_open > 0 or base_valid > 0:
                        selected_username = None
                        selected_password = None

                    if (
                        selected_username is not None
                        or selected_password is not None
                        or base_open > 0
                        or base_valid > 0
                    ):
                        selected_lines, selected_counts = run_elastic_capture(
                            host,
                            selected_username,
                            selected_password,
                            int(group.port),
                            group.scheme_hint,
                            include_data=True,
                        )

                    output_sink.emit_many(selected_lines)
                    output_written = output_sink.output_written
                    part_total, part_open, part_valid, part_auth, part_failed = selected_counts
                    total += part_total
                    open_no_auth += part_open
                    valid += part_valid
                    auth_required += part_auth
                    failed += part_failed
                    if outer_progress is not None:
                        outer_progress.advance(1)
                    _ = (base_total, base_failed)
        else:
            for idx, group in enumerate(execution_groups):
                audit_hosts = group_hosts_by_idx[idx]
                if not audit_hosts:
                    continue
                host_batches = [[host] for host in audit_hosts] if len(credential_runs) > 1 else [audit_hosts]
                for host_batch in host_batches:
                    deep_already_emitted = False
                    for run_username, run_password in credential_runs:
                        run_show_deep = not deep_already_emitted
                        part_total, part_open, part_valid, part_auth, part_failed = audit_elastic_targets(
                            hosts=host_batch,
                            port=group.port,
                            timeout=args.timeout,
                            retries=args.retries,
                            workers=args.workers,
                            username=run_username,
                            password=run_password,
                            api_token=api_token,
                            ca_file=getattr(args, "ca_file", None),
                            show_endpoints=show_endpoints and run_show_deep,
                            show_plugins=show_plugins and run_show_deep,
                            show_cluster=show_cluster and run_show_deep,
                            show_users=show_users and run_show_deep,
                            discover=discover and run_show_deep,
                            output_path=args.output,
                            output_format=args.output_format,
                            emit_line=emit_line,
                            logger=logger if args.debug else None,
                            append_output=output_written,
                            suppress_timeout_status_lines=not bool(args.debug),
                            preferred_scheme=group.scheme_hint,
                            debug_emit=emit_debug if args.debug else None,
                            show_progress=not use_single_global_progress,
                        )
                        total += part_total
                        open_no_auth += part_open
                        valid += part_valid
                        auth_required += part_auth
                        failed += part_failed
                        if outer_progress is not None:
                            outer_progress.advance(part_total)
                        if part_open > 0 or part_valid > 0:
                            deep_already_emitted = True
                        output_written = True
    except OSError as exc:
        console.error(f"failed to process elastic output: {exc}")
        return 2
    finally:
        if outer_progress is not None:
            outer_progress.close()

    if (
        stream_to_stdout
        and total > 0
        and open_no_auth == 0
        and valid == 0
        and auth_required == 0
        and failed == total
        and args.output_format == "txt"
    ):
        console.warn("all elastic targets are unreachable; check host/port, network reachability, and service status")

    if args.debug:
        console.info(
            f"elastic audit complete: total={total} anonymous={open_no_auth} valid={valid} "
            f"auth_required={auth_required} fail={failed}"
        )

    return 0
