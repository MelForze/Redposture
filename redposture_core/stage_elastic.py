"""Elasticsearch audit stage."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .console import Console
from .logger import AttemptLogger
from .progress import iter_completed_with_progress
from .utils import collect_scan_ports, collect_scan_targets, utc_now_iso

_ELASTIC_TAG = "ELASTIC"
_DISCOVER_QUERY_SIZE = 10000
_DISCOVER_MAX_PRINT_PER_INDEX = 200

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


def _clip(text: str, width: int = 96) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


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
    insecure: bool,
    ca_file: str | None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> tuple[int, bytes, dict[str, str], str | None, str, bool, bool]:
    status, payload, response_headers, error = _elastic_request(
        host,
        port,
        path,
        timeout,
        use_https=True,
        insecure=insecure,
        ca_file=ca_file,
        method=method,
        headers=headers,
        data=data,
    )
    if status > 0:
        return status, payload, response_headers, error, "https", insecure, False

    if not _is_tls_or_protocol_error(error or ""):
        return status, payload, response_headers, error, "https", insecure, False

    fallback_status, fallback_payload, fallback_headers, fallback_error = _elastic_request(
        host,
        port,
        path,
        timeout,
        use_https=False,
        insecure=False,
        ca_file=None,
        method=method,
        headers=headers,
        data=data,
    )
    if fallback_status > 0:
        return fallback_status, fallback_payload, fallback_headers, fallback_error, "http", False, True

    combined_error = (
        "; ".join(part for part in (str(error or "").strip(), str(fallback_error or "").strip()) if part)
        or "connection failed"
    )
    return fallback_status, fallback_payload, fallback_headers, combined_error, "http", False, True


def _load_json_dict(payload: bytes) -> dict[str, Any] | None:
    try:
        parsed = json.loads(payload.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


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
        body_dict = _load_json_dict(payload)
        if isinstance(body_dict, dict):
            version = body_dict.get("version")
            if isinstance(version, dict):
                number = version.get("number")
                if isinstance(number, str) and number.strip():
                    return True, number.strip()
        return True, None

    if status not in {200, 401, 403}:
        return False, None

    body_dict = _load_json_dict(payload)
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
            "query_string": {
                "query": query_string,
                "default_operator": "OR",
                "analyze_wildcard": True,
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


def _audit_elastic_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    api_token: str | None,
    insecure: bool,
    ca_file: str | None,
    show_endpoints: bool,
    show_plugins: bool,
    show_cluster: bool,
    show_users: bool,
    discover: bool,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None

    provided_credentials = bool(username is not None and password is not None)
    provided_token = bool(api_token)
    auth_provided = provided_token or provided_credentials

    for attempt in range(attempts):
        started = time.monotonic()
        status, payload, root_headers, error, scheme, effective_insecure, tls_auto_plain = _request_with_tls_fallback(
            host,
            port,
            "/",
            timeout,
            insecure=insecure,
            ca_file=ca_file,
        )
        if error and status <= 0:
            last_error = error
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))
            continue

        is_elastic, version = _looks_like_elastic_root(status, payload, root_headers)
        if not is_elastic:
            return {
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
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": None,
            }

        auth_required: bool | None
        if status in {401, 403}:
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

        can_read: bool | None = None
        can_write: bool | None = None
        can_manage: bool | None = None
        can_manage_security: bool | None = None
        rights_error: str | None = None
        access_level = "unknown"
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

        cat_endpoints: list[str] | None = None
        endpoints_error: str | None = None
        endpoint_diagnostics: list[dict[str, Any]] | None = None
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

        cat_plugins: list[dict[str, str]] | None = None
        plugins_error: str | None = None
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

        cluster_health: dict[str, Any] | None = None
        cluster_nodes: list[dict[str, Any]] | None = None
        cluster_error: str | None = None
        misconfig_findings: list[dict[str, str]] | None = None
        misconfig_error: str | None = None
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

        users: list[dict[str, Any]] | None = None
        users_error: str | None = None
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

        discover_results: list[dict[str, Any]] | None = None
        discover_error: str | None = None
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

        return {
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
            "api_key_probe_status": api_key_probe_status,
            "api_key_probe_error": api_key_probe_error,
            "effective_username": effective_username,
            "auth_valid": auth_valid,
            "show_endpoints": show_endpoints,
            "show_plugins": show_plugins,
            "show_cluster": show_cluster,
            "show_users": show_users,
            "discover": discover,
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
            "scheme": scheme,
            "insecure_effective": effective_insecure,
            "tls_auto_plain": tls_auto_plain,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": "; ".join(errors) if errors else None,
        }

    return {
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
        "elapsed_ms": None,
        "error": _friendly_error_text(last_error or "connection failed"),
    }


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
    if not line.startswith(_ELASTIC_TAG):
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
        tag = _ELASTIC_TAG
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

        for capability in ("read", "write", "manage", "manage_security"):
            match = re.search(rf"\({capability}:(True|False|unknown)\)", right)
            if not match:
                continue
            value = match.group(1)
            if value == "True":
                color = "red"
            elif value == "False":
                color = "bright_green"
            else:
                color = "yellow"
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
            f"{console._paint(marker, marker_color[marker], sys.stdout)} "
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
    insecure: bool,
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
) -> tuple[int, int, int, int, int]:
    total = 0
    open_no_auth = 0
    valid = 0
    auth_required = 0
    failed = 0

    out_fh: Any = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, "a" if append_output else "w", encoding="utf-8")

    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            future_map = {
                executor.submit(
                    _audit_elastic_host,
                    host,
                    port,
                    timeout,
                    retries,
                    username,
                    password,
                    api_token,
                    insecure,
                    ca_file,
                    show_endpoints,
                    show_plugins,
                    show_cluster,
                    show_users,
                    discover,
                ): host
                for host in hosts
            }
            for future in iter_completed_with_progress(future_map, label=_ELASTIC_TAG):
                record = future.result()
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

                suppress_timeout_detect_line = (
                    suppress_timeout_status_lines
                    and output_format == "txt"
                    and _is_connection_timeout_fail_record(record)
                )
                if not suppress_timeout_detect_line:
                    _emit_line(out_fh, emit_line, _format_detect_record(record, output_format))

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
                        access_level=record.get("access_level"),
                        endpoints=len(record.get("cat_endpoints") or [])
                        if isinstance(record.get("cat_endpoints"), list)
                        else 0,
                        plugins=len(record.get("cat_plugins") or [])
                        if isinstance(record.get("cat_plugins"), list)
                        else 0,
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
    if bool(args.username) != bool(args.password):
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
        hosts = collect_scan_targets(targets)
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2
    if not hosts:
        console.error("elastic requires -t/--targets")
        return 2

    api_token = str(getattr(args, "apitoken", "") or "").strip() or None
    username = getattr(args, "username", None)
    password = getattr(args, "password", None)
    if api_token and (username is not None or password is not None):
        console.warn("--apitoken is set; basic credentials are ignored")
        username = None
        password = None

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

    if args.debug:
        mode_parts: list[str] = []
        if api_token:
            mode_parts.append("apikey")
        elif username and password:
            mode_parts.append("basic")
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
            f"elastic audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={mode} {output_part}"
        )

    total = 0
    open_no_auth = 0
    valid = 0
    auth_required = 0
    failed = 0

    try:
        for idx, audit_port in enumerate(ports):
            part_total, part_open, part_valid, part_auth, part_failed = audit_elastic_targets(
                hosts=hosts,
                port=audit_port,
                timeout=args.timeout,
                retries=args.retries,
                workers=args.workers,
                username=username,
                password=password,
                api_token=api_token,
                insecure=bool(getattr(args, "insecure", False)),
                ca_file=getattr(args, "ca_file", None),
                show_endpoints=show_endpoints,
                show_plugins=show_plugins,
                show_cluster=show_cluster,
                show_users=show_users,
                discover=discover,
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                logger=logger if args.debug else None,
                append_output=idx > 0,
                suppress_timeout_status_lines=not bool(args.debug),
            )
            total += part_total
            open_no_auth += part_open
            valid += part_valid
            auth_required += part_auth
            failed += part_failed
    except OSError as exc:
        console.error(f"failed to process elastic output: {exc}")
        return 2

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
