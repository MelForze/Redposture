"""qdrant audit actions and compatibility helpers."""

from __future__ import annotations

import json
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ...clients.http_api import HttpApiClient, HttpClientConfig
from ...console import Console
from ...rendering import CountColorRule, RegexColorRule, render_colored_marker_line
from ...stage_runtime import (
    AuditHookContext,
    AuditRecord,
    _invoke_module_host_stage,
    merge_stage_records,
)
from ...utils import (
    collect_scan_ports,
    collect_scan_targets,
    utc_now_iso,
)

_QDRANT_TAG = "QDRANT"
_QDRANT_DEFAULT_PORT = 6333
_QDRANT_SSRF_PRIORITY = "replica"
_QDRANT_SSRF_LISTENER_BIND = "0.0.0.0"
_QDRANT_GHSA_F632_VM87_2M2F_RANGE_MIN = (1, 9, 3)
_QDRANT_GHSA_F632_VM87_2M2F_RANGE_MAX_EXCL = (1, 15, 6)
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_CONNECTION_REFUSED_PREFIX = "connection refused"
_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_QDRANT_DEEP_STATUSES = {"open_no_auth", "open_auth", "unknown_auth"}


def _clip(text: str, width: int = 80) -> str:
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


def _is_connection_timeout_fail_record(record: dict[str, Any]) -> bool:
    if str(record.get("status") or "") != "fail":
        return False
    error_text = str(record.get("error") or "").strip().lower()
    return bool(error_text) and (
        error_text.startswith(_CONNECTION_TIMEOUT_PREFIX) or error_text.startswith(_CONNECTION_REFUSED_PREFIX)
    )


def _normalize_inline_text(value: str) -> str:
    return " ".join(str(value or "").split())


def _json_compact(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return _normalize_inline_text(str(value))


def _http_json_request(
    host: str,
    port: int,
    method: str,
    path: str,
    timeout: float,
    *,
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
) -> tuple[int, Any, str | None]:
    url = f"http://{host}:{port}{path}"
    body_bytes: bytes | None = None
    req_headers = {
        "User-Agent": "RedPosture/1.0",
        "Accept": "application/json",
    }
    if headers:
        req_headers.update(headers)
    if payload is not None:
        body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req_headers["Content-Type"] = "application/json"

    response = HttpApiClient(HttpClientConfig(timeout=timeout, response_size_cap=10 * 1024 * 1024)).request(
        method,
        url,
        headers=req_headers,
        body=body_bytes,
        timeout=timeout,
    )
    if response.error:
        return 0, None, _friendly_error_text(response.error)
    status = int(response.status)
    raw = response.body

    if not raw:
        return status, None, None
    text = raw.decode("utf-8", errors="replace")
    try:
        return status, json.loads(text), None
    except json.JSONDecodeError:
        return status, text, None


def _qdrant_headers(api_key: str | None) -> dict[str, str] | None:
    token = str(api_key or "").strip()
    if not token:
        return None
    return {"api-key": token}


def _qdrant_extract_version(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    raw_version = payload.get("version")
    if isinstance(raw_version, str) and raw_version.strip():
        return raw_version.strip()
    result = payload.get("result")
    if isinstance(result, dict):
        raw_version = result.get("version")
        if isinstance(raw_version, str) and raw_version.strip():
            return raw_version.strip()
    return None


def _parse_semver_triplet(value: str | None) -> tuple[int, int, int] | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", raw)
    if not match:
        return None
    try:
        return int(match.group(1)), int(match.group(2)), int(match.group(3))
    except (TypeError, ValueError):
        return None


def _semver_in_half_open_range(
    version: tuple[int, int, int] | None,
    *,
    min_incl: tuple[int, int, int],
    max_excl: tuple[int, int, int],
) -> bool | None:
    if version is None:
        return None
    return min_incl <= version < max_excl


def _qdrant_is_root_payload(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    title = str(payload.get("title") or "").strip().lower()
    version = str(payload.get("version") or "").strip()
    if "qdrant" in title:
        return True
    if title == "" and version and "result" in payload:
        # Some proxied responses may wrap the object but still expose version fields.
        return True
    return False


def _qdrant_error_text(payload: Any, *, fallback_status: int | None = None) -> str | None:
    if isinstance(payload, dict):
        status_value = payload.get("status")
        if isinstance(status_value, dict):
            err = status_value.get("error")
            if isinstance(err, str) and err.strip():
                return _normalize_inline_text(err)
        for key in ("error", "message", "detail"):
            raw = payload.get(key)
            if isinstance(raw, str) and raw.strip():
                return _normalize_inline_text(raw)
        try:
            rendered = _json_compact(payload)
        except Exception:
            rendered = None
        if rendered:
            return rendered
    if isinstance(payload, list):
        return _json_compact(payload)
    if isinstance(payload, str):
        text = _normalize_inline_text(payload)
        return text or None
    if fallback_status is not None and fallback_status > 0:
        return f"status={fallback_status}"
    return None


def _qdrant_collections_from_payload(payload: Any) -> list[str] | None:
    if not isinstance(payload, dict):
        return None
    result = payload.get("result")
    if not isinstance(result, dict):
        return None
    items = result.get("collections")
    if not isinstance(items, list):
        return None
    names: list[str] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        raw_name = item.get("name")
        if not isinstance(raw_name, str):
            continue
        name = raw_name.strip()
        if not name or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def _qdrant_looks_like_response(payload: Any) -> bool:
    if isinstance(payload, dict):
        if _qdrant_is_root_payload(payload):
            return True
        if "result" in payload and ("status" in payload or "time" in payload or "usage" in payload):
            return True
        status_value = payload.get("status")
        if isinstance(status_value, dict) and "error" in status_value:
            return True
    return False


def _qdrant_get_root_info(
    host: str,
    port: int,
    timeout: float,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any, str | None]:
    status, payload, error = _http_json_request(host, port, "GET", "/", timeout, headers=headers)
    if error is None and status not in {0, 404}:
        return status, payload, None
    # Fallback for some deployments/proxies: `/service/info`.
    status2, payload2, error2 = _http_json_request(host, port, "GET", "/service/info", timeout, headers=headers)
    if error2 is None or error is not None:
        return status2, payload2, error2
    return status, payload, error


def _qdrant_get_collections(
    host: str,
    port: int,
    timeout: float,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any, str | None]:
    return _http_json_request(host, port, "GET", "/collections", timeout, headers=headers)


def _qdrant_get_collection_info(
    host: str,
    port: int,
    timeout: float,
    collection_name: str,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any, str | None]:
    encoded_name = urllib.parse.quote(collection_name, safe="")
    return _http_json_request(host, port, "GET", f"/collections/{encoded_name}", timeout, headers=headers)


def _qdrant_edit_probe_empty_patch(
    host: str,
    port: int,
    timeout: float,
    collection_name: str,
    *,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    encoded_name = urllib.parse.quote(collection_name, safe="")
    status, payload, error = _http_json_request(
        host,
        port,
        "PATCH",
        f"/collections/{encoded_name}",
        timeout,
        headers=headers,
        payload={},
    )
    result: dict[str, Any] = {
        "collection": collection_name,
        "method": "PATCH",
        "payload": "{}",
        "status": status,
        "error": None,
        "ok": False,
        "reachable": False,
        "validation_only": False,
        "response_raw": None,
    }
    if error:
        result["error"] = error
        return result

    result["response_raw"] = _json_compact(payload) if payload is not None else None
    if status in {200, 202}:
        result["ok"] = True
        result["reachable"] = True
        return result
    if status in {400, 409, 422}:
        # Endpoint is reachable and processed the request, but empty payload was rejected (expected for no-op probe).
        result["reachable"] = True
        result["validation_only"] = True
        result["error"] = _qdrant_error_text(payload, fallback_status=status) or f"status={status}"
        return result
    result["error"] = _qdrant_error_text(payload, fallback_status=status) or f"status={status}"
    return result


def _qdrant_logger_endpoint_probe(
    host: str,
    port: int,
    timeout: float,
    *,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    # Intentionally invalid payload type for `enabled` -> authorization/endpoint reachability probe
    # without applying a real logger configuration or writing files.
    probe_payload = {
        "on_disk": {
            "enabled": "redposture-probe-invalid-type",
            "log_file": "redposture_probe.log",
        }
    }
    status, payload, error = _http_json_request(
        host,
        port,
        "POST",
        "/logger",
        timeout,
        headers=headers,
        payload=probe_payload,
    )
    result: dict[str, Any] = {
        "status": status,
        "reachable": False,
        "ok": False,
        "validation_only": False,
        "blocked": False,
        "error": None,
        "response_raw": None,
        "probe_mode": "invalid_payload_noop",
    }
    if error:
        result["error"] = error
        return result

    if payload is not None:
        result["response_raw"] = _json_compact(payload)

    if status in {200, 202}:
        result["reachable"] = True
        result["ok"] = True
        return result
    if status in {400, 409, 422}:
        result["reachable"] = True
        result["validation_only"] = True
        result["error"] = _qdrant_error_text(payload, fallback_status=status) or f"status={status}"
        return result
    if status in {401, 403}:
        result["blocked"] = True
        result["error"] = _qdrant_error_text(payload, fallback_status=status) or f"status={status}"
        return result

    result["error"] = _qdrant_error_text(payload, fallback_status=status) or f"status={status}"
    return result


def _qdrant_assess_ghsa_f632_vm87_2m2f(
    *,
    version: str | None,
    logger_probe: dict[str, Any] | None,
) -> dict[str, Any]:
    parsed_version = _parse_semver_triplet(version)
    version_affected = _semver_in_half_open_range(
        parsed_version,
        min_incl=_QDRANT_GHSA_F632_VM87_2M2F_RANGE_MIN,
        max_excl=_QDRANT_GHSA_F632_VM87_2M2F_RANGE_MAX_EXCL,
    )
    logger_reachable = None
    logger_blocked = None
    logger_status: int | None = None
    logger_error: str | None = None
    if isinstance(logger_probe, dict):
        logger_reachable = bool(logger_probe.get("reachable"))
        logger_blocked = bool(logger_probe.get("blocked"))
        raw_status = logger_probe.get("status")
        if isinstance(raw_status, int):
            logger_status = raw_status
        logger_error = str(logger_probe.get("error") or "").strip() or None

    assessment = "unknown"
    marker = "[!]"
    if version_affected is False:
        assessment = "not_affected_version"
        marker = "[*]"
    elif version_affected is True:
        if logger_reachable is True:
            assessment = "potentially_vulnerable"
            marker = "[+]"
        elif logger_blocked is True:
            assessment = "logger_endpoint_blocked"
            marker = "[-]"
        else:
            assessment = "affected_version_probe_inconclusive"
            marker = "[!]"
    else:
        if logger_reachable is True:
            assessment = "logger_reachable_version_unknown"
            marker = "[!]"

    return {
        "id": "GHSA-f632-vm87-2m2f",
        "cve": "CVE-2026-25628",
        "endpoint": "/logger",
        "affected_range": ">=1.9.3,<1.15.6",
        "version": version,
        "parsed_version": ".".join(str(x) for x in parsed_version) if parsed_version else None,
        "version_affected": version_affected,
        "logger_reachable": logger_reachable,
        "logger_blocked": logger_blocked,
        "logger_status": logger_status,
        "logger_error": logger_error,
        "assessment": assessment,
        "marker": marker,
    }


def _qdrant_ssrf_snapshot_recover_probe(
    host: str,
    port: int,
    timeout: float,
    collection_name: str,
    target_url: str,
    *,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    encoded_name = urllib.parse.quote(collection_name, safe="")
    status, payload, error = _http_json_request(
        host,
        port,
        "PUT",
        f"/collections/{encoded_name}/snapshots/recover?wait=true",
        timeout,
        headers=headers,
        payload={
            "location": target_url,
            "priority": _QDRANT_SSRF_PRIORITY,
        },
    )
    result: dict[str, Any] = {
        "target_url": target_url,
        "collection": collection_name,
        "status": status,
        "ok": False,
        "error": None,
        "response_raw": None,
    }
    if error:
        result["error"] = error
        return result

    if payload is not None:
        result["response_raw"] = _json_compact(payload)

    if status in {200, 202}:
        result["ok"] = True
        return result

    result["error"] = _qdrant_error_text(payload, fallback_status=status) or f"status={status}"
    return result


def _normalize_ssrf_path(path_str: str | None) -> tuple[str, str] | None:
    raw = (path_str or "").strip()
    if not raw:
        return None
    parsed_query = ""
    parsed_path = raw
    if "://" in raw:
        try:
            parsed = urllib.parse.urlsplit(raw)
        except ValueError:
            return None
        parsed_path = parsed.path or "/"
        parsed_query = parsed.query
    else:
        if "?" in raw:
            parsed_path, parsed_query = raw.split("?", 1)
        else:
            parsed_path, parsed_query = raw, ""
    parsed_path = parsed_path.strip() or "/"
    if not parsed_path.startswith("/"):
        parsed_path = f"/{parsed_path}"
    return parsed_path, parsed_query


def _normalize_ssrf_urls(targets_str: str | None, ports_str: str | None, path_str: str | None = None) -> list[str]:
    if not targets_str:
        return []
    raw_targets = [t.strip() for t in str(targets_str).split(",") if t.strip()]
    if not raw_targets:
        return []
    parsed_ports: list[int] = []
    if ports_str:
        parsed_ports = collect_scan_ports(ports_str)
        if not parsed_ports:
            return []
    path_override = _normalize_ssrf_path(path_str)
    if path_str and path_override is None:
        return []

    results: list[str] = []
    seen: set[str] = set()
    for target in raw_targets:
        candidate_urls: list[str] = []
        if "://" not in target and "/" in target:
            try:
                expanded_hosts = collect_scan_targets(target, max_network_hosts=256)
            except (OSError, ValueError):
                expanded_hosts = []
            if expanded_hosts:
                for host in expanded_hosts:
                    if ":" in host and not host.startswith("["):
                        candidate_urls.append(f"http://[{host}]")
                    else:
                        candidate_urls.append(f"http://{host}")
        if not candidate_urls:
            candidate_urls = [target if "://" in target else f"http://{target}"]

        for candidate in candidate_urls:
            try:
                parsed = urllib.parse.urlsplit(candidate)
            except ValueError:
                continue
            scheme = parsed.scheme.lower() or "http"
            if scheme not in {"http", "https"}:
                scheme = "http"
            host = parsed.hostname
            if not host:
                continue
            path = parsed.path or "/"
            query = parsed.query
            if path_override is not None:
                path, query = path_override
            if parsed_ports:
                ports_for_target = parsed_ports
            elif parsed.port is not None:
                ports_for_target = [parsed.port]
            else:
                ports_for_target = [443 if scheme == "https" else 80]

            for port_int in ports_for_target:
                netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
                netloc += f":{port_int}"
                normalized = urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
                if normalized in seen:
                    continue
                seen.add(normalized)
                results.append(normalized)
    return results


class _QdrantSsrfCaptureServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class _QdrantSsrfCaptureHandler(BaseHTTPRequestHandler):
    server_version = "RedPostureSSRFCapture/1.0"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def _capture_and_reply(self) -> None:
        body_len = 0
        body_preview = ""
        body_truncated = False
        try:
            raw_len = str(self.headers.get("Content-Length") or "0").strip()
            body_len = int(raw_len) if raw_len.isdigit() else 0
        except (TypeError, ValueError):
            body_len = 0
        if body_len > 0:
            preview_bytes = self.rfile.read(min(body_len, 512))
            body_preview = preview_bytes.decode("utf-8", errors="replace")
            remaining = max(0, body_len - len(preview_bytes))
            if remaining:
                body_truncated = True
                _ = self.rfile.read(remaining)

        request_line = str(getattr(self, "requestline", "") or "").strip()
        if not request_line:
            method_text = str(self.command or "GET")
            path_text = str(self.path or "/")
            version_text = str(getattr(self, "request_version", "HTTP/1.1") or "HTTP/1.1")
            request_line = f"{method_text} {path_text} {version_text}"
        header_lines = [f"{str(k)}: {str(v)}" for k, v in self.headers.items()]
        raw_request_lines = [request_line, *header_lines, ""]
        if body_preview:
            raw_request_lines.append(body_preview)
            if body_truncated:
                raw_request_lines.append("[[truncated]]")
        raw_request_text = "\n".join(raw_request_lines)

        hit = {
            "timestamp": utc_now_iso(),
            "port": int(self.server.server_address[1]),  # type: ignore[attr-defined]
            "client_host": str(self.client_address[0]),
            "client_port": int(self.client_address[1]),
            "method": str(self.command or "-"),
            "path": str(self.path or "/"),
            "host": str(self.headers.get("Host") or ""),
            "user_agent": str(self.headers.get("User-Agent") or ""),
            "content_type": str(self.headers.get("Content-Type") or ""),
            "content_length": body_len,
            "body_preview": _normalize_inline_text(body_preview) if body_preview else "",
            "request_line": request_line,
            "headers": header_lines,
            "raw_request": raw_request_text,
        }
        lock = getattr(self.server, "capture_lock", None)  # type: ignore[attr-defined]
        hits = getattr(self.server, "capture_hits", None)  # type: ignore[attr-defined]
        if hits is not None and isinstance(hits, list) and lock is not None and hasattr(lock, "__enter__"):
            with lock:
                hits.append(hit)
        elif isinstance(hits, list):
            hits.append(hit)

        body = b"redposture-ssrf-capture-ok\n"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._capture_and_reply()

    def do_POST(self) -> None:  # noqa: N802
        self._capture_and_reply()

    def do_PUT(self) -> None:  # noqa: N802
        self._capture_and_reply()

    def do_HEAD(self) -> None:  # noqa: N802
        self._capture_and_reply()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._capture_and_reply()


def _start_qdrant_ssrf_capture_listener(port: int) -> dict[str, Any]:
    port_value = int(port)
    result: dict[str, Any] = {
        "attempted": True,
        "bind": _QDRANT_SSRF_LISTENER_BIND,
        "port": port_value,
        "started": False,
        "thread": None,
        "server": None,
        "hits": [],
        "lock": threading.Lock(),
        "error": None,
    }
    try:
        server = _QdrantSsrfCaptureServer((_QDRANT_SSRF_LISTENER_BIND, port_value), _QdrantSsrfCaptureHandler)
        server.capture_hits = result["hits"]  # type: ignore[attr-defined]
        server.capture_lock = result["lock"]  # type: ignore[attr-defined]
    except OSError as exc:
        result["error"] = str(exc)
        return result

    thread = threading.Thread(target=server.serve_forever, daemon=True, name=f"qdrant-ssrf-capture-{port_value}")
    thread.start()
    result["started"] = True
    result["thread"] = thread
    result["server"] = server
    return result


def _stop_qdrant_ssrf_capture_listener(listener: dict[str, Any]) -> None:
    server = listener.get("server")
    if server is None:
        return
    try:
        server.shutdown()
    except Exception:
        pass
    try:
        server.server_close()
    except Exception:
        pass
    thread = listener.get("thread")
    if isinstance(thread, threading.Thread):
        thread.join(timeout=1.0)


def _qdrant_ssrf_capture_hits(listener: dict[str, Any]) -> list[dict[str, Any]]:
    hits = listener.get("hits")
    if not isinstance(hits, list):
        return []
    lock = listener.get("lock")
    if lock is not None and hasattr(lock, "__enter__"):
        with lock:
            return [dict(item) for item in hits if isinstance(item, dict)]
    return [dict(item) for item in hits if isinstance(item, dict)]


def _empty_qdrant_record(
    host: str,
    port: int,
    *,
    show_collections: bool,
    dump_requested: bool,
    dump_limit: int | None,
    collection_name: str | None,
    ssrf_urls: list[str] | None,
) -> dict[str, Any]:
    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_qdrant": False,
        "status": "fail",
        "auth_required": None,
        "anonymous_access": None,
        "version": None,
        "api_key_provided": False,
        "api_key_access": None,
        "collections_count": None,
        "collections_source": None,
        "show_collections": show_collections,
        "dump": dump_requested,
        "dump_limit": dump_limit,
        "collection_name": collection_name,
        "collections": None,
        "collections_list_error": None,
        "collection_dump_items": None,
        "collection_dump_error": None,
        "edit_probe": None,
        "logger_probe": None,
        "ghsa_f632_vm87_2m2f": None,
        "ssrf_requested": bool(ssrf_urls),
        "ssrf_collection": collection_name,
        "ssrf_results": None,
        "ssrf_error": None,
        "elapsed_ms": None,
        "error": "connection failed",
    }


def _audit_qdrant_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    api_key: str | None,
    show_collections: bool,
    dump_requested: bool,
    collection_name: str | None,
    ssrf_urls: list[str] | None,
    dump_limit: int | None = None,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    auth_headers = _qdrant_headers(api_key)
    ssrf_targets = list(ssrf_urls or [])

    for attempt in range(attempts):
        started = time.monotonic()
        try:
            record = _empty_qdrant_record(
                host,
                port,
                show_collections=show_collections,
                dump_requested=dump_requested,
                dump_limit=dump_limit,
                collection_name=collection_name,
                ssrf_urls=ssrf_targets,
            )
            record["api_key_provided"] = bool(auth_headers)

            root_status, root_payload, root_error = _qdrant_get_root_info(host, port, timeout, headers=None)
            root_auth_status = 0
            root_auth_payload: Any = None
            root_auth_error: str | None = None
            if auth_headers and (root_error or root_status in {401, 403, 404}):
                root_auth_status, root_auth_payload, root_auth_error = _qdrant_get_root_info(
                    host, port, timeout, headers=auth_headers
                )

            version = _qdrant_extract_version(root_payload)
            if not version:
                version = _qdrant_extract_version(root_auth_payload)
            record["version"] = version

            anon_col_status, anon_col_payload, anon_col_error = _qdrant_get_collections(
                host, port, timeout, headers=None
            )
            record["collections_list_error"] = anon_col_error

            anon_names = _qdrant_collections_from_payload(anon_col_payload) if anon_col_error is None else None
            anon_collections_ok = anon_col_status == 200 and isinstance(anon_names, list)

            is_qdrant = False
            if _qdrant_is_root_payload(root_payload) or _qdrant_is_root_payload(root_auth_payload):
                is_qdrant = True
            elif _qdrant_looks_like_response(anon_col_payload):
                is_qdrant = True
            elif _qdrant_looks_like_response(root_payload) or _qdrant_looks_like_response(root_auth_payload):
                is_qdrant = True
            elif anon_col_status in {401, 403} and isinstance(anon_col_payload, dict):
                # Auth-required collections endpoint still strongly indicates Qdrant.
                is_qdrant = True

            if not is_qdrant:
                if anon_col_error:
                    last_error = anon_col_error
                    raise OSError(anon_col_error)
                if root_error and not (root_auth_error is None and root_auth_status > 0):
                    last_error = root_error
                    raise OSError(root_error)
                record["error"] = "service is not qdrant"
                record["elapsed_ms"] = int((time.monotonic() - started) * 1000)
                return record

            record["is_qdrant"] = True

            anonymous_access: bool | None = None
            auth_required: bool | None = None
            collections: list[str] | None = None
            collections_source: str | None = None
            api_key_access: bool | None = None
            action_headers: dict[str, str] | None = None
            action_source: str | None = None

            if anon_col_error is not None:
                record["collections_list_error"] = anon_col_error
            elif anon_collections_ok:
                anonymous_access = True
                auth_required = False
                collections = list(anon_names or [])
                collections_source = "anonymous"
                action_headers = None
                action_source = "anonymous"
                record["collections_list_error"] = None
            elif anon_col_status in {401, 403}:
                anonymous_access = False
                auth_required = True
                record["collections_list_error"] = _qdrant_error_text(anon_col_payload, fallback_status=anon_col_status)
                if auth_headers:
                    auth_col_status, auth_col_payload, auth_col_error = _qdrant_get_collections(
                        host, port, timeout, headers=auth_headers
                    )
                    if auth_col_error:
                        api_key_access = False
                        record["collections_list_error"] = auth_col_error
                    else:
                        auth_names = _qdrant_collections_from_payload(auth_col_payload)
                        if auth_col_status == 200 and isinstance(auth_names, list):
                            api_key_access = True
                            collections = list(auth_names)
                            collections_source = "api_key"
                            action_headers = auth_headers
                            action_source = "api_key"
                            record["collections_list_error"] = None
                        elif auth_col_status in {401, 403}:
                            api_key_access = False
                            record["collections_list_error"] = _qdrant_error_text(
                                auth_col_payload, fallback_status=auth_col_status
                            )
                        else:
                            api_key_access = False
                            record["collections_list_error"] = _qdrant_error_text(
                                auth_col_payload, fallback_status=auth_col_status
                            )
            else:
                # Unexpected but reachable response; we can still try with API key for details.
                record["collections_list_error"] = _qdrant_error_text(anon_col_payload, fallback_status=anon_col_status)
                if auth_headers:
                    auth_col_status, auth_col_payload, auth_col_error = _qdrant_get_collections(
                        host, port, timeout, headers=auth_headers
                    )
                    if auth_col_error:
                        api_key_access = False
                    else:
                        auth_names = _qdrant_collections_from_payload(auth_col_payload)
                        if auth_col_status == 200 and isinstance(auth_names, list):
                            api_key_access = True
                            collections = list(auth_names)
                            collections_source = "api_key"
                            action_headers = auth_headers
                            action_source = "api_key"
                            if anonymous_access is None:
                                auth_required = None
                            record["collections_list_error"] = None
                        elif auth_col_status in {401, 403}:
                            api_key_access = False
                            record["collections_list_error"] = _qdrant_error_text(
                                auth_col_payload, fallback_status=auth_col_status
                            )
                        else:
                            api_key_access = False
                            record["collections_list_error"] = _qdrant_error_text(
                                auth_col_payload, fallback_status=auth_col_status
                            )

            record["anonymous_access"] = anonymous_access
            record["auth_required"] = auth_required
            record["api_key_access"] = api_key_access
            record["collections"] = collections
            record["collections_source"] = collections_source
            record["collections_count"] = len(collections) if isinstance(collections, list) else None

            if anonymous_access is True:
                record["status"] = "open_no_auth"
            elif auth_required is True and api_key_access is True:
                record["status"] = "open_auth"
            elif auth_required is True:
                record["status"] = "auth_required"
            elif _qdrant_looks_like_response(anon_col_payload) or _qdrant_looks_like_response(root_payload):
                record["status"] = "unknown_auth"
            else:
                record["status"] = "unknown_auth"

            if dump_requested:
                dump_items: list[dict[str, Any]] = []
                record["collection_dump_items"] = dump_items
                if collection_name:
                    dump_targets = [collection_name]
                else:
                    dump_targets = list(collections or [])
                    if dump_limit is not None:
                        dump_targets = dump_targets[:dump_limit]

                if not dump_targets:
                    if record["status"] == "auth_required":
                        record["collection_dump_error"] = "authentication required for collection dump"
                    else:
                        record["collection_dump_error"] = "no collections available for dump"
                else:
                    for dump_name in dump_targets:
                        item: dict[str, Any] = {
                            "name": dump_name,
                            "ok": False,
                            "status": None,
                            "error": None,
                            "info_raw": None,
                        }
                        info_status, info_payload, info_error = _qdrant_get_collection_info(
                            host,
                            port,
                            timeout,
                            dump_name,
                            headers=action_headers,
                        )
                        item["status"] = info_status
                        if info_error:
                            item["error"] = info_error
                        elif info_status == 200:
                            item["ok"] = True
                            item["info_raw"] = _json_compact(info_payload)
                        else:
                            item["error"] = (
                                _qdrant_error_text(info_payload, fallback_status=info_status) or f"status={info_status}"
                            )
                        dump_items.append(item)

            edit_probe_target = collection_name
            if not edit_probe_target and isinstance(collections, list) and collections:
                edit_probe_target = collections[0]
            if edit_probe_target:
                edit_probe = _qdrant_edit_probe_empty_patch(
                    host,
                    port,
                    timeout,
                    edit_probe_target,
                    headers=action_headers,
                )
                edit_probe["source"] = action_source or ("anonymous" if action_headers is None else "api_key")
                record["edit_probe"] = edit_probe

            logger_probe_headers = action_headers if action_headers is not None else auth_headers
            logger_probe = _qdrant_logger_endpoint_probe(
                host,
                port,
                timeout,
                headers=logger_probe_headers,
            )
            logger_probe["source"] = action_source or ("anonymous" if logger_probe_headers is None else "api_key")
            record["logger_probe"] = logger_probe
            record["ghsa_f632_vm87_2m2f"] = _qdrant_assess_ghsa_f632_vm87_2m2f(
                version=record.get("version"),
                logger_probe=logger_probe,
            )

            if ssrf_targets:
                record["ssrf_collection"] = collection_name
                if not collection_name:
                    record["ssrf_error"] = "--collection is required for qdrant snapshot-restore SSRF probe"
                else:
                    ssrf_results: list[dict[str, Any]] = []
                    for target_url in ssrf_targets:
                        ssrf_results.append(
                            _qdrant_ssrf_snapshot_recover_probe(
                                host,
                                port,
                                timeout,
                                collection_name,
                                target_url,
                                headers=action_headers,
                            )
                        )
                    record["ssrf_results"] = ssrf_results

            # Prefer a more explicit top-level error only for true failures.
            record["error"] = None
            record["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            return record
        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
            last_error = _friendly_error_from_exception(exc)
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))

    record = _empty_qdrant_record(
        host,
        port,
        show_collections=show_collections,
        dump_requested=dump_requested,
        dump_limit=dump_limit,
        collection_name=collection_name,
        ssrf_urls=ssrf_targets,
    )
    record["api_key_provided"] = bool(auth_headers)
    record["error"] = last_error or "connection failed"
    return record


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{_QDRANT_TAG:<8}\t{host}\t{port}\t"


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
                "service": "qdrant",
                "host": record.get("host"),
                "port": record.get("port"),
                "detected": bool(record.get("is_qdrant")),
                "version": record.get("version"),
                "auth_required": auth_required_value,
                "anonymous_access": record.get("anonymous_access"),
            },
            ensure_ascii=False,
        )

    prefix = _nxc_prefix(record)
    version_text = str(record.get("version") or "-")
    return f"{prefix} [*] Qdrant API (auth required:{auth_required_text}) (version:{version_text})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 96)
    collections_count = record.get("collections_count")
    collections_text = str(collections_count) if isinstance(collections_count, int) else "-"
    edit_probe = record.get("edit_probe")
    ghsa_check = record.get("ghsa_f632_vm87_2m2f")
    idor_text = "unknown"
    if isinstance(edit_probe, dict):
        probe_source = str(edit_probe.get("source") or "").strip().lower()
        if probe_source == "anonymous":
            if (
                bool(edit_probe.get("ok"))
                or bool(edit_probe.get("validation_only"))
                or bool(edit_probe.get("reachable"))
            ):
                idor_text = "true"
            else:
                probe_status = edit_probe.get("status")
                if probe_status in {401, 403}:
                    idor_text = "false"
                elif str(edit_probe.get("error") or "").strip():
                    idor_text = "false"
        elif probe_source:
            idor_text = "false"
    rce_suffix = ""
    if isinstance(ghsa_check, dict) and str(ghsa_check.get("assessment") or "").strip() == "potentially_vulnerable":
        rce_suffix = " RCE!"

    if status == "open_no_auth":
        return f"{prefix} [+] anonymous access{rce_suffix} (collections:{collections_text}) (idor:{idor_text})"
    if status == "open_auth":
        return (
            f"{prefix} [+] collections access with api-key{rce_suffix} "
            f"(anonymous:blocked) (collections:{collections_text})"
        )
    if status == "auth_required":
        line = f"{prefix} [-] authentication required for collections"
        detail = str(record.get("collections_list_error") or "").strip()
        if detail:
            return f"{line} err={_clip(detail, 96)}"
        return line
    if status == "unknown_auth":
        line = f"{prefix} [!] auth status unknown"
        detail = str(record.get("collections_list_error") or "").strip()
        if detail:
            return f"{line} err={_clip(detail, 96)}"
        return line

    line = f"{prefix} [!] connection failed"
    if err != "-":
        return f"{line} err={err}"
    return line


def _format_detail_records(record: dict[str, Any], output_format: str, *, debug: bool = False) -> list[str]:
    show_collections = bool(record.get("show_collections"))
    dump_requested = bool(record.get("dump"))
    collection_selector = str(record.get("collection_name") or "").strip()
    collections = record.get("collections")
    collection_dump_items = record.get("collection_dump_items")
    edit_probe = record.get("edit_probe")
    logger_probe = record.get("logger_probe")
    ghsa_check = record.get("ghsa_f632_vm87_2m2f")
    ssrf_requested = bool(record.get("ssrf_requested"))
    ssrf_results = record.get("ssrf_results")
    edit_probe_visible = bool(edit_probe) and (debug or output_format == "json")
    ghsa_visible = isinstance(ghsa_check, dict) and (debug or output_format == "json")
    if not any([show_collections, dump_requested, edit_probe_visible, ghsa_visible, ssrf_requested]):
        return []

    prefix = _nxc_prefix(record)
    lines: list[str] = []

    if output_format == "json":
        if show_collections:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "collections_list",
                        "service": "qdrant",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "source": record.get("collections_source"),
                        "collection_count": record.get("collections_count"),
                        "collections": collections if isinstance(collections, list) else [],
                        "error": record.get("collections_list_error"),
                    },
                    ensure_ascii=False,
                )
            )
        if dump_requested:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "collections_dump",
                        "service": "qdrant",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "selector": collection_selector or None,
                        "items": collection_dump_items if isinstance(collection_dump_items, list) else [],
                        "error": record.get("collection_dump_error"),
                    },
                    ensure_ascii=False,
                )
            )
        if isinstance(edit_probe, dict):
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "edit_probe",
                        "service": "qdrant",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        **edit_probe,
                    },
                    ensure_ascii=False,
                )
            )
        if isinstance(ghsa_check, dict):
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "vuln_check",
                        "service": "qdrant",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "advisory": ghsa_check,
                        "logger_probe": logger_probe if isinstance(logger_probe, dict) else None,
                    },
                    ensure_ascii=False,
                )
            )
        if ssrf_requested:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "ssrf_snapshot_recover",
                        "service": "qdrant",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "collection": record.get("ssrf_collection"),
                        "results": ssrf_results if isinstance(ssrf_results, list) else [],
                        "error": record.get("ssrf_error"),
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    if show_collections:
        source = str(record.get("collections_source") or "-")
        count = record.get("collections_count")
        count_text = str(count) if isinstance(count, int) else "-"
        suffix = f" (source:{source})" if source and source != "-" else ""
        lines.append(f"{prefix} [*] Collections (count:{count_text}){suffix}")
        if isinstance(collections, list):
            if not collections:
                lines.append(f"{prefix} <no collections>")
            for name in collections:
                lines.append(f"{prefix} {name}")
        else:
            err = str(record.get("collections_list_error") or "").strip()
            if err:
                lines.append(f"{prefix} [-] collections unavailable err={_clip(err, 120)}")
            else:
                lines.append(f"{prefix} [-] collections unavailable")

    if debug and isinstance(ghsa_check, dict):
        marker = str(ghsa_check.get("marker") or "[*]")
        assessment = str(ghsa_check.get("assessment") or "unknown")
        version_affected = ghsa_check.get("version_affected")
        if version_affected is True:
            version_affected_text = "true"
        elif version_affected is False:
            version_affected_text = "false"
        else:
            version_affected_text = "unknown"
        logger_reachable = ghsa_check.get("logger_reachable")
        if logger_reachable is True:
            logger_post_text = "true"
        elif logger_reachable is False:
            logger_post_text = "false"
        else:
            logger_post_text = "unknown"
        line = (
            f"{prefix} {marker} GHSA-f632-vm87-2m2f (/logger) "
            f"(version_affected:{version_affected_text}) (logger_post:{logger_post_text}) "
            f"(status:{assessment})"
        )
        logger_status = ghsa_check.get("logger_status")
        if isinstance(logger_status, int) and logger_status > 0:
            line += f" (logger_status:{logger_status})"
        lines.append(line)
        logger_error = str(ghsa_check.get("logger_error") or "").strip()
        if debug and logger_error:
            lines.append(f"{prefix} [*] ghsa logger probe err={_clip(logger_error, 180)}")
        if debug and isinstance(logger_probe, dict):
            response_raw = str(logger_probe.get("response_raw") or "").strip()
            if response_raw:
                lines.append(f"{prefix} [*] ghsa logger probe response={response_raw}")

    if dump_requested:
        selector_suffix = f" (name:{collection_selector})" if collection_selector else ""
        lines.append(f"{prefix} [*] Collections Dump{selector_suffix}")
        dump_error = str(record.get("collection_dump_error") or "").strip()
        if dump_error:
            lines.append(f"{prefix} [-] dump unavailable err={_clip(dump_error, 120)}")
        items = collection_dump_items if isinstance(collection_dump_items, list) else []
        if not items and not dump_error:
            lines.append(f"{prefix} <collection not found>" if collection_selector else f"{prefix} <no collections>")
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "-")
            ok = bool(item.get("ok"))
            status = item.get("status")
            status_text = f" status={status}" if status is not None else ""
            if ok:
                lines.append(f"{prefix} [*] Collection (name:{name})")
                info_raw = str(item.get("info_raw") or "").strip()
                if info_raw:
                    lines.append(f"{prefix} info={info_raw}")
            else:
                err = _clip(str(item.get("error") or "unknown"), 120)
                lines.append(f"{prefix} [-] collection dump failed name={name}{status_text} err={err}")

    if debug and isinstance(edit_probe, dict):
        probe_collection = str(edit_probe.get("collection") or "-")
        source = str(edit_probe.get("source") or "-")
        status = edit_probe.get("status")
        status_text = f" status={status}" if status is not None else ""
        if bool(edit_probe.get("ok")):
            lines.append(
                f"{prefix} [+] update probe accepted (collection:{probe_collection}) (source:{source})"
                f"{status_text} (payload:{{}})"
            )
        elif bool(edit_probe.get("validation_only")):
            err = _clip(str(edit_probe.get("error") or "validation error"), 120)
            lines.append(
                f"{prefix} [+] update probe reached endpoint (collection:{probe_collection}) (source:{source})"
                f"{status_text} (payload:{{}}) validation={err}"
            )
        else:
            err = _clip(str(edit_probe.get("error") or "probe failed"), 120)
            if status in {401, 403}:
                lines.append(
                    f"{prefix} [-] update probe blocked (collection:{probe_collection}) (source:{source})"
                    f"{status_text} err={err}"
                )
            else:
                lines.append(
                    f"{prefix} [!] update probe failed (collection:{probe_collection}) (source:{source})"
                    f"{status_text} err={err}"
                )

    if ssrf_requested:
        ssrf_collection = str(record.get("ssrf_collection") or "").strip() or "-"
        lines.append(f"{prefix} [*] Snapshot-recover SSRF (collection:{ssrf_collection})")
        ssrf_error = str(record.get("ssrf_error") or "").strip()
        if ssrf_error:
            lines.append(f"{prefix} [-] ssrf probe unavailable err={_clip(ssrf_error, 120)}")
        elif isinstance(ssrf_results, list):
            if not ssrf_results:
                lines.append(f"{prefix} <no ssrf targets>")
            for item in ssrf_results:
                if not isinstance(item, dict):
                    continue
                target = _clip(str(item.get("target_url") or "-"), 120)
                status = item.get("status")
                status_text = f" status={status}" if status is not None else ""
                if bool(item.get("ok")):
                    lines.append(f"{prefix} [+] target={target}{status_text}")
                    response_raw = str(item.get("response_raw") or "").strip()
                    if response_raw:
                        lines.append(f"{prefix} response={response_raw}")
                else:
                    err = str(item.get("error") or "probe failed").strip() or "probe failed"
                    lines.append(f"{prefix} [-] target={target}{status_text} err={err}")
                    response_raw = str(item.get("response_raw") or "").strip()
                    if response_raw:
                        lines.append(f"{prefix} response={response_raw}")
        else:
            lines.append(f"{prefix} [-] ssrf probe unavailable")

    return lines


def _render_colored_qdrant_line(console: Console, line: str) -> bool:
    return render_colored_marker_line(
        console,
        line,
        tag=_QDRANT_TAG,
        regexes=(
            RegexColorRule(r"(?i)\(idor:true\)", "red"),
            RegexColorRule(r"RCE!", "orange"),
        ),
        counts=(CountColorRule("collections", "red"),),
    )


def _call_audit_qdrant_host_with_stage_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    api_key: str | None,
    show_collections: bool,
    dump_requested: bool,
    collection_name: str | None,
    ssrf_urls: list[str] | None,
    run_deep_checks: bool,
    debug: bool,
    debug_emit: Callable[[str], None] | None,
    dump_limit: int | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    dump_kwargs = {"dump_limit": dump_limit if run_deep_checks else None} if dump_limit is not None else {}
    record = _audit_qdrant_host(
        host,
        port,
        timeout,
        retries,
        api_key=api_key,
        show_collections=show_collections if run_deep_checks else False,
        dump_requested=dump_requested if run_deep_checks else False,
        collection_name=collection_name if run_deep_checks else None,
        ssrf_urls=ssrf_urls if run_deep_checks else None,
        **dump_kwargs,
    )

    result: dict[str, Any] = dict(record)
    debug_events: list[str] = []

    def _debug(message: str) -> None:
        if not debug:
            return
        debug_events.append(message)
        if debug_emit is not None:
            debug_emit(f"{host}:{port} {message}")

    attempts = max(1, retries + 1)
    status = str(result.get("status") or "fail")
    is_qdrant = bool(result.get("is_qdrant"))
    elapsed_ms = int((time.monotonic() - started) * 1000)

    if attempts > 1 and status == "fail":
        _debug(
            f"retry_decision stage={_STAGE_DETECT_PROTOCOL} attempt=1/{attempts} "
            f"backoff={_retry_delay(0):.2f}s reason=error"
        )

    stages: list[dict[str, Any]] = []

    def _push_stage(stage_name: str, stage_result: str, stage_error: str | None = None, duration_ms: int = 0) -> None:
        entry = {
            "stage_name": stage_name,
            "attempt": 1,
            "duration_ms": int(max(0, duration_ms)),
            "result": stage_result,
            "error": stage_error or None,
        }
        stages.append(entry)
        _debug(
            f"stage_trace stage_name={stage_name} attempt=1 duration_ms={entry['duration_ms']} "
            f"result={stage_result} error={entry['error'] or '-'}"
        )

    detect_result = "ok" if is_qdrant else ("error" if status == "fail" else "skip")
    detect_error = str(result.get("error") or "") if detect_result == "error" else None
    _push_stage(_STAGE_DETECT_PROTOCOL, detect_result, detect_error, 0)

    auth_result = "ok" if is_qdrant and status in _QDRANT_DEEP_STATUSES.union({"auth_required"}) else detect_result
    _push_stage(_STAGE_AUTH_INFERENCE, auth_result, detect_error if auth_result == "error" else None, 0)

    if run_deep_checks and status in _QDRANT_DEEP_STATUSES:
        _push_stage(_STAGE_ACCESS_CAPABILITIES, "ok", None, 0)
        data_result = "error" if status == "fail" and result.get("error") else "ok"
        _push_stage(
            _STAGE_DATA,
            data_result,
            str(result.get("error") or "") if data_result == "error" else None,
            elapsed_ms,
        )
    else:
        _push_stage(_STAGE_ACCESS_CAPABILITIES, "skip", "deep checks disabled", 0)
        _push_stage(_STAGE_DATA, "skip", "deep checks disabled", 0)

    stage_failed_at: str | None = None
    for entry in stages:
        if str(entry.get("result") or "") == "error":
            stage_failed_at = str(entry.get("stage_name") or "")
            break

    stage_durations_ms = {str(item.get("stage_name") or ""): int(item.get("duration_ms") or 0) for item in stages}
    stage_attempts = {str(item.get("stage_name") or ""): attempts for item in stages}
    _debug(
        f"stage_timing_summary status={status} attempts=1/{attempts} "
        f"detect_ms={stage_durations_ms.get(_STAGE_DETECT_PROTOCOL, 0)} "
        f"auth_ms={stage_durations_ms.get(_STAGE_AUTH_INFERENCE, 0)} "
        f"capabilities_ms={stage_durations_ms.get(_STAGE_ACCESS_CAPABILITIES, 0)} "
        f"data_ms={stage_durations_ms.get(_STAGE_DATA, 0)} total_ms={elapsed_ms}"
    )

    result["stages"] = stages
    result["stage_failed_at"] = stage_failed_at
    result["stage_durations_ms"] = stage_durations_ms
    result["stage_attempts"] = stage_attempts
    result["debug_events"] = debug_events
    result["debug_events_streamed"] = bool(debug and debug_emit is not None)
    return result


def _merge_stage2_record(detect_record: dict[str, Any], deep_record: dict[str, Any]) -> dict[str, Any]:
    return merge_stage_records(detect_record, deep_record)


# Typed runner boundary -----------------------------------------------------


def record_from_mapping(payload: dict[str, Any]) -> AuditRecord:
    """Convert module protocol payloads to the typed runtime model."""

    return AuditRecord.from_mapping(payload, module="qdrant", service="qdrant")


def _credential_is_anonymous(ctx: AuditHookContext) -> bool:
    return ctx.credential.username is None and ctx.credential.password is None and ctx.credential.token is None


def _run_host_stage(ctx: AuditHookContext, *, run_deep_checks: bool) -> AuditRecord:
    return _invoke_module_host_stage(
        sys.modules[__name__],
        module="qdrant",
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
