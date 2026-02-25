"""Consul audit stage."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
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
_CONSUL_SCOPE_NAMES = ("kv", "services", "agents", "health")


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
        host,
        port,
        method,
        path,
        timeout,
        use_https=use_https,
        insecure=insecure,
        headers=headers,
        body=body,
    )
    if use_https and not insecure and error and _is_tls_verify_error_text(error):
        status, payload, resp_headers, error = _http_request(
            host,
            port,
            method,
            path,
            timeout,
            use_https=use_https,
            insecure=True,
            headers=headers,
            body=body,
        )
        return status, payload, resp_headers, error, True, True
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
            # Protected endpoint but likely Consul if JSON status structure looks familiar.
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
        return sum(1 for _k in payload.keys())
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
            raw = section.get("Version")
            if isinstance(raw, str) and raw.strip():
                return raw.strip()
            raw = section.get("version")
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
                    if v.strip().lower() in {"true", "false"}:
                        return v.strip().lower() == "true"
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
        "health": _scope_probe(
            host,
            port,
            "/v1/health/state/any",
            timeout,
            scheme=scheme,
            insecure=insecure,
            headers=headers,
            count_fn=_count_health_checks,
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


def _safe_excerpt(text: str, limit: int = 180) -> str:
    return _clip(" ".join(str(text or "").split()), limit)


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
    interval_seconds = max(2, int(round(max(timeout, 1.0))))
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
        "deregistered": False,
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
        for _ in range(5):
            time.sleep(min(0.6, max(0.2, timeout / 4)))
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
            if result["status"] in {"passing", "warning", "critical"}:
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
                    "error": probe_error or "not a Consul API",
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                }

            assert scheme is not None  # pragma: no cover - guarded by is_consul
            anonymous_scopes = _consul_access_matrix(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=insecure_effective,
                headers=None,
            )
            anonymous_self = _agent_self_probe(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=insecure_effective,
                headers=None,
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
                    host,
                    port,
                    timeout,
                    scheme=scheme,
                    insecure=insecure_effective,
                    headers=auth_headers,
                )
                auth_self = _agent_self_probe(
                    host,
                    port,
                    timeout,
                    scheme=scheme,
                    insecure=insecure_effective,
                    headers=auth_headers,
                )
                auth_valid = _all_scopes_ok(auth_scopes) or bool(auth_self.get("ok"))
                if auth_valid is False and _no_scopes_ok(auth_scopes):
                    # Prefer first explicit scope error.
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
                line += "(tls_auto_insecure:True)"
            lines.append(line)

        local_flag = record.get("local_script_checks")
        remote_flag = record.get("remote_script_checks")
        if local_flag is not None or remote_flag is not None:
            lines.append(
                f"{prefix} [*] Agent Config (local_script_checks:{_bool_text(local_flag)})"
                f" (remote_script_checks:{_bool_text(remote_flag)})"
            )
        if bool(record.get("rce")):
            lines.append(f"{prefix} [!] RCE! (EnableLocalScriptChecks:True) (EnableRemoteScriptChecks:True)")

    auth_scopes = record.get("auth_scopes") if isinstance(record.get("auth_scopes"), dict) else {}
    if auth_scopes:
        for item in _scope_status_detail_lines(prefix, auth_scopes):
            lines.append(item)

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
        ):
            idx = right.find(fragment)
            if idx >= 0:
                spans.append((idx, idx + len(fragment), color))

        for match in re.finditer(r"Pwned!", right):
            spans.append((match.start(), match.end(), "orange"))

        for pattern, color in (
            (r"\(kv:(\d+)\)", "red"),
            (r"\(services:(\d+)\)", "orange"),
            (r"\(agents:(\d+)\)", "orange"),
            (r"\(health:(\d+)\)", "orange"),
        ):
            for match in re.finditer(pattern, right):
                if match.group(1).isdigit() and int(match.group(1)) > 0:
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
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
) -> tuple[int, int, int]:
    total = 0
    detected = 0
    failed = 0

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
                ): host
                for host in hosts
            }
            for future in as_completed(future_map):
                record = future.result()
                total += 1
                if bool(record.get("is_consul")):
                    detected += 1
                if str(record.get("status") or "fail") == "fail":
                    failed += 1

                record_out = dict(record)
                if username is not None or password is not None:
                    record_out["_username_display"] = username or ""
                    record_out["_password_display"] = password or ""

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
                    anon_scopes = (
                        record.get("anonymous_scopes") if isinstance(record.get("anonymous_scopes"), dict) else {}
                    )
                    logger.log(
                        "consul",
                        (str(record.get("host") or "-"), int(record.get("port") or port)),
                        phase="audit",
                        status=record.get("status"),
                        scheme=record.get("scheme"),
                        version=record.get("version"),
                        anon_kv=bool((anon_scopes.get("kv") or {}).get("ok")) if anon_scopes else None,
                        anon_services=bool((anon_scopes.get("services") or {}).get("ok")) if anon_scopes else None,
                        anon_agents=bool((anon_scopes.get("agents") or {}).get("ok")) if anon_scopes else None,
                        anon_health=bool((anon_scopes.get("health") or {}).get("ok")) if anon_scopes else None,
                        rce=bool(record.get("rce")),
                        error=record.get("error"),
                    )
    finally:
        if out_fh is not None:
            out_fh.close()

    return total, detected, failed


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
    if not do_ssrf and str(ssrf_port or "").strip():
        console.error("--ssrf-port requires --ssrf-target")
        return 2
    if not do_ssrf and str(ssrf_path or "").strip():
        console.error("--ssrf-path requires --ssrf-target")
        return 2
    try:
        ssrf_urls = _normalize_ssrf_urls(ssrf_target, ssrf_port, ssrf_path) if do_ssrf else []
    except ValueError as exc:
        console.error(f"failed to parse --ssrf-port: {exc}")
        return 2
    if do_ssrf and not ssrf_urls:
        console.error("no valid SSRF targets generated from --ssrf-target/--ssrf-port")
        return 2

    stream_to_stdout = not bool(args.output)

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith(_CONSUL_TAG) and all(token_ not in line for token_ in (" [*] ", " [+] ", " [-] ", " [!] ")):
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
            f"workers={args.workers} retries={args.retries} auth={auth_label} ssrf={do_ssrf} format=txt"
        )

    total = 0
    detected = 0
    failed = 0
    try:
        for idx, port in enumerate(ports):
            part_total, part_detected, part_failed = audit_consul_targets(
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
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                logger=logger if args.debug else None,
                append_output=idx > 0,
            )
            total += part_total
            detected += part_detected
            failed += part_failed
    except OSError as exc:
        console.error(f"failed to process consul output: {exc}")
        return 2

    if stream_to_stdout and total > 0 and detected == 0 and failed == total and args.output_format == "txt":
        console.warn("all consul targets are unreachable; check host/port and network reachability")

    if args.debug:
        console.info(f"consul audit complete: total={total} detected={detected} fail={failed}")
    return 0
