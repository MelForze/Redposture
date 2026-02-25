"""Grafana audit stage."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import socket
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


def _clip(text: str, width: int = 64) -> str:
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


def _http_request(
    host: str,
    port: int,
    path: str,
    timeout: float,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> tuple[int, str, dict[str, str]]:
    url = f"http://{host}:{port}{path}"
    req_headers = {"User-Agent": "RedPosture/1.0"}
    if headers:
        req_headers.update(headers)
    request = urllib.request.Request(url, data=data, method=method, headers=req_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            body = response.read().decode("utf-8", errors="replace")
            response_headers = {str(key): str(value) for key, value in response.headers.items()}
            return status, body, response_headers
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        response_headers = {str(key): str(value) for key, value in exc.headers.items()}
        return int(exc.code), body, response_headers


def _load_json_dict(body: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _load_json_list(body: str) -> list[Any] | None:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, list):
        return None
    return parsed


def _header_lookup(headers: dict[str, str], name: str) -> str | None:
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            return str(value)
    return None


def _looks_like_grafana_login(status: int, body: str, headers: dict[str, str]) -> bool:
    if status not in {200, 301, 302, 303, 307, 308}:
        return False
    text = (body or "").lower()
    if "grafana" in text:
        return True
    set_cookie = (_header_lookup(headers, "Set-Cookie") or "").lower()
    if "grafana_session" in set_cookie:
        return True
    location = (_header_lookup(headers, "Location") or "").lower()
    if "/login" in location:
        return True
    return False


def _looks_like_grafana_health(status: int, body: str) -> tuple[bool, str | None]:
    if status != 200:
        return False, None
    payload = _load_json_dict(body)
    if payload is not None:
        if "version" in payload or "database" in payload or "commit" in payload:
            version = payload.get("version")
            return True, str(version) if isinstance(version, str) else None
    text = (body or "").lower()
    if "grafana" in text:
        return True, None
    return False, None


def _auth_header(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode()
    token = base64.b64encode(raw).decode("ascii")
    return f"Basic {token}"


def _verify_credentials(host: str, port: int, timeout: float, username: str, password: str) -> tuple[bool, str | None]:
    status, _body, _headers = _http_request(
        host,
        port,
        "/api/user",
        timeout,
        headers={"Authorization": _auth_header(username, password)},
    )
    if status == 200:
        return True, None
    if status in {401, 403}:
        return False, "invalid credentials"
    return False, f"/api/user returned status {status}"


def _fetch_datasources(
    host: str,
    port: int,
    timeout: float,
    *,
    auth_header: str | None = None,
) -> tuple[list[dict[str, str]] | None, str | None, int]:
    headers: dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header
    status, body, _response_headers = _http_request(host, port, "/api/datasources", timeout, headers=headers)
    if status == 200:
        payload = _load_json_list(body)
        if payload is None:
            return None, "/api/datasources returned invalid JSON", status
        result: list[dict[str, str]] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            result.append(
                {
                    "name": str(item.get("name") or "-"),
                    "type": str(item.get("type") or "-"),
                    "url": str(item.get("url") or "-"),
                    "access": str(item.get("access") or "-"),
                }
            )
        return result, None, status
    if status in {401, 403}:
        return None, "authentication required", status
    return None, f"/api/datasources returned status {status}", status


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


def _expand_ssrf_cidr_targets(token: str, max_hosts: int = 4096) -> list[str] | None:
    try:
        network = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None

    if network.version == 4:
        estimated = int(network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2)
    else:
        estimated = int(network.num_addresses if network.prefixlen >= 127 else network.num_addresses)

    if estimated > max_hosts:
        return []

    hosts = [str(addr) for addr in network.hosts()]
    if not hosts:
        hosts = [str(network.network_address)]
    return hosts


def _normalize_check_urls(targets_str: str | None, ports_str: str | None, path_str: str | None = None) -> list[str]:
    if not targets_str:
        return []

    raw_targets = [t.strip() for t in targets_str.split(",") if t.strip()]
    raw_ports = [p.strip() for p in (ports_str or "").split(",") if p.strip()]

    if not raw_targets:
        return []

    parsed_ports: list[int] = []
    for port_str in raw_ports:
        try:
            port_int = int(port_str)
        except ValueError:
            continue
        if 1 <= port_int <= 65535:
            parsed_ports.append(port_int)

    if ports_str and not parsed_ports:
        return []

    path_override = _normalize_ssrf_path(path_str)
    if path_str and path_override is None:
        return []

    results: list[str] = []
    seen: set[str] = set()

    for target in raw_targets:
        candidate_urls: list[str] = []
        if "://" not in target and "/" in target:
            expanded_hosts = _expand_ssrf_cidr_targets(target)
            if expanded_hosts is not None:
                if not expanded_hosts:
                    continue
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
            target_port = parsed.port

            if parsed_ports:
                ports_for_target = parsed_ports
            elif target_port is not None:
                ports_for_target = [target_port]
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
    compact = " ".join(str(text or "").split())
    return _clip(compact, limit)


def _safe_full_line(text: str) -> str:
    return " ".join(str(text or "").split())


def _extract_create_payload(body: str) -> tuple[int | None, str | None]:
    payload = _load_json_dict(body)
    if payload is None:
        return None, None
    ds_id: int | None = None
    ds_uid: str | None = None
    if isinstance(payload.get("id"), int):
        ds_id = int(payload["id"])
    uid_raw = payload.get("uid")
    if isinstance(uid_raw, str) and uid_raw.strip():
        ds_uid = uid_raw.strip()
    datasource_raw = payload.get("datasource")
    if isinstance(datasource_raw, dict):
        if ds_id is None and isinstance(datasource_raw.get("id"), int):
            ds_id = int(datasource_raw["id"])
        ds_uid_raw = datasource_raw.get("uid")
        if ds_uid is None and isinstance(ds_uid_raw, str) and ds_uid_raw.strip():
            ds_uid = ds_uid_raw.strip()
    return ds_id, ds_uid


def _split_check_target_url(target_url: str) -> tuple[str, str] | None:
    try:
        parsed = urllib.parse.urlsplit(str(target_url or ""))
    except ValueError:
        return None
    if not parsed.scheme or not parsed.netloc:
        return None

    base_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return base_url, path


def _delete_temp_datasource(
    host: str,
    port: int,
    timeout: float,
    auth_header: str | None,
    datasource_id: int | None,
    datasource_uid: str | None,
) -> tuple[bool | None, str | None]:
    headers: dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header
    if datasource_uid:
        encoded_uid = urllib.parse.quote(datasource_uid, safe="")
        path = f"/api/datasources/uid/{encoded_uid}"
    elif datasource_id is not None:
        path = f"/api/datasources/{int(datasource_id)}"
    else:
        return None, "temporary datasource id/uid is missing"
    try:
        status, body, _ = _http_request(host, port, path, timeout, method="DELETE", headers=headers)
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        return False, _friendly_error_from_exception(exc)
    if status in {200, 202}:
        return True, None
    detail = _safe_excerpt(body) if body else f"status {status}"
    return False, f"delete failed: {detail}"


def _run_temp_prometheus_check(
    host: str,
    port: int,
    timeout: float,
    auth_header: str | None,
    target_url: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "enabled": True,
        "target_url": target_url,
        "probe_proxy_path": None,
        "create_ok": False,
        "create_status": None,
        "create_error": None,
        "datasource_id": None,
        "datasource_uid": None,
        "probe_ok": None,
        "probe_status": None,
        "probe_elapsed_ms": None,
        "probe_error": None,
        "probe_sample": None,
        "cleanup_ok": None,
        "cleanup_error": None,
    }
    headers: dict[str, str] = {
        "Content-Type": "application/json; charset=utf-8",
    }
    if auth_header:
        headers["Authorization"] = auth_header

    split_target = _split_check_target_url(target_url)
    if split_target is None:
        result["create_error"] = "invalid target url"
        return result
    datasource_url, upstream_path = split_target

    temp_name = f"redposture-egress-{int(time.time() * 1000)}"
    create_payload = {
        "name": temp_name,
        "type": "prometheus",
        "access": "proxy",
        "url": datasource_url,
        "basicAuth": False,
        "isDefault": False,
        "jsonData": {"httpMethod": "GET"},
    }
    try:
        create_status, create_body, _ = _http_request(
            host,
            port,
            "/api/datasources",
            timeout,
            method="POST",
            headers=headers,
            data=json.dumps(create_payload).encode("utf-8"),
        )
        result["create_status"] = create_status
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        result["create_error"] = _friendly_error_from_exception(exc)
        return result

    datasource_id, datasource_uid = _extract_create_payload(create_body)
    result["datasource_id"] = datasource_id
    result["datasource_uid"] = datasource_uid

    if create_status not in {200, 201}:
        detail = _safe_excerpt(create_body) if create_body else f"status {create_status}"
        result["create_error"] = f"create failed: {detail}"
        return result
    if datasource_id is None:
        result["create_error"] = "create succeeded but datasource id is missing in response"
        return result

    result["create_ok"] = True

    probe_headers: dict[str, str] = {}
    if auth_header:
        probe_headers["Authorization"] = auth_header
    probe_started = time.monotonic()
    try:
        proxy_path = f"/api/datasources/proxy/{int(datasource_id)}{upstream_path}"
        result["probe_proxy_path"] = proxy_path
        probe_status, probe_body, _ = _http_request(
            host,
            port,
            proxy_path,
            timeout,
            headers=probe_headers,
        )
        result["probe_status"] = probe_status
        result["probe_ok"] = 200 <= int(probe_status) < 300
        if not result["probe_ok"]:
            result["probe_error"] = f"upstream returned status {probe_status}"
        result["probe_sample"] = _safe_full_line(probe_body)
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        result["probe_ok"] = False
        result["probe_error"] = _friendly_error_from_exception(exc)
    finally:
        result["probe_elapsed_ms"] = int((time.monotonic() - probe_started) * 1000)

    cleanup_ok, cleanup_error = _delete_temp_datasource(
        host,
        port,
        timeout,
        auth_header,
        datasource_id,
        datasource_uid,
    )
    result["cleanup_ok"] = cleanup_ok
    result["cleanup_error"] = cleanup_error
    return result


def _build_credential_candidates(
    username: str | None,
    password: str | None,
    defcreds: bool,
) -> list[tuple[str, str, str]]:
    candidates: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    if password is not None:
        user = (username or "admin").strip() or "admin"
        pair = (user, password)
        candidates.append((user, password, "provided"))
        seen.add(pair)
    if defcreds:
        defaults = (("admin", "admin"), ("admin", "prom-operator"))
        for user, secret in defaults:
            pair = (user, secret)
            if pair in seen:
                continue
            candidates.append((user, secret, "default"))
            seen.add(pair)
    return candidates


def _audit_grafana_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    defcreds: bool,
    check_urls: list[str] | None,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    provided_credentials = password is not None
    for attempt in range(attempts):
        started = time.monotonic()
        try:
            health_status, health_body, health_headers = _http_request(host, port, "/api/health", timeout)
            is_grafana, version = _looks_like_grafana_health(health_status, health_body)
            login_status = 0
            login_body = ""
            login_headers: dict[str, str] = {}
            if not is_grafana or health_status in {401, 403}:
                login_status, login_body, login_headers = _http_request(host, port, "/login", timeout)
                if _looks_like_grafana_login(login_status, login_body, login_headers):
                    is_grafana = True
            if not is_grafana:
                return {
                    "timestamp": utc_now_iso(),
                    "host": host,
                    "port": port,
                    "is_grafana": False,
                    "status": "fail",
                    "auth_required": None,
                    "server_version": None,
                    "provided_credentials": provided_credentials,
                    "provided_username": username,
                    "provided_credentials_ok": None,
                    "default_credentials": None,
                    "defcreds_enabled": defcreds,
                    "attempted_credentials": 0,
                    "credentials_source": None,
                    "effective_username": None,
                    "effective_password": None,
                    "datasource_count": None,
                    "datasources": None,
                    "check_urls": check_urls,
                    "check_results": None,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": "service is not grafana",
                }

            auth_required: bool | None
            if health_status == 200:
                auth_required = False
            elif health_status in {401, 403}:
                auth_required = True
            else:
                auth_required = None

            errors: list[str] = []
            candidates = _build_credential_candidates(username, password, defcreds)
            attempted_credentials = 0
            credentials_source: str | None = None
            effective_username: str | None = None
            effective_password: str | None = None
            default_credentials = False
            provided_credentials_ok: bool | None = None
            auth_header: str | None = None

            def _try_candidates(
                candidates_local: list[tuple[str, str, str]] = candidates,
                errors_local: list[str] = errors,
            ) -> None:
                nonlocal attempted_credentials, credentials_source, effective_username, effective_password
                nonlocal default_credentials, provided_credentials_ok, auth_header
                if effective_username is not None:
                    return
                for cand_user, cand_pass, source in candidates_local:
                    attempted_credentials += 1
                    ok, cred_error = _verify_credentials(host, port, timeout, cand_user, cand_pass)
                    if ok:
                        credentials_source = source
                        effective_username = cand_user
                        effective_password = cand_pass
                        auth_header = _auth_header(cand_user, cand_pass)
                        if source == "default":
                            default_credentials = True
                        if source == "provided":
                            provided_credentials_ok = True
                        return
                    if cred_error:
                        errors_local.append(cred_error)

            if provided_credentials:
                provided_credentials_ok = False

            if auth_required is True or auth_required is None:
                _try_candidates()

            datasources: list[dict[str, str]] | None = None
            datasource_count: int | None = None
            datasource_error: str | None = None

            if auth_required is False:
                datasources, datasource_error, datasource_status = _fetch_datasources(
                    host, port, timeout, auth_header=None
                )
                if datasource_error and datasource_status in {401, 403}:
                    auth_required = True
                    _try_candidates()

            if auth_header is not None:
                datasources, datasource_error, _ = _fetch_datasources(
                    host,
                    port,
                    timeout,
                    auth_header=auth_header,
                )
            elif datasource_error:
                errors.append(datasource_error)

            if isinstance(datasources, list):
                datasource_count = len(datasources)

            check_results = None
            if check_urls:
                check_results = []
                for target_url in check_urls:
                    res = _run_temp_prometheus_check(
                        host,
                        port,
                        timeout,
                        auth_header,
                        target_url,
                    )
                    check_results.append(res)

            if auth_required is False:
                status = "open_no_auth"
            elif effective_username is not None:
                status = "valid_credentials"
            elif auth_required is True:
                status = "auth_required"
            else:
                status = "unknown_auth"

            dedup_errors: list[str] = []
            for item in errors:
                clean = str(item).strip()
                if not clean or clean in dedup_errors:
                    continue
                dedup_errors.append(clean)
            error = "; ".join(dedup_errors) if dedup_errors else None

            return {
                "timestamp": utc_now_iso(),
                "host": host,
                "port": port,
                "is_grafana": True,
                "status": status,
                "auth_required": auth_required,
                "server_version": version,
                "provided_credentials": provided_credentials,
                "provided_username": username,
                "provided_credentials_ok": provided_credentials_ok,
                "default_credentials": default_credentials,
                "defcreds_enabled": defcreds,
                "attempted_credentials": attempted_credentials,
                "credentials_source": credentials_source,
                "effective_username": effective_username,
                "effective_password": effective_password,
                "datasource_count": datasource_count,
                "datasources": datasources,
                "check_urls": check_urls,
                "check_results": check_results,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": error,
            }
        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
            last_error = _friendly_error_from_exception(exc)
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_grafana": False,
        "status": "fail",
        "auth_required": None,
        "server_version": None,
        "provided_credentials": provided_credentials,
        "provided_username": username,
        "provided_credentials_ok": None,
        "default_credentials": None,
        "defcreds_enabled": defcreds,
        "attempted_credentials": 0,
        "credentials_source": None,
        "effective_username": None,
        "effective_password": None,
        "datasource_count": None,
        "datasources": None,
        "check_urls": check_urls,
        "check_results": None,
        "elapsed_ms": None,
        "error": last_error or "connection failed",
    }


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{'GRAFANA':<8}\t{host}\t{port}\t"


def _with_optional_datasources(record: dict[str, Any], message: str) -> str:
    datasource_count = record.get("datasource_count")
    if isinstance(datasource_count, int):
        return f"{message} (datasources:{datasource_count})"
    return f"{message} (datasources:-)"


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
                "host": record.get("host"),
                "port": record.get("port"),
                "service": "grafana",
                "detected": bool(record.get("is_grafana")),
                "auth_required": auth_required_value,
                "version": record.get("server_version"),
            },
            ensure_ascii=False,
        )
    return f"{_nxc_prefix(record)} [*] Grafana Service (auth required:{auth_required_text})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        payload = dict(record)
        payload.pop("effective_password", None)
        return json.dumps(payload, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 72)

    if status == "open_no_auth":
        return _with_optional_datasources(record, f"{prefix} [+] anonymous access")
    if status == "valid_credentials":
        user = str(record.get("effective_username") or "admin")
        source = str(record.get("credentials_source") or "")
        if source == "default":
            password_text = str(record.get("effective_password") or "")
            return _with_optional_datasources(record, f"{prefix} [+] {user}:{password_text}")
        return _with_optional_datasources(record, f"{prefix} [+] {user}")
    if status == "auth_required":
        if int(record.get("attempted_credentials") or 0) > 0:
            return f"{prefix} [-] authentication required (credentials invalid)"
        return f"{prefix} [-] authentication required"
    if status == "unknown_auth":
        line = f"{prefix} [!] auth status unknown"
        if err != "-":
            return f"{line} err={err}"
        return line
    line = f"{prefix} [!] connection failed"
    if err != "-":
        return f"{line} err={err}"
    return line


def _format_datasources_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if not bool(record.get("show_datasources")):
        return []
    datasources = record.get("datasources")
    if not isinstance(datasources, list) or not datasources:
        return []
    items: list[dict[str, str]] = []
    for item in datasources:
        if not isinstance(item, dict):
            continue
        items.append(
            {
                "name": str(item.get("name") or "-"),
                "type": str(item.get("type") or "-"),
                "url": str(item.get("url") or "-"),
                "access": str(item.get("access") or "-"),
            }
        )
    if not items:
        return []
    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "datasources_dump",
                    "service": "grafana",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "datasource_count": len(items),
                    "datasources": items,
                },
                ensure_ascii=False,
            )
        ]
    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Dump Datasources"]
    for item in items:
        lines.append(f"{prefix} name={item['name']} type={item['type']} url={item['url']} access={item['access']}")
    return lines


def _format_check_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    check_results = record.get("check_results")
    if not isinstance(check_results, list) or not check_results:
        return []

    if output_format == "json":
        lines: list[str] = []
        total = len(check_results)
        for i, res in enumerate(check_results, 1):
            payload = {
                "timestamp": record.get("timestamp"),
                "type": "ssrf_check",
                "service": "grafana",
                "host": record.get("host"),
                "port": record.get("port"),
                "index": i,
                "total": total,
                "target_url": res.get("target_url"),
                "probe_proxy_path": res.get("probe_proxy_path"),
                "create_ok": res.get("create_ok"),
                "create_status": res.get("create_status"),
                "create_error": res.get("create_error"),
                "probe_ok": res.get("probe_ok"),
                "probe_status": res.get("probe_status"),
                "probe_elapsed_ms": res.get("probe_elapsed_ms"),
                "probe_error": res.get("probe_error"),
                "probe_sample": res.get("probe_sample"),
                "cleanup_ok": res.get("cleanup_ok"),
                "cleanup_error": res.get("cleanup_error"),
            }
            lines.append(json.dumps(payload, ensure_ascii=False))
        return lines

    prefix = _nxc_prefix(record)
    lines: list[str] = []

    for i, res in enumerate(check_results, 1):
        url = str(res.get("target_url") or "-")
        lines.append(f"{prefix} [*] Check {i}/{len(check_results)} → {url}")

        if res.get("create_ok"):
            lines.append(f"{prefix} [+]   temporary datasource created")
        else:
            err = res.get("create_error") or f"status {res.get('create_status')}"
            lines.append(f"{prefix} [!]   create failed → {err}")
            continue
        proxy_path = str(res.get("probe_proxy_path") or "").strip()
        if proxy_path:
            lines.append(f"{prefix} [*]   proxy request: GET {proxy_path}")

        if res.get("probe_ok"):
            elapsed = res.get("probe_elapsed_ms")
            status = res.get("probe_status")
            sample = res.get("probe_sample") or ""
            elapsed_part = f" elapsed={elapsed}ms" if elapsed is not None else ""
            lines.append(f"{prefix} [+]   probe succeeded status={status}{elapsed_part}")
            if sample:
                lines.append(f"{prefix}       sample: {_safe_full_line(sample)}")
        else:
            err = res.get("probe_error") or "unknown error"
            elapsed = res.get("probe_elapsed_ms")
            status = res.get("probe_status")
            elapsed_part = f" elapsed={elapsed}ms" if elapsed is not None else ""
            status_part = f" status={status}" if status is not None else ""
            lines.append(f"{prefix} [!]   probe failed{status_part}{elapsed_part} → {err}")
            sample = res.get("probe_sample") or ""
            if sample:
                lines.append(f"{prefix}       sample: {_safe_full_line(sample)}")

        if res.get("cleanup_ok"):
            lines.append(f"{prefix} [+]   temporary datasource deleted")
        elif res.get("cleanup_ok") is False:
            err = res.get("cleanup_error") or "unknown error"
            lines.append(f"{prefix} [!]   cleanup failed → {err}")

    return lines


def _render_colored_grafana_line(console: Console, line: str) -> bool:
    if not line.startswith("GRAFANA"):
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
        tag = "GRAFANA"
        rest = left[len(tag) :] if left.startswith(tag) else left
        spans: list[tuple[int, int, str]] = []
        auth_true = "(auth required:True)"
        auth_false = "(auth required:False)"
        auth_unknown = "(auth required:unknown)"
        idx_true = right.find(auth_true)
        if idx_true >= 0:
            spans.append((idx_true, idx_true + len(auth_true), "bright_green"))
        idx_false = right.find(auth_false)
        if idx_false >= 0:
            spans.append((idx_false, idx_false + len(auth_false), "red"))
        idx_unknown = right.find(auth_unknown)
        if idx_unknown >= 0:
            spans.append((idx_unknown, idx_unknown + len(auth_unknown), "yellow"))
        ds_match = re.search(r"\(datasources:(\d+)(?: [^)]*)?\)", right)
        if ds_match:
            ds_value = ds_match.group(1).strip()
            if ds_value.isdigit() and int(ds_value) > 0:
                spans.append((ds_match.start(), ds_match.end(), "red"))
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


def audit_grafana_targets(
    hosts: list[str],
    port: int,
    timeout: float,
    retries: int,
    workers: int,
    username: str | None,
    password: str | None,
    defcreds: bool,
    check_urls: list[str] | None,
    show_datasources: bool,
    output_path: str | None,
    output_format: str,
    emit_line: Callable[[str], None] | None = None,
    logger: AttemptLogger | None = None,
    append_output: bool = False,
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
                    _audit_grafana_host,
                    host,
                    port,
                    timeout,
                    retries,
                    username,
                    password,
                    defcreds,
                    check_urls,
                ): host
                for host in hosts
            }
            for future in as_completed(future_map):
                record = future.result()
                record["show_datasources"] = show_datasources
                total += 1
                status = str(record.get("status") or "fail")
                if status == "open_no_auth":
                    open_no_auth += 1
                elif status == "valid_credentials":
                    valid += 1
                elif status == "auth_required":
                    auth_required += 1
                else:
                    failed += 1
                if bool(record.get("is_grafana")):
                    _emit_line(out_fh, emit_line, _format_detect_record(record, output_format))
                suppress_auth_required_status_line = (
                    output_format == "txt"
                    and bool(record.get("is_grafana"))
                    and status == "auth_required"
                    and int(record.get("attempted_credentials") or 0) <= 0
                )
                if not suppress_auth_required_status_line:
                    _emit_line(out_fh, emit_line, _format_record(record, output_format))
                if bool(record.get("is_grafana")):
                    for ds_line in _format_datasources_detail_records(record, output_format):
                        _emit_line(out_fh, emit_line, ds_line)
                    for check_line in _format_check_detail_records(record, output_format):
                        _emit_line(out_fh, emit_line, check_line)
                if logger is not None:
                    logger.log(
                        "grafana",
                        (str(record.get("host") or "-"), int(record.get("port") or port)),
                        phase="audit",
                        status=record.get("status"),
                        auth_required=record.get("auth_required"),
                        default_credentials=record.get("default_credentials"),
                        provided_credentials_ok=record.get("provided_credentials_ok"),
                        datasource_count=record.get("datasource_count"),
                        check_urls=record.get("check_urls"),
                        check_results=record.get("check_results"),
                        error=record.get("error"),
                    )
    finally:
        if out_fh is not None:
            out_fh.close()
    return total, open_no_auth, valid, auth_required, failed


def run_grafana_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
        return 2
    if args.username and args.password is None:
        console.error("--password is required when --username is set")
        return 2
    try:
        ports = collect_scan_ports(getattr(args, "ports", None))
    except ValueError as exc:
        console.error(f"failed to parse --port: {exc}")
        return 2
    if not ports:
        ports = [int(args.port)]

    check_urls = _normalize_check_urls(args.ssrf_target, args.ssrf_port, args.ssrf_path)

    if args.ssrf_target and not check_urls:
        console.error("No valid SSRF targets/ports after parsing")
        return 2

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
        console.error("grafana requires -t/--targets")
        return 2

    stream_to_stdout = not bool(args.output)

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith("GRAFANA") and all(token not in line for token in (" [*] ", " [+] ", " [-] ", " [!] ")):
            if console.render_tagged_payload_line(line, "GRAFANA", payload_color="orange"):
                return
            console.plain(line, color="white")
            return
        if _render_colored_grafana_line(console, line):
            return
        if args.debug:
            console.plain(line)

    if args.debug and stream_to_stdout and args.output_format == "txt":
        mode_parts: list[str] = []
        if args.defcreds:
            mode_parts.append("defcreds")
        if args.show_datasources:
            mode_parts.append("show-datasources")
        if check_urls:
            mode_parts.append(f"temp-check ({len(check_urls)} targets)")
        if args.password is not None:
            mode_parts.append("provided-creds")
        mode = ",".join(mode_parts) if mode_parts else "detect-only"
        console.info(
            f"grafana audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={mode} format=txt"
        )

    if args.debug and not stream_to_stdout:
        mode_parts = []
        if args.defcreds:
            mode_parts.append("defcreds")
        if args.show_datasources:
            mode_parts.append("show-datasources")
        if check_urls:
            mode_parts.append(f"temp-check ({len(check_urls)} targets)")
        if args.password is not None:
            mode_parts.append("provided-creds")
        mode = ",".join(mode_parts) if mode_parts else "detect-only"
        console.info(
            f"grafana audit started: hosts={len(hosts)} ports={len(ports)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} mode={mode} "
            f"format={args.output_format} output={args.output}"
        )

    total = 0
    open_no_auth = 0
    valid = 0
    auth_required = 0
    failed = 0
    try:
        for idx, audit_port in enumerate(ports):
            part_total, part_open, part_valid, part_auth, part_failed = audit_grafana_targets(
                hosts=hosts,
                port=audit_port,
                timeout=args.timeout,
                retries=args.retries,
                workers=args.workers,
                username=args.username,
                password=args.password,
                defcreds=args.defcreds,
                check_urls=check_urls,
                show_datasources=args.show_datasources,
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                logger=logger if args.debug else None,
                append_output=idx > 0,
            )
            total += part_total
            open_no_auth += part_open
            valid += part_valid
            auth_required += part_auth
            failed += part_failed
    except OSError as exc:
        console.error(f"failed to process grafana output: {exc}")
        return 2

    if stream_to_stdout:
        if (
            total > 0
            and open_no_auth == 0
            and valid == 0
            and auth_required == 0
            and failed == total
            and args.output_format == "txt"
        ):
            console.warn(
                "all grafana targets are unreachable; check host/port, network reachability, and service status"
            )

    if args.debug:
        console.info(
            f"grafana audit complete: total={total} no_auth={open_no_auth} valid={valid} "
            f"auth_required={auth_required} fail={failed}"
        )

    return 0
