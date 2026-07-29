"""grafana audit actions and compatibility helpers."""

from __future__ import annotations

import base64
import ipaddress
import json
import time
import urllib.error
import urllib.parse
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ...clients.http_api import HttpApiClient, HttpClientConfig, resolve_http_scheme
from ...console import Console
from ...rendering import CountColorRule, format_count_value, render_colored_marker_line, render_tagged_detail_line
from ...stage_runtime import (
    StageTelemetryBuilder,
    format_retry_decision,
    merge_stage_records,
)
from ...utils import (
    DEFAULT_MAX_NETWORK_HOSTS,
    is_signature_compat_typeerror,
    utc_now_iso,
)

_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_CONNECTION_REFUSED_PREFIX = "connection refused"
_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_GRAFANA_DEEP_STATUSES = {
    "open_no_auth",
    "invalid_credentials_anonymous",
    "valid_credentials",
    "weak_default_creds",
}


@dataclass
class GrafanaLifecycleState:
    auth_attempts: list[dict[str, Any]] = field(default_factory=list)
    auth_header: str | None = None
    credentials_source: str | None = None
    effective_username: str | None = None
    effective_password: str | None = None
    deep_record: dict[str, Any] | None = None


def _clip(text: str, width: int = 64) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _friendly_error_text(value: str) -> str:
    from ...utils import friendly_error_text

    return friendly_error_text(value)


def _friendly_error_from_exception(exc: BaseException) -> str:
    from ...utils import friendly_error_from_exception

    return friendly_error_from_exception(exc)


def _is_connection_timeout_fail_record(record: dict[str, Any]) -> bool:
    if str(record.get("status") or "") != "fail":
        return False
    error_text = str(record.get("error") or "").strip().lower()
    return bool(error_text) and (
        error_text.startswith(_CONNECTION_TIMEOUT_PREFIX) or error_text.startswith(_CONNECTION_REFUSED_PREFIX)
    )


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
    scheme = resolve_http_scheme(host, port, timeout, probe_path="/api/health")
    url = f"{scheme}://{host}:{port}{path}"
    req_headers = {"User-Agent": "RedPosture/1.0"}
    if headers:
        req_headers.update(headers)
    client = HttpApiClient(HttpClientConfig(timeout=timeout, response_size_cap=10 * 1024 * 1024, insecure=True))
    response = client.request(method, url, headers=req_headers, body=data, timeout=timeout)
    if response.error:
        raise urllib.error.URLError(response.error)
    return int(response.status), response.text, response.headers


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


def _verify_apitoken(host: str, port: int, timeout: float, apitoken: str) -> tuple[bool, str | None]:
    """E2E-batch fix: previously the grafana module had no way to accept an
    API key / service-account token; users could only try Basic auth. This
    helper mirrors `_verify_credentials` for `Authorization: Bearer <token>`
    so `--apitoken glsa-...` reaches the same success/failure classification
    as user/pass, and downstream fields (provided_credentials_ok, effective_*)
    are populated uniformly."""
    status, _body, _headers = _http_request(
        host,
        port,
        "/api/user",
        timeout,
        headers={"Authorization": f"Bearer {apitoken}"},
    )
    if status == 200:
        return True, None
    if status in {401, 403}:
        return False, "invalid api token"
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


def _expand_ssrf_cidr_targets(token: str, max_hosts: int = DEFAULT_MAX_NETWORK_HOSTS) -> list[str] | None:
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

            host = parsed.hostname or ""
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

    temp_name = f"redposture-egress-{uuid.uuid4().hex}"
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
    if datasource_id is None and not datasource_uid:
        result["create_error"] = "create succeeded but datasource id/uid is missing in response"
        return result

    result["create_ok"] = True

    probe_headers: dict[str, str] = {}
    if auth_header:
        probe_headers["Authorization"] = auth_header
    probe_started = time.monotonic()
    try:
        # Grafana 13 removed the legacy numeric datasource proxy route and
        # returns a local 404 before contacting the configured upstream. The
        # UID route is supported by current Grafana releases and keeps the
        # probe on the real server-side datasource path. Retain the numeric
        # fallback for older responses that do not include a UID.
        if datasource_uid:
            encoded_uid = urllib.parse.quote(datasource_uid, safe="")
            proxy_path = f"/api/datasources/proxy/uid/{encoded_uid}{upstream_path}"
        else:
            assert datasource_id is not None
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
        defaults = (
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "grafana"),
            ("admin", "changeme"),
            ("grafana", "grafana"),
            ("grafana", "password"),
            ("root", "root"),
            ("user", "user"),
            ("root", "password"),
            ("user", "password"),
        )
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
    apitoken: str | None = None,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    provided_credentials = password is not None or bool(apitoken)
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
                    "attempted_credentials": [],
                    "attempted_credentials_count": 0,
                    "credential_attempts": [],
                    "credentials_source": None,
                    "effective_username": None,
                    "effective_password": None,
                    "datasource_count": None,
                    "datasources": None,
                    "auth_attempts": [],
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
            candidates_checked = False
            auth_attempts: list[dict[str, Any]] = []

            def _try_candidates(
                candidates_local: list[tuple[str, str, str]] = candidates,
                errors_local: list[str] = errors,
                auth_attempts_local: list[dict[str, Any]] = auth_attempts,
            ) -> None:
                nonlocal candidates_checked
                nonlocal attempted_credentials, credentials_source, effective_username, effective_password
                nonlocal default_credentials, provided_credentials_ok, auth_header
                if candidates_checked or (not defcreds and auth_header is not None):
                    return
                candidates_checked = True
                for cand_user, cand_pass, source in candidates_local:
                    attempted_credentials += 1
                    try:
                        ok, cred_error = _verify_credentials(host, port, timeout, cand_user, cand_pass)
                    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
                        if not defcreds:
                            raise
                        ok = False
                        cred_error = _friendly_error_from_exception(exc)
                    auth_attempts_local.append(
                        {
                            "username": cand_user,
                            "password": cand_pass,
                            "source": source,
                            "ok": bool(ok),
                            "error": str(cred_error or ""),
                        }
                    )
                    if ok:
                        if auth_header is None:
                            credentials_source = source
                            effective_username = cand_user
                            effective_password = cand_pass
                            auth_header = _auth_header(cand_user, cand_pass)
                        if source == "default":
                            default_credentials = True
                        if source == "provided":
                            provided_credentials_ok = True
                    if cred_error:
                        errors_local.append(cred_error)
                    if ok and not defcreds:
                        break

            if provided_credentials:
                # Reset to False if not already verified elsewhere (e.g. by the
                # apitoken block below). E2E revealed this line used to
                # unconditionally overwrite `True` back to `False`, causing a
                # successful token check to silently downgrade to
                # `invalid_credentials_anonymous`.
                if provided_credentials_ok is None:
                    provided_credentials_ok = False

            # E2E-batch fix: try `--apitoken` BEFORE the username/password
            # candidate loop. Grafana treats API keys and service-account
            # tokens as first-class credentials, so downstream fields must
            # reflect a successful token check just like a successful basic
            # auth check would.
            if apitoken:
                try:
                    token_ok, token_error = _verify_apitoken(host, port, timeout, apitoken)
                except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
                    if not defcreds:
                        raise
                    token_ok = False
                    token_error = _friendly_error_from_exception(exc)
                attempted_credentials += 1
                auth_attempts.append(
                    {
                        "username": None,
                        "password": None,
                        "source": "apitoken",
                        "ok": bool(token_ok),
                        "error": str(token_error or ""),
                    }
                )
                if token_ok:
                    provided_credentials_ok = True
                    credentials_source = "apitoken"
                    effective_username = None
                    auth_header = f"Bearer {apitoken}"
                elif token_error:
                    errors.append(token_error)

            if candidates and (auth_required is True or auth_required is None or provided_credentials or defcreds):
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

            # E2E-batch fix: recognize a successful token check as
            # valid_credentials too. Previously only `effective_username` was
            # inspected, so `--apitoken glsa-...` (where effective_username
            # stays None) fell through to invalid_credentials_anonymous even
            # when Grafana had returned 200 to the Bearer probe.
            if effective_username is not None or (provided_credentials_ok is True and credentials_source == "apitoken"):
                status = "weak_default_creds" if credentials_source == "default" else "valid_credentials"
            elif auth_required is False and attempted_credentials > 0 and (provided_credentials or defcreds):
                status = "invalid_credentials_anonymous"
            elif auth_required is False:
                status = "open_no_auth"
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
                # E2E-batch fix: `attempted_credentials` used to be exposed as an
                # int counter here, breaking every downstream JSON/render helper
                # that walks `attempted_credentials` as `list[dict]` (mongo/kafka/
                # postgres shape). Keep the auth-attempt shape uniform with the
                # rest of the modules and expose the count under a distinct key.
                "attempted_credentials": auth_attempts,
                "attempted_credentials_count": attempted_credentials,
                "credential_attempts": auth_attempts,
                "credentials_source": credentials_source,
                "effective_username": effective_username,
                "effective_password": effective_password,
                "datasource_count": datasource_count,
                "datasources": datasources,
                "auth_attempts": auth_attempts,
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
        "attempted_credentials": [],
        "attempted_credentials_count": 0,
        "credential_attempts": [],
        "credentials_source": None,
        "effective_username": None,
        "effective_password": None,
        "datasource_count": None,
        "datasources": None,
        "auth_attempts": [],
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
    return f"{message} (datasources:{format_count_value(record.get('datasource_count'))})"


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
        payload.pop("auth_attempts", None)
        return json.dumps(payload, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 72)

    if status == "open_no_auth":
        return ""
    attempts_raw = record.get("auth_attempts")
    has_attempt_history = isinstance(attempts_raw, list) and bool(attempts_raw)

    if status == "invalid_credentials_anonymous":
        if has_attempt_history:
            return ""
        return _with_optional_datasources(record, f"{prefix} [-] credentials invalid (anonymous access)")
    if status in {"valid_credentials", "weak_default_creds"}:
        if has_attempt_history:
            return ""
        user = str(record.get("effective_username") or "admin")
        source = str(record.get("credentials_source") or "")
        if source == "default":
            password_text = str(record.get("effective_password") or "")
            return _with_optional_datasources(record, f"{prefix} [+] {user}:{password_text}")
        return _with_optional_datasources(record, f"{prefix} [+] {user}")
    if status == "auth_required":
        if has_attempt_history:
            return ""
        # E2E fix: `attempted_credentials` is now the list of attempt dicts.
        # Read the count from `attempted_credentials_count` first, but keep a
        # `len()`-fallback so we render correctly against any older cached
        # records that still store the int in `attempted_credentials`.
        n_attempts_raw = record.get("attempted_credentials_count")
        if n_attempts_raw is None:
            legacy = record.get("attempted_credentials")
            if isinstance(legacy, list):
                n_attempts_raw = len(legacy)
            else:
                n_attempts_raw = legacy
        if int(n_attempts_raw or 0) > 0:
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


def _format_auth_attempt_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []

    attempts_raw = record.get("auth_attempts")
    if not isinstance(attempts_raw, list) or not attempts_raw:
        return []

    attempts: list[dict[str, Any]] = [item for item in attempts_raw if isinstance(item, dict)]
    if not attempts:
        return []

    prefix = _nxc_prefix(record)
    lines: list[str] = []
    effective_username = record.get("effective_username")
    effective_password = record.get("effective_password")
    credentials_source = str(record.get("credentials_source") or "")
    for attempt in attempts:
        raw_username = attempt.get("username")
        raw_password = attempt.get("password")
        source = str(attempt.get("source") or "provided")
        token_attempt = raw_username is None and raw_password is None
        if token_attempt:
            credential_text = f"API token (source:{source})"
        else:
            username = str(raw_username or "admin")
            password = "" if raw_password is None else str(raw_password)
            password_text = "<empty>" if password == "" else password
            credential_text = f"{username}:{password_text}"
        ok = bool(attempt.get("ok"))
        if ok:
            if token_attempt:
                selected = effective_username is None and bool(credentials_source) and source == credentials_source
            else:
                selected = (
                    effective_username is not None
                    and str(raw_username or "admin") == str(effective_username)
                    and raw_password == effective_password
                    and (not credentials_source or source == credentials_source)
                )
            line = f"{prefix} [+] {credential_text}"
            lines.append(_with_optional_datasources(record, line) if selected else line)
            continue
        lines.append(f"{prefix} [-] {credential_text}")
    return lines


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
    lines = []

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
    if render_colored_marker_line(
        console,
        line,
        tag="GRAFANA",
        counts=(CountColorRule("datasources", "red"),),
    ):
        return True
    if line.startswith("GRAFANA") and "\t" in line:
        return render_tagged_detail_line(console, line, tag="GRAFANA", default_color="orange")
    return False


def _call_audit_grafana_host_with_stage_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    username: str | None,
    password: str | None,
    defcreds: bool,
    check_urls: list[str] | None,
    *,
    show_datasources: bool,
    apitoken: str | None = None,
    run_deep_checks: bool,
    debug: bool,
    debug_emit: Callable[[str], None] | None,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        record = _audit_grafana_host(
            host,
            port,
            timeout,
            retries,
            username,
            password,
            defcreds,
            check_urls if run_deep_checks else None,
            apitoken=apitoken,
        )
    except TypeError as exc:
        # E2E-batch fix: tests monkeypatch `_audit_grafana_host` with fakes
        # that predate the `apitoken` kwarg. Fall back to the legacy signature
        # when only the newly-added keyword is missing.
        if not is_signature_compat_typeerror(exc, expected_keywords={"apitoken"}):
            raise
        record = _audit_grafana_host(
            host,
            port,
            timeout,
            retries,
            username,
            password,
            defcreds,
            check_urls if run_deep_checks else None,
        )

    result: dict[str, Any] = dict(record)
    result["show_datasources"] = bool(show_datasources and run_deep_checks)

    attempts = max(1, retries + 1)
    status = str(result.get("status") or "fail")
    is_grafana = bool(result.get("is_grafana"))
    elapsed_ms = int((time.monotonic() - started) * 1000)
    telemetry = StageTelemetryBuilder(host=host, port=port, attempts=attempts, debug=debug, debug_emit=debug_emit)
    if attempts > 1 and status == "fail":
        telemetry.debug(format_retry_decision(_STAGE_DETECT_PROTOCOL, 1, attempts, _retry_delay(0), "error"))

    detect_result = "ok" if is_grafana else ("error" if status == "fail" else "skip")
    detect_error = str(result.get("error") or "") if detect_result == "error" else None
    telemetry.stage(_STAGE_DETECT_PROTOCOL, detect_result, detect_error, 0)

    auth_result = (
        "ok"
        if is_grafana and status in _GRAFANA_DEEP_STATUSES.union({"auth_required", "unknown_auth"})
        else detect_result
    )
    telemetry.stage(_STAGE_AUTH_INFERENCE, auth_result, detect_error if auth_result == "error" else None, 0)

    if run_deep_checks and status in _GRAFANA_DEEP_STATUSES:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "ok", None, 0)
        data_result = "error" if status == "fail" and result.get("error") else "ok"
        telemetry.stage(
            _STAGE_DATA,
            data_result,
            str(result.get("error") or "") if data_result == "error" else None,
            elapsed_ms,
        )
    else:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "skip", "deep checks disabled", 0)
        telemetry.stage(_STAGE_DATA, "skip", "deep checks disabled", 0)

    stage_durations_ms = {
        str(item.get("stage_name") or ""): int(item.get("duration_ms") or 0) for item in telemetry.stages
    }
    telemetry.debug(
        f"stage_timing_summary status={status} attempts=1/{attempts} "
        f"detect_ms={stage_durations_ms.get(_STAGE_DETECT_PROTOCOL, 0)} "
        f"auth_ms={stage_durations_ms.get(_STAGE_AUTH_INFERENCE, 0)} "
        f"capabilities_ms={stage_durations_ms.get(_STAGE_ACCESS_CAPABILITIES, 0)} "
        f"data_ms={stage_durations_ms.get(_STAGE_DATA, 0)} total_ms={elapsed_ms}"
    )
    return telemetry.attach(result, status=status, total_ms=elapsed_ms)


def _merge_stage2_record(detect_record: dict[str, Any], deep_record: dict[str, Any]) -> dict[str, Any]:
    return merge_stage_records(detect_record, deep_record)


def detect_grafana(ctx: Any, options: dict[str, Any]) -> dict[str, Any]:
    attempts = max(1, int(getattr(ctx.args, "retries", 0) or 0) + 1)
    last_error: str | None = None
    for attempt in range(attempts):
        started = time.monotonic()
        try:
            health_status, health_body, _health_headers = _http_request(
                str(ctx.host), int(ctx.port), "/api/health", float(getattr(ctx.args, "timeout", 5.0))
            )
            is_grafana, version = _looks_like_grafana_health(health_status, health_body)
            if not is_grafana or health_status in {401, 403}:
                login_status, login_body, login_headers = _http_request(
                    str(ctx.host), int(ctx.port), "/login", float(getattr(ctx.args, "timeout", 5.0))
                )
                is_grafana = is_grafana or _looks_like_grafana_login(login_status, login_body, login_headers)
            if not is_grafana:
                return {
                    "timestamp": utc_now_iso(),
                    "host": str(ctx.host),
                    "port": int(ctx.port),
                    "is_grafana": False,
                    "status": "not_grafana",
                    "auth_required": None,
                    "server_version": version,
                    "provided_credentials": False,
                    "attempted_credentials": [],
                    "attempted_credentials_count": 0,
                    "credential_attempts": [],
                    "auth_attempts": [],
                    "show_datasources": bool(options["show_datasources"]),
                    "check_urls": list(options["check_urls"]),
                    "check_results": None,
                    "error": "service is not grafana",
                }
            return {
                "timestamp": utc_now_iso(),
                "host": str(ctx.host),
                "port": int(ctx.port),
                "is_grafana": True,
                "status": "open_no_auth" if health_status == 200 else "auth_required",
                "auth_required": False if health_status == 200 else True if health_status in {401, 403} else None,
                "server_version": version,
                "provided_credentials": False,
                "provided_username": None,
                "provided_credentials_ok": None,
                "default_credentials": False,
                "defcreds_enabled": False,
                "attempted_credentials": [],
                "attempted_credentials_count": 0,
                "credential_attempts": [],
                "credentials_source": None,
                "effective_username": None,
                "effective_password": None,
                "datasource_count": None,
                "datasources": None,
                "auth_attempts": [],
                "show_datasources": bool(options["show_datasources"]),
                "check_urls": list(options["check_urls"]),
                "check_results": None,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": None,
            }
        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
            last_error = _friendly_error_from_exception(exc)
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))
    return {
        "timestamp": utc_now_iso(),
        "host": str(ctx.host),
        "port": int(ctx.port),
        "is_grafana": False,
        "status": "fail",
        "auth_required": None,
        "server_version": None,
        "provided_credentials": False,
        "attempted_credentials": [],
        "attempted_credentials_count": 0,
        "credential_attempts": [],
        "auth_attempts": [],
        "show_datasources": bool(options["show_datasources"]),
        "check_urls": list(options["check_urls"]),
        "check_results": None,
        "error": last_error or "connection failed",
    }


def authenticate_grafana(ctx: Any, detect_record: Any, _options: dict[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, GrafanaLifecycleState):
        raise TypeError("grafana lifecycle state is unavailable")
    record = dict(detect_record.to_dict() if hasattr(detect_record, "to_dict") else detect_record)
    credential = ctx.credential
    token = str(credential.token or "").strip() or None
    username = credential.username
    password = credential.password
    source = str(credential.source or "provided")
    if source == "anonymous" and (token is not None or username is not None or password is not None):
        source = "provided"
    if token is None and username is None and password is None:
        return record
    continue_after_error = bool(getattr(ctx.args, "defcreds", False))
    if token is not None:
        try:
            ok, error = _verify_apitoken(
                str(ctx.host),
                int(ctx.port),
                float(getattr(ctx.args, "timeout", 5.0)),
                token,
            )
        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
            if not continue_after_error:
                raise
            ok = False
            error = _friendly_error_from_exception(exc)
        attempt = {"username": None, "password": None, "source": source, "ok": bool(ok), "error": error or ""}
        auth_header = f"Bearer {token}"
    else:
        effective_user = (username or "admin").strip() or "admin"
        effective_password = password or ""
        try:
            ok, error = _verify_credentials(
                str(ctx.host),
                int(ctx.port),
                float(getattr(ctx.args, "timeout", 5.0)),
                effective_user,
                effective_password,
            )
        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
            if not continue_after_error:
                raise
            ok = False
            error = _friendly_error_from_exception(exc)
        attempt = {
            "username": effective_user,
            "password": effective_password,
            "source": source,
            "ok": bool(ok),
            "error": error or "",
        }
        auth_header = _auth_header(effective_user, effective_password)
        username, password = effective_user, effective_password
    state.auth_attempts.append(attempt)
    if ok and state.auth_header is None:
        state.auth_header = auth_header
        state.credentials_source = source
        state.effective_username = username
        state.effective_password = password
    anonymous_open = record.get("auth_required") is False
    status = (
        "weak_default_creds"
        if ok and source == "default"
        else "valid_credentials"
        if ok
        else "invalid_credentials_anonymous"
        if anonymous_open
        else "auth_required"
    )
    record.update(
        {
            "timestamp": utc_now_iso(),
            "status": status,
            "provided_credentials": source != "default",
            "provided_username": username,
            "provided_credentials_ok": bool(ok) if source != "default" else None,
            "default_credentials": bool(ok and source == "default"),
            "defcreds_enabled": source == "default",
            "attempted_credentials": list(state.auth_attempts),
            "attempted_credentials_count": len(state.auth_attempts),
            "credential_attempts": list(state.auth_attempts),
            "auth_attempts": list(state.auth_attempts),
            "credentials_source": source if ok else None,
            "effective_username": username if ok else None,
            "effective_password": password if ok else None,
            "error": None if ok or anonymous_open else error,
        }
    )
    return record


def collect_grafana_data(ctx: Any, source_record: Any, options: dict[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, GrafanaLifecycleState):
        raise TypeError("grafana lifecycle state is unavailable")
    if state.deep_record is not None:
        return state.deep_record
    record = dict(source_record.to_dict() if hasattr(source_record, "to_dict") else source_record)
    runtime_attempts = record.get("attempted_credentials")

    def _attempt_key(attempt: dict[str, Any]) -> tuple[str | None, str | None, str]:
        raw_username = attempt.get("username")
        raw_password = attempt.get("password")
        source = str(attempt.get("source") or "provided")
        if raw_username is None and raw_password is None:
            return None, None, source
        return (
            str(raw_username or "admin"),
            "" if raw_password is None else str(raw_password),
            source,
        )

    merged_attempts = list(state.auth_attempts)
    if isinstance(runtime_attempts, list):
        actual_by_key = {_attempt_key(attempt): attempt for attempt in state.auth_attempts}
        merged_attempts = []
        for runtime_attempt in runtime_attempts:
            if not isinstance(runtime_attempt, dict):
                continue
            key = _attempt_key(runtime_attempt)
            actual_attempt = actual_by_key.get(key)
            if actual_attempt is not None:
                merged_attempts.append(dict(actual_attempt))
                continue
            merged_attempts.append(
                {
                    "username": key[0],
                    "password": key[1],
                    "source": key[2],
                    "ok": str(runtime_attempt.get("status") or "") in {"valid_credentials", "weak_default_creds"},
                    "error": str(runtime_attempt.get("error") or ""),
                }
            )
    record["attempted_credentials"] = merged_attempts
    record["attempted_credentials_count"] = len(merged_attempts)
    record["credential_attempts"] = merged_attempts
    record["auth_attempts"] = merged_attempts
    record["defcreds_enabled"] = bool(record.get("defcreds_enabled")) or any(
        str(attempt.get("source") or "") == "default" for attempt in merged_attempts
    )
    timeout = float(getattr(ctx.args, "timeout", 5.0))
    datasources, datasource_error, datasource_status = _fetch_datasources(
        str(ctx.host),
        int(ctx.port),
        timeout,
        auth_header=state.auth_header,
    )
    if datasource_status in {401, 403} and state.auth_header is None:
        record["auth_required"] = True
        record["status"] = "auth_required"
    record["datasources"] = datasources
    record["datasource_count"] = len(datasources) if isinstance(datasources, list) else None
    record["show_datasources"] = bool(options["show_datasources"])
    record["check_results"] = [
        _run_temp_prometheus_check(str(ctx.host), int(ctx.port), timeout, state.auth_header, target_url)
        for target_url in options["check_urls"]
    ]
    record["check_urls"] = list(options["check_urls"])
    if datasource_error:
        record["error"] = datasource_error
    state.deep_record = record
    return record


# Typed runner boundary -----------------------------------------------------
host_stage = _call_audit_grafana_host_with_stage_debug
