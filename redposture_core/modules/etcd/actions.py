"""etcd audit stage."""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
from collections.abc import Callable
from typing import Any

from ...clients import transport
from ...clients.http_api import (
    HttpApiClient,
    HttpClientConfig,
    build_http_target_url,
    current_http_target_binding,
    http_target_context,
    resolve_http_scheme,
)
from ...console import Console
from ...rendering import CountColorRule, format_count_value, render_colored_marker_line, render_tagged_detail_line
from ...show_limits import (
    limit_metadata,
    limit_sequence,
)
from ...stage_runtime import (
    StageTelemetryBuilder,
    format_retry_decision,
    merge_stage_records,
)
from ...utils import is_signature_compat_typeerror, utc_now_iso

# Connection-error classification + framed reads are shared via the transport layer.
_is_connection_refused_error = transport.is_connection_refused
_is_connection_refused_fail_record = transport.is_connection_refused_fail_record
_is_connection_timeout_error = transport.is_connection_timeout

_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_ETCD_DEEP_STATUSES = {"open_no_auth", "weak_default_creds", "valid_credentials"}
_ETCD_V3_ALL_RANGE_KEY_B64 = "AA=="
_ETCD_V3_PREFIXES: tuple[str, ...] = ("/v3", "/v3beta", "/v3alpha")
_ETCD_V3_PREFIX_CACHE: dict[tuple[str, int, str | None, str], str] = {}
_ETCD_V3_PREFIX_CACHE_LOCK = threading.Lock()
_ETCD_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "changeme"),
    ("admin", "etcd"),
    ("admin", "password"),
    ("etcd", "etcd"),
    ("etcd", "password"),
    ("root", "admin"),
    ("root", "etcd"),
    ("root", "password"),
    ("root", "root"),
    ("root", "rootpass"),
    ("service", "service"),
    ("user", "password"),
    ("user", "user"),
)


def _build_etcd_credential_candidates(
    username: str | None,
    password: str | None,
    defcreds: bool,
    credential_candidates: list[dict[str, Any]] | None = None,
) -> list[tuple[str, str, str]]:
    """Normalize one source-aware etcd credential batch in stable order."""

    candidates: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(user: str, secret: str, source: str) -> None:
        pair = (user, secret)
        if pair in seen:
            return
        seen.add(pair)
        candidates.append((user, secret, source))

    if credential_candidates is not None:
        for candidate in credential_candidates:
            raw_username = candidate.get("username")
            raw_password = candidate.get("password")
            if raw_username is None or raw_password is None:
                continue
            source = str(candidate.get("source") or "provided")
            _add(str(raw_username), str(raw_password), source)
        return candidates

    if username is not None and password is not None:
        _add(str(username), str(password), "provided")
    if defcreds:
        for default_user, default_secret in _ETCD_DEFAULT_CREDS:
            _add(default_user, default_secret, "default")
    return candidates


def _etcd_v3_authenticate(
    host: str,
    port: int,
    timeout: float,
    username: str,
    password: str,
) -> tuple[str | None, str | None]:
    """Ask /v3/auth/authenticate for a token; return (token, error)."""
    status, body = _http_json_request(
        host,
        port,
        "POST",
        "/v3/auth/authenticate",
        timeout,
        payload={"name": username, "password": password},
    )
    if status == 200:
        parsed = _load_json(body)
        if isinstance(parsed, dict):
            token = parsed.get("token")
            if isinstance(token, str) and token:
                return token, None
        return None, "unexpected authenticate response"
    if status in (401, 403):
        return None, "invalid credentials"
    return None, f"authenticate returned status {status}"


def _etcd_v2_authenticate(
    host: str,
    port: int,
    timeout: float,
    username: str,
    password: str,
) -> tuple[bool, str | None]:
    status, body = _http_json_request(
        host,
        port,
        "GET",
        "/v2/keys?recursive=true",
        timeout,
        basic_auth=(username, password),
    )
    if status == 200 and _count_v2_keys(body) is not None:
        return True, None
    if status in {401, 403} or _body_indicates_auth_required(body):
        return False, "invalid credentials"
    return False, f"v2 key probe returned status {status}"


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


def _is_suppressed_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail"


def _http_json_request(
    host: str,
    port: int,
    method: str,
    path: str,
    timeout: float,
    *,
    payload: dict[str, Any] | None = None,
    auth_token: str | None = None,
    basic_auth: tuple[str, str] | None = None,
) -> tuple[int, str]:
    scheme = resolve_http_scheme(host, port, timeout, probe_path="/version")
    body_bytes: bytes | None = None
    headers = {"User-Agent": "RedPosture/1.0"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if auth_token:
        # etcd gateway accepts the raw token in Authorization; also send the
        # grpc-metadata alias which upstream tooling uses.
        headers["Authorization"] = auth_token
        headers["Grpc-Metadata-Authorization"] = auth_token
    elif basic_auth is not None:
        user, secret = basic_auth
        encoded = base64.b64encode(f"{user}:{secret}".encode()).decode("ascii")
        headers["Authorization"] = f"Basic {encoded}"
    client = HttpApiClient(HttpClientConfig(timeout=timeout, response_size_cap=10 * 1024 * 1024, insecure=True))

    requested_path = str(path or "/")
    candidates = [requested_path]
    if requested_path.startswith("/v3/"):
        binding = current_http_target_binding()
        key = (str(host), int(port), binding.scheme, binding.base_path)
        with _ETCD_V3_PREFIX_CACHE_LOCK:
            cached_prefix = _ETCD_V3_PREFIX_CACHE.get(key)
        suffix = requested_path[len("/v3") :]
        prefixes = ([cached_prefix] if cached_prefix else []) + list(_ETCD_V3_PREFIXES)
        candidates = []
        for prefix in prefixes:
            if prefix and f"{prefix}{suffix}" not in candidates:
                candidates.append(f"{prefix}{suffix}")

    last_status = 0
    last_text = ""
    for index, candidate_path in enumerate(candidates):
        url = build_http_target_url(host, port, candidate_path, default_scheme=scheme)
        response = client.request(method, url, headers=headers, body=body_bytes, timeout=timeout)
        if response.error:
            raise urllib.error.URLError(response.error)
        last_status, last_text = int(response.status), response.text
        if not requested_path.startswith("/v3/") or last_status not in {404, 501}:
            if requested_path.startswith("/v3/"):
                selected_prefix = candidate_path[: -len(requested_path[len("/v3") :])]
                with _ETCD_V3_PREFIX_CACHE_LOCK:
                    _ETCD_V3_PREFIX_CACHE[key] = selected_prefix
            return last_status, last_text
        if index == len(candidates) - 1:
            break
    return last_status, last_text


def _load_json(body: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _body_indicates_auth_required(body: str) -> bool:
    text = (body or "").lower()
    needles = (
        "authentication required",
        "requires user authentication",
        "permission denied",
        "invalid auth token",
        "invalid authentication",
        "etcdserver: user name is empty",
        "etcdserver: authentication failed",
        "unauthenticated",
    )
    return any(needle in text for needle in needles)


def _major_version(value: str | None) -> int | None:
    raw = (value or "").strip()
    if not raw:
        return None
    part = raw.split(".", 1)[0]
    if not part.isdigit():
        return None
    return int(part)


def _count_v2_nodes(node: Any) -> int:
    if not isinstance(node, dict):
        return 0
    if bool(node.get("dir")):
        children = node.get("nodes")
        if not isinstance(children, list):
            return 0
        return sum(_count_v2_nodes(item) for item in children)
    if "key" in node:
        return 1
    return 0


def _count_v2_keys(body: str) -> int | None:
    payload = _load_json(body)
    if payload is None:
        return None
    node = payload.get("node")
    return _count_v2_nodes(node)


def _looks_like_v2_keys_response(body: str) -> bool:
    payload = _load_json(body)
    if payload is None:
        return False
    return isinstance(payload.get("action"), str) and isinstance(payload.get("node"), dict)


def _parse_v3_key_count(body: str) -> tuple[int | None, str | None]:
    payload = _load_json(body)
    if payload is None:
        return None, "count response returned invalid JSON"
    if "count" not in payload:
        # protobuf JSON omits scalar zero-values, so a successful count_only
        # response with no count field represents an empty keyspace.
        return 0, None
    raw_count = payload.get("count")
    if isinstance(raw_count, int) and not isinstance(raw_count, bool) and raw_count >= 0:
        return raw_count, None
    if isinstance(raw_count, str) and raw_count.isdigit():
        return int(raw_count), None
    return None, f"count response returned invalid count: {raw_count!r}"


def _count_v3_keys(body: str) -> int | None:
    count, _error = _parse_v3_key_count(body)
    return count


def _join_api_versions(v2_supported: bool, v3_supported: bool) -> str:
    versions: list[str] = []
    if v2_supported:
        versions.append("v2")
    if v3_supported:
        versions.append("v3")
    if not versions:
        return "-"
    return ",".join(versions)


def _format_etcd_text(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("\n", "\\n")


def _normalize_etcd_key(value: str | None) -> str | None:
    raw = (value or "").strip()
    if not raw:
        return None
    if raw.startswith("/"):
        return raw
    return f"/{raw}"


def _etcd_kv_entry(key: str, value: str | None = None, *, error: str | None = None) -> dict[str, str | None]:
    return {"key": str(key), "value": value, "error": error}


def _etcd_kv_entry_text(entry: Any) -> str:
    if isinstance(entry, dict):
        key = str(entry.get("key") or "")
        error = entry.get("error")
        if error:
            return f"{key}:<{_format_etcd_text(error)}>"
        return f"{key}:{_format_etcd_text(entry.get('value'))}"
    return str(entry)


def _key_name_from_entry(entry: Any) -> str:
    if isinstance(entry, dict):
        return str(entry.get("key") or "").strip()
    key, _sep, _value = str(entry).partition(":")
    return key.strip()


def _b64_encode_text(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _b64_decode_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    padded = value + ("=" * (-len(value) % 4))
    try:
        raw = base64.b64decode(padded, validate=False)
    except Exception:
        return ""
    return raw.decode("utf-8", errors="replace")


def _next_key_b64(key_b64: str) -> str:
    """Return the base64 of the key immediately after ``key_b64``.

    etcd range pagination continues from ``last_key + \\x00`` (the smallest key strictly
    greater than the last one returned). Works on the raw key bytes so binary keys page
    correctly.
    """
    padded = key_b64 + ("=" * (-len(key_b64) % 4))
    try:
        raw = base64.b64decode(padded, validate=False)
    except Exception:
        raw = b""
    return base64.b64encode(raw + b"\x00").decode("ascii")


def _collect_v2_pairs(node: Any, sink: list[tuple[str, str]]) -> None:
    if not isinstance(node, dict):
        return
    if bool(node.get("dir")):
        children = node.get("nodes")
        if isinstance(children, list):
            for child in children:
                _collect_v2_pairs(child, sink)
        return

    key = str(node.get("key") or "").strip()
    if not key:
        return
    if bool(node.get("dir")):
        sink.append((key, "<dir>"))
        return

    value = _format_etcd_text(node.get("value"))
    sink.append((key, value))


def _dump_v2_all_from_body(body: str) -> list[dict[str, str | None]] | None:
    payload = _load_json(body)
    if payload is None:
        return None
    node = payload.get("node")
    pairs: list[tuple[str, str]] = []
    _collect_v2_pairs(node, pairs)
    pairs.sort(key=lambda item: item[0])
    return [_etcd_kv_entry(key, value) for key, value in pairs]


def _dump_v2_key(
    host: str,
    port: int,
    key: str,
    timeout: float,
    *,
    basic_auth: tuple[str, str] | None = None,
) -> tuple[dict[str, str | None] | None, str | None]:
    if basic_auth is None:
        status, body = _http_json_request(host, port, "GET", f"/v2/keys{key}", timeout)
    else:
        status, body = _http_json_request(
            host,
            port,
            "GET",
            f"/v2/keys{key}",
            timeout,
            basic_auth=basic_auth,
        )
    if status == 404:
        return _etcd_kv_entry(key, "<not found>"), None
    if status != 200:
        return None, f"/v2/keys{key} returned status {status}"

    payload = _load_json(body)
    if payload is None:
        return None, f"/v2/keys{key} returned invalid JSON"
    node = payload.get("node")
    if not isinstance(node, dict):
        return None, f"/v2/keys{key} returned invalid node"
    if bool(node.get("dir")):
        return _etcd_kv_entry(key, "<dir>"), None
    resolved_key = str(node.get("key") or key).strip() or key
    return _etcd_kv_entry(resolved_key, _format_etcd_text(node.get("value"))), None


def _dump_v3_all(
    host: str,
    port: int,
    timeout: float,
    *,
    limit: int | None = None,
    auth_token: str | None = None,
) -> tuple[list[dict[str, str | None]] | None, str | None]:
    request_payload: dict[str, Any] = {"key": _ETCD_V3_ALL_RANGE_KEY_B64, "range_end": _ETCD_V3_ALL_RANGE_KEY_B64}
    if limit is not None:
        request_payload["limit"] = limit
    if auth_token is None:
        status, body = _http_json_request(host, port, "POST", "/v3/kv/range", timeout, payload=request_payload)
    else:
        status, body = _http_json_request(
            host, port, "POST", "/v3/kv/range", timeout, payload=request_payload, auth_token=auth_token
        )
    if status in (401, 403) or _body_indicates_auth_required(body):
        return None, "authentication required"
    if status != 200:
        return None, f"/v3/kv/range returned status {status}"

    payload = _load_json(body)
    if payload is None:
        return None, "/v3/kv/range returned invalid JSON"
    kvs = payload.get("kvs")
    if not isinstance(kvs, list):
        return [], None

    result: list[dict[str, str | None]] = []
    for item in kvs:
        if not isinstance(item, dict):
            continue
        key = _b64_decode_text(item.get("key"))
        if not key:
            continue
        value = _format_etcd_text(_b64_decode_text(item.get("value")))
        result.append(_etcd_kv_entry(key, value))
    result.sort(key=lambda item: str(item.get("key") or ""))
    return result, None


def _stream_dump_v3_all(
    host: str,
    port: int,
    timeout: float,
    *,
    batch: int,
    delay_ms: int,
    limit: int | None = None,
    auth_token: str | None = None,
) -> tuple[list[dict[str, str | None]] | None, str | None]:
    """Dump the whole v3 keyspace gradually, one range page at a time.

    Instead of one ``/v3/kv/range`` over the entire keyspace (which forces etcd to
    materialise the full response in a single shot -- it can exceed the server's response
    size limit and get truncated, on top of being a load spike), this pages through the
    range with ``limit`` + a continuation key (``last_key + \\x00``), pausing ``delay_ms``
    milliseconds between pages. ``limit`` caps the total number of dumped entries;
    ``None`` dumps everything.
    """
    page_size = max(1, batch)
    delay_seconds = max(0, delay_ms) / 1000.0
    entries: list[dict[str, str | None]] = []
    start_key_b64 = _ETCD_V3_ALL_RANGE_KEY_B64

    while True:
        page_limit = page_size
        if limit is not None:
            remaining = limit - len(entries)
            if remaining <= 0:
                break
            page_limit = min(page_size, remaining)

        request_payload: dict[str, Any] = {
            "key": start_key_b64,
            "range_end": _ETCD_V3_ALL_RANGE_KEY_B64,
            "limit": page_limit,
        }
        if auth_token is None:
            status, body = _http_json_request(host, port, "POST", "/v3/kv/range", timeout, payload=request_payload)
        else:
            status, body = _http_json_request(
                host,
                port,
                "POST",
                "/v3/kv/range",
                timeout,
                payload=request_payload,
                auth_token=auth_token,
            )
        if status in (401, 403) or _body_indicates_auth_required(body):
            return (entries if entries else None), "authentication required"
        if status != 200:
            return (entries if entries else None), f"/v3/kv/range returned status {status}"

        payload = _load_json(body)
        if payload is None:
            return (entries if entries else None), "/v3/kv/range returned invalid JSON"
        kvs = payload.get("kvs")
        if not isinstance(kvs, list):
            break

        last_key_b64: str | None = None
        for item in kvs:
            if not isinstance(item, dict):
                continue
            raw_key_b64 = item.get("key")
            if isinstance(raw_key_b64, str):
                last_key_b64 = raw_key_b64  # advance past every returned key, even empty-decoding ones
            key = _b64_decode_text(raw_key_b64)
            if not key:
                continue
            value = _format_etcd_text(_b64_decode_text(item.get("value")))
            entries.append(_etcd_kv_entry(key, value))

        if not bool(payload.get("more")) or last_key_b64 is None:
            break
        start_key_b64 = _next_key_b64(last_key_b64)
        if delay_seconds > 0:
            time.sleep(delay_seconds)

    entries.sort(key=lambda item: str(item.get("key") or ""))
    return entries, None


def _dump_v3_key(
    host: str, port: int, key: str, timeout: float, *, auth_token: str | None = None
) -> tuple[dict[str, str | None] | None, str | None]:
    request_payload = {"key": _b64_encode_text(key)}
    if auth_token is None:
        status, body = _http_json_request(host, port, "POST", "/v3/kv/range", timeout, payload=request_payload)
    else:
        status, body = _http_json_request(
            host, port, "POST", "/v3/kv/range", timeout, payload=request_payload, auth_token=auth_token
        )
    if status in (401, 403) or _body_indicates_auth_required(body):
        return None, "authentication required"
    if status != 200:
        return None, f"/v3/kv/range returned status {status}"

    payload = _load_json(body)
    if payload is None:
        return None, "/v3/kv/range returned invalid JSON"
    kvs = payload.get("kvs")
    if not isinstance(kvs, list) or not kvs:
        return _etcd_kv_entry(key, "<not found>"), None
    first = kvs[0]
    if not isinstance(first, dict):
        return _etcd_kv_entry(key, "<not found>"), None
    resolved_key = _b64_decode_text(first.get("key")) or key
    value = _format_etcd_text(_b64_decode_text(first.get("value")))
    return _etcd_kv_entry(resolved_key, value), None


def _audit_etcd_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    show_keys: bool,
    dump_keys: bool,
    query_key: str | None,
    show_keys_limit: int | None = None,
    dump_keys_limit: int | None = None,
    dump_batch: int = 10000,
    dump_delay: int = 20,
    *,
    username: str | None = None,
    password: str | None = None,
    defcreds: bool = False,
    credential_candidates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    normalized_candidates = _build_etcd_credential_candidates(
        username,
        password,
        defcreds,
        credential_candidates,
    )
    provided_candidates = [candidate for candidate in normalized_candidates if candidate[2] != "default"]
    provided_credentials = bool(provided_candidates)
    provided_username = provided_candidates[0][0] if provided_candidates else None
    provided_password = provided_candidates[0][1] if provided_candidates else None
    defaults_enabled = any(source == "default" for _user, _secret, source in normalized_candidates)

    for attempt in range(attempts):
        started = time.monotonic()
        try:
            version_status, version_body = _http_json_request(host, port, "GET", "/version", timeout)
            version_json = _load_json(version_body)

            server_version: str | None = None
            is_etcd = False
            if version_status == 200 and isinstance(version_json, dict):
                etcdserver = version_json.get("etcdserver")
                if isinstance(etcdserver, str) and etcdserver:
                    server_version = etcdserver
                    is_etcd = True
                elif "etcdcluster" in version_json:
                    is_etcd = True

            major = _major_version(server_version)
            v3_supported = bool(is_etcd and (major is None or major >= 3))

            v2_supported = False
            v2_auth_required: bool | None = None
            key_count_v2: int | None = None
            key_count_v2_error: str | None = None
            v2_error: str | None = None

            v2_status, v2_body = _http_json_request(host, port, "GET", "/v2/keys?recursive=true", timeout)
            v2_json = _load_json(v2_body)
            v2_shape_valid = _looks_like_v2_keys_response(v2_body) or (
                is_etcd and isinstance(v2_json, dict) and isinstance(v2_json.get("node"), dict)
            )
            if v2_status == 200 and v2_shape_valid:
                v2_supported = True
                v2_auth_required = False
                key_count_v2 = _count_v2_keys(v2_body)
                if key_count_v2 is None:
                    key_count_v2_error = "v2 key count response returned invalid JSON"
            elif v2_status in {401, 403} and _body_indicates_auth_required(v2_body):
                v2_supported = True
                v2_auth_required = True
            elif v2_status not in (404,):
                v2_error = f"/v2/keys returned status {v2_status}"

            v3_auth_required: bool | None = None
            key_count_v3: int | None = None
            key_count_v3_error: str | None = None
            v3_error: str | None = None

            if v3_supported:
                auth_status, auth_body = _http_json_request(host, port, "POST", "/v3/auth/status", timeout, payload={})
                auth_json = _load_json(auth_body)
                if auth_status == 200 and isinstance(auth_json, dict) and isinstance(auth_json.get("enabled"), bool):
                    v3_auth_required = bool(auth_json.get("enabled"))
                elif auth_status in (401, 403) or _body_indicates_auth_required(auth_body):
                    v3_auth_required = True

                if v3_auth_required is None or v3_auth_required is False:
                    range_status, range_body = _http_json_request(
                        host,
                        port,
                        "POST",
                        "/v3/kv/range",
                        timeout,
                        payload={
                            "key": _ETCD_V3_ALL_RANGE_KEY_B64,
                            "range_end": _ETCD_V3_ALL_RANGE_KEY_B64,
                            "count_only": True,
                        },
                    )
                    if range_status == 200:
                        v3_auth_required = False
                        key_count_v3, key_count_v3_error = _parse_v3_key_count(range_body)
                    elif range_status in (401, 403) or _body_indicates_auth_required(range_body):
                        v3_auth_required = True
                    elif v3_auth_required is None:
                        v3_error = f"/v3/kv/range returned status {range_status}"

            api_auth_required = {
                "v2": v2_auth_required if v2_supported else None,
                "v3": v3_auth_required if v3_supported else None,
            }
            auth_candidates = [value for value in api_auth_required.values() if isinstance(value, bool)]
            auth_required: bool | None
            if False in auth_candidates:
                auth_required = False
            elif True in auth_candidates:
                auth_required = True
            else:
                auth_required = None

            # ---- v3 authentication attempt --------------------------------------
            auth_token: str | None = None
            v2_basic_auth: tuple[str, str] | None = None
            credential_attempts: list[dict[str, Any]] = []
            selected_credential: dict[str, Any] | None = None
            effective_username: str | None = None
            effective_password: str | None = None

            if v3_supported and v3_auth_required is True and normalized_candidates:
                for user, secret, source in normalized_candidates:
                    is_default = source == "default"
                    try:
                        candidate_token, err = _etcd_v3_authenticate(host, port, timeout, user, secret)
                    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
                        if not defaults_enabled:
                            raise
                        candidate_token = None
                        err = _friendly_error_from_exception(exc)
                    credential_attempts.append(
                        {
                            "username": user,
                            "password": secret,
                            "source": source,
                            "api": "v3",
                            "default": is_default,
                            "ok": candidate_token is not None,
                            "error": err,
                        }
                    )
                    if candidate_token is not None and auth_token is None:
                        auth_token = candidate_token
                        selected_credential = {
                            "username": user,
                            "password": secret,
                            "source": source,
                            "default": is_default,
                        }
                        effective_username = user
                        effective_password = secret
                    if candidate_token is not None and not defaults_enabled:
                        break

            if v2_supported and v2_auth_required is True and normalized_candidates:
                for user, secret, source in normalized_candidates:
                    is_default = source == "default"
                    try:
                        candidate_ok, err = _etcd_v2_authenticate(host, port, timeout, user, secret)
                    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
                        if not defaults_enabled:
                            raise
                        candidate_ok = False
                        err = _friendly_error_from_exception(exc)
                    credential_attempts.append(
                        {
                            "username": user,
                            "password": secret,
                            "source": source,
                            "api": "v2",
                            "default": is_default,
                            "ok": candidate_ok,
                            "error": err,
                        }
                    )
                    if candidate_ok and v2_basic_auth is None:
                        v2_basic_auth = (user, secret)
                        if selected_credential is None:
                            selected_credential = {
                                "username": user,
                                "password": secret,
                                "source": source,
                                "default": is_default,
                            }
                            effective_username = user
                            effective_password = secret
                    if candidate_ok and not defaults_enabled:
                        break

            if v2_basic_auth is not None:
                v2_status, v2_body = _http_json_request(
                    host,
                    port,
                    "GET",
                    "/v2/keys?recursive=true",
                    timeout,
                    basic_auth=v2_basic_auth,
                )
                if v2_status == 200 and _count_v2_keys(v2_body) is not None:
                    key_count_v2 = _count_v2_keys(v2_body)
                    key_count_v2_error = (
                        None if key_count_v2 is not None else "v2 key count response returned invalid JSON"
                    )

            # If we successfully authenticated, re-run the /v3/kv/range probe with
            # the token so downstream key enumeration reflects post-auth state.
            if auth_token is not None:
                range_status, range_body = _http_json_request(
                    host,
                    port,
                    "POST",
                    "/v3/kv/range",
                    timeout,
                    payload={
                        "key": _ETCD_V3_ALL_RANGE_KEY_B64,
                        "range_end": _ETCD_V3_ALL_RANGE_KEY_B64,
                        "count_only": True,
                    },
                    auth_token=auth_token,
                )
                if range_status == 200:
                    v3_auth_required = True  # confirmed auth-gated
                    key_count_v3, key_count_v3_error = _parse_v3_key_count(range_body)

            key_count: int | None = None
            key_count_by_api: dict[str, int | None] = {
                "v2": key_count_v2 if v2_supported else None,
                "v3": key_count_v3 if v3_supported else None,
            }
            keys: list[str] | None = None
            key_values: list[str] | None = None
            key_value_entries: list[dict[str, str | None]] | None = None
            key_value_entries_by_api: dict[str, list[dict[str, str | None]] | None] = {}
            query_key_value: str | None = None
            query_key_entry: dict[str, str | None] | None = None
            query_key_entries_by_api: dict[str, dict[str, str | None] | None] = {}
            key_dump_error: str | None = None
            key_count_error: str | None = None
            v2_has_access = bool(v2_supported and (v2_auth_required is False or v2_basic_auth is not None))
            v3_has_access = bool(v3_supported and (v3_auth_required is False or auth_token is not None))
            api_has_access = {"v2": v2_has_access, "v3": v3_has_access}
            has_access = v2_has_access or v3_has_access
            if has_access:
                known_counts = [
                    count
                    for api_name, count in key_count_by_api.items()
                    if api_has_access[api_name] and isinstance(count, int)
                ]
                accessible_api_count = sum(api_has_access.values())
                if len(known_counts) == accessible_api_count:
                    key_count = sum(known_counts)
                if key_count is None:
                    count_errors = [
                        item
                        for item in (
                            key_count_v2_error if v2_has_access else None,
                            key_count_v3_error if v3_has_access else None,
                        )
                        if item
                    ]
                    key_count_error = "; ".join(count_errors) or "one or more API key counts are unknown"
                if show_keys or dump_keys:
                    dump_errors: list[str] = []
                    if v2_has_access:
                        v2_entries = _dump_v2_all_from_body(v2_body)
                        key_value_entries_by_api["v2"] = v2_entries
                        if v2_entries is None:
                            dump_errors.append("v2: /v2/keys returned invalid JSON")
                    if v3_has_access:
                        if dump_keys:
                            v3_entries, v3_dump_error = _stream_dump_v3_all(
                                host,
                                port,
                                timeout,
                                batch=dump_batch,
                                delay_ms=dump_delay,
                                limit=dump_keys_limit,
                                auth_token=auth_token,
                            )
                        else:
                            v3_entries, v3_dump_error = _dump_v3_all(
                                host,
                                port,
                                timeout,
                                limit=show_keys_limit,
                                auth_token=auth_token,
                            )
                        key_value_entries_by_api["v3"] = v3_entries
                        if v3_dump_error:
                            dump_errors.append(f"v3: {v3_dump_error}")

                    combined_entries: list[dict[str, str | None]] = []
                    for api_name in ("v2", "v3"):
                        api_entries = key_value_entries_by_api.get(api_name)
                        if not isinstance(api_entries, list):
                            continue
                        for item in api_entries:
                            combined_entries.append({**item, "api": api_name})
                    if combined_entries:
                        if show_keys:
                            names = {_key_name_from_entry(item) for item in combined_entries}
                            keys = sorted(item for item in names if item)
                            if show_keys_limit is not None:
                                keys = keys[:show_keys_limit]
                        if dump_keys:
                            entries = list(combined_entries)
                            if dump_keys_limit is not None:
                                entries = entries[:dump_keys_limit]
                            key_value_entries = entries
                            key_values = [_etcd_kv_entry_text(item) for item in entries]
                    elif show_keys:
                        keys = []
                    elif dump_keys:
                        key_value_entries = []
                        key_values = []
                    key_dump_error = "; ".join(dump_errors) or None

                if query_key:
                    query_errors: list[str] = []
                    if v2_has_access:
                        v2_entry, one_key_error = _dump_v2_key(
                            host,
                            port,
                            query_key,
                            timeout,
                            basic_auth=v2_basic_auth,
                        )
                        query_key_entries_by_api["v2"] = v2_entry
                        if one_key_error:
                            query_errors.append(f"v2: {one_key_error}")
                    if v3_has_access:
                        v3_entry, one_key_error = _dump_v3_key(
                            host,
                            port,
                            query_key,
                            timeout,
                            auth_token=auth_token,
                        )
                        query_key_entries_by_api["v3"] = v3_entry
                        if one_key_error:
                            query_errors.append(f"v3: {one_key_error}")
                    for api_name in ("v2", "v3"):
                        key_entry = query_key_entries_by_api.get(api_name)
                        if key_entry:
                            query_key_entry = {**key_entry, "api": api_name}
                            query_key_value = _etcd_kv_entry_text(key_entry)
                            break
                    if query_errors:
                        query_error = "; ".join(query_errors)
                        key_dump_error = query_error if key_dump_error is None else f"{key_dump_error}; {query_error}"

            api_versions = _join_api_versions(v2_supported=v2_supported, v3_supported=v3_supported)

            errors = [item for item in (v2_error, v3_error) if item]
            if key_dump_error:
                errors.append(key_dump_error)
            error = "; ".join(errors) if errors else None

            if not is_etcd and not v2_supported:
                return {
                    "timestamp": utc_now_iso(),
                    "host": host,
                    "port": port,
                    "is_etcd": False,
                    "status": "fail",
                    "api_versions": "-",
                    "server_version": None,
                    "auth_required": None,
                    "api_auth_required": {"v2": None, "v3": None},
                    "api_has_access": {"v2": False, "v3": False},
                    "key_count": None,
                    "key_count_by_api": {"v2": None, "v3": None},
                    "key_count_state": "unknown",
                    "key_count_error": "service is not etcd",
                    "show_keys": show_keys,
                    "show_keys_limit": show_keys_limit,
                    "dump_keys": dump_keys,
                    "query_key": query_key,
                    "keys": None,
                    "key_values": None,
                    "key_value_entries": None,
                    "key_value_entries_by_api": {},
                    "query_key_value": None,
                    "query_key_entry": None,
                    "query_key_entries_by_api": {},
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "error": "service is not etcd",
                }

            if auth_token is not None and selected_credential is not None:
                status = "weak_default_creds" if selected_credential.get("default") else "valid_credentials"
            elif auth_required is True:
                status = "auth_required"
            elif auth_required is None:
                status = "unknown_auth"
            else:
                status = "open_no_auth"

            return {
                "timestamp": utc_now_iso(),
                "host": host,
                "port": port,
                "is_etcd": True,
                "status": status,
                "api_versions": api_versions,
                "server_version": server_version,
                "auth_required": auth_required,
                "api_auth_required": api_auth_required,
                "api_has_access": api_has_access,
                "provided_credentials": provided_credentials,
                "provided_username": provided_username,
                "provided_password": provided_password,
                "provided_credentials_ok": (
                    None
                    if not provided_credentials
                    else bool(selected_credential is not None and not selected_credential.get("default"))
                ),
                "defcreds_enabled": defaults_enabled,
                "effective_username": effective_username,
                "effective_password": effective_password,
                "credential_attempts": credential_attempts,
                "key_count": key_count,
                "key_count_by_api": key_count_by_api,
                "key_count_state": "known" if isinstance(key_count, int) else "unknown",
                "key_count_error": key_count_error,
                "show_keys": show_keys,
                "show_keys_limit": show_keys_limit,
                "dump_keys": dump_keys,
                "query_key": query_key,
                "keys": keys,
                "key_values": key_values,
                "key_value_entries": key_value_entries,
                "key_value_entries_by_api": key_value_entries_by_api,
                "query_key_value": query_key_value,
                "query_key_entry": query_key_entry,
                "query_key_entries_by_api": query_key_entries_by_api,
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
        "is_etcd": False,
        "status": "fail",
        "api_versions": "-",
        "server_version": None,
        "auth_required": None,
        "api_auth_required": {"v2": None, "v3": None},
        "api_has_access": {"v2": False, "v3": False},
        "key_count": None,
        "key_count_by_api": {"v2": None, "v3": None},
        "key_count_state": "unknown",
        "key_count_error": last_error or "connection failed",
        "show_keys": show_keys,
        "show_keys_limit": show_keys_limit,
        "dump_keys": dump_keys,
        "query_key": query_key,
        "keys": None,
        "key_values": None,
        "key_value_entries": None,
        "key_value_entries_by_api": {},
        "query_key_value": None,
        "query_key_entry": None,
        "query_key_entries_by_api": {},
        "elapsed_ms": None,
        "error": last_error or "connection failed",
    }


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{'ETCD':<8}\t{host}\t{port}\t"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    api_versions = str(record.get("api_versions") or "-")
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
                "service": "etcd",
                "detected": bool(record.get("is_etcd")),
                "api_versions": api_versions,
                "auth_required": auth_required_value,
                "server_version": record.get("server_version"),
            },
            ensure_ascii=False,
        )

    prefix = _nxc_prefix(record)
    return f"{prefix} [*] etcd Database (api:{api_versions}) (auth required:{auth_required_text})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    status = str(record.get("status") or "fail")
    prefix = _nxc_prefix(record)
    err = _clip(str(record.get("error") or "-"), 72)

    if status == "open_no_auth":
        return ""

    if status in {"weak_default_creds", "valid_credentials"}:
        attempts = record.get("credential_attempts")
        if isinstance(attempts, list) and attempts:
            return ""
        user = str(record.get("effective_username") or "-")
        pw = record.get("provided_password") if status == "valid_credentials" else record.get("effective_password")
        password_text = str(pw) if pw is not None else "<none>"
        key_count = record.get("key_count")
        if isinstance(key_count, int):
            return f"{prefix} [+] {user}:{password_text} (keys:{format_count_value(key_count)})"
        count_error = _clip(str(record.get("key_count_error") or "unknown count"), 72)
        return f"{prefix} [+] {user}:{password_text} (keys:unknown) err={count_error}"

    if status == "auth_required":
        attempts = record.get("credential_attempts")
        if isinstance(attempts, list) and attempts:
            return ""
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


def _format_credential_attempts_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []

    attempts_raw = record.get("credential_attempts")
    if not isinstance(attempts_raw, list) or not attempts_raw:
        return []

    attempts = [attempt for attempt in attempts_raw if isinstance(attempt, dict)]
    if not attempts:
        return []

    effective_username = record.get("effective_username")
    effective_password = record.get("effective_password")
    prefix = _nxc_prefix(record)
    lines: list[str] = []
    for attempt in attempts:
        raw_username = attempt.get("username")
        raw_password = attempt.get("password")
        username = str(raw_username or "-")
        password = "<none>" if raw_password is None else "<empty>" if raw_password == "" else str(raw_password)
        if not bool(attempt.get("ok")):
            lines.append(f"{prefix} [-] {username}:{password}")
            continue

        line = f"{prefix} [+] {username}:{password}"
        selected = (
            effective_username is not None
            and str(raw_username or "-") == str(effective_username)
            and raw_password == effective_password
        )
        if selected:
            key_count = record.get("key_count")
            if isinstance(key_count, int):
                line = f"{line} (keys:{format_count_value(key_count)})"
            else:
                count_error = _clip(str(record.get("key_count_error") or "unknown count"), 72)
                line = f"{line} (keys:unknown) err={count_error}"
        lines.append(line)
    return lines


def _format_keys_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    show_keys = bool(record.get("show_keys"))
    dump_keys = bool(record.get("dump_keys"))
    query_key = str(record.get("query_key") or "").strip()
    query_key_value = record.get("query_key_value")
    query_key_entry = record.get("query_key_entry")
    keys = record.get("keys")
    key_entries = record.get("key_value_entries")
    key_values = record.get("key_values")
    if not show_keys and not dump_keys and not query_key:
        return []

    key_names: list[str] = []
    if isinstance(keys, list):
        key_names = sorted(str(item) for item in keys)
    raw_limit = record.get("show_keys_limit")
    show_keys_limit = raw_limit if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) else None
    key_meta = limit_metadata(key_names, show_keys_limit)
    displayed_key_names = limit_sequence(key_names, show_keys_limit)

    dumped_key_values: list[str] = []
    dumped_key_entries: list[dict[str, str | None]] = []
    if isinstance(key_entries, list):
        for item in key_entries:
            if isinstance(item, dict):
                dumped_key_entries.append(
                    _etcd_kv_entry(str(item.get("key") or ""), item.get("value"), error=item.get("error"))
                )
        dumped_key_values = [_etcd_kv_entry_text(item) for item in dumped_key_entries]
    elif isinstance(key_values, list):
        dumped_key_values = [str(item) for item in key_values]

    if output_format == "json":
        lines: list[str] = []
        if show_keys and key_names:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "keys_list",
                        "service": "etcd",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "key_count": record.get("key_count"),
                        "keys": displayed_key_names,
                        "keys_shown": key_meta["shown"],
                        "keys_limit": key_meta["limit"],
                        "keys_truncated": key_meta["truncated"],
                    },
                    ensure_ascii=False,
                )
            )
        if query_key and isinstance(query_key_value, str):
            query_entry = query_key_entry if isinstance(query_key_entry, dict) else None
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "key_dump",
                        "service": "etcd",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "query_key": query_key,
                        "key_value": query_key_value,
                        "key_entry": query_entry,
                    },
                    ensure_ascii=False,
                )
            )
        if dump_keys and dumped_key_values:
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "keys_dump",
                        "service": "etcd",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "key_count": record.get("key_count"),
                        "key_values": dumped_key_values,
                        "key_value_entries": dumped_key_entries,
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    prefix = _nxc_prefix(record)
    lines = []
    if show_keys and key_names:
        total = record.get("key_count")
        if show_keys_limit is not None and isinstance(total, int) and total > len(displayed_key_names):
            lines.append(f"{prefix} [*] Show Keys (showing:{len(displayed_key_names)} of {total})")
        else:
            lines.append(f"{prefix} [*] Show Keys")
        for item in displayed_key_names:
            lines.append(f"{prefix} {_format_etcd_text(item)}")
    if query_key and isinstance(query_key_value, str):
        lines.append(f"{prefix} [*] Dump Key {query_key}")
        lines.append(f"{prefix} {_format_etcd_text(query_key_value)}")
    if dump_keys and dumped_key_values:
        lines.append(f"{prefix} [*] Dump Keys")
        for item in dumped_key_values:
            lines.append(f"{prefix} {_format_etcd_text(item)}")
    return lines


def _render_colored_etcd_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(console, line, tag="ETCD", counts=(CountColorRule("keys", "red"),)):
        return True
    if line.startswith("ETCD") and "\t" in line:
        return render_tagged_detail_line(console, line, tag="ETCD", default_color="orange")
    return False


def _call_audit_etcd_host_with_stage_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    show_keys: bool,
    dump_keys: bool,
    query_key: str | None,
    show_keys_limit: int | None = None,
    dump_keys_limit: int | None = None,
    dump_batch: int = 10000,
    dump_delay: int = 20,
    *,
    username: str | None = None,
    password: str | None = None,
    defcreds: bool = False,
    credential_candidates: list[dict[str, Any]] | None = None,
    run_deep_checks: bool,
    debug: bool,
    debug_emit: Callable[[str], None] | None,
    target_spec: Any | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    audit_limit_kwargs: dict[str, Any] = (
        {"show_keys_limit": show_keys_limit if run_deep_checks else None} if show_keys_limit is not None else {}
    )
    if dump_keys_limit is not None:
        audit_limit_kwargs["dump_keys_limit"] = dump_keys_limit if run_deep_checks else None
    audit_kwargs: dict[str, Any] = dict(audit_limit_kwargs)
    audit_kwargs["dump_batch"] = dump_batch
    audit_kwargs["dump_delay"] = dump_delay
    # The shared runtime supplies one source-aware candidate batch during the
    # deep phase.  Direct/legacy calls still use username/password + defcreds;
    # when a batch is present, _audit_etcd_host ignores that legacy expansion.
    audit_kwargs["username"] = username
    audit_kwargs["password"] = password
    audit_kwargs["defcreds"] = defcreds
    if credential_candidates:
        audit_kwargs["credential_candidates"] = credential_candidates
    with http_target_context(target_spec, api_prefixes=("/version", "/v2", "/v3", "/v3beta", "/v3alpha")):
        try:
            record = _audit_etcd_host(
                host,
                port,
                timeout,
                retries,
                show_keys if run_deep_checks else False,
                dump_keys if run_deep_checks else False,
                query_key if run_deep_checks else None,
                **audit_kwargs,
            )
        except TypeError as exc:
            # Backward-compat: tests patch _audit_etcd_host with a legacy signature.
            if not is_signature_compat_typeerror(
                exc,
                expected_keywords={"username", "password", "defcreds", "credential_candidates"},
            ):
                raise
            for legacy_key in ("username", "password", "defcreds", "credential_candidates"):
                audit_kwargs.pop(legacy_key, None)
            record = _audit_etcd_host(
                host,
                port,
                timeout,
                retries,
                show_keys if run_deep_checks else False,
                dump_keys if run_deep_checks else False,
                query_key if run_deep_checks else None,
                **audit_kwargs,
            )

    result: dict[str, Any] = dict(record)
    status = str(result.get("status") or "fail")
    is_etcd = bool(result.get("is_etcd"))
    attempts = max(1, retries + 1)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    telemetry = StageTelemetryBuilder(host=host, port=port, attempts=attempts, debug=debug, debug_emit=debug_emit)
    if attempts > 1 and status == "fail":
        telemetry.debug(format_retry_decision(_STAGE_DETECT_PROTOCOL, 1, attempts, _retry_delay(0), "error"))

    detect_result = "ok" if is_etcd else ("error" if status == "fail" else "skip")
    detect_error = str(result.get("error") or "") if detect_result == "error" else None
    telemetry.stage(_STAGE_DETECT_PROTOCOL, detect_result, detect_error, 0)

    auth_result = "ok" if is_etcd and status in _ETCD_DEEP_STATUSES.union({"auth_required"}) else detect_result
    telemetry.stage(_STAGE_AUTH_INFERENCE, auth_result, detect_error if auth_result == "error" else None, 0)

    if run_deep_checks and status in _ETCD_DEEP_STATUSES:
        telemetry.stage(_STAGE_ACCESS_CAPABILITIES, "ok", None, 0)
        data_result = "error" if status == "fail" and result.get("error") else "ok"
        telemetry.stage(
            _STAGE_DATA, data_result, str(result.get("error") or "") if data_result == "error" else None, elapsed_ms
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


# Typed runner boundary -----------------------------------------------------
host_stage = _call_audit_etcd_host_with_stage_debug
