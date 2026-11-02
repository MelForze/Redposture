"""etcd audit stage."""

from __future__ import annotations

import base64
import binascii
import codecs
import itertools
import json
import re
import tempfile
import threading
import time
import urllib.error
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...clients import transport
from ...clients.http_api import (
    HttpApiClient,
    HttpClientConfig,
    build_http_target_url,
    current_http_target_binding,
    http_response_origin,
    http_response_requires_https,
    http_scheme_candidates,
    http_target_context,
    resolve_http_scheme,
)
from ...clients.http_session import HttpSessionPool
from ...console import Console
from ...credential_evidence import attempt_capabilities
from ...detection_io import DetectCall, DetectDelay, HttpRead, run_sync
from ...discovery_frontier import DiscoveryFrontier
from ...discovery_json import DiskJSONDocument
from ...discovery_options import DEFAULT_DISCOVER_TIME, UNLIMITED_DISCOVER_BYTES
from ...discovery_spool import SpoolingRecords, SpoolingStrings
from ...discovery_values import DiskBackedText
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
from ...storage_discovery import DiscoveryCollector
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
    ("root", "12345678"),
    ("service", "service"),
    ("user", "password"),
    ("user", "user"),
)
_ETCD_HTTP_LOCAL = threading.local()


@dataclass
class _EtcdHttpLifecycle:
    pool: HttpSessionPool
    scheme: str | None = None
    host: str | None = None
    port: int | None = None
    origin_resolved: bool = False

    def close(self) -> None:
        self.pool.close()


@dataclass
class _EtcdDiscoveryBudget:
    deadline: float
    remaining_bytes: int
    collector: DiscoveryCollector | None = None

    def request_timeout(self, timeout: float) -> float | None:
        remaining = self.deadline - time.monotonic()
        return min(timeout, remaining) if remaining > 0 and self.remaining_bytes > 0 else None


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
    if status == 401:
        return None, "invalid credentials"
    if status == 400:
        parsed = _load_json(body)
        if isinstance(parsed, dict) and parsed.get("code") == 3:
            message = str(parsed.get("message") or parsed.get("error") or "").lower()
            if "authentication failed, invalid user id or password" in message:
                return None, "invalid credentials"
    return None, f"authenticate returned status {status}"


def _etcd_v2_authenticate(
    host: str,
    port: int,
    timeout: float,
    username: str,
    password: str,
) -> tuple[bool | None, str | None]:
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
    if status == 401:
        return False, "invalid credentials"
    return None, f"v2 key probe returned status {status}"


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
    response_size_cap: int | None = None,
) -> tuple[int, str]:
    return run_sync(
        _detect_http_json_request_steps(
            host,
            port,
            method,
            path,
            timeout,
            payload=payload,
            auth_token=auth_token,
            basic_auth=basic_auth,
            response_size_cap=response_size_cap,
        )
    )


def _detect_http_json_request_steps(
    host: str,
    port: int,
    method: str,
    path: str,
    timeout: float,
    *,
    payload: dict[str, Any] | None = None,
    auth_token: str | None = None,
    basic_auth: tuple[str, str] | None = None,
    response_size_cap: int | None = None,
) -> Any:
    lifecycle = getattr(_ETCD_HTTP_LOCAL, "state", None)
    request_host = lifecycle.host or str(host) if isinstance(lifecycle, _EtcdHttpLifecycle) else str(host)
    request_port = lifecycle.port or int(port) if isinstance(lifecycle, _EtcdHttpLifecycle) else int(port)
    scheme = (
        lifecycle.scheme
        if isinstance(lifecycle, _EtcdHttpLifecycle) and lifecycle.scheme in {"http", "https"}
        else (yield DetectCall(resolve_http_scheme, (host, port, timeout), {"probe_path": "/version"}))
        if not isinstance(lifecycle, _EtcdHttpLifecycle)
        else None
    )
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
    requested_path = str(path or "/")
    response_cap = (
        256 * 1024
        if requested_path.startswith(("/version", "/v3/auth/", "/v3beta/auth/", "/v3alpha/auth/"))
        else 10 * 1024 * 1024
    )
    if response_size_cap is not None:
        response_cap = min(response_cap, max(0, int(response_size_cap)))
    client = (
        None
        if isinstance(lifecycle, _EtcdHttpLifecycle)
        else HttpApiClient(HttpClientConfig(timeout=timeout, response_size_cap=response_cap, insecure=True))
    )

    candidates = [requested_path]
    if requested_path.startswith("/v3/"):
        binding = current_http_target_binding()
        key = (request_host, request_port, scheme or binding.scheme, binding.base_path)
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
        candidate_schemes = (
            (str(scheme or ("https" if request_port in {443, 8443} else "http")),)
            if method.upper() not in {"GET", "HEAD"}
            else http_scheme_candidates(scheme, request_port, tls_ports=frozenset({443, 8443}))
        )
        response = None
        for candidate_scheme in candidate_schemes:
            url = build_http_target_url(
                request_host,
                request_port,
                candidate_path,
                default_scheme=str(candidate_scheme),
                override_bound_scheme=True,
            )
            if isinstance(lifecycle, _EtcdHttpLifecycle):
                response = yield HttpRead(
                    lifecycle.pool,
                    method,
                    url,
                    {
                        "headers": headers,
                        "body": body_bytes,
                        "timeout": timeout,
                        "response_size_cap": response_cap,
                        "replay_safe": method.upper() in {"GET", "HEAD"},
                    },
                    readonly_post=method.upper() == "POST" and requested_path in {"/v3/auth/status", "/v3/kv/range"},
                )
            else:
                assert client is not None
                response = yield DetectCall(
                    client.request, (method, url), {"headers": headers, "body": body_bytes, "timeout": timeout}
                )
            if response.error is None and not (
                candidate_scheme == "http"
                and http_response_requires_https(
                    response.status, getattr(response, "body", getattr(response, "text", ""))
                )
            ):
                scheme, request_host, request_port = http_response_origin(
                    response,
                    fallback_scheme=str(candidate_scheme),
                    fallback_host=request_host,
                    fallback_port=request_port,
                )
                if isinstance(lifecycle, _EtcdHttpLifecycle):
                    lifecycle.scheme = scheme
                    lifecycle.host = request_host
                    lifecycle.port = request_port
                    lifecycle.origin_resolved = True
                break
        assert response is not None
        if bool(getattr(response, "truncated", False)):
            raise urllib.error.URLError("HTTP response exceeds limit")
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


def _looks_like_etcd_version(payload: Any) -> tuple[bool, str | None]:
    if not isinstance(payload, dict):
        return False, None
    server_version = payload.get("etcdserver")
    if not isinstance(server_version, str):
        return False, None
    clean = server_version.strip()
    if not re.fullmatch(r"v?\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?", clean):
        return False, None
    cluster_version = payload.get("etcdcluster")
    if cluster_version is not None and not (
        isinstance(cluster_version, str)
        and re.fullmatch(r"v?\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?", cluster_version.strip())
    ):
        return False, None
    return True, clean


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


def _etcd_kv_entry(key: str, value: Any = None, *, error: str | None = None) -> dict[str, Any]:
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


def _b64_decode_discovery_value(value: Any) -> str | DiskBackedText:
    """Decode a large JSON base64 scalar without materializing it in memory."""
    if not isinstance(value, DiskBackedText):
        decoded = _b64_decode_text(value)
        if len(decoded) <= 65_536:
            return decoded
        output = DiskBackedText()
        try:
            output.append_text(decoded)
            output.finish()
            return output
        except BaseException:
            output.close()
            raise
    output = DiskBackedText()
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    pending = ""
    try:
        for part in value.iter_text_chunks():
            pending += part
            length = len(pending) // 4 * 4
            if length:
                output.append_text(decoder.decode(base64.b64decode(pending[:length], validate=True)))
                pending = pending[length:]
        if pending:
            output.append_text(decoder.decode(base64.b64decode(pending + "=" * (-len(pending) % 4), validate=True)))
        output.append_text(decoder.decode(b"", final=True))
        output.finish()
        return output
    except (ValueError, binascii.Error, UnicodeError):
        output.close()
        raise


def _stream_v3_page(
    host: str,
    port: int,
    timeout: float,
    payload: dict[str, Any],
    *,
    auth_token: str | None,
    deadline: float,
) -> tuple[int, Mapping[str, Any] | None, str | None, int]:
    """Retry one oversized etcd range page with disk-backed JSON scalars."""
    lifecycle = getattr(_ETCD_HTTP_LOCAL, "state", None)
    pool = (
        lifecycle.pool if isinstance(lifecycle, _EtcdHttpLifecycle) else HttpSessionPool(timeout=timeout, insecure=True)
    )
    own_pool = not isinstance(lifecycle, _EtcdHttpLifecycle)
    binding = current_http_target_binding()
    request_host = lifecycle.host or host if isinstance(lifecycle, _EtcdHttpLifecycle) else host
    request_port = lifecycle.port or port if isinstance(lifecycle, _EtcdHttpLifecycle) else port
    scheme = lifecycle.scheme if isinstance(lifecycle, _EtcdHttpLifecycle) else None
    scheme = scheme or binding.scheme or ("https" if request_port in {443, 8443} else "http")
    cache_key = (request_host, request_port, scheme, binding.base_path)
    with _ETCD_V3_PREFIX_CACHE_LOCK:
        cached_prefix = _ETCD_V3_PREFIX_CACHE.get(cache_key)
    prefixes = list(dict.fromkeys(([cached_prefix] if cached_prefix else []) + list(_ETCD_V3_PREFIXES)))
    headers = {"User-Agent": "RedPosture/1.0", "Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = auth_token
        headers["Grpc-Metadata-Authorization"] = auth_token
    request_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    builder: DiskJSONDocument | None = None
    try:
        for prefix in prefixes:
            if builder is not None:
                builder.close()
            active_document = DiskJSONDocument(deadline=deadline)
            builder = active_document
            count = 0
            status = 0

            def on_response(code: int, _headers: Any) -> None:
                nonlocal status
                status = code

            def on_chunk(chunk: bytes, target: DiskJSONDocument = active_document) -> None:
                nonlocal count
                count += len(chunk)
                target.feed(chunk)

            url = build_http_target_url(
                request_host,
                request_port,
                prefix + "/kv/range",
                default_scheme=scheme,
                override_bound_scheme=True,
            )
            try:
                response = pool.request_stream(
                    "POST",
                    url,
                    on_chunk=on_chunk,
                    on_response=on_response,
                    body=request_body,
                    headers=headers,
                    chunk_size=65_536,
                    timeout=max(0.001, min(timeout, deadline - time.monotonic())),
                    deadline=deadline,
                    allow_cross_origin_redirects=False,
                    preserve_authorization_on_cross_origin=False,
                )
            except (OSError, ValueError, UnicodeError) as exc:
                return status, _retained_etcd_json(builder, status), str(exc), count
            status = response.status
            if status in {404, 501}:
                continue
            if response.error or response.truncated:
                return status, _retained_etcd_json(builder, status), str(response.error or "response_truncated"), count
            if status != 200:
                return status, None, None, count
            try:
                parsed = builder.finish()
            except (OSError, ValueError, UnicodeError) as exc:
                return status, _retained_etcd_json(builder, status), f"invalid_json:{exc}", count
            if not isinstance(parsed, Mapping):
                return status, None, "invalid_json", count
            with _ETCD_V3_PREFIX_CACHE_LOCK:
                _ETCD_V3_PREFIX_CACHE[cache_key] = prefix
            return status, parsed, None, count
        return 404, None, "v3_range_unavailable", 0
    finally:
        if builder is not None:
            builder.close()
        if own_pool:
            pool.close()


def _stream_v2_tree(
    host: str,
    port: int,
    timeout: float,
    path: str,
    *,
    deadline: float,
    basic_auth: tuple[str, str] | None = None,
) -> tuple[int, Mapping[str, Any] | None, str | None, int]:
    """Read a v2 tree or selected key without buffering the full JSON body."""
    lifecycle = getattr(_ETCD_HTTP_LOCAL, "state", None)
    pool = (
        lifecycle.pool if isinstance(lifecycle, _EtcdHttpLifecycle) else HttpSessionPool(timeout=timeout, insecure=True)
    )
    own_pool = not isinstance(lifecycle, _EtcdHttpLifecycle)
    request_host = lifecycle.host or host if isinstance(lifecycle, _EtcdHttpLifecycle) else host
    request_port = lifecycle.port or port if isinstance(lifecycle, _EtcdHttpLifecycle) else port
    binding = current_http_target_binding()
    scheme = (lifecycle.scheme if isinstance(lifecycle, _EtcdHttpLifecycle) else None) or binding.scheme
    scheme = scheme or ("https" if request_port in {443, 8443} else "http")
    headers = {"User-Agent": "RedPosture/1.0", "Accept": "application/json"}
    if basic_auth is not None:
        encoded = base64.b64encode(f"{basic_auth[0]}:{basic_auth[1]}".encode()).decode("ascii")
        headers["Authorization"] = f"Basic {encoded}"
    url = build_http_target_url(request_host, request_port, path, default_scheme=scheme, override_bound_scheme=True)
    builder = DiskJSONDocument(deadline=deadline)
    status = 0
    count = 0

    def on_response(code: int, _headers: Any) -> None:
        nonlocal status
        status = code

    def on_chunk(chunk: bytes) -> None:
        nonlocal count
        count += len(chunk)
        builder.feed(chunk)

    try:
        response = pool.request_stream(
            "GET",
            url,
            on_chunk=on_chunk,
            on_response=on_response,
            headers=headers,
            chunk_size=65_536,
            timeout=max(0.001, min(timeout, deadline - time.monotonic())),
            deadline=deadline,
            allow_cross_origin_redirects=False,
            preserve_authorization_on_cross_origin=False,
        )
        status = response.status
        if response.error or response.truncated:
            return (
                status,
                _retained_etcd_json(builder, status, v2=True),
                str(response.error or "response_truncated"),
                count,
            )
        if status != 200:
            return status, None, None, count
        try:
            payload = builder.finish()
        except (OSError, ValueError, UnicodeError) as exc:
            return status, _retained_etcd_json(builder, status, v2=True), f"invalid_json:{exc}", count
        return status, payload if isinstance(payload, Mapping) else None, None, count
    except (OSError, ValueError, UnicodeError) as exc:
        return status, _retained_etcd_json(builder, status, v2=True), str(exc), count
    finally:
        builder.close()
        if own_pool:
            pool.close()


def _retained_etcd_json(builder: DiskJSONDocument, status: int, *, v2: bool = False) -> Mapping[str, Any] | None:
    """Keep complete array records, never an interrupted KV or leaf node."""
    if status != 200:
        return None
    node_open = builder.is_open_container(("node",))
    value = builder.partial_value(completed_arrays_only=True)
    if not isinstance(value, Mapping):
        return None
    if v2 and node_open:
        node = value.get("node")
        if not isinstance(node, Mapping) or not bool(node.get("dir")):
            return None
    return value


def _iter_v2_leaves(root: Any):
    if not isinstance(root, Mapping):
        return
    pending = [iter((root,))]
    while pending:
        node = next(pending[-1], None)
        if node is None:
            pending.pop()
            continue
        if not isinstance(node, Mapping):
            continue
        if bool(node.get("dir")):
            children = node.get("nodes")
            if isinstance(children, list):
                pending.append(iter(children))
            continue
        yield node


def _count_v2_payload(payload: Any) -> int | None:
    if not isinstance(payload, Mapping) or not isinstance(payload.get("node"), Mapping):
        return None
    return sum(1 for _ in _iter_v2_leaves(payload["node"]))


def _dump_v2_payload(payload: Any, collector: DiscoveryCollector | None) -> list[dict[str, Any]] | None:
    if not isinstance(payload, Mapping) or not isinstance(payload.get("node"), Mapping):
        return None
    entries: list[dict[str, Any]] = SpoolingRecords() if collector is not None else []
    for node in _iter_v2_leaves(payload["node"]):
        key = node.get("key")
        if not isinstance(key, str) or not key:
            if collector is not None:
                collector.partial("v2", "invalid_key")
            continue
        value = node.get("value")
        if collector is not None:
            source = f"key_value_entries.{key}"
            if isinstance(value, DiskBackedText):
                collector.scan_disk_text(source, value, key=key.rsplit("/", 1)[-1])
            else:
                collector.add(source, {key.rsplit("/", 1)[-1]: value}, charge=False)
        entry = _etcd_kv_entry(key, value if collector is not None else _format_etcd_text(value))
        if isinstance(entries, SpoolingRecords):
            entries.append(entry, sort_key=key)
        else:
            entries.append(entry)
    if isinstance(entries, SpoolingRecords):
        entries.finish()
    return entries


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
    discovery_budget: _EtcdDiscoveryBudget | None = None,
    retained_payload: Mapping[str, Any] | None = None,
    retained_error: str | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    path = f"/v2/keys{key}"
    request_options: dict[str, Any] = {}
    if basic_auth is not None:
        request_options["basic_auth"] = basic_auth
    if discovery_budget is not None and retained_payload is None:
        bounded_timeout = discovery_budget.request_timeout(timeout)
        if bounded_timeout is None:
            return None, "time_budget"
        timeout = bounded_timeout
    payload = retained_payload
    stream_error = retained_error
    try:
        if retained_payload is None:
            status, body = _http_json_request(host, port, "GET", path, timeout, **request_options)
        else:
            status, body = 200, ""
    except urllib.error.URLError as exc:
        if discovery_budget is None or "HTTP response exceeds limit" not in str(exc):
            raise
        status, payload, stream_error, streamed_bytes = _stream_v2_tree(
            host,
            port,
            timeout,
            path,
            deadline=discovery_budget.deadline,
            basic_auth=basic_auth,
        )
        if discovery_budget.collector is not None:
            discovery_budget.collector.bytes_read += streamed_bytes
            if stream_error:
                discovery_budget.collector.partial("v2", stream_error)
        if stream_error is not None and payload is None:
            return None, stream_error
        body = ""
    if status == 404:
        return _etcd_kv_entry(key, "<not found>"), None
    if status != 200:
        return None, f"/v2/keys{key} returned status {status}"

    if payload is None:
        payload = _load_json(body)
    if payload is None:
        return None, f"/v2/keys{key} returned invalid JSON"
    node = payload.get("node")
    if not isinstance(node, Mapping):
        return None, f"/v2/keys{key} returned invalid node"
    if bool(node.get("dir")):
        return _etcd_kv_entry(key, "<dir>"), stream_error
    resolved_key = str(node.get("key") or key).strip() or key
    value = node.get("value")
    if discovery_budget is not None and discovery_budget.collector is not None:
        collector = discovery_budget.collector
        if stream_error:
            collector.partial("v2", stream_error)
        collector.mark_accessible_source()
        source = f"key_value_entries.{resolved_key}"
        if isinstance(value, DiskBackedText):
            collector.scan_disk_text(source, value, key=resolved_key.rsplit("/", 1)[-1])
        else:
            collector.add(source, {resolved_key.rsplit("/", 1)[-1]: value}, charge=False)
    return _etcd_kv_entry(
        resolved_key, value if discovery_budget is not None else _format_etcd_text(value)
    ), stream_error


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
    discovery_budget: _EtcdDiscoveryBudget | None = None,
) -> tuple[list[dict[str, str | None]] | None, str | None]:
    """Dump the whole v3 keyspace gradually, one range page at a time.

    Instead of one ``/v3/kv/range`` over the entire keyspace (which forces etcd to
    materialise the full response in a single shot -- it can exceed the server's response
    size limit and get truncated, on top of being a load spike), this pages through the
    range with ``limit`` + a continuation key (``last_key + \\x00``), pausing ``delay_ms``
    milliseconds between pages. ``limit`` caps the total number of dumped entries;
    ``None`` dumps everything.
    """
    page_size = min(16, max(1, batch)) if discovery_budget is not None else max(1, batch)
    adaptive_ceiling = max(1, batch)
    delay_seconds = max(0, delay_ms) / 1000.0
    entries: list[dict[str, str | None]] = SpoolingRecords() if discovery_budget is not None else []
    start_key_b64 = _ETCD_V3_ALL_RANGE_KEY_B64

    while True:
        request_timeout = timeout
        request_options: dict[str, Any] = {}
        if discovery_budget is not None:
            bounded_timeout = discovery_budget.request_timeout(timeout)
            if bounded_timeout is None:
                reason = "time_budget" if time.monotonic() >= discovery_budget.deadline else "byte_budget"
                return entries, reason
            request_timeout = bounded_timeout
            request_options["response_size_cap"] = min(discovery_budget.remaining_bytes, 4 * 1024 * 1024)
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
        streamed_payload: Mapping[str, Any] | None = None
        stream_error: str | None = None
        streamed_bytes = 0
        body = ""
        try:
            if auth_token is None:
                status, body = _http_json_request(
                    host,
                    port,
                    "POST",
                    "/v3/kv/range",
                    request_timeout,
                    payload=request_payload,
                    **request_options,
                )
            else:
                status, body = _http_json_request(
                    host,
                    port,
                    "POST",
                    "/v3/kv/range",
                    request_timeout,
                    payload=request_payload,
                    auth_token=auth_token,
                    **request_options,
                )
        except urllib.error.URLError as exc:
            if discovery_budget is not None and "timed out" in str(exc).lower() and page_limit > 1:
                page_size = max(1, min(32, page_limit // 2))
                adaptive_ceiling = min(adaptive_ceiling, page_size)
                continue
            if discovery_budget is not None and "limit" in str(exc).lower():
                if page_limit > 1:
                    page_size = max(1, page_limit // 2)
                    adaptive_ceiling = min(adaptive_ceiling, page_size)
                    continue
                status, streamed_payload, stream_error, streamed_bytes = _stream_v3_page(
                    host,
                    port,
                    request_timeout,
                    request_payload,
                    auth_token=auth_token,
                    deadline=discovery_budget.deadline,
                )
                if stream_error and discovery_budget.collector is not None:
                    discovery_budget.collector.partial("v3", stream_error)
                if stream_error and streamed_payload is None:
                    return entries, stream_error
            else:
                return entries, str(exc.reason)
        if status in (401, 403) or _body_indicates_auth_required(body):
            return (
                entries if entries else None
            ), "access_denied" if auth_token is not None else "authentication required"
        if status != 200:
            return (entries if entries else None), f"/v3/kv/range returned status {status}"

        if discovery_budget is not None and discovery_budget.collector is not None:
            discovery_budget.collector.bytes_read += streamed_bytes or len(body.encode("utf-8"))
            if stream_error:
                discovery_budget.collector.partial("v3", stream_error)

        payload = streamed_payload if streamed_payload is not None else _load_json(body)
        if payload is None:
            return (entries if entries else None), "/v3/kv/range returned invalid JSON"
        kvs = payload.get("kvs")
        if not isinstance(kvs, list):
            if stream_error:
                return entries, stream_error
            break

        if stream_error and not kvs:
            return entries, stream_error
        if not kvs and bool(payload.get("more")):
            return entries, "pagination_stalled"
        if kvs and start_key_b64 != _ETCD_V3_ALL_RANGE_KEY_B64:
            last_item = kvs[-1]
            last_key = last_item.get("key") if isinstance(last_item, Mapping) else None
            try:
                requested = base64.b64decode(start_key_b64 + "===", validate=False)
                returned = base64.b64decode(str(last_key) + "===", validate=False)
            except (ValueError, binascii.Error):
                return entries, "pagination_stalled"
            if returned < requested:
                return entries, "pagination_stalled"

        last_key_b64: str | None = None
        for item in kvs:
            if not isinstance(item, Mapping):
                continue
            raw_key_b64 = item.get("key")
            if isinstance(raw_key_b64, str):
                last_key_b64 = raw_key_b64  # advance past every returned key, even empty-decoding ones
            key = _b64_decode_text(raw_key_b64)
            if not key:
                continue
            try:
                value = (
                    _b64_decode_discovery_value(item.get("value"))
                    if discovery_budget is not None
                    else _b64_decode_text(item.get("value"))
                )
            except (ValueError, binascii.Error, UnicodeError):
                return entries, "invalid_base64_value"
            if discovery_budget is not None and discovery_budget.collector is not None:
                source = f"key_value_entries.{key}"
                if isinstance(value, DiskBackedText):
                    discovery_budget.collector.scan_disk_text(source, value, key=key.rsplit("/", 1)[-1])
                else:
                    discovery_budget.collector.add(source, {key.rsplit("/", 1)[-1]: value}, charge=False)
            if discovery_budget is None:
                value = _format_etcd_text(value)
            entry = _etcd_kv_entry(key, value)
            if isinstance(entries, SpoolingRecords):
                entries.append(entry, sort_key=key)
            else:
                entries.append(entry)

        if stream_error:
            return entries, stream_error
        if not bool(payload.get("more")) or last_key_b64 is None:
            break
        if discovery_budget is not None and len(kvs) >= page_limit:
            # Learn from a small first page instead of asking an unknown
            # server to materialize ten thousand large values at once.
            wire_bytes = max(1, streamed_bytes or len(body.encode("utf-8")))
            target_bytes = min(discovery_budget.remaining_bytes, 4 * 1024 * 1024)
            suggested = max(1, target_bytes * len(kvs) // wire_bytes)
            page_size = min(adaptive_ceiling, page_limit * 2, suggested)
        start_key_b64 = _next_key_b64(last_key_b64)
        if delay_seconds > 0:
            time.sleep(
                min(delay_seconds, max(0.0, discovery_budget.deadline - time.monotonic()))
                if discovery_budget
                else delay_seconds
            )

    if isinstance(entries, SpoolingRecords):
        entries.finish()
    else:
        entries.sort(key=lambda item: str(item.get("key") or ""))
    return entries, None


def _dump_v3_key(
    host: str,
    port: int,
    key: str,
    timeout: float,
    *,
    auth_token: str | None = None,
    discovery_budget: _EtcdDiscoveryBudget | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    request_payload = {"key": _b64_encode_text(key)}
    streamed_payload: Mapping[str, Any] | None = None
    error: str | None = None
    streamed_bytes = 0
    body = ""
    try:
        status, body = _http_json_request(
            host, port, "POST", "/v3/kv/range", timeout, payload=request_payload, auth_token=auth_token
        )
    except urllib.error.URLError as exc:
        if discovery_budget is None or "limit" not in str(exc).lower():
            raise
        status, streamed_payload, error, streamed_bytes = _stream_v3_page(
            host,
            port,
            timeout,
            request_payload,
            auth_token=auth_token,
            deadline=discovery_budget.deadline,
        )
        if error and discovery_budget.collector is not None:
            discovery_budget.collector.partial("v3", error)
        if error and streamed_payload is None:
            return None, error
    if status in (401, 403) or _body_indicates_auth_required(body):
        return None, "authentication required"
    if status != 200:
        return None, f"/v3/kv/range returned status {status}"

    if discovery_budget is not None and discovery_budget.collector is not None:
        discovery_budget.collector.bytes_read += streamed_bytes or len(body.encode("utf-8"))
        if error:
            discovery_budget.collector.partial("v3", error)
    payload = streamed_payload if streamed_payload is not None else _load_json(body)
    if payload is None:
        return None, "/v3/kv/range returned invalid JSON"
    kvs = payload.get("kvs")
    if not isinstance(kvs, list) or not kvs:
        if error:
            return None, error
        if discovery_budget is not None and discovery_budget.collector is not None:
            discovery_budget.collector.mark_accessible_source()
        return _etcd_kv_entry(key, "<not found>"), None
    first = kvs[0]
    if not isinstance(first, Mapping):
        if error:
            return None, error
        return _etcd_kv_entry(key, "<not found>"), None
    resolved_key = _b64_decode_text(first.get("key")) or key
    if discovery_budget is not None and resolved_key != key:
        return None, "selected_key_mismatch"
    try:
        value = (
            _b64_decode_discovery_value(first.get("value"))
            if discovery_budget is not None
            else _format_etcd_text(_b64_decode_text(first.get("value")))
        )
    except (ValueError, binascii.Error, UnicodeError):
        return None, "invalid_base64_value"
    if discovery_budget is not None and discovery_budget.collector is not None:
        source = f"key_value_entries.{key}"
        if isinstance(value, DiskBackedText):
            discovery_budget.collector.scan_disk_text(source, value, key=key.rsplit("/", 1)[-1])
        else:
            discovery_budget.collector.add(source, {key.rsplit("/", 1)[-1]: value}, charge=False)
    return _etcd_kv_entry(resolved_key, value), error


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
    discover: bool = False,
    discover_time: float | None = None,
    discover_max_bytes: int | None = None,
    discover_ctx: Any | None = None,
) -> dict[str, Any]:
    return run_sync(
        _detect_audit_etcd_host_steps(
            host,
            port,
            timeout,
            retries,
            show_keys,
            dump_keys,
            query_key,
            show_keys_limit,
            dump_keys_limit,
            dump_batch,
            dump_delay,
            username=username,
            password=password,
            defcreds=defcreds,
            credential_candidates=credential_candidates,
            discover=discover,
            discover_time=discover_time,
            discover_max_bytes=discover_max_bytes,
            discover_ctx=discover_ctx,
        )
    )


def _detect_audit_etcd_host_steps(
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
    discover: bool = False,
    discover_time: float | None = None,
    discover_max_bytes: int | None = None,
    discover_ctx: Any | None = None,
) -> Any:
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
    discovery_budget = (
        _EtcdDiscoveryBudget(
            deadline=float(getattr(discover_ctx, "discovery_started_at", None) or time.monotonic())
            + float(discover_time or DEFAULT_DISCOVER_TIME),
            remaining_bytes=int(discover_max_bytes or UNLIMITED_DISCOVER_BYTES),
        )
        if discover and (dump_keys or query_key)
        else None
    )

    for attempt in range(attempts):
        started = time.monotonic()
        pre_collector_streamed_bytes = 0
        try:
            version_status, version_body = yield DetectCall(
                _http_json_request, (host, port, "GET", "/version", timeout), {}
            )
            version_json = _load_json(version_body)

            server_version: str | None = None
            is_etcd = False
            if version_status == 200:
                is_etcd, server_version = _looks_like_etcd_version(version_json)

            major = _major_version(server_version)
            v3_supported = bool(is_etcd and (major is None or major >= 3))

            v2_supported = False
            v2_auth_required: bool | None = None
            key_count_v2: int | None = None
            key_count_v2_error: str | None = None
            v2_error: str | None = None

            v2_probe_error: str | None = None
            v2_streamed_payload: Mapping[str, Any] | None = None
            v2_probe_path = (
                f"/v2/keys{query_key}" if discovery_budget is not None and query_key else "/v2/keys?recursive=true"
            )
            v2_options: dict[str, Any] = {}
            v2_timeout = timeout
            if discovery_budget is not None and is_etcd:
                bounded_timeout = discovery_budget.request_timeout(timeout)
                if bounded_timeout is None:
                    v2_probe_error = "time_budget" if time.monotonic() >= discovery_budget.deadline else "byte_budget"
                else:
                    v2_timeout = bounded_timeout
                    v2_options["response_size_cap"] = min(discovery_budget.remaining_bytes, 4 * 1024 * 1024)
            v2_status, v2_body = 0, ""
            if v2_probe_error is None:
                try:
                    v2_status, v2_body = yield DetectCall(
                        _http_json_request,
                        (host, port, "GET", v2_probe_path, v2_timeout),
                        v2_options,
                    )
                except urllib.error.URLError as exc:
                    if not is_etcd or "HTTP response exceeds limit" not in str(exc):
                        raise
                    if discovery_budget is None:
                        # A strong /version fingerprint already confirmed etcd.
                        # The detect pass must not fail because inventory is large.
                        v2_probe_error = "v2 response exceeds buffered limit"
                    else:
                        v2_status, v2_streamed_payload, v2_probe_error, streamed_bytes = yield DetectCall(
                            _stream_v2_tree,
                            (host, port, v2_timeout, v2_probe_path),
                            {"deadline": discovery_budget.deadline},
                        )
                        pre_collector_streamed_bytes += streamed_bytes
            v2_json = v2_streamed_payload if v2_streamed_payload is not None else _load_json(v2_body)
            v2_shape_valid = _looks_like_v2_keys_response(v2_body) or (
                is_etcd and isinstance(v2_json, Mapping) and isinstance(v2_json.get("node"), Mapping)
            )
            if v2_probe_error is not None:
                v2_error = v2_probe_error
                if v2_status == 200 and v2_shape_valid:
                    v2_supported = True
                    v2_auth_required = False
                    key_count_v2_error = v2_probe_error
            elif v2_status == 200 and v2_shape_valid:
                v2_supported = True
                v2_auth_required = False
                key_count_v2 = (
                    _count_v2_payload(v2_json) if v2_streamed_payload is not None else _count_v2_keys(v2_body)
                )
                if key_count_v2 is None:
                    key_count_v2_error = "v2 key count response returned invalid JSON"
            elif is_etcd and v2_status in {401, 403} and _body_indicates_auth_required(v2_body):
                v2_supported = True
                v2_auth_required = True
            elif v2_status not in (404,):
                v2_error = f"/v2/keys returned status {v2_status}"

            v3_auth_required: bool | None = None
            key_count_v3: int | None = None
            key_count_v3_error: str | None = None
            v3_error: str | None = None

            if v3_supported:
                auth_status, auth_body = yield DetectCall(
                    _http_json_request, (host, port, "POST", "/v3/auth/status", timeout), {"payload": {}}
                )
                auth_json = _load_json(auth_body)
                if auth_status == 200 and isinstance(auth_json, dict) and isinstance(auth_json.get("enabled"), bool):
                    v3_auth_required = bool(auth_json.get("enabled"))
                elif auth_status in (401, 403) or _body_indicates_auth_required(auth_body):
                    v3_auth_required = True

                if v3_auth_required is None or v3_auth_required is False:
                    range_status, range_body = yield DetectCall(
                        _http_json_request,
                        (host, port, "POST", "/v3/kv/range", timeout),
                        {
                            "payload": {
                                "key": _ETCD_V3_ALL_RANGE_KEY_B64,
                                "range_end": _ETCD_V3_ALL_RANGE_KEY_B64,
                                "count_only": True,
                            }
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
                            "ok": (
                                True
                                if candidate_token is not None
                                else False
                                if str(err or "").lower() in {"invalid credentials", "authentication failed"}
                                else None
                            ),
                            "error": err,
                        }
                    )
                    if candidate_token is not None and auth_token is not None:
                        try:
                            count_status, count_body = yield DetectCall(
                                _http_json_request,
                                (host, port, "POST", "/v3/kv/range", timeout),
                                {
                                    "payload": {
                                        "key": _ETCD_V3_ALL_RANGE_KEY_B64,
                                        "range_end": _ETCD_V3_ALL_RANGE_KEY_B64,
                                        "count_only": True,
                                    },
                                    "auth_token": candidate_token,
                                },
                            )
                            own_count, own_error = (
                                _parse_v3_key_count(count_body)
                                if count_status == 200
                                else (None, f"HTTP {count_status}")
                            )
                        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
                            own_count, own_error = None, _friendly_error_from_exception(exc)
                        credential_attempts[-1]["credential_capabilities"] = {
                            "key_count": own_count,
                            "key_count_error": own_error,
                        }
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
                        candidate_ok = None
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
                    if candidate_ok and v2_basic_auth is not None:
                        try:
                            count_status, count_body = yield DetectCall(
                                _http_json_request,
                                (host, port, "GET", "/v2/keys?recursive=true", timeout),
                                {"basic_auth": (user, secret)},
                            )
                            own_count = _count_v2_keys(count_body) if count_status == 200 else None
                            own_error = (
                                None if own_count is not None else f"v2 key count unavailable: HTTP {count_status}"
                            )
                        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
                            own_count, own_error = None, _friendly_error_from_exception(exc)
                        credential_attempts[-1]["credential_capabilities"] = {
                            "key_count": own_count,
                            "key_count_error": own_error,
                        }
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
                replay_timeout = timeout
                replay_options: dict[str, Any] = {"basic_auth": v2_basic_auth}
                replay_error: str | None = None
                if discovery_budget is not None:
                    bounded_timeout = discovery_budget.request_timeout(timeout)
                    if bounded_timeout is None:
                        replay_error = "time_budget" if time.monotonic() >= discovery_budget.deadline else "byte_budget"
                    else:
                        replay_timeout = bounded_timeout
                        replay_options["response_size_cap"] = min(discovery_budget.remaining_bytes, 4 * 1024 * 1024)
                if replay_error is None:
                    try:
                        v2_status, v2_body = yield DetectCall(
                            _http_json_request,
                            (host, port, "GET", "/v2/keys?recursive=true", replay_timeout),
                            replay_options,
                        )
                    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
                        if discovery_budget is not None and "HTTP response exceeds limit" in str(exc):
                            v2_status, v2_streamed_payload, replay_error, streamed_bytes = yield DetectCall(
                                _stream_v2_tree,
                                (host, port, replay_timeout, "/v2/keys?recursive=true"),
                                {"deadline": discovery_budget.deadline, "basic_auth": v2_basic_auth},
                            )
                            pre_collector_streamed_bytes += streamed_bytes
                        else:
                            v2_status = 0
                            replay_error = _friendly_error_from_exception(exc)
                    if replay_error is None and v2_status == 200:
                        key_count_v2 = (
                            _count_v2_payload(v2_streamed_payload)
                            if v2_streamed_payload is not None
                            else _count_v2_keys(v2_body)
                        )
                        key_count_v2_error = (
                            None if key_count_v2 is not None else "v2 key count response returned invalid JSON"
                        )
                    elif replay_error is None:
                        replay_error = f"v2 key count unavailable: HTTP {v2_status}"
                if replay_error is not None:
                    v2_error = replay_error
                    key_count_v2 = None
                    key_count_v2_error = replay_error

            # If we successfully authenticated, re-run the /v3/kv/range probe with
            # the token so downstream key enumeration reflects post-auth state.
            if auth_token is not None:
                try:
                    range_status, range_body = yield DetectCall(
                        _http_json_request,
                        (host, port, "POST", "/v3/kv/range", timeout),
                        {
                            "payload": {
                                "key": _ETCD_V3_ALL_RANGE_KEY_B64,
                                "range_end": _ETCD_V3_ALL_RANGE_KEY_B64,
                                "count_only": True,
                            },
                            "auth_token": auth_token,
                        },
                    )
                    if range_status == 200:
                        v3_auth_required = True  # confirmed auth-gated
                        key_count_v3, key_count_v3_error = _parse_v3_key_count(range_body)
                    else:
                        key_count_v3, key_count_v3_error = None, f"HTTP {range_status}"
                except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
                    key_count_v3, key_count_v3_error = None, _friendly_error_from_exception(exc)

            for credential_attempt in credential_attempts:
                if credential_attempt.get("ok") is True and "credential_capabilities" not in credential_attempt:
                    api_v3 = credential_attempt.get("api") == "v3"
                    credential_attempt["credential_capabilities"] = {
                        "key_count": key_count_v3 if api_v3 else key_count_v2,
                        "key_count_error": key_count_v3_error if api_v3 else key_count_v2_error,
                    }
            key_count: int | None = None
            key_count_by_api: dict[str, int | None] = {
                "v2": key_count_v2 if v2_supported else None,
                "v3": key_count_v3 if v3_supported else None,
            }
            keys: list[str] | None = None
            key_values: list[str] | None = None
            key_value_entries: list[Mapping[str, Any]] | None = None
            key_value_entries_by_api: dict[str, list[dict[str, str | None]] | None] = {}
            query_key_value: str | None = None
            query_key_entry: dict[str, str | None] | None = None
            query_key_entries_by_api: dict[str, dict[str, str | None] | None] = {}
            key_dump_error: str | None = (
                v2_error
                if v2_probe_error is not None
                or v2_streamed_payload is not None
                or v2_error in {"byte_budget", "time_budget"}
                else None
            )
            key_count_error: str | None = None
            v2_has_access = bool(v2_supported and (v2_auth_required is False or v2_basic_auth is not None))
            v3_has_access = bool(v3_supported and (v3_auth_required is False or auth_token is not None))
            api_has_access = {"v2": v2_has_access, "v3": v3_has_access}
            has_access = v2_has_access or v3_has_access
            collector = None
            if discovery_budget is not None and discover_ctx is not None:
                collector = DiscoveryCollector(
                    "etcd",
                    discover_ctx,
                    {"status": "valid_credentials" if selected_credential is not None else "open_no_auth"},
                )
                collector.bytes_read += pre_collector_streamed_bytes
                discovery_budget.collector = collector
                if key_dump_error:
                    collector.partial("v2", key_dump_error)
                if not has_access:
                    collector.partial("etcd", "access_denied")
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
                if show_keys or (dump_keys and not (discover and query_key)):
                    dump_errors: list[str] = [f"v2: {key_dump_error}"] if key_dump_error else []
                    if v2_has_access:
                        v2_entries = (
                            _dump_v2_payload(v2_streamed_payload, collector)
                            if v2_streamed_payload is not None
                            else None
                            if v2_error in {"byte_budget", "time_budget"}
                            else _dump_v2_all_from_body(v2_body)
                        )
                        key_value_entries_by_api["v2"] = v2_entries
                        if collector is not None and v2_entries is not None:
                            collector.mark_accessible_source()
                            if v2_streamed_payload is None:
                                for entry in v2_entries:
                                    key = str(entry.get("key") or "")
                                    collector.add(
                                        f"key_value_entries.{key}",
                                        {key.rsplit("/", 1)[-1]: entry.get("value")},
                                        charge=False,
                                    )
                        if v2_entries is None:
                            dump_errors.append(
                                f"v2: {v2_error}"
                                if v2_error in {"byte_budget", "time_budget"}
                                else "v2: /v2/keys returned invalid JSON"
                            )
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
                                **({"discovery_budget": discovery_budget} if discovery_budget is not None else {}),
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
                        if collector is not None:
                            api_has_access["v3"] = v3_entries is not None
                        if collector is not None and v3_entries is not None:
                            collector.mark_accessible_source()
                        if v3_dump_error:
                            dump_errors.append(f"v3: {v3_dump_error}")

                    combined_entries: list[Mapping[str, Any]] = (
                        SpoolingRecords() if discovery_budget is not None else []
                    )
                    for api_name in ("v2", "v3"):
                        api_entries = key_value_entries_by_api.get(api_name)
                        if not isinstance(api_entries, list):
                            continue
                        for item in api_entries:
                            entry = {**item, "api": api_name}
                            if isinstance(combined_entries, SpoolingRecords):
                                combined_entries.append(entry, sort_key=str(item.get("key") or ""))
                            else:
                                combined_entries.append(entry)
                    if combined_entries:
                        if show_keys:
                            if discovery_budget is not None:
                                names = SpoolingRecords()
                                with DiscoveryFrontier() as seen_names:
                                    for catalog_entry in combined_entries:
                                        name = _key_name_from_entry(catalog_entry)
                                        if name and seen_names.claim(name):
                                            names.append({"name": name}, sort_key=name)
                                keys = SpoolingStrings(str(item["name"]) for item in names)
                                keys.finish()
                            else:
                                unique_names = {_key_name_from_entry(item) for item in combined_entries}
                                keys = sorted(item for item in unique_names if item)
                            if show_keys_limit is not None:
                                if isinstance(keys, SpoolingStrings):
                                    keys = SpoolingStrings(itertools.islice(keys, max(0, show_keys_limit)))
                                    keys.finish()
                                else:
                                    keys = keys[:show_keys_limit]
                        if dump_keys:
                            entries: list[Mapping[str, Any]] = (
                                combined_entries
                                if isinstance(combined_entries, SpoolingRecords)
                                else list(combined_entries)
                            )
                            if dump_keys_limit is not None:
                                if isinstance(entries, SpoolingRecords):
                                    limited_entries = SpoolingRecords()
                                    for ordinal, entry in enumerate(entries):
                                        if ordinal >= dump_keys_limit:
                                            break
                                        limited_entries.append(entry)
                                    entries = limited_entries
                                else:
                                    entries = entries[:dump_keys_limit]
                            key_value_entries = entries
                            key_values = (
                                None
                                if discovery_budget is not None
                                else [_etcd_kv_entry_text(item) for item in entries]
                            )
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
                            discovery_budget=discovery_budget,
                            retained_payload=v2_streamed_payload if v2_error else None,
                            retained_error=v2_error if v2_streamed_payload is not None else None,
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
                            **({"discovery_budget": discovery_budget} if discovery_budget is not None else {}),
                        )
                        query_key_entries_by_api["v3"] = v3_entry
                        if one_key_error:
                            query_errors.append(f"v3: {one_key_error}")
                    for api_name in ("v2", "v3"):
                        key_entry = query_key_entries_by_api.get(api_name)
                        if key_entry:
                            query_key_entry = {**key_entry, "api": api_name}
                            query_key_value = (
                                None
                                if isinstance(key_entry.get("value"), DiskBackedText)
                                else _etcd_kv_entry_text(key_entry)
                            )
                            break
                    if query_errors:
                        query_error = "; ".join(query_errors)
                        key_dump_error = query_error if key_dump_error is None else f"{key_dump_error}; {query_error}"

            api_versions = _join_api_versions(v2_supported=v2_supported, v3_supported=v3_supported)

            errors = [item for item in (v2_error, v3_error) if item]
            if key_dump_error:
                errors.append(key_dump_error)
            if collector is not None and key_dump_error:
                collector.partial("etcd", key_dump_error.replace("authentication required", "access_denied"))
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

            if selected_credential is not None and (auth_token is not None or v2_basic_auth is not None):
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
                **({"content_discovery": collector.result()} if collector is not None else {}),
                "provided_credentials": provided_credentials,
                "provided_username": provided_username,
                "provided_password": provided_password,
                "provided_credentials_ok": (
                    None
                    if not provided_credentials
                    else True
                    if selected_credential is not None and not selected_credential.get("default")
                    else False
                    if any(attempt.get("source") != "default" for attempt in credential_attempts)
                    and all(
                        attempt.get("ok") is False
                        for attempt in credential_attempts
                        if attempt.get("source") != "default"
                    )
                    else None
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
                "dump_error": key_dump_error,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "error": error,
            }
        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
            last_error = _friendly_error_from_exception(exc)
            if attempt >= attempts - 1:
                break
            (yield DetectDelay(_retry_delay(attempt)))

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
        return ""

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

    runtime_attempts = record.get("attempted_credentials")
    attempts_raw = record.get("credential_attempts")
    if isinstance(runtime_attempts, list) and runtime_attempts:
        attempts_raw = [
            {**attempt, "ok": str(attempt.get("status") or "") in {"valid_credentials", "weak_default_creds"}}
            for attempt in runtime_attempts
            if isinstance(attempt, dict)
        ]
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
        if attempt.get("ok") is None:
            continue
        raw_username = attempt.get("username")
        raw_password = attempt.get("password")
        username = str(raw_username or "-")
        password = "<none>" if raw_password is None else "<empty>" if raw_password == "" else str(raw_password)
        if attempt.get("ok") is False:
            lines.append(f"{prefix} [-] {username}:{password}")
            continue

        line = f"{prefix} [+] {username}:{password}"
        selected = (
            effective_username is not None
            and str(raw_username or "-") == str(effective_username)
            and raw_password == effective_password
        )
        capabilities = attempt_capabilities(record, attempt, selected=selected)
        key_count = capabilities.get("key_count")
        if isinstance(key_count, int):
            line = f"{line} (keys:{format_count_value(key_count)})"
        else:
            count_error = _clip(str(capabilities.get("key_count_error") or "unknown count"), 72)
            line = f"{line} (keys:unknown) err={count_error}"
        lines.append(line)
    return lines


def _format_keys_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if record.get("_etcd_keys_streamed"):
        return []
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
    dumped_by_key: dict[str, list[tuple[int, str]]] = {}
    for index, entry in enumerate(dumped_key_entries):
        if entry.get("key") is not None:
            dumped_by_key.setdefault(str(entry["key"]), []).append((index, _etcd_kv_entry_text(entry)))
    emitted_entries: set[int] = set()
    if show_keys and key_names:
        total = record.get("key_count")
        if show_keys_limit is not None and isinstance(total, int) and total > len(displayed_key_names):
            lines.append(f"{prefix} [*] Keys Enumeration (showing:{len(displayed_key_names)} of {total})")
        else:
            lines.append(f"{prefix} [*] Keys Enumeration")
        for item in displayed_key_names:
            lines.append(f"{prefix} {_format_etcd_text(item)}")
            if dump_keys:
                for index, value in dumped_by_key.get(item, []):
                    lines.append(f"{prefix} {_format_etcd_text(value)}")
                    emitted_entries.add(index)
    if query_key and isinstance(query_key_value, str):
        lines.append(f"{prefix} [*] Dump Key {query_key}")
        lines.append(f"{prefix} {_format_etcd_text(query_key_value)}")
    if dump_keys and dumped_key_values and (not show_keys or len(emitted_entries) < len(dumped_key_values)):
        lines.append(f"{prefix} [*] Dump Keys")
        remaining = (
            [
                _etcd_kv_entry_text(entry)
                for index, entry in enumerate(dumped_key_entries)
                if index not in emitted_entries
            ]
            if dumped_key_entries
            else dumped_key_values
        )
        for item in remaining:
            lines.append(f"{prefix} {_format_etcd_text(item)}")
    return lines


def _spool_keys_details(record: dict[str, Any], *, dump_values: bool) -> str:
    """Render the disk catalog without making parallel lists of every value."""
    prefix = _nxc_prefix(record)
    show_keys = bool(record.get("show_keys"))
    limit = record.get("show_keys_limit")
    rows = record.get("key_value_entries") or []
    escapes = {index: f"\\u{index:04x}" for index in range(32)}
    escapes.update({9: "\\t", 10: "\\n", 13: "\\r"})
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix="redposture-etcd-dump-", delete=False
    ) as output:
        path = output.name

        def value_line(entry: Mapping[str, Any]) -> None:
            output.write(prefix + " ")
            key = str(entry.get("key") or "")
            output.write(key.translate(escapes) + ":")
            value = entry.get("value")
            if entry.get("error"):
                value = "<" + str(entry["error"]) + ">"
            chunks = (
                value.iter_text_chunks()
                if isinstance(value, DiskBackedText)
                else (
                    str(value or "")[position : position + 65536] for position in range(0, len(str(value or "")), 65536)
                )
            )
            for chunk in chunks:
                output.write(chunk.translate(escapes))
            output.write("\n")

        try:
            if show_keys and rows:
                total = record.get("key_count")
                suffix = (
                    f" (showing:{limit} of {total})"
                    if isinstance(limit, int) and isinstance(total, int) and total > limit
                    else ""
                )
                output.write(f"{prefix} [*] Keys Enumeration{suffix}\n")
            if dump_values and rows and not show_keys:
                output.write(f"{prefix} [*] Dump Keys\n")
            remaining = SpoolingRecords()
            current_key: str | None = None
            shown = 0
            show_current = False
            for entry in rows:
                key = str(entry.get("key") or "")
                if key != current_key:
                    show_current = show_keys and (not isinstance(limit, int) or shown < limit)
                    current_key = key
                    if show_current:
                        shown += 1
                        output.write(prefix + " " + key.translate(escapes) + "\n")
                if dump_values:
                    if not show_keys or show_current:
                        value_line(entry)
                    else:
                        remaining.append(entry)
            if remaining:
                output.write(f"{prefix} [*] Dump Keys\n")
                for entry in remaining:
                    value_line(entry)
            if record.get("query_key") and isinstance(record.get("query_key_entry"), dict):
                output.write(f"{prefix} [*] Dump Key {record['query_key']}\n")
                value_line(record["query_key_entry"])
        except BaseException:
            Path(path).unlink(missing_ok=True)
            raise
    return path


def _render_colored_etcd_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(
        console,
        line,
        tag="ETCD",
        counts=(CountColorRule("keys", "true_red", unknown_color="orange", zero_color="bright_green"),),
    ):
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
    proxy: Any | None = None,
    discover: bool = False,
    discover_time: float | None = None,
    discover_max_bytes: int | None = None,
    discover_ctx: Any | None = None,
    lifecycle_state: Any | None = None,
) -> dict[str, Any]:
    return run_sync(
        _detect_call_audit_etcd_host_with_stage_debug_steps(
            host,
            port,
            timeout,
            retries,
            show_keys,
            dump_keys,
            query_key,
            show_keys_limit,
            dump_keys_limit,
            dump_batch,
            dump_delay,
            username=username,
            password=password,
            defcreds=defcreds,
            credential_candidates=credential_candidates,
            run_deep_checks=run_deep_checks,
            debug=debug,
            debug_emit=debug_emit,
            target_spec=target_spec,
            proxy=proxy,
            discover=discover,
            discover_time=discover_time,
            discover_max_bytes=discover_max_bytes,
            discover_ctx=discover_ctx,
            lifecycle_state=lifecycle_state,
        )
    )


def _detect_call_audit_etcd_host_with_stage_debug_steps(
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
    proxy: Any | None = None,
    discover: bool = False,
    discover_time: float | None = None,
    discover_max_bytes: int | None = None,
    discover_ctx: Any | None = None,
    lifecycle_state: Any | None = None,
) -> Any:
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
    if discover and run_deep_checks:
        audit_kwargs["discover"] = True
        audit_kwargs["discover_time"] = discover_time
        audit_kwargs["discover_max_bytes"] = discover_max_bytes
        if discover_ctx is not None:
            audit_kwargs["discover_ctx"] = discover_ctx
    if credential_candidates:
        audit_kwargs["credential_candidates"] = credential_candidates
    target_scheme = str(getattr(target_spec, "scheme", "") or "").lower()
    # `_audit_etcd_host` owns the command retry budget. The reusable transport
    # must not retry again inside every outer attempt (which would square the
    # number of sockets and TLS handshakes).
    external_state = lifecycle_state if isinstance(lifecycle_state, _EtcdHttpLifecycle) else None
    transport_state = (
        external_state
        or getattr(_ETCD_HTTP_LOCAL, "native_state", None)
        or _EtcdHttpLifecycle(
            pool=HttpSessionPool(timeout=timeout, insecure=True, proxy=proxy),
            scheme=target_scheme if target_scheme in {"http", "https"} else None,
            host=str(host),
            port=int(port),
        )
    )
    _ETCD_HTTP_LOCAL.state = transport_state
    with http_target_context(
        target_spec,
        api_prefixes=("/version", "/v2", "/v3", "/v3beta", "/v3alpha"),
        route_state=transport_state,
    ):
        try:
            try:
                record = yield DetectCall(
                    _audit_etcd_host,
                    (
                        host,
                        port,
                        timeout,
                        retries,
                        show_keys if run_deep_checks else False,
                        dump_keys if run_deep_checks else False,
                        query_key if run_deep_checks else None,
                    ),
                    {**audit_kwargs},
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
                record = yield DetectCall(
                    _audit_etcd_host,
                    (
                        host,
                        port,
                        timeout,
                        retries,
                        show_keys if run_deep_checks else False,
                        dump_keys if run_deep_checks else False,
                        query_key if run_deep_checks else None,
                    ),
                    {**audit_kwargs},
                )
        finally:
            if external_state is None:
                transport_state.pool.close()
            try:
                delattr(_ETCD_HTTP_LOCAL, "state")
            except AttributeError:
                pass

    result: dict[str, Any] = dict(record)
    if (
        discover_ctx is not None
        and run_deep_checks
        and str(getattr(discover_ctx.args, "output_format", "txt")) == "txt"
        and (
            isinstance(result.get("key_value_entries"), SpoolingRecords)
            or isinstance((result.get("query_key_entry") or {}).get("value"), DiskBackedText)
        )
        and (show_keys or not getattr(discover_ctx.args, "_discover_implicit_dump", False))
    ):
        result["_stream_lines_file"] = _spool_keys_details(
            result, dump_values=not getattr(discover_ctx.args, "_discover_implicit_dump", False)
        )
        result["_etcd_keys_streamed"] = True
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
    if status in {"valid_credentials", "weak_default_creds"}:
        result["credential_capabilities"] = {
            key: result.get(key) for key in ("key_count", "key_count_by_api", "key_count_state", "key_count_error")
        }
    return telemetry.attach(result, status=status, total_ms=elapsed_ms)


def _merge_stage2_record(detect_record: dict[str, Any], deep_record: dict[str, Any]) -> dict[str, Any]:
    return merge_stage_records(detect_record, deep_record)


# Typed runner boundary -----------------------------------------------------
host_stage = _call_audit_etcd_host_with_stage_debug


_ASYNC_DETECT_STEPS: dict[Any, Any] = {
    _call_audit_etcd_host_with_stage_debug: _detect_call_audit_etcd_host_with_stage_debug_steps,
    _audit_etcd_host: _detect_audit_etcd_host_steps,
    _http_json_request: _detect_http_json_request_steps,
}
