"""Elasticsearch audit stage."""

from __future__ import annotations

import base64
import gzip
import json
import re
import ssl
import threading
import time
import zlib
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any

from ...clients.http_api import HttpApiClient, HttpClientConfig
from ...console import Console
from ...rendering import BooleanColorRule, render_colored_marker_line, render_tagged_detail_line
from ...utils import (
    is_signature_compat_typeerror,
    utc_now_iso,
)
from .discover import DiscoverReport, DiscoverRequest, DiscoverResponse, run_discovery
from .http_session import ElasticHttpSession

_ELASTIC_TAG = "ELASTIC"
_DISCOVER_QUERY_SIZE = 200
_DISCOVER_MAX_PRINT_PER_INDEX = 200
_TRANSPORT_DIAGNOSTIC_HEADER = "__redposture_transport_error__"
_RESPONSE_TRUNCATED_HEADER = "__redposture_response_truncated__"
_DETECT_EXTENDED_TIMEOUT = 2.5
_DETECT_CONFIRM_PATHS = (
    "/_nodes?filter_path=nodes.*.version",
    "/_security/_authenticate",
    "/_plugins/_security/authinfo",
    "/_cluster/health",
    "/_cat/health",
)
_TLS_HINT_PORTS = frozenset({443, 4443, 6443, 8443, 8501, 9243})

_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_THREAD_LOCAL_DEBUG_EMIT = threading.local()
_THREAD_LOCAL_ELASTIC_SESSION = threading.local()
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
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "changeme"),
    ("opensearch", "opensearch"),
    ("opensearch", "password"),
    ("kibana", "kibana"),
    ("kibana", "changeme"),
    ("logstash", "logstash"),
    ("logstash_system", "changeme"),
)
_AUTH_UNSUPPORTED_REASON_RE = re.compile(
    r"(?:"
    r"no handler found|unknown (?:api|endpoint)|"
    r"(?:authenticate|authentication|security|auth) (?:api|endpoint|plugin)?.*"
    r"(?:disabled|not (?:available|found|installed)|unavailable|unsupported)|"
    r"(?:endpoint|api|plugin).*(?:disabled|not (?:available|found|installed)|unavailable|unsupported)"
    r")",
    re.IGNORECASE,
)


@dataclass
class ElasticLifecycleState:
    """Anonymous classification plus per-candidate authorization headers."""

    detect_record: dict[str, Any] | None = None
    auth_headers: dict[tuple[str | None, str | None, str | None, str], dict[str, str]] = dataclass_field(
        default_factory=dict
    )
    supported_auth_endpoint: str | None = None
    unsupported_auth_endpoints: set[str] = dataclass_field(default_factory=set)
    unsupported_auth_details: dict[str, dict[str, Any]] = dataclass_field(default_factory=dict)
    session: ElasticHttpSession | None = None


@dataclass(frozen=True)
class ElasticAuthProbeResult:
    """Identity-aware result of one Elasticsearch/OpenSearch auth probe."""

    valid: bool | None
    error: str | None
    username: str | None
    status: int
    endpoint: str
    detail: dict[str, Any] | None = None
    network_attempted: bool = True
    verification_capability: str = "indeterminate"


def _redact_exact_secrets(value: Any, secrets: Iterable[str]) -> Any:
    """Recursively remove exact secret strings from diagnostic values."""

    candidates = sorted({secret for secret in secrets if secret}, key=len, reverse=True)
    if not candidates:
        return value
    if isinstance(value, str):
        redacted = value
        for secret in candidates:
            redacted = redacted.replace(secret, "<redacted>")
        return redacted
    if isinstance(value, dict):
        return {
            _redact_exact_secrets(key, candidates): _redact_exact_secrets(item, candidates)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_exact_secrets(item, candidates) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_exact_secrets(item, candidates) for item in value)
    return value


def _redact_api_token(value: Any, api_token: str | None) -> Any:
    if not api_token:
        return value
    return _redact_exact_secrets(value, (f"ApiKey {api_token}", api_token))


def _redact_auth_probe_result(
    result: ElasticAuthProbeResult,
    api_token: str | None,
) -> ElasticAuthProbeResult:
    if not api_token:
        return result
    redacted_detail = _redact_api_token(result.detail, api_token)
    return ElasticAuthProbeResult(
        valid=result.valid,
        error=_redact_api_token(result.error, api_token),
        username=_redact_api_token(result.username, api_token),
        status=result.status,
        endpoint=result.endpoint,
        detail=redacted_detail if isinstance(redacted_detail, dict) else None,
        network_attempted=result.network_attempted,
        verification_capability=result.verification_capability,
    )


def _redact_auth_state_details(state: ElasticLifecycleState, api_token: str | None) -> None:
    if not api_token:
        return
    for endpoint, detail in tuple(state.unsupported_auth_details.items()):
        redacted = _redact_api_token(detail, api_token)
        state.unsupported_auth_details[endpoint] = redacted if isinstance(redacted, dict) else {}


def _auth_probe_status(result: ElasticAuthProbeResult) -> str:
    if result.valid is True:
        return "verified"
    if result.valid is False:
        return "rejected"
    if result.status == 0:
        return "error"
    return "unverified"


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
    from ...utils import friendly_error_text

    return friendly_error_text(value)


def _friendly_error_from_exception(exc: BaseException) -> str:
    from ...utils import friendly_error_from_exception

    return friendly_error_from_exception(exc)


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
        "connection reset",
        "connection aborted",
        "broken pipe",
        "remote end closed",
        "unexpected eof",
        "closed (eof)",
        "ssleoferror",
    )
    return any(token in lower for token in tokens)


def _is_permanent_transport_error(error_text: str) -> bool:
    lower = str(error_text or "").lower()
    markers = (
        "connection refused",
        "no route to host",
        "network unreachable",
        "host is down",
        "name or service not known",
        "nodename nor servname",
        "temporary failure in name resolution",
        "getaddrinfo",
    )
    return any(marker in lower for marker in markers)


def _is_transient_transport_error(error_text: str) -> bool:
    lower = str(error_text or "").lower()
    markers = (
        "timed out",
        "timeout",
        "temporarily unavailable",
        "connection reset",
        "connection aborted",
        "broken pipe",
        "unexpected eof",
        "remote end closed",
    )
    return any(marker in lower for marker in markers)


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


@contextmanager
def _elastic_session_scope(session: ElasticHttpSession | None) -> Iterator[None]:
    """Expose a direct per-target session to legacy request helpers."""

    sentinel = object()
    previous = getattr(_THREAD_LOCAL_ELASTIC_SESSION, "session", sentinel)
    if session is None:
        try:
            delattr(_THREAD_LOCAL_ELASTIC_SESSION, "session")
        except AttributeError:
            pass
    else:
        _THREAD_LOCAL_ELASTIC_SESSION.session = session
    try:
        yield
    finally:
        if previous is sentinel:
            try:
                delattr(_THREAD_LOCAL_ELASTIC_SESSION, "session")
            except AttributeError:
                pass
        else:
            _THREAD_LOCAL_ELASTIC_SESSION.session = previous


def _active_elastic_session(host: str, port: int) -> ElasticHttpSession | None:
    session = getattr(_THREAD_LOCAL_ELASTIC_SESSION, "session", None)
    if not isinstance(session, ElasticHttpSession):
        return None
    normalized_host = str(host or "").strip().strip("[]")
    if session.host != normalized_host or session.port != int(port):
        return None
    return session


def _http_url_host(host: str) -> str:
    normalized = str(host or "").strip()
    if ":" in normalized and not normalized.startswith("["):
        return f"[{normalized}]"
    return normalized


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
    req_headers = {"User-Agent": "RedPosture/1.0"}
    if headers:
        req_headers.update(headers)
    active_session = _active_elastic_session(host, port)
    if active_session is not None:
        response = active_session.request(
            scheme,
            method,
            path,
            headers=req_headers,
            data=data,
        )
    else:
        url = f"{scheme}://{_http_url_host(host)}:{port}{path}"
        response = HttpApiClient(
            HttpClientConfig(
                timeout=timeout,
                insecure=bool(use_https and insecure),
                ca_file=ca_file if use_https and ca_file else None,
                response_size_cap=10 * 1024 * 1024,
            )
        ).request(method, url, headers=req_headers, body=data, timeout=timeout)
    if response.error:
        return 0, b"", {}, str(response.error)
    response_headers = dict(response.headers)
    if response.truncated:
        response_headers[_RESPONSE_TRUNCATED_HEADER] = "true"
    return int(response.status), response.body, response_headers, None


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
    allow_fallback: bool = True,
) -> tuple[int, bytes, dict[str, str], str | None, str, bool, bool]:
    normalized_scheme = str(preferred_scheme or "").strip().lower()
    if normalized_scheme not in {"http", "https"}:
        normalized_scheme = "https"
    first_use_https = normalized_scheme == "https"
    second_use_https = not first_use_https
    first_scheme = "https" if first_use_https else "http"
    second_scheme = "http" if first_use_https else "https"
    first_insecure = bool(first_use_https and not ca_file)
    second_insecure = bool(second_use_https and not ca_file)

    status, payload, response_headers, error = _elastic_request(
        host,
        port,
        path,
        timeout,
        use_https=first_use_https,
        insecure=first_insecure,
        ca_file=ca_file if first_use_https else None,
        method=method,
        headers=headers,
        data=data,
    )
    if status > 0:
        return status, payload, response_headers, error, first_scheme, first_insecure, False

    first_error = str(error or "").strip() or "connection failed"
    if not allow_fallback or not _is_tls_or_protocol_error(first_error):
        return (
            status,
            payload,
            response_headers,
            f"{first_scheme}={first_error}",
            first_scheme,
            first_insecure,
            False,
        )

    fallback_status, fallback_payload, fallback_headers, fallback_error = _elastic_request(
        host,
        port,
        path,
        timeout,
        use_https=second_use_https,
        insecure=second_insecure,
        ca_file=ca_file if second_use_https else None,
        method=method,
        headers=headers,
        data=data,
    )
    if fallback_status > 0:
        diagnostic_headers = dict(fallback_headers)
        if str(error or "").strip():
            diagnostic_headers[_TRANSPORT_DIAGNOSTIC_HEADER] = f"{first_scheme}={error}"
        return (
            fallback_status,
            fallback_payload,
            diagnostic_headers,
            fallback_error,
            second_scheme,
            second_insecure,
            first_scheme == "https" and second_scheme == "http",
        )

    second_error = str(fallback_error or "").strip() or "connection failed"
    combined_error = f"{first_scheme}={first_error}; {second_scheme}={second_error}"
    return (
        fallback_status,
        fallback_payload,
        fallback_headers,
        combined_error,
        second_scheme,
        second_insecure,
        first_scheme == "https" and second_scheme == "http",
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


def _normalize_vendor(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"elasticsearch", "opensearch"}:
        return normalized
    return "compatible"


def _api_label(record: Mapping[str, Any]) -> str:
    vendor = _normalize_vendor(record.get("vendor"))
    if vendor == "elasticsearch":
        return "Elasticsearch API"
    if vendor == "opensearch":
        return "OpenSearch API"
    return "Elasticsearch-compatible API"


def _parse_elastic_error(status: int, payload: bytes) -> dict[str, Any]:
    """Preserve an Elasticsearch/OpenSearch error without leaking whole bodies."""

    parsed = _load_json_dict_loose(payload)
    error_type: str | None = None
    reason: str | None = None
    root_causes: list[dict[str, str]] = []
    if isinstance(parsed, dict):
        error_obj = parsed.get("error")
        if isinstance(error_obj, dict):
            raw_type = error_obj.get("type")
            raw_reason = error_obj.get("reason")
            error_type = str(raw_type).strip() if raw_type is not None and str(raw_type).strip() else None
            reason = str(raw_reason).strip() if raw_reason is not None and str(raw_reason).strip() else None
            raw_causes = error_obj.get("root_cause")
            if isinstance(raw_causes, list):
                for raw_cause in raw_causes:
                    if not isinstance(raw_cause, dict):
                        continue
                    cause_type = str(raw_cause.get("type") or "").strip()
                    cause_reason = str(raw_cause.get("reason") or "").strip()
                    if cause_type or cause_reason:
                        root_causes.append(
                            {
                                "type": cause_type or "unknown",
                                "reason": cause_reason or "-",
                            }
                        )
        elif isinstance(error_obj, str) and error_obj.strip():
            reason = error_obj.strip()
        if reason is None:
            message = parsed.get("message")
            if isinstance(message, str) and message.strip():
                reason = message.strip()

    if reason is None and payload:
        body_text = payload.decode("utf-8", errors="replace").strip()
        if body_text:
            reason = _clip(re.sub(r"\s+", " ", body_text), 240)

    detail: dict[str, Any] = {
        "status": int(status),
        "type": error_type or "http_error",
        "reason": reason or f"status={int(status)}",
        "root_cause": root_causes,
    }
    return detail


def _format_elastic_error_detail(detail: Mapping[str, Any] | None) -> str:
    if not isinstance(detail, Mapping):
        return ""
    status = int(detail.get("status") or 0)
    error_type = str(detail.get("type") or "http_error").strip()
    reason = str(detail.get("reason") or f"status={status}").strip()
    parts = []
    if status:
        parts.append(f"status={status}")
    if error_type:
        parts.append(f"type={error_type}")
    if reason:
        parts.append(f"reason={reason}")
    root_causes = detail.get("root_cause")
    if isinstance(root_causes, list):
        formatted_causes: list[str] = []
        for cause in root_causes[:3]:
            if not isinstance(cause, Mapping):
                continue
            cause_type = str(cause.get("type") or "unknown").strip()
            cause_reason = str(cause.get("reason") or "-").strip()
            formatted_causes.append(f"{cause_type}:{cause_reason}")
        if formatted_causes:
            parts.append(f"root_cause={_clip(' | '.join(formatted_causes), 240)}")
    return " ".join(parts)


def _transport_errors_from_combined(error: str | None) -> dict[str, str]:
    text = str(error or "").strip()
    if not text:
        return {}
    matches = list(
        re.finditer(
            r"(?:^|;\s*)(https?)=(.*?)(?=;\s*https?=|$)",
            text,
            flags=re.IGNORECASE | re.DOTALL,
        )
    )
    if not matches:
        return {"unknown": text}
    return {match.group(1).lower(): match.group(2).strip() for match in matches}


def _transport_error_kind(errors: Mapping[str, Any]) -> str | None:
    text = " ".join(str(value) for value in errors.values()).lower()
    if not text:
        return None
    peer_closed = any(
        marker in text
        for marker in (
            "closed (eof)",
            "unexpected eof",
            "broken pipe",
            "remote end closed",
            "connection reset",
        )
    )
    if peer_closed:
        return "peer_closed_before_http_response"
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if "refused" in text:
        return "connection_refused"
    return "transport_error"


def _collect_detect_transport_errors(probes: list[dict[str, Any]]) -> dict[str, str]:
    collected: dict[str, str] = {}
    for probe in probes:
        error = probe.get("transport_error") or probe.get("error")
        if not isinstance(error, str) or not error.strip():
            continue
        parsed = _transport_errors_from_combined(error)
        if parsed:
            for scheme, message in parsed.items():
                collected.setdefault(str(scheme), str(message))
            continue
        scheme = str(probe.get("scheme") or "unknown")
        collected.setdefault(scheme, error.strip())
    return collected


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
    vendor: str | None = None

    if error and status <= 0:
        return {"signal_kind": kind, "signals": signals, "version": version, "vendor": vendor}

    body = _load_json_dict_loose(payload, headers)
    opensearch_marker = _detect_opensearch_marker(headers, body)
    if opensearch_marker:
        version = _extract_version_from_body_dict(body) if isinstance(body, dict) else None
        return {
            "signal_kind": "hard_positive",
            "signals": [opensearch_marker],
            "version": version,
            "vendor": "opensearch",
        }

    product_header = _header_lookup(headers, "X-Elastic-Product")
    if isinstance(product_header, str) and product_header.strip().lower() == "elasticsearch":
        signals.append("header_x_elastic_product")
        kind = "hard_positive"
        vendor = "elasticsearch"

    if isinstance(body, dict):
        version = _extract_version_from_body_dict(body)

        if path == "/":
            tagline = str(body.get("tagline") or "").strip()
            if tagline == "You Know, for Search":
                if "root_tagline" not in signals:
                    signals.append("root_tagline")
                kind = "hard_positive"
                vendor = vendor or "elasticsearch"
            if version and (body.get("cluster_name") is not None or body.get("name") is not None):
                if "root_version_shape" not in signals:
                    signals.append("root_version_shape")
                kind = "hard_positive"
            if status in {401, 403} and _is_elastic_auth_error_payload(body):
                if "security_exception_missing_auth" not in signals:
                    signals.append("security_exception_missing_auth")
                kind = "hard_positive"
                vendor = vendor or "elasticsearch"

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
                vendor = "elasticsearch"
            elif kind != "hard_positive":
                username = body.get("username")
                if isinstance(username, str) and username.strip():
                    signals.append("authenticate_username_shape")
                    kind = "soft_positive"
                    vendor = "elasticsearch"

        elif path == "/_plugins/_security/authinfo":
            username = body.get("user_name")
            user_repr = body.get("user")
            if status == 200 and (
                isinstance(username, str) and username.strip() or isinstance(user_repr, str) and user_repr.strip()
            ):
                signals.append("opensearch_authinfo_shape")
                kind = "hard_positive"
                vendor = "opensearch"
            elif status in {401, 403}:
                error_text = json.dumps(body, ensure_ascii=False).lower()
                if "unauthorized" in error_text or "authentication" in error_text:
                    signals.append("opensearch_authinfo_auth_required")
                    kind = "soft_positive"
                    vendor = "opensearch"

    elif path == "/_cat/health":
        text = payload.decode("utf-8", errors="replace").strip().lower()
        if status == 200 and "cluster" in text and "status" in text:
            signals.append("cat_health_text_shape")
            kind = "soft_positive"

    if path == "/" and kind == "neutral" and _looks_like_non_json_gateway_payload(payload, headers):
        signals.append("root_non_json_payload")
        kind = "hard_negative"

    return {"signal_kind": kind, "signals": signals, "version": version, "vendor": vendor}


def _request_detect_probe(
    host: str,
    port: int,
    path: str,
    timeout: float,
    *,
    preferred_scheme: str,
    ca_file: str | None,
    allow_fallback: bool = True,
) -> tuple[int, bytes, dict[str, str], str | None, str]:
    use_https = preferred_scheme == "https"
    insecure = bool(use_https and not ca_file)
    status, payload, headers, error = _elastic_request(
        host,
        port,
        path,
        timeout,
        use_https=use_https,
        insecure=insecure,
        ca_file=ca_file if use_https else None,
    )
    if status > 0:
        return status, payload, headers, error, preferred_scheme

    primary_error = str(error or "").strip() or "connection failed"
    if not allow_fallback or not _is_tls_or_protocol_error(primary_error):
        return status, payload, headers, f"{preferred_scheme}={primary_error}", preferred_scheme

    fallback_scheme = "http" if preferred_scheme == "https" else "https"
    fallback_https = fallback_scheme == "https"
    fallback_insecure = bool(fallback_https and not ca_file)
    fallback_status, fallback_payload, fallback_headers, fallback_error = _elastic_request(
        host,
        port,
        path,
        timeout,
        use_https=fallback_https,
        insecure=fallback_insecure,
        ca_file=ca_file if fallback_https else None,
    )
    if fallback_status > 0:
        diagnostic_headers = dict(fallback_headers)
        if str(error or "").strip():
            diagnostic_headers[_TRANSPORT_DIAGNOSTIC_HEADER] = f"{preferred_scheme}={error}"
        return fallback_status, fallback_payload, diagnostic_headers, fallback_error, fallback_scheme

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
    else:
        detected = False
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

    vendors = {
        str(probe.get("vendor") or "").strip().lower()
        for probe in hard_positive + soft_positive + probes
        if str(probe.get("vendor") or "").strip().lower() in {"elasticsearch", "opensearch"}
    }
    root_explicit_vendor: str | None = None
    has_elasticsearch_product_marker = False
    has_opensearch_specific_marker = False
    for probe in probes:
        probe_signals = {str(signal) for signal in (probe.get("signals") or [])}
        path = str(probe.get("path") or "")
        if path == "/" and any(signal.startswith("vendor_opensearch_") for signal in probe_signals):
            root_explicit_vendor = "opensearch"
            break
        if path == "/" and {"header_x_elastic_product", "root_tagline"} & probe_signals:
            root_explicit_vendor = "elasticsearch"
        if "header_x_elastic_product" in probe_signals:
            has_elasticsearch_product_marker = True
        if any(signal.startswith("vendor_opensearch_") for signal in probe_signals) or any(
            signal.startswith("opensearch_authinfo_") for signal in probe_signals
        ):
            has_opensearch_specific_marker = True

    if root_explicit_vendor is not None:
        vendor = root_explicit_vendor
    elif has_elasticsearch_product_marker:
        vendor = "elasticsearch"
    elif has_opensearch_specific_marker:
        vendor = "opensearch"
    else:
        vendor = next(iter(vendors)) if len(vendors) == 1 else "compatible"

    return {
        "detected": detected,
        "confidence": confidence,
        "signals": signals,
        "primary_probe": primary_probe,
        "has_hard_negative": bool(hard_negative),
        "has_positive": bool(hard_positive or soft_positive),
        "version": version,
        "vendor": vendor,
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


def _build_discover_query_string(keywords: Iterable[str] | None = None) -> str:
    tokens: list[str] = []
    seen: set[str] = set()
    for keyword in keywords if keywords is not None else _DISCOVER_KEYWORDS:
        clean = str(keyword).strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        escaped = re.sub(r'([+\-=|><!(){}\[\]^"~*?:\\/])', r"\\\1", clean)
        if re.search(r"\s", clean):
            tokens.append(f'"{escaped}"')
        else:
            tokens.append(escaped)
    return " | ".join(tokens)


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


def _list_index_names_detailed(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
) -> tuple[list[str] | None, str | None, dict[str, Any] | None]:
    paths = (
        "/_cat/indices?format=json&expand_wildcards=open,hidden&h=index,status",
        "/_cat/indices?format=json&expand_wildcards=all&h=index,status",
    )
    last_detail: dict[str, Any] | None = None
    for path_index, path in enumerate(paths):
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
        if error:
            detail = {
                "status": 0,
                "type": "transport_error",
                "reason": error,
                "root_cause": [],
            }
            return None, error, detail
        if status in {401, 403}:
            detail = _parse_elastic_error(status, payload)
            return None, "Access Denied", detail
        if status != 200:
            last_detail = _parse_elastic_error(status, payload)
            if path_index == 0 and status in {400, 404}:
                continue
            return None, _format_elastic_error_detail(last_detail), last_detail

        payload_list = _load_json_list(payload)
        if payload_list is None:
            detail = {
                "status": status,
                "type": "invalid_indices_payload",
                "reason": "invalid indices payload",
                "root_cause": [],
            }
            return None, "invalid indices payload", detail

        indices: list[str] = []
        seen: set[str] = set()
        for item in payload_list:
            if not isinstance(item, dict):
                continue
            index_status = str(item.get("status") or "open").strip().lower()
            if index_status in {"close", "closed"}:
                continue
            name = str(item.get("index") or "").strip()
            if not name or name in seen:
                continue
            seen.add(name)
            indices.append(name)
        indices.sort()
        return indices, None, None

    return None, _format_elastic_error_detail(last_detail), last_detail


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
    indices, error, _detail = _list_index_names_detailed(
        host,
        port,
        timeout,
        scheme=scheme,
        insecure=insecure,
        ca_file=ca_file,
        auth_headers=auth_headers,
    )
    return indices, error


def _search_index_detailed(
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
) -> dict[str, Any]:
    """Compatibility adapter backed by the mapping-aware v2 engine.

    ``query_string`` is intentionally ignored: callers retain their previous
    signature without reintroducing parser-based wildcard searches.
    """

    _ = query_string
    report = _collect_discover_report(
        host,
        port,
        timeout,
        scheme=scheme,
        insecure=insecure,
        ca_file=ca_file,
        auth_headers=auth_headers,
    )
    for result in report.legacy_results:
        if str(result.get("index") or "") == index_name:
            return result
    return {
        "index": index_name,
        "total_hits": 0,
        "total_hits_relation": "unknown" if report.error else "exact",
        "shown_hits": 0,
        "truncated": bool(report.error),
        "hits": [],
        "error": report.error,
        "error_detail": report.error_detail,
        "retried": False,
        "retry_chunks": 0,
        "partial_error_details": [],
    }


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
    result = _search_index_detailed(
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
    hits = result.get("hits")
    return (
        int(result.get("total_hits") or 0),
        [item for item in hits if isinstance(item, dict)] if isinstance(hits, list) else None,
        str(result.get("error")) if result.get("error") else None,
    )


def _collect_discover_report(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
    vendor: str | None = None,
) -> DiscoverReport:
    """Run the v2 discovery engine while preserving the module HTTP policy."""

    def _request(request: DiscoverRequest) -> DiscoverResponse:
        request_headers = dict(auth_headers)
        request_headers.update(request.headers)
        status, payload, response_headers, error = _elastic_request(
            host,
            port,
            request.path,
            timeout,
            use_https=scheme == "https",
            insecure=insecure,
            ca_file=ca_file,
            method=request.method,
            headers=request_headers,
            data=request.body,
        )
        normalized_headers = dict(response_headers)
        truncated = normalized_headers.pop(_RESPONSE_TRUNCATED_HEADER, "").strip().lower() == "true"
        return DiscoverResponse(
            status=status,
            payload=payload,
            headers=normalized_headers,
            error=error,
            truncated=truncated,
        )

    return run_discovery(_request, vendor=_normalize_vendor(vendor))


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
    report = _collect_discover_report(
        host,
        port,
        timeout,
        scheme=scheme,
        insecure=insecure,
        ca_file=ca_file,
        auth_headers=auth_headers,
    )
    return report.legacy_results, report.error


def _collect_discover_results_detailed(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
) -> tuple[list[dict[str, Any]] | None, str | None, dict[str, Any] | None]:
    report = _collect_discover_report(
        host,
        port,
        timeout,
        scheme=scheme,
        insecure=insecure,
        ca_file=ca_file,
        auth_headers=auth_headers,
    )
    return report.legacy_results, report.error, report.error_detail


def _auth_endpoint_candidates(vendor: str | None) -> tuple[str, ...]:
    normalized = _normalize_vendor(vendor)
    if normalized == "opensearch":
        return ("/_plugins/_security/authinfo", "/_security/_authenticate")
    if normalized == "elasticsearch":
        return ("/_security/_authenticate",)
    return ("/_security/_authenticate", "/_plugins/_security/authinfo")


def _auth_response_is_conclusively_unsupported(status: int, detail: Mapping[str, Any] | None) -> bool:
    """Return whether an identity endpoint can safely be cached as absent."""

    if status in {404, 405}:
        return True
    if status != 400 or not isinstance(detail, Mapping):
        return False
    error_type = str(detail.get("type") or "").strip().lower()
    if error_type in {"resource_not_found_exception", "unsupported_operation_exception"}:
        return True
    reasons = [str(detail.get("reason") or "")]
    root_causes = detail.get("root_cause")
    if isinstance(root_causes, list):
        reasons.extend(str(cause.get("reason") or "") for cause in root_causes if isinstance(cause, Mapping))
    return any(_AUTH_UNSUPPORTED_REASON_RE.search(reason) is not None for reason in reasons)


def _cached_unverified_auth_result(
    *,
    anonymous_status: int,
    endpoints: tuple[str, ...],
    state: ElasticLifecycleState,
) -> ElasticAuthProbeResult:
    detail = {
        "status": int(anonymous_status),
        "type": "authentication_unverified",
        "reason": "root endpoint is also anonymously accessible",
        "root_cause": [],
        "fallback": True,
        "fallback_endpoint": "/",
        "auth_endpoints": list(endpoints),
        "cached_capability": True,
        "unsupported_endpoint_details": {
            endpoint: dict(state.unsupported_auth_details[endpoint])
            for endpoint in endpoints
            if endpoint in state.unsupported_auth_details
        },
    }
    return ElasticAuthProbeResult(
        valid=None,
        error=str(detail["reason"]),
        username=None,
        status=int(anonymous_status),
        endpoint="/",
        detail=detail,
        network_attempted=False,
        verification_capability="identity_endpoint_unavailable",
    )


def _auth_username_from_body(body: dict[str, Any] | None) -> str | None:
    if not isinstance(body, dict):
        return None
    for field in ("username", "user_name"):
        raw = body.get(field)
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    raw_user = body.get("user")
    if isinstance(raw_user, str) and raw_user.strip():
        match = re.search(r"(?:name=|User \[name=)([^,\]]+)", raw_user)
        if match:
            return match.group(1).strip()
    return None


def _probe_authenticate(
    host: str,
    port: int,
    timeout: float,
    *,
    scheme: str,
    insecure: bool,
    ca_file: str | None,
    auth_headers: dict[str, str],
    vendor: str | None = None,
    anonymous_status: int | None = None,
    expected_username: str | None = None,
    capability_state: ElasticLifecycleState | None = None,
) -> ElasticAuthProbeResult:
    last_result: ElasticAuthProbeResult | None = None
    unsupported_statuses = {400, 404, 405}
    all_endpoints = _auth_endpoint_candidates(vendor)
    if (
        capability_state is not None
        and anonymous_status == 200
        and all(endpoint in capability_state.unsupported_auth_endpoints for endpoint in all_endpoints)
    ):
        return _cached_unverified_auth_result(
            anonymous_status=anonymous_status,
            endpoints=all_endpoints,
            state=capability_state,
        )
    endpoints: tuple[str, ...]
    if capability_state is not None and capability_state.supported_auth_endpoint is not None:
        endpoints = (capability_state.supported_auth_endpoint,)
    elif capability_state is not None:
        endpoints = tuple(
            endpoint for endpoint in all_endpoints if endpoint not in capability_state.unsupported_auth_endpoints
        )
    else:
        endpoints = all_endpoints

    for endpoint in endpoints:
        status, payload, _headers, error = _elastic_request(
            host,
            port,
            endpoint,
            timeout,
            use_https=scheme == "https",
            insecure=insecure,
            ca_file=ca_file,
            headers=auth_headers,
        )
        if error:
            return ElasticAuthProbeResult(
                valid=None,
                error=error,
                username=None,
                status=0,
                endpoint=endpoint,
                detail={"status": 0, "type": "transport_error", "reason": error, "root_cause": []},
                verification_capability="transport_error",
            )
        if status == 200:
            if capability_state is not None:
                capability_state.supported_auth_endpoint = endpoint
                capability_state.unsupported_auth_endpoints.discard(endpoint)
                capability_state.unsupported_auth_details.pop(endpoint, None)
            body = _load_json_dict_loose(payload)
            authenticated_username = _auth_username_from_body(body)
            if expected_username is not None and authenticated_username != expected_username:
                detail = {
                    "status": 200,
                    "type": "identity_mismatch",
                    "reason": (
                        f"expected username {expected_username!r}, endpoint returned {authenticated_username!r}"
                    ),
                    "root_cause": [],
                }
                return ElasticAuthProbeResult(
                    valid=None,
                    error=str(detail["reason"]),
                    username=authenticated_username,
                    status=status,
                    endpoint=endpoint,
                    detail=detail,
                    verification_capability="identity_endpoint_supported",
                )
            if authenticated_username is None:
                detail = {
                    "status": 200,
                    "type": "identity_unavailable",
                    "reason": "authentication endpoint did not return an identity",
                    "root_cause": [],
                }
                return ElasticAuthProbeResult(
                    valid=None,
                    error=str(detail["reason"]),
                    username=None,
                    status=status,
                    endpoint=endpoint,
                    detail=detail,
                    verification_capability="identity_endpoint_supported",
                )
            authorization = str(_header_lookup(auth_headers, "Authorization") or "")
            if expected_username is None and authorization.lower().startswith("apikey "):
                anonymous_status_code, anonymous_payload, _anonymous_headers, anonymous_error = _elastic_request(
                    host,
                    port,
                    endpoint,
                    timeout,
                    use_https=scheme == "https",
                    insecure=insecure,
                    ca_file=ca_file,
                    headers=_elastic_headers(username=None, password=None, api_token=None),
                )
                anonymous_body = _load_json_dict_loose(anonymous_payload)
                anonymous_username = _auth_username_from_body(anonymous_body)
                token_changed_identity = (
                    anonymous_status_code == 200
                    and anonymous_username is not None
                    and anonymous_username != authenticated_username
                )
                if anonymous_error or (anonymous_status_code not in {401, 403} and not token_changed_identity):
                    detail = {
                        "status": status,
                        "type": "token_identity_unverified",
                        "reason": (
                            f"anonymous control failed: {anonymous_error}"
                            if anonymous_error
                            else "auth endpoint is anonymously accessible with the same identity"
                        ),
                        "root_cause": [],
                        "anonymous_control_status": anonymous_status_code,
                        "anonymous_control_username": anonymous_username,
                    }
                    return ElasticAuthProbeResult(
                        valid=None,
                        error=str(detail["reason"]),
                        username=authenticated_username,
                        status=status,
                        endpoint=endpoint,
                        detail=detail,
                        verification_capability="identity_endpoint_supported",
                    )
            return ElasticAuthProbeResult(
                valid=True,
                error=None,
                username=authenticated_username,
                status=status,
                endpoint=endpoint,
                detail=None,
                verification_capability="identity_endpoint_supported",
            )
        if status in {401, 403}:
            if capability_state is not None:
                capability_state.supported_auth_endpoint = endpoint
                capability_state.unsupported_auth_endpoints.discard(endpoint)
                capability_state.unsupported_auth_details.pop(endpoint, None)
            detail = _parse_elastic_error(status, payload)
            return ElasticAuthProbeResult(
                valid=False,
                error="authentication failed",
                username=None,
                status=status,
                endpoint=endpoint,
                detail=detail,
                verification_capability="identity_endpoint_supported",
            )

        detail = _parse_elastic_error(status, payload)
        conclusively_unsupported = _auth_response_is_conclusively_unsupported(status, detail)
        if capability_state is not None and conclusively_unsupported:
            if capability_state.supported_auth_endpoint == endpoint:
                capability_state.supported_auth_endpoint = None
            capability_state.unsupported_auth_endpoints.add(endpoint)
            capability_state.unsupported_auth_details[endpoint] = dict(detail)
        last_result = ElasticAuthProbeResult(
            valid=None,
            error=_format_elastic_error_detail(detail),
            username=None,
            status=status,
            endpoint=endpoint,
            detail=detail,
            verification_capability=("identity_endpoint_unavailable" if conclusively_unsupported else "indeterminate"),
        )
        if status not in unsupported_statuses:
            return last_result

    root_status, root_payload, root_headers, root_error = _elastic_request(
        host,
        port,
        "/",
        timeout,
        use_https=scheme == "https",
        insecure=insecure,
        ca_file=ca_file,
        headers=auth_headers,
    )
    auth_endpoint = last_result.endpoint if last_result is not None else None
    fallback_detail: dict[str, Any]
    if root_error:
        fallback_detail = {
            "status": 0,
            "type": "auth_fallback_transport_error",
            "reason": root_error,
            "root_cause": [],
            "fallback_endpoint": "/",
        }
        return ElasticAuthProbeResult(
            valid=None,
            error=root_error,
            username=None,
            status=0,
            endpoint="/",
            detail=fallback_detail,
            verification_capability="transport_error",
        )
    if root_status in {401, 403}:
        fallback_detail = _parse_elastic_error(root_status, root_payload)
        fallback_detail["fallback"] = True
        fallback_detail["fallback_endpoint"] = "/"
        return ElasticAuthProbeResult(
            valid=False,
            error="authentication failed",
            username=None,
            status=root_status,
            endpoint="/",
            detail=fallback_detail,
            verification_capability="root_access_control",
        )

    root_classification = _classify_detect_probe("/", root_status, root_payload, root_headers, None)
    root_is_service = str(root_classification.get("signal_kind") or "") in {"hard_positive", "soft_positive"}
    if root_status == 200 and root_is_service and anonymous_status in {401, 403}:
        fallback_reason = "authenticated root became accessible, but identity could not be confirmed"
    elif root_status == 200 and anonymous_status == 200:
        fallback_reason = "root endpoint is also anonymously accessible"
    else:
        fallback_reason = "authentication endpoint is unsupported and root fallback is inconclusive"
    fallback_detail = {
        "status": int(root_status),
        "type": "authentication_unverified",
        "reason": fallback_reason,
        "root_cause": [],
        "fallback": True,
        "fallback_endpoint": "/",
        "auth_endpoint": auth_endpoint,
    }
    if last_result is not None and isinstance(last_result.detail, dict):
        fallback_detail["auth_endpoint_error"] = dict(last_result.detail)
    identity_endpoints_unavailable = capability_state is not None and all(
        endpoint in capability_state.unsupported_auth_endpoints for endpoint in all_endpoints
    )
    return ElasticAuthProbeResult(
        valid=None,
        error=str(fallback_detail["reason"]),
        username=None,
        status=int(root_status),
        endpoint="/",
        detail=fallback_detail,
        verification_capability=(
            "identity_endpoint_unavailable" if identity_endpoints_unavailable else "indeterminate"
        ),
    )


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
    """Backward-compatible tuple wrapper around the identity-aware probe."""

    result = _probe_authenticate(
        host,
        port,
        timeout,
        scheme=scheme,
        insecure=insecure,
        ca_file=ca_file,
        auth_headers=auth_headers,
    )
    return result.valid, result.error, result.username


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
                scheme_locked=str(preferred_scheme or "").strip().lower() in {"http", "https"},
            )
        except TypeError as exc:
            if not is_signature_compat_typeerror(
                exc,
                expected_keywords={"debug", "run_deep_checks", "scheme_locked"},
            ):
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
    scheme_locked: bool = False,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    normalized_preferred_scheme = str(preferred_scheme or "").strip().lower()
    if normalized_preferred_scheme not in {"http", "https"}:
        normalized_preferred_scheme = "https" if int(port) in _TLS_HINT_PORTS else "http"
    preferred_scheme = normalized_preferred_scheme

    provided_credentials = bool(username is not None and password is not None)
    provided_token = bool(api_token)
    auth_provided = provided_token or provided_credentials
    requested_actions = bool(show_endpoints or show_plugins or show_cluster or show_users or discover)
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
        safe_message = str(_redact_api_token(str(message), api_token))
        debug_line = f"{host}:{port} {safe_message}"
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
        redacted_record = _redact_api_token(record, api_token)
        if not isinstance(redacted_record, dict):
            raise TypeError("elastic audit record must remain a mapping")
        redacted_record["api_token"] = None
        return redacted_record

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
            preferred_scheme=preferred_scheme,
            allow_fallback=not scheme_locked,
        )
        root_transport_error = root_headers.pop(_TRANSPORT_DIAGNOSTIC_HEADER, None)
        if error and status <= 0:
            last_error = error
            preferred_scheme = scheme
            retryable = _is_transient_transport_error(last_error) and not _is_permanent_transport_error(last_error)
            if retryable and attempt < attempts - 1:
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
            break

        root_detection = _classify_detect_probe("/", status, payload, root_headers, error)
        root_detection_version = root_detection.get("version")
        if not isinstance(root_detection_version, str) or not root_detection_version.strip():
            root_detection["version"] = _extract_version_hint(payload, root_headers)
        detect_probes: list[dict[str, Any]] = [
            {
                "path": "/",
                "status": int(status),
                "scheme": scheme,
                "error": error,
                "transport_error": root_transport_error,
                "signal_kind": str(root_detection.get("signal_kind") or "neutral"),
                "signals": list(root_detection.get("signals") or []),
                "version": root_detection.get("version"),
                "vendor": root_detection.get("vendor"),
                "payload": payload,
                "headers": root_headers,
                "insecure_effective": effective_insecure,
                "tls_auto_plain": tls_auto_plain,
                "pass": "base",
            }
        ]
        root_probe_status = int(status)
        preferred_scheme = scheme

        def _run_confirmation_probe(probe_path: str, pass_name: str) -> dict[str, Any]:
            nonlocal preferred_scheme
            requested_scheme = preferred_scheme
            probe_kwargs: dict[str, Any] = {
                "preferred_scheme": requested_scheme,
                "ca_file": ca_file,
            }
            if scheme_locked:
                probe_kwargs["allow_fallback"] = False
            probe_status, probe_payload, probe_headers, probe_error, probe_scheme = _request_detect_probe(
                host,
                port,
                probe_path,
                timeout,
                **probe_kwargs,
            )
            probe_transport_error = probe_headers.pop(_TRANSPORT_DIAGNOSTIC_HEADER, None)
            probe_detection = _classify_detect_probe(
                probe_path,
                probe_status,
                probe_payload,
                probe_headers,
                probe_error,
            )
            probe_detection_version = probe_detection.get("version")
            if not isinstance(probe_detection_version, str) or not probe_detection_version.strip():
                probe_detection["version"] = _extract_version_hint(probe_payload, probe_headers)
            if probe_status > 0:
                preferred_scheme = probe_scheme
            return {
                "path": probe_path,
                "status": int(probe_status),
                "scheme": probe_scheme,
                "error": probe_error,
                "transport_error": probe_transport_error,
                "signal_kind": str(probe_detection.get("signal_kind") or "neutral"),
                "signals": list(probe_detection.get("signals") or []),
                "version": probe_detection.get("version"),
                "vendor": probe_detection.get("vendor"),
                "payload": probe_payload,
                "headers": probe_headers,
                "insecure_effective": probe_scheme == "https" and not ca_file,
                "tls_auto_plain": probe_scheme == "http" and requested_scheme == "https",
                "pass": pass_name,
            }

        detect_decision = _evaluate_detect_decision(detect_probes)
        transient_probe_paths: list[str] = []
        if not bool(detect_decision.get("detected")):
            for probe_path in _DETECT_CONFIRM_PATHS:
                probe = _run_confirmation_probe(probe_path, "base")
                detect_probes.append(probe)
                probe_error = str(probe.get("error") or "")
                if (
                    int(probe.get("status") or 0) <= 0
                    and _is_transient_transport_error(probe_error)
                    and not _is_permanent_transport_error(probe_error)
                ):
                    transient_probe_paths.append(probe_path)
                detect_decision = _evaluate_detect_decision(detect_probes)
                if bool(detect_decision.get("detected")):
                    break

        retry_paths = list(dict.fromkeys(transient_probe_paths))
        for retry_round in range(max(0, retries)):
            if bool(detect_decision.get("detected")) or not retry_paths:
                break
            next_retry_paths: list[str] = []
            for probe_path in retry_paths:
                probe = _run_confirmation_probe(probe_path, f"retry:{retry_round + 1}")
                detect_probes.append(probe)
                probe_error = str(probe.get("error") or "")
                if (
                    int(probe.get("status") or 0) <= 0
                    and _is_transient_transport_error(probe_error)
                    and not _is_permanent_transport_error(probe_error)
                ):
                    next_retry_paths.append(probe_path)
                detect_decision = _evaluate_detect_decision(detect_probes)
                if bool(detect_decision.get("detected")):
                    break
            retry_paths = next_retry_paths

        detect_confidence = str(detect_decision.get("confidence") or "low")
        detect_signals = [str(item) for item in (detect_decision.get("signals") or []) if str(item).strip()]
        detect_probe_trace = [
            {
                "path": str(probe.get("path") or "-"),
                "status": int(probe.get("status") or 0),
                "scheme": str(probe.get("scheme") or "-"),
                "signal_kind": str(probe.get("signal_kind") or "neutral"),
                "signals": list(probe.get("signals") or []),
                "vendor": probe.get("vendor"),
                "error": probe.get("error"),
                "transport_error": probe.get("transport_error"),
            }
            for probe in detect_probes
        ]
        transport_errors = _collect_detect_transport_errors(detect_probes)
        transport_error_kind = _transport_error_kind(transport_errors)

        is_elastic = bool(detect_decision.get("detected"))
        vendor = _normalize_vendor(detect_decision.get("vendor"))
        version_raw = detect_decision.get("version")
        version = str(version_raw).strip() if isinstance(version_raw, str) and version_raw.strip() else None

        primary_probe = detect_decision.get("primary_probe")
        if isinstance(primary_probe, dict):
            status = int(primary_probe.get("status") or status)
            primary_probe_payload = primary_probe.get("payload")
            if isinstance(primary_probe_payload, (bytes, bytearray)):
                payload = bytes(primary_probe_payload)
            primary_probe_headers = primary_probe.get("headers")
            if isinstance(primary_probe_headers, dict):
                root_headers = {str(key): str(value) for key, value in primary_probe_headers.items()}
            primary_error_value = primary_probe.get("error")
            if isinstance(primary_error_value, str):
                error = primary_error_value
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
                    "api_token": None,
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
                    "discover_error_detail": None,
                    "scheme": scheme,
                    "insecure_effective": effective_insecure,
                    "tls_auto_plain": tls_auto_plain,
                    "vendor": vendor,
                    "detect_confidence": detect_confidence,
                    "detect_signals": detect_signals,
                    "detect_probe_trace": detect_probe_trace,
                    "transport_errors": transport_errors,
                    "transport_error_kind": transport_error_kind,
                    "anonymous_root_status": root_probe_status,
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
        auth_probe_status: str | None = None
        auth_probe_http_status: int | None = None
        auth_probe_endpoint: str | None = None
        auth_error_detail: dict[str, Any] | None = None
        network_attempted: bool | None = None
        verification_capability = "not_requested"
        if auth_provided:
            auth_probe = _probe_authenticate(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=auth_headers,
                vendor=vendor,
                anonymous_status=root_probe_status,
                expected_username=username,
            )
            auth_probe = _redact_auth_probe_result(auth_probe, api_token)
            auth_valid = auth_probe.valid
            auth_error = auth_probe.error
            effective_username = auth_probe.username
            auth_probe_status = _auth_probe_status(auth_probe)
            auth_probe_http_status = auth_probe.status
            auth_probe_endpoint = auth_probe.endpoint
            auth_error_detail = auth_probe.detail
            network_attempted = auth_probe.network_attempted
            verification_capability = auth_probe.verification_capability

        deep_auth_headers = (
            auth_headers if auth_valid is True else _elastic_headers(username=None, password=None, api_token=None)
        )
        api_key_probe_status = "not_run"
        api_key_probe_error: str | None = None
        if provided_token and requested_actions:
            api_key_probe_status, api_key_probe_error = _verify_api_key_probe(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=deep_auth_headers,
            )

        if auth_valid is True:
            service_status = "valid_credentials"
        elif auth_required is False and auth_provided and auth_valid is False:
            service_status = "invalid_credentials_anonymous"
        elif auth_required is False and auth_provided and auth_valid is None:
            service_status = "credentials_unverified_anonymous"
        elif auth_required is False:
            service_status = "open_no_auth"
        elif auth_required is True:
            service_status = "auth_required"
        else:
            service_status = "unknown_auth"

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
            "api_token": None,
            "api_key_probe_status": "not_run",
            "api_key_probe_error": None,
            "effective_username": effective_username,
            "auth_valid": auth_valid,
            "auth_probe_status": auth_probe_status,
            "auth_probe_http_status": auth_probe_http_status,
            "auth_probe_endpoint": auth_probe_endpoint,
            "auth_error_detail": auth_error_detail,
            "network_attempted": network_attempted,
            "verification_capability": verification_capability,
            "credential_verification": {
                "status": auth_probe_status or "not_requested",
                "capability": verification_capability,
                "supported_endpoint": auth_probe_endpoint
                if verification_capability == "identity_endpoint_supported"
                else None,
                "unsupported_endpoints": [],
            },
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
            "discover_error_detail": None,
            "scheme": scheme,
            "insecure_effective": effective_insecure,
            "tls_auto_plain": tls_auto_plain,
            "vendor": vendor,
            "detect_confidence": detect_confidence,
            "detect_signals": detect_signals,
            "detect_probe_trace": detect_probe_trace,
            "transport_errors": transport_errors,
            "transport_error_kind": transport_error_kind,
            "anonymous_root_status": root_probe_status,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": None,
        }

        if not run_deep_checks:
            _debug(
                f"attempt={attempt + 1}/{attempts} detect-only result={service_status} "
                f"total_ms={int((time.monotonic() - started) * 1000)}"
            )
            return _record(base_record, attempts_done=attempt + 1, max_attempts=attempts)

        if service_status not in {
            "open_no_auth",
            "valid_credentials",
            "invalid_credentials_anonymous",
            "credentials_unverified_anonymous",
        }:
            _debug(f"stage2_gate=skip reason=status={service_status}")
            return _record(base_record, attempts_done=attempt + 1, max_attempts=attempts)

        _debug(f"stage2_gate=run reason=status={service_status}")
        deep_auth_headers = (
            auth_headers
            if service_status == "valid_credentials"
            else _elastic_headers(username=None, password=None, api_token=None)
        )
        stage3_started = time.monotonic()
        can_read: bool | None = None
        can_write: bool | None = None
        can_manage: bool | None = None
        can_manage_security: bool | None = None
        rights_error: str | None = None
        access_level = "unknown"
        api_key_probe_status = "not_run"
        api_key_probe_error = None
        if auth_provided and requested_actions:
            can_read, can_write, can_manage, can_manage_security, rights_error = _check_privileges(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=deep_auth_headers,
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
                    auth_headers=deep_auth_headers,
                )
            stage3_error = "; ".join(
                str(item) for item in (rights_error, api_key_probe_error) if str(item or "").strip()
            )
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
                error="no requested actions" if auth_provided else "no auth provided",
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
        discover_error_detail: dict[str, Any] | None = None
        discover_findings: list[dict[str, Any]] | None = None
        discover_coverage: dict[str, Any] | None = None
        if show_endpoints:
            cat_endpoints, endpoints_error, endpoint_diagnostics = _fetch_cat_endpoints(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=deep_auth_headers,
            )
        if show_plugins:
            cat_plugins, plugins_error = _fetch_cat_plugins(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=deep_auth_headers,
            )
        if show_cluster:
            cluster_health, cluster_nodes, cluster_error = _fetch_cluster_data(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=deep_auth_headers,
            )
            misconfig_findings, misconfig_error = _fetch_cluster_misconfig_findings(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=deep_auth_headers,
            )
        if show_users:
            users, users_error = _fetch_security_users(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=deep_auth_headers,
            )
        if discover:
            discover_report = _collect_discover_report(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=effective_insecure,
                ca_file=ca_file,
                auth_headers=deep_auth_headers,
                vendor=str(base_record.get("vendor") or "compatible"),
            )
            serialized_discover_report = discover_report.to_dict()
            discover_results = list(serialized_discover_report.get("discover_results") or [])
            discover_error = discover_report.error
            discover_error_detail = discover_report.error_detail
            discover_findings = list(serialized_discover_report.get("discover_findings") or [])
            discover_coverage = dict(serialized_discover_report.get("discover_coverage") or {})
        stage4_error = "; ".join(
            str(item)
            for item in (endpoints_error, plugins_error, cluster_error, misconfig_error, users_error, discover_error)
            if str(item or "").strip()
        )
        stage4_requested = requested_actions
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
                "discover_error_detail": discover_error_detail,
                "error": "; ".join(errors) if errors else None,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
        )
        if discover:
            final_record.update(
                {
                    "discover_schema_version": 2,
                    "discover_findings": discover_findings or [],
                    "discover_coverage": discover_coverage or {},
                }
            )
        _debug(
            f"attempt={attempt + 1}/{attempts} result={service_status} "
            f"total_ms={int((time.monotonic() - started) * 1000)}"
        )
        return _record(final_record, attempts_done=attempt + 1, max_attempts=attempts)

    _debug(f"final fail attempts={attempts}/{attempts} error={last_error or 'connection failed'}")
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
            "api_token": None,
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
            "discover_error_detail": None,
            "scheme": None,
            "insecure_effective": None,
            "tls_auto_plain": None,
            "vendor": None,
            "detect_confidence": None,
            "detect_signals": [],
            "detect_probe_trace": [],
            "transport_errors": _transport_errors_from_combined(last_error),
            "transport_error_kind": _transport_error_kind(_transport_errors_from_combined(last_error)),
            "anonymous_root_status": None,
            "elapsed_ms": None,
            "error": last_error or "connection failed",
        },
        attempts_done=attempts,
        max_attempts=attempts,
    )


def _make_lifecycle_session(ctx: Any) -> ElasticHttpSession | None:
    if str(getattr(ctx.args, "proxy", "") or "").strip():
        return None
    ca_file = str(getattr(ctx.args, "ca_file", "") or "").strip() or None
    return ElasticHttpSession(
        str(ctx.host),
        int(ctx.port),
        timeout=float(getattr(ctx.args, "timeout", 5.0)),
        insecure=ca_file is None,
        ca_file=ca_file,
    )


def _activate_lifecycle_session(ctx: Any, state: ElasticLifecycleState) -> ElasticHttpSession | None:
    session = state.session
    if session is None:
        session = _make_lifecycle_session(ctx)
        state.session = session
    return session


def close_elastic_lifecycle_state(state: Any) -> None:
    if not isinstance(state, ElasticLifecycleState):
        return
    session = state.session
    state.session = None
    active = getattr(_THREAD_LOCAL_ELASTIC_SESSION, "session", None)
    if active is session:
        try:
            delattr(_THREAD_LOCAL_ELASTIC_SESSION, "session")
        except AttributeError:
            pass
    if session is not None:
        session.close()


def _elastic_lifecycle_key(ctx: Any) -> tuple[str | None, str | None, str | None, str]:
    credential = ctx.credential
    return (
        credential.username,
        credential.password,
        credential.token,
        str(credential.source or "provided"),
    )


def _credential_verification_payload(
    state: ElasticLifecycleState,
    auth_probe: ElasticAuthProbeResult,
) -> dict[str, Any]:
    return {
        "status": _auth_probe_status(auth_probe),
        "capability": auth_probe.verification_capability,
        "supported_endpoint": state.supported_auth_endpoint,
        "unsupported_endpoints": sorted(state.unsupported_auth_endpoints),
    }


def detect_elastic(ctx: Any, options: Mapping[str, Any]) -> dict[str, Any]:
    """Perform the complete anonymous identity/version classification once."""

    state = ctx.lifecycle_state
    if not isinstance(state, ElasticLifecycleState):
        raise TypeError("elastic lifecycle state is unavailable")
    target_scheme_raw = str(getattr(ctx.target, "scheme", "") or "").strip().lower()
    target_scheme = target_scheme_raw if target_scheme_raw in {"http", "https"} else None
    preferred_scheme = target_scheme or ("https" if int(ctx.port) in _TLS_HINT_PORTS else "http")
    session = _make_lifecycle_session(ctx)
    state.session = session
    try:
        with _elastic_session_scope(session):
            record = _audit_elastic_host(
                str(ctx.host),
                int(ctx.port),
                float(getattr(ctx.args, "timeout", 5.0)),
                int(getattr(ctx.args, "retries", 0) or 0),
                None,
                None,
                None,
                str(getattr(ctx.args, "ca_file", "") or "").strip() or None,
                False,
                False,
                False,
                False,
                False,
                preferred_scheme=preferred_scheme,
                debug=bool(getattr(ctx.args, "debug", False)),
                run_deep_checks=False,
                scheme_locked=target_scheme is not None,
            )
    finally:
        if session is not None:
            session.close()
        state.session = None
    state.detect_record = dict(record)
    return record


def authenticate_elastic(ctx: Any, detect_record: Any, options: Mapping[str, Any]) -> dict[str, Any]:
    """Verify one credential candidate without replaying detection probes."""

    state = ctx.lifecycle_state
    if not isinstance(state, ElasticLifecycleState):
        raise TypeError("elastic lifecycle state is unavailable")
    payload = dict(detect_record.to_dict() if hasattr(detect_record, "to_dict") else detect_record)
    credential = ctx.credential
    if credential.username is None and credential.password is None and credential.token is None:
        return payload

    headers = _elastic_headers(
        username=credential.username,
        password=credential.password,
        api_token=credential.token,
    )
    state.auth_headers[_elastic_lifecycle_key(ctx)] = headers
    session = _activate_lifecycle_session(ctx, state)
    scheme = str(payload.get("scheme") or "https")
    insecure = bool(payload.get("insecure_effective"))
    ca_file = str(getattr(ctx.args, "ca_file", "") or "").strip() or None
    with _elastic_session_scope(session):
        auth_probe = _probe_authenticate(
            str(ctx.host),
            int(ctx.port),
            float(getattr(ctx.args, "timeout", 5.0)),
            scheme=scheme,
            insecure=insecure,
            ca_file=ca_file,
            auth_headers=headers,
            vendor=str(payload.get("vendor") or "compatible"),
            anonymous_status=(
                int(payload["anonymous_root_status"]) if isinstance(payload.get("anonymous_root_status"), int) else None
            ),
            expected_username=credential.username,
            capability_state=state,
        )
    auth_probe = _redact_auth_probe_result(auth_probe, credential.token)
    _redact_auth_state_details(state, credential.token)
    auth_valid = auth_probe.valid
    auth_error = auth_probe.error
    effective_username = auth_probe.username
    auth_required = payload.get("auth_required")
    if auth_valid is True:
        status = "weak_default_creds" if credential.source == "default" else "valid_credentials"
    elif auth_valid is False and auth_required is False:
        status = "invalid_credentials_anonymous"
    elif auth_valid is None and auth_required is False:
        status = "credentials_unverified_anonymous"
    elif auth_required is True:
        status = "auth_required"
    else:
        status = "unknown_auth"

    version = payload.get("server_version")

    payload.update(
        {
            "timestamp": utc_now_iso(),
            "status": status,
            "server_version": version,
            "provided_credentials": (
                credential.source != "default" and credential.username is not None and credential.password is not None
            ),
            "provided_username": credential.username,
            "provided_password": credential.password if credential.source != "default" else None,
            "provided_token": credential.token is not None,
            "api_token": None,
            "effective_username": effective_username,
            "auth_valid": auth_valid,
            "auth_probe_status": _auth_probe_status(auth_probe),
            "auth_probe_http_status": auth_probe.status,
            "auth_probe_endpoint": auth_probe.endpoint,
            "auth_error_detail": auth_probe.detail,
            "network_attempted": auth_probe.network_attempted,
            "verification_capability": auth_probe.verification_capability,
            "credential_verification": _credential_verification_payload(state, auth_probe),
            "defcreds_enabled": credential.source == "default",
            "credentials_source": str(credential.source),
            "error": None if auth_valid is True or status == "invalid_credentials_anonymous" else auth_error,
        }
    )
    return payload


def _collect_elastic_data_with_session(
    ctx: Any,
    record: Any,
    options: Mapping[str, Any],
) -> dict[str, Any]:
    """Run capabilities and requested Elastic actions inside an active session scope."""

    state = ctx.lifecycle_state
    if not isinstance(state, ElasticLifecycleState):
        raise TypeError("elastic lifecycle state is unavailable")
    payload = dict(record.to_dict() if hasattr(record, "to_dict") else record)
    credential = ctx.credential
    status = str(payload.get("status") or "")
    use_authenticated = status in {"valid_credentials", "weak_default_creds"}
    if use_authenticated:
        auth_headers = state.auth_headers.get(_elastic_lifecycle_key(ctx))
        if auth_headers is None:
            auth_headers = _elastic_headers(
                username=credential.username,
                password=credential.password,
                api_token=credential.token,
            )
    else:
        auth_headers = _elastic_headers(username=None, password=None, api_token=None)

    host = str(ctx.host)
    port = int(ctx.port)
    timeout = float(getattr(ctx.args, "timeout", 5.0))
    scheme = str(payload.get("scheme") or "https")
    insecure = bool(payload.get("insecure_effective"))
    ca_file = str(getattr(ctx.args, "ca_file", "") or "").strip() or None

    can_read: bool | None = None
    can_write: bool | None = None
    can_manage: bool | None = None
    can_manage_security: bool | None = None
    rights_error: str | None = None
    access_level = "unknown"
    api_key_probe_status = "not_run"
    api_key_probe_error: str | None = None
    requested_actions = any(
        bool(options[name]) for name in ("show_endpoints", "show_plugins", "show_cluster", "show_users", "discover")
    )
    if use_authenticated and requested_actions:
        can_read, can_write, can_manage, can_manage_security, rights_error = _check_privileges(
            host,
            port,
            timeout,
            scheme=scheme,
            insecure=insecure,
            ca_file=ca_file,
            auth_headers=auth_headers,
        )
        access_level = _normalize_access_level(
            can_read=can_read,
            can_write=can_write,
            can_manage=can_manage,
            can_manage_security=can_manage_security,
        )
        if credential.token is not None:
            api_key_probe_status, api_key_probe_error = _verify_api_key_probe(
                host,
                port,
                timeout,
                scheme=scheme,
                insecure=insecure,
                ca_file=ca_file,
                auth_headers=auth_headers,
            )

    cat_endpoints: list[str] | None = None
    endpoint_diagnostics: list[dict[str, Any]] | None = None
    endpoints_error: str | None = None
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
    discover_error_detail: dict[str, Any] | None = None
    discover_findings: list[dict[str, Any]] | None = None
    discover_coverage: dict[str, Any] | None = None

    if bool(options["show_endpoints"]):
        cat_endpoints, endpoints_error, endpoint_diagnostics = _fetch_cat_endpoints(
            host,
            port,
            timeout,
            scheme=scheme,
            insecure=insecure,
            ca_file=ca_file,
            auth_headers=auth_headers,
        )
    if bool(options["show_plugins"]):
        cat_plugins, plugins_error = _fetch_cat_plugins(
            host,
            port,
            timeout,
            scheme=scheme,
            insecure=insecure,
            ca_file=ca_file,
            auth_headers=auth_headers,
        )
    if bool(options["show_cluster"]):
        cluster_health, cluster_nodes, cluster_error = _fetch_cluster_data(
            host,
            port,
            timeout,
            scheme=scheme,
            insecure=insecure,
            ca_file=ca_file,
            auth_headers=auth_headers,
        )
        misconfig_findings, misconfig_error = _fetch_cluster_misconfig_findings(
            host,
            port,
            timeout,
            scheme=scheme,
            insecure=insecure,
            ca_file=ca_file,
            auth_headers=auth_headers,
        )
    if bool(options["show_users"]):
        users, users_error = _fetch_security_users(
            host,
            port,
            timeout,
            scheme=scheme,
            insecure=insecure,
            ca_file=ca_file,
            auth_headers=auth_headers,
        )
    if bool(options["discover"]):
        discover_report = _collect_discover_report(
            host,
            port,
            timeout,
            scheme=scheme,
            insecure=insecure,
            ca_file=ca_file,
            auth_headers=auth_headers,
            vendor=str(payload.get("vendor") or "compatible"),
        )
        serialized_discover_report = discover_report.to_dict()
        discover_results = list(serialized_discover_report.get("discover_results") or [])
        discover_error = discover_report.error
        discover_error_detail = discover_report.error_detail
        discover_findings = list(serialized_discover_report.get("discover_findings") or [])
        discover_coverage = dict(serialized_discover_report.get("discover_coverage") or {})

    errors: list[str] = []
    for item in (
        payload.get("error"),
        rights_error,
        api_key_probe_error,
        endpoints_error,
        plugins_error,
        cluster_error,
        misconfig_error,
        users_error,
        discover_error,
    ):
        clean = str(item or "").strip()
        if clean and clean not in errors:
            errors.append(clean)
    payload.update(
        {
            "timestamp": utc_now_iso(),
            "show_endpoints": bool(options["show_endpoints"]),
            "show_plugins": bool(options["show_plugins"]),
            "show_cluster": bool(options["show_cluster"]),
            "show_users": bool(options["show_users"]),
            "discover": bool(options["discover"]),
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
            "discover_error_detail": discover_error_detail,
            "error": "; ".join(errors) if errors else None,
        }
    )
    if bool(options["discover"]):
        payload.update(
            {
                "discover_schema_version": 2,
                "discover_findings": discover_findings or [],
                "discover_coverage": discover_coverage or {},
            }
        )
    redacted_payload = _redact_api_token(payload, credential.token)
    if not isinstance(redacted_payload, dict):
        raise TypeError("elastic data payload must remain a mapping")
    redacted_payload["api_token"] = None
    return redacted_payload


def collect_elastic_data(ctx: Any, record: Any, options: Mapping[str, Any]) -> dict[str, Any]:
    """Run capabilities and requested actions using the target's reusable session."""

    state = ctx.lifecycle_state
    if not isinstance(state, ElasticLifecycleState):
        raise TypeError("elastic lifecycle state is unavailable")
    session = _activate_lifecycle_session(ctx, state)
    with _elastic_session_scope(session):
        return _collect_elastic_data_with_session(ctx, record, options)


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
        "auth_probe_status",
        "auth_probe_http_status",
        "auth_probe_endpoint",
        "auth_error_detail",
        "network_attempted",
        "verification_capability",
        "credential_verification",
        "cat_endpoints",
        "endpoint_diagnostics",
        "cat_plugins",
        "cluster_health",
        "cluster_nodes",
        "misconfig_findings",
        "misconfig_error",
        "users",
        "discover_results",
        "discover_schema_version",
        "discover_findings",
        "discover_coverage",
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
        "discover_error_detail",
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
                "vendor": _normalize_vendor(record.get("vendor")),
                "scheme": record.get("scheme"),
                "detect_confidence": record.get("detect_confidence"),
                "detect_signals": record.get("detect_signals") or [],
                "detect_probe_trace": record.get("detect_probe_trace") or [],
                "transport_errors": record.get("transport_errors") or {},
                "transport_error_kind": record.get("transport_error_kind"),
            },
            ensure_ascii=False,
        )

    prefix = _nxc_prefix(record)
    status = str(record.get("status") or "fail")
    if status == "fail":
        err = _clip(str(record.get("error") or "connection failed"), 96)
        return f"{prefix} [!] connection failed err={err}"
    if status == "not_elastic":
        return f"{prefix} [-] not an Elasticsearch/OpenSearch API"

    auth_required_text = _bool_text(record.get("auth_required"))
    version_text = str(record.get("server_version") or "-")
    return f"{prefix} [*] {_api_label(record)} (auth required:{auth_required_text}) (version:{version_text})"


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
    attempted_credentials = record.get("attempted_credentials")
    has_attempt_history = isinstance(attempted_credentials, list) and bool(attempted_credentials)

    if status == "open_no_auth":
        return ""

    if status == "invalid_credentials_anonymous":
        return "" if has_attempt_history else f"{prefix} [-] credentials invalid{counts}"

    if status == "credentials_unverified_anonymous":
        if has_attempt_history:
            return ""
        line = f"{prefix} [!] credentials unverified{counts}"
        return f"{line} err={err}" if err != "-" else line

    if status in {"valid_credentials", "weak_default_creds"}:
        if has_attempt_history:
            return ""
        if bool(record.get("provided_token")):
            return f"{prefix} [+] apikey auth{counts}{caps}"
        username = str(record.get("provided_username") or record.get("effective_username") or "elastic")
        provided_password = record.get("provided_password")
        password_text = (
            "<empty>"
            if provided_password == ""
            else str(provided_password)
            if provided_password is not None
            else "<verified-default>"
        )
        return f"{prefix} [+] {username}:{password_text}{counts}{caps}"

    if status == "auth_required":
        if has_attempt_history:
            return ""
        if bool(record.get("provided_credentials") or record.get("provided_token")):
            return f"{prefix} [-] authentication required (credentials invalid){counts}{caps}"
        return f"{prefix} [-] authentication required{counts}"

    if status == "unknown_auth":
        if has_attempt_history:
            return ""
        line = f"{prefix} [!] auth status unknown{counts}{caps}"
        if err != "-":
            return f"{line} err={err}"
        return line

    if status == "not_elastic":
        return f"{prefix} [-] not an Elasticsearch/OpenSearch API"

    line = f"{prefix} [!] connection failed"
    return f"{line} err={err}" if err != "-" else line


def _is_public_root_unverified_attempt(attempt: Mapping[str, Any]) -> bool:
    if str(attempt.get("status") or "") != "credentials_unverified_anonymous":
        return False
    detail = attempt.get("auth_error_detail")
    if isinstance(detail, Mapping):
        detail_type = str(detail.get("type") or "")
        fallback_endpoint = str(detail.get("fallback_endpoint") or "")
        reason = str(detail.get("reason") or "")
        if (
            detail_type == "authentication_unverified"
            and fallback_endpoint == "/"
            and "anonymously accessible" in reason.lower()
        ):
            return True
    error = str(attempt.get("error") or "")
    if "root endpoint is also anonymously accessible" in error.lower():
        return True
    return False


def _format_credential_attempts_records(
    record: dict[str, Any],
    output_format: str,
    *,
    debug: bool = False,
) -> list[str]:
    if output_format == "json":
        return []
    attempts = record.get("attempted_credentials")
    if not isinstance(attempts, list) or not attempts:
        return []
    prefix = _nxc_prefix(record)
    lines: list[str] = []
    full_default_sweep = len(attempts) > 1 and any(
        isinstance(attempt, dict) and str(attempt.get("source") or "") == "default" for attempt in attempts
    )
    accepted_statuses = {"valid_credentials", "weak_default_creds"}
    rejected_statuses = {"auth_required", "invalid_credentials_anonymous"}
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        source = str(attempt.get("source") or "provided")
        username = attempt.get("username")
        password = attempt.get("password")
        status = str(attempt.get("status") or "unknown_auth")
        error = str(attempt.get("error") or "").strip()
        if username is None and password is None:
            credential_text = f"API token (source:{source})"
        else:
            username_text = str(username or "elastic")
            if password is None:
                password_text = "<no-password>"
            elif password == "":
                password_text = "<empty>"
            else:
                password_text = str(password)
            credential_text = f"{username_text}:{password_text}"
        probe_status = str(attempt.get("auth_probe_status") or "")
        if probe_status == "verified" or (not probe_status and status in accepted_statuses):
            marker = "[+]"
        elif probe_status == "rejected" or (not probe_status and status in rejected_statuses):
            marker = "[-]"
        else:
            marker = "[!]"
        if not debug and full_default_sweep and marker == "[!]":
            marker = "[-]"
        if (
            not debug
            and marker == "[!]"
            and (username is not None or password is not None)
            and _is_public_root_unverified_attempt(attempt)
        ):
            marker = "[-]"
        suffix = ""
        if marker == "[!]" and error:
            suffix = f" err={error if debug else _clip(error, 120)}"
        if debug:
            diagnostics: list[str] = []
            for key in (
                "auth_probe_status",
                "auth_probe_http_status",
                "auth_probe_endpoint",
                "network_attempted",
                "verification_capability",
            ):
                value = attempt.get(key)
                if value is not None and str(value).strip():
                    diagnostics.append(f"{key}={value}")
            if diagnostics:
                suffix = f" {' '.join(diagnostics)}{suffix}"
        lines.append(f"{prefix} {marker} {credential_text}{suffix}")
    return lines


def _format_detail_records(record: dict[str, Any], output_format: str, *, debug: bool = False) -> list[str]:
    status = str(record.get("status") or "fail")
    if status in {"fail", "not_elastic"}:
        if output_format == "json" or not debug:
            return []
        prefix = _nxc_prefix(record)
        debug_lines: list[str] = []
        transport_errors = record.get("transport_errors")
        if isinstance(transport_errors, dict):
            for scheme, transport_error in transport_errors.items():
                debug_lines.append(
                    f"{prefix} [debug] transport scheme={scheme} error={_clip(str(transport_error), 240)}"
                )
        probe_trace = record.get("detect_probe_trace")
        if isinstance(probe_trace, list):
            for probe in probe_trace:
                if not isinstance(probe, dict):
                    continue
                path = str(probe.get("path") or "-")
                probe_status = int(probe.get("status") or 0)
                scheme = str(probe.get("scheme") or "-")
                signal_kind = str(probe.get("signal_kind") or "neutral")
                signals = ",".join(str(signal) for signal in (probe.get("signals") or [])) or "-"
                probe_error = str(probe.get("error") or "").strip()
                suffix = f" error={_clip(probe_error, 240)}" if probe_error else ""
                debug_lines.append(
                    f"{prefix} [debug] probe path={path} status={probe_status} "
                    f"scheme={scheme} signal={signal_kind} signals={signals}{suffix}"
                )
        return debug_lines

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
                        "schema_version": record.get("discover_schema_version"),
                        "findings": record.get("discover_findings") or [],
                        "coverage": record.get("discover_coverage") or {},
                        "query_size": _DISCOVER_QUERY_SIZE,
                        "max_print_per_index": _DISCOVER_MAX_PRINT_PER_INDEX,
                        "error": record.get("discover_error"),
                        "error_detail": record.get("discover_error_detail"),
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    lines = []

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
        discover_findings = record.get("discover_findings")
        findings = (
            [item for item in discover_findings if isinstance(item, dict)]
            if isinstance(discover_findings, list)
            else []
        )
        confidence_counts: dict[str, int] = {}
        for finding in findings:
            confidence = str(finding.get("confidence") or "unknown")
            confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
        confidence_text = " ".join(
            f"{name}:{confidence_counts[name]}"
            for name in ("very_high", "high", "medium")
            if confidence_counts.get(name)
        )
        coverage = record.get("discover_coverage")
        complete = bool(coverage.get("complete")) if isinstance(coverage, dict) else False
        if findings:
            suffix = f" ({confidence_text})" if confidence_text else ""
            lines.append(f"{prefix} [*] {len(findings)} Secret Findings{suffix}")
            for finding in findings:
                secret_type = str(finding.get("secret_type") or "secret")
                confidence = str(finding.get("confidence") or "unknown")
                score = int(finding.get("score") or 0)
                occurrence_count = int(finding.get("occurrence_count") or 1)
                encoded_value = json.dumps(finding.get("value"), ensure_ascii=False, separators=(",", ":"))
                locations = finding.get("locations")
                first_location = locations[0] if isinstance(locations, list) and locations else None
                location_parts: list[str] = []
                if isinstance(first_location, dict):
                    for key in ("source_kind", "object", "index", "id", "path"):
                        location_value = first_location.get(key)
                        if location_value is not None and str(location_value).strip():
                            location_parts.append(f"{key}={json.dumps(str(location_value), ensure_ascii=False)}")
                location_text = " ".join(location_parts) or "location=unknown"
                lines.append(
                    f"{prefix} [+] secret_type={secret_type} confidence={confidence} score={score} "
                    f"value={encoded_value} occurrences={occurrence_count} {location_text}"
                )
        elif complete:
            lines.append(f"{prefix} [*] 0 Secret Findings")
        else:
            lines.append(f"{prefix} [*] 0 Secret Findings in scanned scope")

        if isinstance(coverage, dict):
            indices_discovered = int(
                coverage.get("indices_discovered")
                or coverage.get("inventory_total")
                or coverage.get("indices_total")
                or coverage.get("indices_enumerated")
                or 0
            )
            indices_scanned = int(
                coverage.get("indices_scanned")
                or coverage.get("completed_indices")
                or coverage.get("indices_completed")
                or 0
            )
            documents_analyzed = int(
                coverage.get("documents_analyzed")
                or coverage.get("documents_examined")
                or coverage.get("documents_fetched")
                or coverage.get("documents_scanned")
                or 0
            )
            pages = int(coverage.get("pages_scanned") or coverage.get("pages") or 0)
            source_bytes = int(
                coverage.get("source_bytes")
                or coverage.get("source_bytes_analyzed")
                or coverage.get("source_bytes_scanned")
                or 0
            )
            reasons_raw = coverage.get("truncated_reasons")
            reasons = ",".join(str(reason) for reason in reasons_raw) if isinstance(reasons_raw, list) else ""
            coverage_status = str(coverage.get("status") or ("complete" if complete else "partial"))
            reason_suffix = f" reasons={reasons}" if reasons else ""
            lines.append(
                f"{prefix} [*] Discover coverage status={coverage_status} "
                f"indices={indices_scanned}/{indices_discovered} pages={pages} "
                f"documents={documents_analyzed} source_bytes={source_bytes}{reason_suffix}"
            )

        discover_error = str(record.get("discover_error") or "").strip()
        if isinstance(discover_results, list) and discover_results:
            grouped_errors: dict[tuple[int, str, str, str], list[str]] = {}
            for item in discover_results:
                if not isinstance(item, dict):
                    continue
                index_name = str(item.get("index") or "-")
                total_hits = int(item.get("total_hits") or 0)
                shown_hits = int(item.get("shown_hits") or 0)
                item_error = str(item.get("error") or "").strip()
                if item_error:
                    detail = item.get("error_detail")
                    if isinstance(detail, dict):
                        root_cause_signature = json.dumps(
                            detail.get("root_cause") or [],
                            ensure_ascii=False,
                            sort_keys=True,
                        )
                        error_key = (
                            int(detail.get("status") or 0),
                            str(detail.get("type") or "http_error"),
                            str(detail.get("reason") or item_error),
                            root_cause_signature,
                        )
                    else:
                        error_key = (0, "discover_error", item_error, "[]")
                    grouped_errors.setdefault(error_key, []).append(index_name)
                    if debug:
                        lines.append(
                            f"{prefix} [!] discover error index={index_name}: "
                            f"{_clip(_format_elastic_error_detail(detail) or item_error, 180)}"
                        )
                    continue
                if debug:
                    lines.append(f"{prefix} [debug] candidate index={index_name} hits={total_hits} shown={shown_hits}")
                    if bool(item.get("truncated")):
                        relation = str(item.get("total_hits_relation") or "exact")
                        lines.append(
                            f"{prefix} [debug] showing first {shown_hits} of {total_hits} candidates "
                            f"(relation:{relation}) (max_per_index={_DISCOVER_MAX_PRINT_PER_INDEX})"
                        )
                    hits = item.get("hits")
                    if isinstance(hits, list):
                        for hit in hits:
                            if not isinstance(hit, dict):
                                continue
                            source = hit.get("source")
                            if not isinstance(source, dict):
                                continue
                            lines.append(f"{prefix} [debug] candidate={json.dumps(source, ensure_ascii=False)}")
                    partial_details = item.get("partial_error_details")
                    if isinstance(partial_details, list):
                        for partial_detail in partial_details:
                            if not isinstance(partial_detail, dict):
                                continue
                            lines.append(
                                f"{prefix} [debug] discover retry index={index_name}: "
                                f"{_clip(_format_elastic_error_detail(partial_detail), 240)}"
                            )
            if not debug:
                for (error_status, error_type, error_reason, root_cause_signature), indices in grouped_errors.items():
                    index_preview = ",".join(indices[:4])
                    if len(indices) > 4:
                        index_preview += ",..."
                    root_cause_suffix = (
                        f" root_cause={_clip(root_cause_signature, 160)}" if root_cause_signature != "[]" else ""
                    )
                    lines.append(
                        f"{prefix} [!] discover error: count={len(indices)} indices={index_preview} "
                        f"status={error_status or '-'} type={error_type} reason={_clip(error_reason, 120)}"
                        f"{root_cause_suffix}"
                    )
        elif discover_error:
            detail = record.get("discover_error_detail")
            detail_text = _format_elastic_error_detail(detail) or discover_error
            lines.append(f"{prefix} [!] discover unavailable: {_clip(detail_text, 180)}")

    return lines


def _render_colored_elastic_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(
        console,
        line,
        tag=_ELASTIC_TAG,
        booleans=(
            BooleanColorRule("read"),
            BooleanColorRule("write"),
            BooleanColorRule("manage"),
            BooleanColorRule("manage_security"),
        ),
    ):
        return True
    if line.startswith(_ELASTIC_TAG) and "\t" in line:
        return render_tagged_detail_line(console, line, tag=_ELASTIC_TAG, default_color="orange")
    return False


def _is_connection_timeout_fail_record(record: dict[str, Any]) -> bool:
    if str(record.get("status") or "") != "fail":
        return False
    error_text = str(record.get("error") or "").strip().lower()
    return bool(error_text) and (
        error_text.startswith("connection timeout")
        or error_text.startswith("connection refused")
        or "timed out" in error_text
    )


# Typed runner boundary -----------------------------------------------------
host_stage = _call_audit_elastic_host_with_thread_debug
