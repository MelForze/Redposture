"""Proxmox API audit stage."""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
import ssl
import string
import time
import urllib.error
import urllib.parse
from collections.abc import Callable
from typing import Any

from ...clients import transport
from ...clients.http_api import HttpApiClient, HttpClientConfig
from ...console import Console
from ...rendering import BooleanColorRule, render_colored_marker_line
from ...stage_runtime import (
    StageTelemetryBuilder,
    format_retry_decision,
    merge_stage_records,
)
from ...utils import (
    is_signature_compat_typeerror,
    utc_now_iso,
)

# Connection-error classification + framed reads are shared via the transport layer.
_is_connection_refused_error = transport.is_connection_refused
_is_connection_timeout_error = transport.is_connection_timeout

_PROXMOX_API_PREFIX = "/api2/json"
_MAX_HTTP_BODY_BYTES = 262_144
_MAX_FINDINGS_PER_TARGET = 200
_MAX_FINDINGS_PER_ENDPOINT = 40
_ADD_USER_PASSWORD_LENGTH = 20
_ADD_USER_PASSWORD_ALPHABET = string.ascii_letters + string.digits
_ADD_USER_PRIV_ROLE = "Administrator"
_ADD_USER_PRIV_PATH = "/"
_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_PROXMOX_DEEP_STATUSES = {"token_ok", "insufficient_privileges"}

_SENSITIVE_KEY_TOKENS = (
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "accesskey",
    "secret_key",
    "secretkey",
    "private_key",
    "privatekey",
    "client_secret",
    "clientsecret",
    "credential",
)

_NON_SECRET_KEY_TOKENS = {
    # Proxmox non-secret operational fields that may look sensitive by name.
    "csrfpreventiontoken",
    "tokenid",
    "nodeid",
    "userid",
    "username",
    "vmid",
    "volid",
    "upid",
    "clustername",
    "ticketid",
}

_NON_SECRET_LITERALS = {
    "",
    "-",
    "<empty>",
    "<none>",
    "none",
    "null",
    "n/a",
    "na",
    "true",
    "false",
    "enabled",
    "disabled",
}

_TEXT_SECRET_RE = re.compile(
    r"(?i)([A-Za-z_][A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|credential))\s*[:=]\s*(?:\"([^\"]{1,512})\"|'([^']{1,512})'|([^\s,;{}\[\]\"']{1,512}))"
)
_URL_BASIC_AUTH_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:([^@\s/]+)@")
_AUTH_BASIC_RE = re.compile(r"(?i)\bauthorization\s*[:=]\s*basic\s+[A-Za-z0-9+/=]{8,}")
_AUTH_BEARER_RE = re.compile(r"(?i)\bauthorization\s*[:=]\s*bearer\s+[A-Za-z0-9._~+/-]{10,}")
_URI_WITH_AUTH_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]{1,128}:[^@\s/]{4,256}@[^ \t\r\n\"'<>]{1,512}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_OPAQUE_TOKEN_RE = re.compile(
    r"\b(?:glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|ya29\.[A-Za-z0-9._-]{20,}|[A-Fa-f0-9]{32,64})\b"
)
_BASE64_TEXT_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
_PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PERMISSION_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*\.[A-Za-z][A-Za-z0-9_.-]*$")
_PROXMOX_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("root@pam", "root"),
    ("root@pam", "admin"),
    ("root@pam", "password"),
    ("root@pam", "proxmox"),
)


def _clip(text: str, width: int = 90) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _friendly_error_text(value: str) -> str:
    from ...utils import friendly_error_text

    return friendly_error_text(value, tls_hint="try --insecure")


def _friendly_error_from_exception(exc: BaseException) -> str:
    from ...utils import friendly_error_from_exception

    return friendly_error_from_exception(exc, tls_hint="try --insecure")


def _is_suppressed_fail_record(record: dict[str, Any]) -> bool:
    return str(record.get("status") or "") == "fail"


def _ssl_context(*, use_https: bool, insecure: bool) -> ssl.SSLContext | None:
    if not use_https:
        return None
    if insecure:
        return ssl._create_unverified_context()
    return ssl.create_default_context()


def _auth_header_value(pve_api_token: str) -> str:
    token = str(pve_api_token or "").strip()
    if token.lower().startswith("pveapitoken="):
        return token
    return f"PVEAPIToken={token}"


def _proxmox_auth_headers(pve_api_token: str, auth_headers: dict[str, str] | None = None) -> dict[str, str]:
    if auth_headers is not None:
        return dict(auth_headers)
    token = str(pve_api_token or "").strip()
    if not token:
        return {}
    return {"Authorization": _auth_header_value(token)}


def _generate_random_password(length: int = _ADD_USER_PASSWORD_LENGTH) -> str:
    size = max(1, int(length))
    return "".join(secrets.choice(_ADD_USER_PASSWORD_ALPHABET) for _ in range(size))


def _normalize_add_user_id(raw_username: str) -> str | None:
    user_value = str(raw_username or "").strip()
    if not user_value:
        return None
    if any(ch.isspace() for ch in user_value):
        return None
    if "@" not in user_value:
        return f"{user_value}@pve"
    return user_value


def _proxmox_request_once(
    host: str,
    port: int,
    path: str,
    timeout: float,
    *,
    pve_api_token: str,
    use_https: bool,
    insecure: bool,
    proxy: Any | None,
    method: str = "GET",
    form: dict[str, Any] | None = None,
    auth_headers: dict[str, str] | None = None,
) -> tuple[int, bytes, dict[str, str], str | None]:
    request_method = str(method or "GET").upper()
    request_body = urllib.parse.urlencode(form or {}, doseq=True).encode("utf-8") if form else None
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}{_PROXMOX_API_PREFIX}{path}"
    request_headers = {
        "User-Agent": "RedPosture/1.0",
        "Accept": "application/json,text/plain,*/*",
    }
    request_headers.update(_proxmox_auth_headers(pve_api_token, auth_headers))
    if request_body:
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
    response = HttpApiClient(
        HttpClientConfig(
            timeout=timeout,
            insecure=bool(use_https and insecure),
            proxy=proxy,
            response_size_cap=_MAX_HTTP_BODY_BYTES,
        )
    ).request(
        request_method,
        url,
        headers=request_headers,
        body=request_body,
        timeout=timeout,
    )
    if response.error:
        return 0, b"", {}, _friendly_error_text(response.error)
    return int(response.status), response.body, {str(k).lower(): str(v) for k, v in response.headers.items()}, None


def _proxmox_request(
    host: str,
    port: int,
    path: str,
    timeout: float,
    retries: int,
    *,
    pve_api_token: str,
    use_https: bool,
    insecure: bool,
    proxy: Any | None,
    method: str = "GET",
    form: dict[str, Any] | None = None,
    auth_headers: dict[str, str] | None = None,
) -> tuple[int, bytes, dict[str, str], str | None]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    for attempt in range(attempts):
        status, payload, response_headers, error = _proxmox_request_once(
            host,
            port,
            path,
            timeout,
            pve_api_token=pve_api_token,
            use_https=use_https,
            insecure=insecure,
            proxy=proxy,
            method=method,
            form=form,
            auth_headers=auth_headers,
        )
        if error is None:
            return status, payload, response_headers, None
        last_error = error
        if attempt >= attempts - 1:
            break
        time.sleep(_retry_delay(attempt))
    return 0, b"", {}, last_error or "connection failed"


def _decode_body_text(payload: bytes) -> str:
    return payload.decode("utf-8", errors="replace")


def _parse_json_payload(payload: bytes) -> Any | None:
    try:
        return json.loads(_decode_body_text(payload))
    except json.JSONDecodeError:
        return None


def _extract_error_message(payload: bytes) -> str | None:
    parsed = _parse_json_payload(payload)
    if isinstance(parsed, dict):
        for key in ("errors", "error", "message"):
            value = parsed.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, dict):
                parts: list[str] = []
                for item in value.values():
                    text = str(item or "").strip()
                    if text:
                        parts.append(text)
                if parts:
                    return "; ".join(parts)
        data = parsed.get("data")
        if isinstance(data, str) and data.strip():
            return data.strip()
    text = _decode_body_text(payload).strip()
    return text or None


def _is_invalid_token_message(value: str | None) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    needles = (
        "invalid token",
        "invalid api token",
        "authentication failed",
        "invalid pve ticket",
        "no such token",
        "token not found",
    )
    return any(needle in text for needle in needles)


def _is_permission_denied_message(value: str | None) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    needles = (
        "permission check failed",
        "insufficient privileges",
        "insufficient permission",
        "not enough permissions",
        "access denied",
        "forbidden",
    )
    return any(needle in text for needle in needles)


def _classify_auth_failure(status: int, error_message: str | None) -> str:
    if _is_permission_denied_message(error_message):
        return "insufficient_privileges"
    if status == 401:
        return "auth_failed"
    if _is_invalid_token_message(error_message):
        return "auth_failed"
    if status == 403:
        return "insufficient_privileges"
    return "auth_failed"


def _unwrap_api_data(payload: Any) -> Any:
    if isinstance(payload, dict) and "data" in payload:
        return payload.get("data")
    return payload


def _collect_nodes(payload: bytes) -> list[str]:
    parsed = _parse_json_payload(payload)
    data = _unwrap_api_data(parsed)
    if not isinstance(data, list):
        return []
    nodes: list[str] = []
    seen: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        node = str(item.get("node") or "").strip()
        if not node or node in seen:
            continue
        seen.add(node)
        nodes.append(node)
    return nodes


def _collect_vmids(payload: bytes) -> list[str]:
    parsed = _parse_json_payload(payload)
    data = _unwrap_api_data(parsed)
    if not isinstance(data, list):
        return []
    vmids: list[str] = []
    seen: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        vmid = str(item.get("vmid") or "").strip()
        if not vmid or vmid in seen:
            continue
        seen.add(vmid)
        vmids.append(vmid)
    return vmids


def _collect_storage_ids(payload: bytes) -> list[str]:
    parsed = _parse_json_payload(payload)
    data = _unwrap_api_data(parsed)
    if not isinstance(data, list):
        return []
    storage_ids: list[str] = []
    seen: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        storage_id = str(item.get("storage") or "").strip()
        if not storage_id or storage_id in seen:
            continue
        seen.add(storage_id)
        storage_ids.append(storage_id)
    return storage_ids


def _collect_volids(payload: bytes) -> list[str]:
    parsed = _parse_json_payload(payload)
    data = _unwrap_api_data(parsed)
    if not isinstance(data, list):
        return []
    volids: list[str] = []
    seen: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        volid = str(item.get("volid") or "").strip()
        if not volid or volid in seen:
            continue
        seen.add(volid)
        volids.append(volid)
    return volids


def _collect_user_ids(payload: bytes) -> list[str]:
    parsed = _parse_json_payload(payload)
    data = _unwrap_api_data(parsed)
    if not isinstance(data, list):
        return []
    user_ids: list[str] = []
    seen: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        user_id = str(item.get("userid") or item.get("user") or "").strip()
        if not user_id or user_id in seen:
            continue
        seen.add(user_id)
        user_ids.append(user_id)
    return user_ids


def _collect_permission_tokens(value: Any, sink: set[str]) -> None:
    if isinstance(value, dict):
        for key, inner in value.items():
            key_text = str(key or "").strip()
            if _PERMISSION_TOKEN_RE.fullmatch(key_text):
                if isinstance(inner, bool):
                    if inner:
                        sink.add(key_text)
                elif isinstance(inner, int):
                    if inner != 0:
                        sink.add(key_text)
                else:
                    sink.add(key_text)
            _collect_permission_tokens(inner, sink)
        return
    if isinstance(value, list):
        for item in value:
            _collect_permission_tokens(item, sink)
        return
    if isinstance(value, str):
        candidate = value.strip()
        if _PERMISSION_TOKEN_RE.fullmatch(candidate):
            sink.add(candidate)


def _has_any_permission(permission_tokens: set[str], required: tuple[str, ...]) -> bool:
    for token in required:
        if token in permission_tokens:
            return True
    return False


def _derive_permission_caps(permission_tokens: set[str]) -> dict[str, bool]:
    return {
        "adduser": _has_any_permission(
            permission_tokens,
            ("User.Modify", "Permissions.Modify", "Realm.AllocateUser"),
        ),
        "read": _has_any_permission(
            permission_tokens,
            (
                "Sys.Audit",
                "Sys.Syslog",
                "VM.Audit",
                "Datastore.Audit",
                "Pool.Audit",
                "SDN.Audit",
            ),
        ),
        "modify": _has_any_permission(
            permission_tokens,
            (
                "VM.Config.Options",
                "VM.Config.CPU",
                "VM.Config.Disk",
                "VM.Config.Network",
                "VM.PowerMgmt",
                "Datastore.Allocate",
                "Datastore.AllocateSpace",
                "SDN.Use",
            ),
        ),
        "backup": _has_any_permission(
            permission_tokens,
            ("VM.Backup", "Datastore.AllocateSpace", "Datastore.Allocate"),
        ),
    }


def _cap_text(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "unknown"


def _caps_suffix(record: dict[str, Any]) -> str:
    return " ".join(
        (
            f"(adduser:{_cap_text(record.get('cap_adduser'))})",
            f"(modify:{_cap_text(record.get('cap_modify'))})",
            f"(backup:{_cap_text(record.get('cap_backup'))})",
            f"(read:{_cap_text(record.get('cap_read'))})",
        )
    )


def _normalize_key_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _key_is_non_secret(key: str) -> bool:
    normalized = _normalize_key_token(key)
    if not normalized:
        return False
    return normalized in _NON_SECRET_KEY_TOKENS


def _clean_value_text(value: Any) -> str:
    text = str(value if value is not None else "").strip()
    while text and text[-1] in ",;)}]>":
        text = text[:-1].strip()
    while text and text[0] in "({[<":
        text = text[1:].strip()
    if len(text) >= 2 and (
        (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'"))
    ):
        text = text[1:-1].strip()
    return text


def _value_looks_secret(value: Any) -> bool:
    text = _clean_value_text(value)
    if not text:
        return False
    if text.lower() in _NON_SECRET_LITERALS:
        return False
    if set(text) <= {"*", "x", "X", "."} and len(text) >= 3:
        return False
    if len(text) < 4:
        return False
    return True


def _key_looks_sensitive(key: str) -> bool:
    if _key_is_non_secret(key):
        return False
    normalized = _normalize_key_token(key)
    if not normalized:
        return False
    return any(token in normalized for token in _SENSITIVE_KEY_TOKENS)


def _decode_base64_text(value: str) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if len(raw) < 20 or len(raw) > 4096:
        return None
    if not _BASE64_TEXT_RE.fullmatch(raw):
        return None

    padded = raw + ("=" * ((4 - (len(raw) % 4)) % 4))
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (ValueError, binascii.Error):
        return None
    if not decoded:
        return None
    if len(decoded) > 8192:
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.strip():
        return None
    printable_ratio = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t") / max(1, len(text))
    if printable_ratio < 0.90:
        return None
    return text


def _extract_api_data_dict(payload: bytes) -> dict[str, Any]:
    parsed = _parse_json_payload(payload)
    data = _unwrap_api_data(parsed)
    return data if isinstance(data, dict) else {}


def _login_proxmox_password(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    username: str,
    password: str,
    use_https: bool,
    insecure: bool,
    proxy: Any | None,
) -> tuple[dict[str, str] | None, str | None]:
    status, payload, _headers, error = _proxmox_request(
        host,
        port,
        "/access/ticket",
        timeout,
        retries,
        pve_api_token="",
        use_https=use_https,
        insecure=insecure,
        proxy=proxy,
        method="POST",
        form={"username": username, "password": password},
        auth_headers={},
    )
    if error:
        return None, error
    if status != 200:
        return None, _extract_error_message(payload) or f"unexpected HTTP {status} from /access/ticket"
    data = _extract_api_data_dict(payload)
    ticket = str(data.get("ticket") or "").strip()
    csrf = str(data.get("CSRFPreventionToken") or "").strip()
    if not ticket:
        return None, "missing Proxmox auth ticket"
    headers = {"Cookie": f"PVEAuthCookie={ticket}"}
    if csrf:
        headers["CSRFPreventionToken"] = csrf
    return headers, None


def _resolve_proxmox_auth_headers(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    pve_api_token: str,
    username: str | None,
    password: str | None,
    defcreds: bool,
    use_https: bool,
    insecure: bool,
    proxy: Any | None,
) -> tuple[dict[str, str], str, str | None, str | None, list[dict[str, str]]]:
    token = str(pve_api_token or "").strip()
    if token:
        return _proxmox_auth_headers(token), "pveapitoken", None, None, []

    candidates: list[tuple[str, str, str]] = []
    if username is not None and password is not None:
        candidates.append((str(username), str(password), "provided"))
    if defcreds:
        for user, secret in _PROXMOX_DEFAULT_CREDENTIALS:
            if (user, secret, "defcreds") not in candidates:
                candidates.append((user, secret, "defcreds"))

    attempts: list[dict[str, str]] = []
    for user, secret, source in candidates:
        headers, _error = _login_proxmox_password(
            host,
            port,
            timeout,
            retries,
            username=user,
            password=secret,
            use_https=use_https,
            insecure=insecure,
            proxy=proxy,
        )
        attempts.append({"username": user, "source": source, "ok": str(headers is not None)})
        if headers is not None:
            return headers, "password", user, secret, attempts
    return {}, "password", None, None, attempts or [{"username": "-", "source": "none", "ok": "False"}]


def _looks_like_cloud_init_secret_blob(value: str) -> bool:
    text = str(value or "")
    lower = text.lower()
    if "#cloud-config" not in lower:
        return False
    needles = ("chpasswd:", "password:", "plain_text_passwd", "passwd:", "ssh_authorized_keys:")
    return any(needle in lower for needle in needles)


def _add_finding(
    findings: list[dict[str, str]],
    seen: set[tuple[str, str, str, str]],
    *,
    endpoint: str,
    reason: str,
    path: str,
    sample: str,
) -> None:
    if len(findings) >= _MAX_FINDINGS_PER_TARGET:
        return
    sample_text = _clip(_clean_value_text(sample), 100)
    key = (endpoint, reason, path, sample_text)
    if key in seen:
        return
    seen.add(key)
    findings.append(
        {
            "endpoint": endpoint,
            "reason": reason,
            "path": path,
            "sample": sample_text,
        }
    )


def _collect_text_findings(
    text: str,
    endpoint: str,
    findings: list[dict[str, str]],
    seen: set[tuple[str, str, str, str]],
    *,
    path: str,
    limit: int,
    depth: int = 0,
) -> None:
    added = 0
    for match in _TEXT_SECRET_RE.finditer(text):
        if added >= limit:
            break
        key = str(match.group(1) or "")
        value_raw = match.group(2) or match.group(3) or match.group(4) or ""
        value = _clean_value_text(value_raw)
        if not _key_looks_sensitive(key) or not _value_looks_secret(value):
            continue
        _add_finding(
            findings,
            seen,
            endpoint=endpoint,
            reason=f"text_{key.lower()}",
            path=path,
            sample=f"{key}={value}",
        )
        added += 1

    uri_auth_match = _URI_WITH_AUTH_RE.search(text)
    if uri_auth_match:
        _add_finding(
            findings,
            seen,
            endpoint=endpoint,
            reason="uri_with_auth",
            path=path,
            sample=str(uri_auth_match.group(0) or ""),
        )
    url_basic_match = _URL_BASIC_AUTH_RE.search(text)
    if url_basic_match:
        _add_finding(
            findings,
            seen,
            endpoint=endpoint,
            reason="url_basic_auth",
            path=path,
            sample=str(url_basic_match.group(0) or ""),
        )
    auth_basic_match = _AUTH_BASIC_RE.search(text)
    if auth_basic_match:
        _add_finding(
            findings,
            seen,
            endpoint=endpoint,
            reason="authorization_basic",
            path=path,
            sample=str(auth_basic_match.group(0) or ""),
        )
    auth_bearer_match = _AUTH_BEARER_RE.search(text)
    if auth_bearer_match:
        _add_finding(
            findings,
            seen,
            endpoint=endpoint,
            reason="authorization_bearer",
            path=path,
            sample=str(auth_bearer_match.group(0) or ""),
        )
    jwt_match = _JWT_RE.search(text)
    if jwt_match:
        _add_finding(
            findings, seen, endpoint=endpoint, reason="jwt_token", path=path, sample=str(jwt_match.group(0) or "")
        )
    opaque_match = _OPAQUE_TOKEN_RE.search(text)
    if opaque_match:
        _add_finding(
            findings,
            seen,
            endpoint=endpoint,
            reason="opaque_token",
            path=path,
            sample=str(opaque_match.group(0) or ""),
        )
    if _looks_like_cloud_init_secret_blob(text):
        _add_finding(findings, seen, endpoint=endpoint, reason="cloud_init_blob", path=path, sample=text)
    pem_match = _PEM_PRIVATE_KEY_RE.search(text)
    if pem_match:
        _add_finding(
            findings,
            seen,
            endpoint=endpoint,
            reason="private_key_pem",
            path=path,
            sample=str(pem_match.group(0) or ""),
        )

    if depth >= 1:
        return
    for match in _BASE64_TEXT_RE.finditer(text):
        candidate = str(match.group(0) or "")
        decoded_text = _decode_base64_text(candidate)
        if not decoded_text:
            continue
        _collect_text_findings(
            decoded_text,
            endpoint,
            findings,
            seen,
            path=f"{path}.base64",
            limit=max(4, limit // 2),
            depth=depth + 1,
        )


def _collect_json_findings(
    payload: Any,
    endpoint: str,
    findings: list[dict[str, str]],
    seen: set[tuple[str, str, str, str]],
    *,
    path: str = "$",
) -> None:
    if len(findings) >= _MAX_FINDINGS_PER_TARGET:
        return

    if isinstance(payload, dict):
        for key, value in payload.items():
            key_text = str(key)
            sub_path = f"{path}.{key_text}"
            if _key_looks_sensitive(key_text) and _value_looks_secret(value):
                _add_finding(
                    findings,
                    seen,
                    endpoint=endpoint,
                    reason=f"json_{key_text.lower()}",
                    path=sub_path,
                    sample=str(value),
                )

            if isinstance(value, str):
                _collect_text_findings(
                    value,
                    endpoint,
                    findings,
                    seen,
                    path=sub_path,
                    limit=_MAX_FINDINGS_PER_ENDPOINT,
                )
            _collect_json_findings(value, endpoint, findings, seen, path=sub_path)
        return

    if isinstance(payload, list):
        for idx, value in enumerate(payload):
            sub_path = f"{path}[{idx}]"
            if isinstance(value, str):
                _collect_text_findings(
                    value,
                    endpoint,
                    findings,
                    seen,
                    path=sub_path,
                    limit=_MAX_FINDINGS_PER_ENDPOINT,
                )
            _collect_json_findings(value, endpoint, findings, seen, path=sub_path)


def _scan_endpoint_payload(
    endpoint: str,
    payload: bytes,
    findings: list[dict[str, str]],
    seen: set[tuple[str, str, str, str]],
) -> None:
    text = _decode_body_text(payload)
    _collect_text_findings(
        text,
        endpoint,
        findings,
        seen,
        path="$text",
        limit=_MAX_FINDINGS_PER_ENDPOINT,
    )

    parsed = _parse_json_payload(payload)
    if parsed is None:
        return
    data = _unwrap_api_data(parsed)
    _collect_json_findings(data, endpoint, findings, seen)


def _audit_proxmox_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    pve_api_token: str,
    use_https: bool,
    insecure: bool,
    proxy: Any | None,
    *,
    username: str | None = None,
    password: str | None = None,
    defcreds: bool = False,
    discover_creds: bool = False,
    show_nodes: bool = False,
    show_users: bool = False,
    add_user: str | None = None,
    on_status_ready: Callable[[dict[str, Any]], None] | None = None,
    on_discovered_url: Callable[[str], None] | None = None,
    on_credential_finding: Callable[[dict[str, str]], None] | None = None,
) -> dict[str, Any]:
    endpoint_results: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    findings_seen: set[tuple[str, str, str, str]] = set()
    stream_started = False
    streamed_url_count = 0
    streamed_finding_count = 0
    requested_add_user = str(add_user or "").strip()
    auth_headers, auth_method, auth_username, auth_password, auth_attempts = _resolve_proxmox_auth_headers(
        host,
        port,
        timeout,
        retries,
        pve_api_token=pve_api_token,
        username=username,
        password=password,
        defcreds=defcreds,
        use_https=use_https,
        insecure=insecure,
        proxy=proxy,
    )

    def flush_stream_buffers() -> None:
        nonlocal streamed_url_count, streamed_finding_count
        if not stream_started:
            return
        if discover_creds and on_discovered_url is not None:
            while streamed_url_count < len(endpoint_results):
                item = endpoint_results[streamed_url_count]
                streamed_url_count += 1
                path = str(item.get("path") or "").strip()
                if path.startswith("/"):
                    on_discovered_url(path)
        if discover_creds and on_credential_finding is not None:
            while streamed_finding_count < len(findings):
                finding = findings[streamed_finding_count]
                streamed_finding_count += 1
                if isinstance(finding, dict):
                    on_credential_finding(finding)

    def fetch(
        path: str,
        *,
        method: str = "GET",
        form: dict[str, Any] | None = None,
    ) -> tuple[int, bytes, str | None]:
        request_method = str(method or "GET").upper()
        request_kwargs: dict[str, Any] = {
            "pve_api_token": pve_api_token,
            "use_https": use_https,
            "insecure": insecure,
            "proxy": proxy,
            "auth_headers": auth_headers,
        }
        if request_method != "GET" or form:
            request_kwargs["method"] = request_method
            request_kwargs["form"] = form
        try:
            status, payload, _headers, error = _proxmox_request(
                host,
                port,
                path,
                timeout,
                retries,
                **request_kwargs,
            )
        except TypeError as exc:
            if not is_signature_compat_typeerror(exc, expected_keywords={"auth_headers"}):
                raise
            request_kwargs.pop("auth_headers", None)
            status, payload, _headers, error = _proxmox_request(
                host,
                port,
                path,
                timeout,
                retries,
                **request_kwargs,
            )
        endpoint_results.append(
            {
                "path": path,
                "status": status,
                "error": error,
                "method": request_method,
            }
        )
        if (
            discover_creds
            and request_method == "GET"
            and status == 200
            and payload
            and len(findings) < _MAX_FINDINGS_PER_TARGET
        ):
            _scan_endpoint_payload(path, payload, findings, findings_seen)
        flush_stream_buffers()
        return status, payload, error

    started = time.monotonic()
    access_status, access_payload, access_error = fetch("/access")
    if access_error:
        result = {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "is_proxmox": False,
            "status": "fail",
            "auth_method": auth_method,
            "auth_username": auth_username,
            "auth_password": auth_password,
            "auth_attempts": auth_attempts,
            "discover_creds": discover_creds,
            "use_https": use_https,
            "show_nodes": show_nodes,
            "nodes": None,
            "nodes_error": None,
            "show_users": show_users,
            "users": None,
            "users_error": None,
            "add_user": requested_add_user or None,
            "added_user": None,
            "added_password": None,
            "add_user_error": None,
            "add_user_privileges_granted": None,
            "add_user_privileges_role": None,
            "add_user_privileges_error": None,
            "cap_adduser": None,
            "cap_read": None,
            "cap_modify": None,
            "cap_backup": None,
            "checked_endpoints": len(endpoint_results),
            "successful_endpoints": 0,
            "findings": findings,
            "credential_hits": len(findings),
            "endpoint_results": endpoint_results,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": access_error,
        }
        if on_status_ready is not None:
            on_status_ready(result)
        return result

    if access_status in {401, 403}:
        access_error_text = _extract_error_message(access_payload)
        auth_status = _classify_auth_failure(access_status, access_error_text)

        permissions_status, permissions_payload, permissions_error = fetch("/access/permissions?path=/")
        if permissions_error:
            cap_adduser: bool | None = None
            cap_read: bool | None = None
            cap_modify: bool | None = None
            cap_backup: bool | None = None
        elif permissions_status != 200:
            cap_adduser = None
            cap_read = None
            cap_modify = None
            cap_backup = None
        else:
            permission_tokens: set[str] = set()
            _collect_permission_tokens(_unwrap_api_data(_parse_json_payload(permissions_payload)), permission_tokens)
            caps = _derive_permission_caps(permission_tokens)
            cap_adduser = caps["adduser"]
            cap_read = caps["read"]
            cap_modify = caps["modify"]
            cap_backup = caps["backup"]

        users: list[str] | None = None
        users_error: str | None = None
        if show_users:
            users_status, users_payload, users_fetch_error = fetch("/access/users")
            if users_fetch_error:
                users_error = users_fetch_error
            elif users_status != 200:
                users_error = f"unexpected HTTP {users_status} from /access/users"
            else:
                users = _collect_user_ids(users_payload)

        result = {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "is_proxmox": True,
            "status": auth_status,
            "auth_method": auth_method,
            "auth_username": auth_username,
            "auth_password": auth_password,
            "auth_attempts": auth_attempts,
            "discover_creds": discover_creds,
            "use_https": use_https,
            "show_nodes": show_nodes,
            "nodes": None,
            "nodes_error": access_error_text
            or ("authentication failed" if auth_status == "auth_failed" else "permission denied"),
            "show_users": show_users,
            "users": users,
            "users_error": users_error,
            "add_user": requested_add_user or None,
            "added_user": None,
            "added_password": None,
            "add_user_error": None,
            "add_user_privileges_granted": None,
            "add_user_privileges_role": None,
            "add_user_privileges_error": None,
            "cap_adduser": cap_adduser,
            "cap_read": cap_read,
            "cap_modify": cap_modify,
            "cap_backup": cap_backup,
            "checked_endpoints": len(endpoint_results),
            "successful_endpoints": 0,
            "findings": findings,
            "credential_hits": len(findings),
            "endpoint_results": endpoint_results,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": access_error_text
            or ("authentication failed" if auth_status == "auth_failed" else "insufficient privileges"),
        }
        if on_status_ready is not None:
            on_status_ready(result)
        return result

    if access_status != 200:
        result = {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "is_proxmox": False,
            "status": "fail",
            "auth_method": auth_method,
            "auth_username": auth_username,
            "auth_password": auth_password,
            "auth_attempts": auth_attempts,
            "discover_creds": discover_creds,
            "use_https": use_https,
            "show_nodes": show_nodes,
            "nodes": None,
            "nodes_error": None,
            "show_users": show_users,
            "users": None,
            "users_error": None,
            "add_user": requested_add_user or None,
            "added_user": None,
            "added_password": None,
            "add_user_error": None,
            "add_user_privileges_granted": None,
            "add_user_privileges_role": None,
            "add_user_privileges_error": None,
            "cap_adduser": None,
            "cap_read": None,
            "cap_modify": None,
            "cap_backup": None,
            "checked_endpoints": len(endpoint_results),
            "successful_endpoints": 0,
            "findings": findings,
            "credential_hits": len(findings),
            "endpoint_results": endpoint_results,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "error": f"unexpected HTTP {access_status} from /access",
        }
        if on_status_ready is not None:
            on_status_ready(result)
        return result

    permissions_status, permissions_payload, permissions_error = fetch("/access/permissions?path=/")
    if permissions_error:
        cap_adduser = None
        cap_read = None
        cap_modify = None
        cap_backup = None
    elif permissions_status != 200:
        cap_adduser = None
        cap_read = None
        cap_modify = None
        cap_backup = None
    else:
        permission_tokens = set()
        _collect_permission_tokens(_unwrap_api_data(_parse_json_payload(permissions_payload)), permission_tokens)
        caps = _derive_permission_caps(permission_tokens)
        cap_adduser = caps["adduser"]
        cap_read = caps["read"]
        cap_modify = caps["modify"]
        cap_backup = caps["backup"]

    added_user: str | None = None
    added_password: str | None = None
    add_user_error: str | None = None
    add_user_privileges_granted: bool | None = None
    add_user_privileges_role: str | None = None
    add_user_privileges_error: str | None = None
    if requested_add_user:
        add_user_id = _normalize_add_user_id(requested_add_user)
        if not add_user_id:
            add_user_error = "invalid username format for -add-user"
        else:
            candidate_password = _generate_random_password()
            add_status, add_payload, add_fetch_error = fetch(
                "/access/users",
                method="POST",
                form={
                    "userid": add_user_id,
                    "password": candidate_password,
                    "enable": "1",
                },
            )
            if add_fetch_error:
                add_user_error = add_fetch_error
            elif add_status not in {200, 201}:
                add_user_error = (
                    _extract_error_message(add_payload) or f"unexpected HTTP {add_status} from /access/users"
                )
            else:
                added_user = add_user_id
                added_password = candidate_password
                acl_status, acl_payload, acl_fetch_error = fetch(
                    "/access/acl",
                    method="PUT",
                    form={
                        "path": _ADD_USER_PRIV_PATH,
                        "users": add_user_id,
                        "roles": _ADD_USER_PRIV_ROLE,
                        "propagate": "1",
                    },
                )
                if acl_fetch_error:
                    add_user_privileges_granted = False
                    add_user_privileges_error = acl_fetch_error
                elif acl_status not in {200, 201}:
                    add_user_privileges_granted = False
                    add_user_privileges_error = (
                        _extract_error_message(acl_payload) or f"unexpected HTTP {acl_status} from /access/acl"
                    )
                else:
                    add_user_privileges_granted = True
                    add_user_privileges_role = _ADD_USER_PRIV_ROLE

    users = None
    users_error = None
    if show_users:
        users_status, users_payload, users_fetch_error = fetch("/access/users")
        if users_fetch_error:
            users_error = users_fetch_error
        elif users_status != 200:
            users_error = f"unexpected HTTP {users_status} from /access/users"
        else:
            users = _collect_user_ids(users_payload)
    else:
        users = None
        users_error = None

    status_preview = {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_proxmox": True,
        "status": "token_ok",
        "auth_method": auth_method,
        "auth_username": auth_username,
        "auth_password": auth_password,
        "auth_attempts": auth_attempts,
        "cap_adduser": cap_adduser,
        "cap_read": cap_read,
        "cap_modify": cap_modify,
        "cap_backup": cap_backup,
        "add_user": requested_add_user or None,
        "added_user": added_user,
        "added_password": added_password,
        "add_user_error": add_user_error,
        "add_user_privileges_granted": add_user_privileges_granted,
        "add_user_privileges_role": add_user_privileges_role,
        "add_user_privileges_error": add_user_privileges_error,
        "error": None,
    }
    if on_status_ready is not None:
        on_status_ready(status_preview)
    stream_started = True
    flush_stream_buffers()

    discover_creds_crawl = discover_creds and (
        cap_read is not False or cap_modify is not False or cap_backup is not False
    )

    nodes: list[str] = []
    nodes_error: str | None = None
    if show_nodes or discover_creds_crawl:
        nodes_status, nodes_payload, nodes_fetch_error = fetch("/nodes")
        if nodes_fetch_error:
            nodes_error = nodes_fetch_error
        elif nodes_status == 200:
            nodes = _collect_nodes(nodes_payload)
        elif nodes_status in {401, 403}:
            nodes_error = _extract_error_message(nodes_payload) or "permission denied"
        else:
            nodes_error = f"unexpected HTTP {nodes_status} from /nodes"

    if discover_creds_crawl:
        for node in nodes:
            if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                break
            node_id = urllib.parse.quote(node, safe="")
            fetch(f"/nodes/{node_id}/syslog")
            if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                break
            fetch(f"/nodes/{node_id}/report")
            if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                break
            fetch(f"/nodes/{node_id}/tasks")
            if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                break

            qemu_status, qemu_payload, _qemu_error = fetch(f"/nodes/{node_id}/qemu")
            if qemu_status == 200:
                for vmid in _collect_vmids(qemu_payload):
                    if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                        break
                    vmid_id = urllib.parse.quote(vmid, safe="")
                    fetch(f"/nodes/{node_id}/qemu/{vmid_id}/config")

            lxc_status, lxc_payload, _lxc_error = fetch(f"/nodes/{node_id}/lxc")
            if lxc_status == 200:
                for vmid in _collect_vmids(lxc_payload):
                    if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                        break
                    vmid_id = urllib.parse.quote(vmid, safe="")
                    fetch(f"/nodes/{node_id}/lxc/{vmid_id}/config")

            storages_status, storages_payload, _storages_error = fetch(f"/nodes/{node_id}/storage")
            if storages_status == 200:
                for storage_id in _collect_storage_ids(storages_payload):
                    if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                        break
                    storage_q = urllib.parse.quote(storage_id, safe="")
                    base_path = f"/nodes/{node_id}/storage/{storage_q}"
                    content_status, content_payload, _content_error = fetch(f"{base_path}/content")
                    backup_status, backup_payload, _backup_error = fetch(f"{base_path}/content?content=backup")

                    volids: list[str] = []
                    if content_status == 200:
                        volids.extend(_collect_volids(content_payload))
                    if backup_status == 200:
                        volids.extend(_collect_volids(backup_payload))

                    seen_volids: set[str] = set()
                    for volid in volids:
                        if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                            break
                        if volid in seen_volids:
                            continue
                        seen_volids.add(volid)
                        volid_q = urllib.parse.quote(volid, safe="")
                        fetch(f"{base_path}/content/{volid_q}")
                        if len(findings) >= _MAX_FINDINGS_PER_TARGET:
                            break
                        query = urllib.parse.urlencode({"volumeid": volid})
                        fetch(f"{base_path}/download?{query}")

        if len(findings) < _MAX_FINDINGS_PER_TARGET:
            fetch("/sdn")
        if len(findings) < _MAX_FINDINGS_PER_TARGET:
            fetch("/cluster/backup")

    successful_endpoints = sum(1 for item in endpoint_results if int(item.get("status") or 0) == 200)
    result = {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_proxmox": True,
        "status": "token_ok",
        "auth_method": auth_method,
        "auth_username": auth_username,
        "auth_password": auth_password,
        "auth_attempts": auth_attempts,
        "discover_creds": discover_creds,
        "use_https": use_https,
        "show_nodes": show_nodes,
        "nodes": nodes if show_nodes else None,
        "nodes_error": nodes_error,
        "show_users": show_users,
        "users": users,
        "users_error": users_error,
        "add_user": requested_add_user or None,
        "added_user": added_user,
        "added_password": added_password,
        "add_user_error": add_user_error,
        "add_user_privileges_granted": add_user_privileges_granted,
        "add_user_privileges_role": add_user_privileges_role,
        "add_user_privileges_error": add_user_privileges_error,
        "cap_adduser": cap_adduser,
        "cap_read": cap_read,
        "cap_modify": cap_modify,
        "cap_backup": cap_backup,
        "checked_endpoints": len(endpoint_results),
        "successful_endpoints": successful_endpoints,
        "findings": findings,
        "credential_hits": len(findings),
        "endpoint_results": endpoint_results,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "error": None,
    }
    return result


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{'PROXMOX':<8}\t{host}\t{port}\t"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(
            {
                "timestamp": record.get("timestamp"),
                "type": "detect",
                "host": record.get("host"),
                "port": record.get("port"),
                "service": "proxmox",
                "detected": bool(record.get("is_proxmox")),
            },
            ensure_ascii=False,
        )
    return f"{_nxc_prefix(record)} [*] Proxmox API"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    prefix = _nxc_prefix(record)
    status = str(record.get("status") or "fail")
    if status == "token_ok":
        if str(record.get("auth_method") or "") == "password":
            username = str(record.get("auth_username") or "-")
            password = str(record.get("auth_password") or "-")
            return f"{prefix} [+] {username}:{password} {_caps_suffix(record)}"
        return f"{prefix} [+] token accepted {_caps_suffix(record)}"
    if status == "insufficient_privileges":
        return f"{prefix} [-] token valid but insufficient privileges {_caps_suffix(record)}"
    if status == "auth_failed":
        return f"{prefix} [-] invalid pve api token"
    err = _clip(str(record.get("error") or "connection failed"), 90)
    return f"{prefix} [!] connection failed err={err}"


def _format_findings_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    findings = record.get("findings")
    if not isinstance(findings, list) or not findings:
        return []

    if output_format == "json":
        lines: list[str] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            lines.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "credential_hit",
                        "service": "proxmox",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "endpoint": finding.get("endpoint"),
                        "reason": finding.get("reason"),
                        "path": finding.get("path"),
                        "sample": finding.get("sample"),
                    },
                    ensure_ascii=False,
                )
            )
        return lines

    prefix = _nxc_prefix(record)
    lines = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        reason = _clip(str(finding.get("reason") or "-"), 80)
        path = _clip(str(finding.get("path") or "-"), 100)
        sample = _clip(str(finding.get("sample") or "-"), 100)
        lines.append(f"{prefix} [!] credential candidate reason={reason} path={path} sample={sample}")
    return lines


def _format_single_finding_detail_line(record: dict[str, Any], finding: dict[str, Any]) -> str:
    prefix = _nxc_prefix(record)
    reason = _clip(str(finding.get("reason") or "-"), 80)
    path = _clip(str(finding.get("path") or "-"), 100)
    sample = _clip(str(finding.get("sample") or "-"), 100)
    return f"{prefix} [!] credential candidate reason={reason} path={path} sample={sample}"


def _credential_finding_endpoints(record: dict[str, Any]) -> set[str]:
    findings = record.get("findings")
    if not isinstance(findings, list):
        return set()
    endpoints: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        endpoint = str(finding.get("endpoint") or "").strip()
        if endpoint.startswith("/"):
            endpoints.add(endpoint)
    return endpoints


def _format_discovered_urls_detail_records(
    record: dict[str, Any], output_format: str, *, include_all_urls: bool = False
) -> list[str]:
    if output_format != "txt":
        return []
    if not bool(record.get("discover_creds")):
        return []

    endpoint_results = record.get("endpoint_results")
    if not isinstance(endpoint_results, list):
        return []

    host = str(record.get("host") or "").strip()
    port_text = str(record.get("port") or "").strip()
    if not host or not port_text:
        return []
    scheme = "https" if bool(record.get("use_https")) else "http"

    findings = record.get("findings")
    findings_by_endpoint: dict[str, list[dict[str, Any]]] = {}
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            endpoint = str(finding.get("endpoint") or "").strip()
            if not endpoint.startswith("/"):
                continue
            findings_by_endpoint.setdefault(endpoint, []).append(finding)

    candidate_endpoints = set(findings_by_endpoint)
    urls: list[tuple[str, str]] = []
    seen_urls: set[str] = set()
    for item in endpoint_results:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").strip()
        if not path.startswith("/"):
            continue
        if not include_all_urls and path not in candidate_endpoints:
            continue
        url = f"{scheme}://{host}:{port_text}{_PROXMOX_API_PREFIX}{path}"
        if url in seen_urls:
            continue
        seen_urls.add(url)
        urls.append((path, url))

    for path in candidate_endpoints:
        url = f"{scheme}://{host}:{port_text}{_PROXMOX_API_PREFIX}{path}"
        if url in seen_urls:
            continue
        seen_urls.add(url)
        urls.append((path, url))

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Discovered Credentials"]
    if not urls:
        lines.append(f"{prefix} [*] Discovered URL")
        lines.append(f"{prefix} [*] <none>")
        return lines
    lines.append(f"{prefix} [*] Discovered URL")
    for path, url in urls:
        lines.append(f"{prefix} [*] {url}")
        for finding in findings_by_endpoint.get(path, []):
            lines.append(_format_single_finding_detail_line(record, finding))
    return lines


def _format_nodes_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if not bool(record.get("show_nodes")):
        return []

    nodes = record.get("nodes")
    nodes_error = record.get("nodes_error")

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "nodes_dump",
                    "service": "proxmox",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "nodes": [str(item) for item in nodes] if isinstance(nodes, list) else [],
                    "error": str(nodes_error) if nodes_error else None,
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Nodes"]
    if nodes_error:
        lines.append(f"{prefix} <error:{_clip(str(nodes_error), 120)}>")
        return lines
    if isinstance(nodes, list) and nodes:
        for node in nodes:
            lines.append(f"{prefix} {str(node)}")
        return lines
    lines.append(f"{prefix} <no nodes>")
    return lines


def _format_users_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if not bool(record.get("show_users")):
        return []

    users = record.get("users")
    users_error = record.get("users_error")

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "users_dump",
                    "service": "proxmox",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "users": [str(item) for item in users] if isinstance(users, list) else [],
                    "error": str(users_error) if users_error else None,
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    lines = [f"{prefix} [*] Users"]
    if users_error:
        lines.append(f"{prefix} <error:{_clip(str(users_error), 120)}>")
        return lines
    if isinstance(users, list) and users:
        for user in users:
            lines.append(f"{prefix} {str(user)}")
        return lines
    lines.append(f"{prefix} <no users>")
    return lines


def _format_add_user_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    requested_user = str(record.get("add_user") or "").strip()
    if not requested_user:
        return []

    added_user = str(record.get("added_user") or "").strip()
    added_password = str(record.get("added_password") or "").strip()
    add_user_error = str(record.get("add_user_error") or "").strip()
    add_user_privileges_granted = record.get("add_user_privileges_granted")
    add_user_privileges_role = str(record.get("add_user_privileges_role") or _ADD_USER_PRIV_ROLE).strip()
    add_user_privileges_error = str(record.get("add_user_privileges_error") or "").strip()

    if output_format == "json":
        return [
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "add_user",
                    "service": "proxmox",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "requested_user": requested_user,
                    "added_user": added_user or None,
                    "added_password": added_password or None,
                    "privileges_granted": bool(add_user_privileges_granted)
                    if add_user_privileges_granted is not None
                    else None,
                    "privileges_role": add_user_privileges_role or None,
                    "privileges_error": add_user_privileges_error or None,
                    "error": add_user_error or None,
                },
                ensure_ascii=False,
            )
        ]

    prefix = _nxc_prefix(record)
    if added_user and added_password and add_user_privileges_granted is True:
        return [
            f"{prefix} [+] User {added_user} added with password {added_password} "
            f"and granted privileges {add_user_privileges_role or _ADD_USER_PRIV_ROLE}"
        ]
    if added_user and added_password:
        error_text = _clip(add_user_privileges_error or "failed to grant administrator privileges", 120)
        return [
            f"{prefix} [!] User {added_user} added with password {added_password}, but privileges were not granted err={error_text}"
        ]
    error_text = _clip(add_user_error or "failed to add user", 120)
    return [f"{prefix} [-] failed to add user {requested_user} err={error_text}"]


def _render_colored_proxmox_line(console: Console, line: str) -> bool:
    def _extra_spans(marker: str, payload: str) -> list[tuple[int, int, str]]:
        if marker == "[!]" and payload.startswith("credential candidate "):
            return [(0, len(payload), "orange")]
        return []

    return render_colored_marker_line(
        console,
        line,
        tag="PROXMOX",
        include_auth_required=False,
        booleans=(
            BooleanColorRule("adduser"),
            BooleanColorRule("modify"),
            BooleanColorRule("backup"),
            BooleanColorRule("read"),
        ),
        extra_spans=_extra_spans,
    )


def _call_audit_proxmox_host_with_stage_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    pve_api_token: str,
    use_https: bool,
    insecure: bool,
    proxy: Any | None,
    *,
    username: str | None,
    password: str | None,
    defcreds: bool,
    discover_creds: bool,
    show_nodes: bool,
    show_users: bool,
    add_user: str | None,
    run_deep_checks: bool,
    debug: bool,
    debug_emit: Callable[[str], None] | None,
    on_status_ready: Callable[[dict[str, Any]], None] | None = None,
    on_discovered_url: Callable[[str], None] | None = None,
    on_credential_finding: Callable[[dict[str, str]], None] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    audit_kwargs: dict[str, Any] = {
        "username": username,
        "password": password,
        "defcreds": defcreds,
        "discover_creds": discover_creds if run_deep_checks else False,
        "show_nodes": show_nodes if run_deep_checks else False,
        "show_users": show_users if run_deep_checks else False,
        "add_user": add_user if run_deep_checks else None,
        "on_status_ready": on_status_ready if run_deep_checks else None,
        "on_discovered_url": on_discovered_url if run_deep_checks else None,
        "on_credential_finding": on_credential_finding if run_deep_checks else None,
    }
    try:
        record = _audit_proxmox_host(
            host,
            port,
            timeout,
            retries,
            pve_api_token,
            use_https,
            insecure,
            proxy,
            **audit_kwargs,
        )
    except TypeError as exc:
        if not is_signature_compat_typeerror(exc, expected_keywords={"username", "password", "defcreds"}):
            raise
        audit_kwargs.pop("username", None)
        audit_kwargs.pop("password", None)
        audit_kwargs.pop("defcreds", None)
        record = _audit_proxmox_host(
            host,
            port,
            timeout,
            retries,
            pve_api_token,
            use_https,
            insecure,
            proxy,
            **audit_kwargs,
        )

    result: dict[str, Any] = dict(record)
    attempts = max(1, retries + 1)
    status = str(result.get("status") or "fail")
    is_proxmox = bool(result.get("is_proxmox"))
    elapsed_ms = int((time.monotonic() - started) * 1000)
    telemetry = StageTelemetryBuilder(host=host, port=port, attempts=attempts, debug=debug, debug_emit=debug_emit)
    if attempts > 1 and status == "fail":
        telemetry.debug(format_retry_decision(_STAGE_DETECT_PROTOCOL, 1, attempts, _retry_delay(0), "error"))

    detect_result = "ok" if is_proxmox else ("error" if status == "fail" else "skip")
    detect_error = str(result.get("error") or "") if detect_result == "error" else None
    telemetry.stage(_STAGE_DETECT_PROTOCOL, detect_result, detect_error, 0)

    auth_result = "ok" if is_proxmox and status in _PROXMOX_DEEP_STATUSES.union({"auth_failed"}) else detect_result
    telemetry.stage(_STAGE_AUTH_INFERENCE, auth_result, detect_error if auth_result == "error" else None, 0)

    if run_deep_checks and status in _PROXMOX_DEEP_STATUSES:
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


# Typed runner boundary -----------------------------------------------------
host_stage = _call_audit_proxmox_host_with_stage_debug
