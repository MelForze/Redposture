"""Docker Registry v2 and Harbor audit stage."""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any

from ...clients.http_api import HttpApiClient, HttpClientConfig, build_http_target_url, resolve_http_scheme
from ...clients.http_session import HttpSessionPool
from ...console import Console
from ...rendering import CountColorRule, format_count_value, render_colored_marker_line, render_tagged_detail_line
from ...utils import (
    is_signature_compat_typeerror,
    utc_now_iso,
)

_REGISTRY_MANIFEST_ACCEPT = ",".join(
    (
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
    )
)
_REGISTRY_DOWNLOAD_LIMIT_BYTES = 100 * 1024 * 1024
_REGISTRY_MAX_INSPECT_IMAGES = 100
_REGISTRY_MAX_HISTORY_LINES = 20
_CONNECTION_TIMEOUT_PREFIX = "connection timeout"
_CONNECTION_REFUSED_PREFIX = "connection refused"
_SUSPICIOUS_TEXT_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|aws[_-]?secret|private[_-]?key)"
)
_STAGE_DETECT_PROTOCOL = "detect_protocol"
_STAGE_AUTH_INFERENCE = "auth_inference_credentials"
_STAGE_ACCESS_CAPABILITIES = "access_capabilities"
_STAGE_DATA = "data"
_THREAD_LOCAL_DEBUG_EMIT = threading.local()
_BEARER_TOKEN_CACHE: dict[tuple[str, str, str, str], str] = {}
_BEARER_TOKEN_CACHE_LOCK = threading.Lock()

_RegistryProbe = tuple[int, bytes, dict[str, str], str | None]
_RegistryCredentialKey = tuple[str | None, str | None, str | None, str]


@dataclass
class RegistryLifecycleState:
    anonymous_probe: _RegistryProbe | None = None
    anonymous_nexus: tuple[dict[str, Any] | None, str | None] | None = None
    credential_probes: dict[_RegistryCredentialKey, _RegistryProbe] = dc_field(default_factory=dict)
    credential_nexus: dict[_RegistryCredentialKey, tuple[dict[str, Any] | None, str | None]] = dc_field(
        default_factory=dict
    )
    http: HttpSessionPool | None = None
    scheme: str | None = None

    def close(self) -> None:
        if self.http is not None:
            self.http.close()
            self.http = None


_THREAD_LOCAL_HTTP = threading.local()
_DETECT_RESPONSE_CAP = 256 * 1024


def registry_lifecycle_state_factory(ctx: Any) -> RegistryLifecycleState:
    target_scheme = str(getattr(getattr(ctx, "target", None), "scheme", "") or "").lower()
    return RegistryLifecycleState(
        http=HttpSessionPool(
            timeout=float(getattr(ctx.args, "timeout", 1.0)),
            insecure=True,
            proxy=getattr(ctx.args, "_proxy_config", None),
        ),
        scheme=target_scheme if target_scheme in {"http", "https"} else None,
    )


def _activate_registry_transport(state: RegistryLifecycleState) -> None:
    _THREAD_LOCAL_HTTP.state = state


def _clip(text: str, width: int = 72) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _retry_delay(attempt_index: int) -> float:
    return min(1.50, 0.20 * (2**attempt_index))


def _get_thread_debug_emitter() -> Callable[[str], None] | None:
    callback = getattr(_THREAD_LOCAL_DEBUG_EMIT, "callback", None)
    if callable(callback):
        return callback
    return None


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


def _human_bytes(value: int | float | None) -> str:
    if value is None:
        return "-"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)}B"
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{int(size)}B"


def _normalize_path(path: str) -> str:
    clean = str(path or "").strip()
    if not clean:
        return "/"
    if not clean.startswith("/"):
        clean = "/" + clean
    return clean


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value))
    slug = slug.strip("._-")
    return slug or "item"


def _quote_repo(repo: str) -> str:
    return urllib.parse.quote(repo, safe="/._-")


def _quote_ref(reference: str) -> str:
    return urllib.parse.quote(reference, safe=":@._-")


def _json_loads_bytes(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8", errors="replace"))


def _auth_headers(username: str | None, password: str | None, token: str | None) -> dict[str, str]:
    if token:
        return {"Authorization": f"Bearer {token}"}
    if username is not None and password is not None:
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        return {"Authorization": f"Basic {encoded}"}
    return {}


def _fetch_registry_bearer_token(
    challenge: str,
    timeout: float,
    *,
    request_headers: Mapping[str, str],
) -> tuple[str | None, str | None]:
    scheme, params = _parse_www_authenticate(challenge)
    if scheme != "bearer":
        return None, "unsupported registry authentication challenge"
    realm = str(params.get("realm") or "").strip()
    if not realm:
        return None, "registry bearer challenge is missing realm"
    try:
        parsed = urllib.parse.urlsplit(realm)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None, "registry bearer realm URL is invalid"
    except ValueError:
        return None, "registry bearer realm URL is invalid"

    service = str(params.get("service") or "").strip()
    scope = str(params.get("scope") or "").strip()
    authorization = next(
        (str(value) for key, value in request_headers.items() if str(key).lower() == "authorization"),
        "",
    )
    basic_authorization = authorization if authorization.lower().startswith("basic ") else ""
    cache_key = (realm, service, scope, basic_authorization)
    with _BEARER_TOKEN_CACHE_LOCK:
        cached = _BEARER_TOKEN_CACHE.get(cache_key)
    if cached:
        return cached, None

    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if service and "service" not in query:
        query["service"] = [service]
    if scope and "scope" not in query:
        query["scope"] = [scope]
    token_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", urllib.parse.urlencode(query, doseq=True), "")
    )
    token_headers = {"User-Agent": "RedPosture/1.0", "Accept": "application/json"}
    if basic_authorization:
        token_headers["Authorization"] = basic_authorization
    state = getattr(_THREAD_LOCAL_HTTP, "state", None)
    if isinstance(state, RegistryLifecycleState) and state.http is not None:
        response = state.http.request(
            "GET",
            token_url,
            headers=token_headers,
            timeout=timeout,
            response_size_cap=_DETECT_RESPONSE_CAP,
        )
    else:
        response = HttpApiClient(
            HttpClientConfig(timeout=timeout, response_size_cap=_DETECT_RESPONSE_CAP, insecure=parsed.scheme == "https")
        ).get(token_url, headers=token_headers, timeout=timeout)
    if response.error:
        return None, _friendly_error_text(response.error)
    if response.status != 200:
        return None, f"registry bearer realm returned status {response.status}"
    try:
        payload = response.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, "registry bearer realm returned invalid JSON"
    token = str(payload.get("token") or payload.get("access_token") or "").strip() if isinstance(payload, dict) else ""
    if not token:
        return None, "registry bearer realm did not return a token"
    with _BEARER_TOKEN_CACHE_LOCK:
        _BEARER_TOKEN_CACHE[cache_key] = token
    return token, None


def _http_request(
    host: str,
    port: int,
    method: str,
    path: str,
    timeout: float,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, bytes, dict[str, str], str | None]:
    req_headers = {"User-Agent": "RedPosture/1.0"}
    if headers:
        req_headers.update(headers)
    state = getattr(_THREAD_LOCAL_HTTP, "state", None)
    cap = _DETECT_RESPONSE_CAP if _normalize_path(path).partition("?")[0] == "/v2/" else 10 * 1024 * 1024
    if isinstance(state, RegistryLifecycleState) and state.http is not None:
        schemes = (
            (state.scheme,)
            if state.scheme in {"http", "https"}
            else (("https", "http") if int(port) in {443, 5001} else ("http", "https"))
        )
        response = None
        for scheme in schemes:
            url = build_http_target_url(host, port, _normalize_path(path), default_scheme=str(scheme))
            response = state.http.request(
                method,
                url,
                headers=req_headers,
                body=body,
                timeout=timeout,
                response_size_cap=cap,
            )
            if response.error is None:
                state.scheme = str(scheme)
                break
        assert response is not None
    else:
        scheme = resolve_http_scheme(host, port, timeout, probe_path="/v2/")
        url = build_http_target_url(host, port, _normalize_path(path), default_scheme=scheme)
        response = HttpApiClient(HttpClientConfig(timeout=timeout, response_size_cap=cap, insecure=True)).request(
            method,
            url,
            headers=req_headers,
            body=body,
            timeout=timeout,
        )
    if response.error:
        return 0, b"", {}, _friendly_error_text(response.error)
    response_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
    if int(response.status) == 401:
        challenge = response_headers.get("www-authenticate", "")
        challenge_scheme, _challenge_params = _parse_www_authenticate(challenge)
        if challenge_scheme == "bearer":
            bearer_token, bearer_error = _fetch_registry_bearer_token(
                challenge,
                timeout,
                request_headers=req_headers,
            )
            if bearer_token:
                retry_headers = dict(req_headers)
                retry_headers["Authorization"] = f"Bearer {bearer_token}"
                retry_response = (
                    state.http.request(
                        method,
                        url,
                        headers=retry_headers,
                        body=body,
                        timeout=timeout,
                        response_size_cap=cap,
                    )
                    if isinstance(state, RegistryLifecycleState) and state.http is not None
                    else HttpApiClient(HttpClientConfig(timeout=timeout, response_size_cap=cap, insecure=True)).request(
                        method, url, headers=retry_headers, body=body, timeout=timeout
                    )
                )
                if retry_response.error:
                    return 0, b"", {}, _friendly_error_text(retry_response.error)
                retry_response_headers = {str(key).lower(): str(value) for key, value in retry_response.headers.items()}
                retry_response_headers["x-redposture-bearer-exchanged"] = "true"
                return int(retry_response.status), retry_response.body, retry_response_headers, None
            if bearer_error:
                response_headers["x-redposture-bearer-error"] = bearer_error
    return int(response.status), response.body, response_headers, None


def _http_request_url(
    url: str,
    method: str,
    timeout: float,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, bytes, dict[str, str], str | None]:
    req_headers = {"User-Agent": "RedPosture/1.0"}
    if headers:
        req_headers.update(headers)
    state = getattr(_THREAD_LOCAL_HTTP, "state", None)
    response = (
        state.http.request(
            method,
            url,
            headers=req_headers,
            body=body,
            timeout=timeout,
            response_size_cap=10 * 1024 * 1024,
        )
        if isinstance(state, RegistryLifecycleState) and state.http is not None
        else HttpApiClient(HttpClientConfig(timeout=timeout, response_size_cap=10 * 1024 * 1024)).request(
            method,
            url,
            headers=req_headers,
            body=body,
            timeout=timeout,
        )
    )
    if response.error:
        return 0, b"", {}, _friendly_error_text(response.error)
    return int(response.status), response.body, {str(k).lower(): str(v) for k, v in response.headers.items()}, None


def _http_download(
    host: str,
    port: int,
    path: str,
    timeout: float,
    out_path: str,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, int, str | None]:
    scheme = resolve_http_scheme(host, port, timeout, probe_path="/v2/")
    url = build_http_target_url(host, port, _normalize_path(path), default_scheme=scheme)
    req_headers = {"User-Agent": "RedPosture/1.0"}
    if headers:
        req_headers.update(headers)
    status, size, error = HttpApiClient(HttpClientConfig(timeout=timeout, insecure=scheme == "https")).download_to_file(
        url,
        out_path,
        headers=req_headers,
        timeout=timeout,
    )
    return status, size, _friendly_error_text(error) if error else None


def _parse_link_next(link_header: str | None) -> str | None:
    raw = (link_header or "").strip()
    if not raw:
        return None
    match = re.search(r"<([^>]+)>;\s*rel=\"?next\"?", raw, flags=re.IGNORECASE)
    if not match:
        return None
    target = match.group(1).strip()
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))
    return target


def _fetch_registry_catalog(
    host: str,
    port: int,
    timeout: float,
    *,
    headers: dict[str, str],
) -> tuple[list[str] | None, str | None]:
    repositories: list[str] = []
    seen: set[str] = set()
    next_path = "/v2/_catalog?n=1000"
    pages = 0
    visited_paths: set[str] = set()

    while next_path:
        if next_path in visited_paths:
            repositories.sort()
            return repositories, "partial: registry catalog pagination loop detected"
        visited_paths.add(next_path)
        pages += 1
        if pages > 30:
            repositories.sort()
            return repositories, "partial: registry catalog pagination limit exceeded"
        status, body, resp_headers, error = _http_request(host, port, "GET", next_path, timeout, headers=headers)
        if error:
            return (repositories if repositories else None), f"partial: {error}" if repositories else error
        if status in (401, 403):
            error_text = "authentication required"
            return (repositories if repositories else None), f"partial: {error_text}" if repositories else error_text
        if status != 200:
            error_text = f"{next_path} returned status {status}"
            return (repositories if repositories else None), f"partial: {error_text}" if repositories else error_text

        try:
            payload = _json_loads_bytes(body)
        except json.JSONDecodeError:
            error_text = f"{next_path} returned invalid JSON"
            return (repositories if repositories else None), f"partial: {error_text}" if repositories else error_text
        items = payload.get("repositories") if isinstance(payload, dict) else None
        if isinstance(items, list):
            for item in items:
                repo = str(item or "").strip()
                if not repo or repo in seen:
                    continue
                seen.add(repo)
                repositories.append(repo)
        next_path = _parse_link_next(resp_headers.get("link")) or ""

    repositories.sort()
    return repositories, None


def _fetch_repository_tags(
    host: str,
    port: int,
    repository: str,
    timeout: float,
    *,
    headers: dict[str, str],
) -> tuple[list[str] | None, str | None]:
    next_path = f"/v2/{_quote_repo(repository)}/tags/list?n=1000"
    tags: set[str] = set()
    visited_paths: set[str] = set()
    for _page in range(30):
        if next_path in visited_paths:
            return sorted(tags), "partial: registry tag pagination loop detected"
        visited_paths.add(next_path)
        status, body, response_headers, error = _http_request(host, port, "GET", next_path, timeout, headers=headers)
        if error:
            return (sorted(tags) if tags else None), f"partial: {error}" if tags else error
        if status in (401, 403):
            error_text = "authentication required"
            return (sorted(tags) if tags else None), f"partial: {error_text}" if tags else error_text
        if status == 404:
            return sorted(tags), None
        if status != 200:
            error_text = f"{next_path} returned status {status}"
            return (sorted(tags) if tags else None), f"partial: {error_text}" if tags else error_text
        try:
            payload = _json_loads_bytes(body)
        except json.JSONDecodeError:
            error_text = f"{next_path} returned invalid JSON"
            return (sorted(tags) if tags else None), f"partial: {error_text}" if tags else error_text

        tags_raw = payload.get("tags") if isinstance(payload, dict) else None
        if isinstance(tags_raw, list):
            tags.update(str(item or "").strip() for item in tags_raw if str(item or "").strip())
        parsed_next = _parse_link_next(response_headers.get("link"))
        if not parsed_next:
            return sorted(tags), None
        next_path = parsed_next
    return sorted(tags), "partial: registry tag pagination limit exceeded"


def _split_image_reference(value: str) -> tuple[str, str]:
    raw = str(value or "").strip()
    if not raw:
        return "", ""
    if "@" in raw:
        repo, digest = raw.rsplit("@", 1)
        return repo.strip(), digest.strip()

    slash_pos = raw.rfind("/")
    colon_pos = raw.rfind(":")
    if colon_pos > slash_pos:
        return raw[:colon_pos].strip(), raw[colon_pos + 1 :].strip()
    return raw, "latest"


def _display_image(repository: str, reference: str) -> str:
    if reference.startswith("sha256:"):
        return f"{repository}@{reference}"
    return f"{repository}:{reference}"


def _pick_latest_tag(tags: list[str]) -> str | None:
    clean = [str(item).strip() for item in tags if str(item).strip()]
    if not clean:
        return None
    if "latest" in clean:
        return "latest"
    return sorted(set(clean))[-1]


def _build_gitlab_repository_summaries(
    repositories: list[str],
    repo_tags: dict[str, list[str]],
    last_pushed_by_repo: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    last_pushed_map = last_pushed_by_repo or {}
    summaries: list[dict[str, Any]] = []
    for repo in sorted(set(repositories)):
        tags = sorted(set(repo_tags.get(repo) or []))
        summaries.append(
            {
                "repository": repo,
                "tags": tags,
                "tags_count": len(tags),
                "latest_tag": _pick_latest_tag(tags),
                # Best-effort from image config.created when available.
                "last_pushed": last_pushed_map.get(repo),
            }
        )
    return summaries


def _fetch_manifest_payload(
    host: str,
    port: int,
    repository: str,
    reference: str,
    timeout: float,
    *,
    headers: dict[str, str],
    depth: int = 0,
) -> tuple[dict[str, Any] | None, str | None]:
    if depth > 4:
        return None, "manifest recursion depth exceeded"

    req_headers = dict(headers)
    req_headers["Accept"] = _REGISTRY_MANIFEST_ACCEPT
    path = f"/v2/{_quote_repo(repository)}/manifests/{_quote_ref(reference)}"
    status, body, resp_headers, error = _http_request(host, port, "GET", path, timeout, headers=req_headers)
    if error:
        return None, error
    if status in (401, 403):
        return None, "authentication required"
    if status == 404:
        return None, "image/tag not found"
    if status != 200:
        return None, f"{path} returned status {status}"

    try:
        manifest_payload = _json_loads_bytes(body)
    except json.JSONDecodeError:
        return None, "manifest is not valid JSON"
    if not isinstance(manifest_payload, dict):
        return None, "manifest payload is invalid"

    manifests_raw = manifest_payload.get("manifests")
    if isinstance(manifests_raw, list) and manifests_raw:
        chosen_digest: str | None = None
        for item in manifests_raw:
            if not isinstance(item, dict):
                continue
            digest = str(item.get("digest") or "").strip()
            if not digest:
                continue
            platform = item.get("platform")
            if isinstance(platform, dict):
                os_name = str(platform.get("os") or "").lower()
                arch = str(platform.get("architecture") or "").lower()
                if os_name == "linux" and arch in {"amd64", "x86_64"}:
                    chosen_digest = digest
                    break
            if chosen_digest is None:
                chosen_digest = digest
        if chosen_digest:
            return _fetch_manifest_payload(
                host,
                port,
                repository,
                chosen_digest,
                timeout,
                headers=headers,
                depth=depth + 1,
            )

    return (
        {
            "manifest": manifest_payload,
            "manifest_raw": body.decode("utf-8", errors="replace"),
            "content_type": resp_headers.get("content-type"),
            "resolved_reference": reference,
        },
        None,
    )


def _fetch_blob_json(
    host: str,
    port: int,
    repository: str,
    digest: str,
    timeout: float,
    *,
    headers: dict[str, str],
) -> tuple[dict[str, Any] | None, str | None]:
    path = f"/v2/{_quote_repo(repository)}/blobs/{_quote_ref(digest)}"
    status, body, _resp_headers, error = _http_request(host, port, "GET", path, timeout, headers=headers)
    if error:
        return None, error
    if status in (401, 403):
        return None, "authentication required"
    if status != 200:
        return None, f"{path} returned status {status}"
    try:
        payload = _json_loads_bytes(body)
    except json.JSONDecodeError:
        return None, "blob JSON payload is invalid"
    if not isinstance(payload, dict):
        return None, "blob payload is invalid"
    return payload, None


def _extract_image_metadata(repository: str, reference: str, manifest_data: dict[str, Any]) -> dict[str, Any]:
    manifest = manifest_data.get("manifest")
    if not isinstance(manifest, dict):
        return {
            "image": _display_image(repository, reference),
            "error": "manifest payload is invalid",
        }

    config_descriptor = manifest.get("config")
    layers_raw = manifest.get("layers")
    config_digest: str | None = None
    config_size = 0
    if isinstance(config_descriptor, dict):
        digest = str(config_descriptor.get("digest") or "").strip()
        if digest:
            config_digest = digest
        size_raw = config_descriptor.get("size")
        if isinstance(size_raw, int) and size_raw >= 0:
            config_size = size_raw

    layers: list[dict[str, Any]] = []
    total_layer_size = 0
    if isinstance(layers_raw, list):
        for item in layers_raw:
            if not isinstance(item, dict):
                continue
            digest = str(item.get("digest") or "").strip()
            media_type = str(item.get("mediaType") or "").strip()
            size_raw = item.get("size")
            size = int(size_raw) if isinstance(size_raw, int) and size_raw >= 0 else 0
            if digest:
                layers.append({"digest": digest, "media_type": media_type, "size": size})
                total_layer_size += size

    return {
        "image": _display_image(repository, reference),
        "repository": repository,
        "reference": reference,
        "resolved_reference": str(manifest_data.get("resolved_reference") or reference),
        "manifest_raw": str(manifest_data.get("manifest_raw") or ""),
        "content_type": str(manifest_data.get("content_type") or ""),
        "config_digest": config_digest,
        "config_size": config_size,
        "layers": layers,
        "layer_count": len(layers),
        "total_size": total_layer_size + config_size,
    }


def _inspect_image(
    host: str,
    port: int,
    repository: str,
    reference: str,
    timeout: float,
    *,
    headers: dict[str, str],
) -> dict[str, Any]:
    manifest_payload, manifest_error = _fetch_manifest_payload(
        host, port, repository, reference, timeout, headers=headers
    )
    if manifest_error:
        return {
            "image": _display_image(repository, reference),
            "repository": repository,
            "reference": reference,
            "error": manifest_error,
        }

    metadata = _extract_image_metadata(repository, reference, manifest_payload or {})
    config_digest = metadata.get("config_digest")
    env_values: list[str] = []
    exposed_ports: list[str] = []
    label_items: list[str] = []
    cmd_items: list[str] = []
    history_items: list[str] = []
    config_blob: dict[str, Any] | None = None
    config_error: str | None = None
    suspicious: list[str] = []
    config_created: str | None = None

    if isinstance(config_digest, str) and config_digest:
        config_blob, config_error = _fetch_blob_json(host, port, repository, config_digest, timeout, headers=headers)
        if config_blob is not None:
            config_created_raw = config_blob.get("created")
            if isinstance(config_created_raw, str) and config_created_raw.strip():
                config_created = config_created_raw.strip()
            config_section = config_blob.get("config")
            if isinstance(config_section, dict):
                env_raw = config_section.get("Env")
                if isinstance(env_raw, list):
                    env_values = [str(item) for item in env_raw if str(item).strip()]
                cmd_raw = config_section.get("Cmd")
                if isinstance(cmd_raw, list):
                    cmd_items = [str(item) for item in cmd_raw if str(item).strip()]
                labels_raw = config_section.get("Labels")
                if isinstance(labels_raw, dict):
                    label_items = [f"{key}={value}" for key, value in labels_raw.items()]
                exposed_raw = config_section.get("ExposedPorts")
                if isinstance(exposed_raw, dict):
                    exposed_ports = sorted(str(key) for key in exposed_raw.keys())

            history_raw = config_blob.get("history")
            if isinstance(history_raw, list):
                for item in history_raw[:_REGISTRY_MAX_HISTORY_LINES]:
                    if not isinstance(item, dict):
                        continue
                    created_by = str(item.get("created_by") or "").strip()
                    comment = str(item.get("comment") or "").strip()
                    line = created_by
                    if comment:
                        line = f"{line} | comment={comment}" if line else f"comment={comment}"
                    if line:
                        history_items.append(line)

            for item in env_values + label_items + cmd_items + history_items:
                if _SUSPICIOUS_TEXT_RE.search(item):
                    suspicious.append(item)

    metadata["config_fetch_error"] = config_error
    metadata["created"] = config_created
    metadata["env"] = env_values
    metadata["cmd"] = cmd_items
    metadata["exposed_ports"] = exposed_ports
    metadata["labels"] = sorted(label_items)
    metadata["history"] = history_items
    metadata["suspicious"] = suspicious
    metadata["config_blob"] = config_blob
    return metadata


def _should_download_large(total_size: int, image_name: str, console: Console) -> bool:
    if total_size <= _REGISTRY_DOWNLOAD_LIMIT_BYTES:
        return True

    size_text = _human_bytes(total_size)
    limit_text = _human_bytes(_REGISTRY_DOWNLOAD_LIMIT_BYTES)
    prompt = f"image {image_name} size={size_text} exceeds {limit_text}. Continue download? [y/N]: "
    if not sys.stdin.isatty():
        console.warn(
            f"download skipped for {image_name}: size={size_text} exceeds {limit_text} (non-interactive shell)"
        )
        return False

    try:
        answer = input(prompt).strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def _download_image(
    host: str,
    port: int,
    timeout: float,
    *,
    headers: dict[str, str],
    inspect_data: dict[str, Any],
    download_dir: str,
    console: Console,
) -> dict[str, Any]:
    image_name = str(inspect_data.get("image") or "-")
    repository = str(inspect_data.get("repository") or "").strip()
    if not repository:
        return {"status": "fail", "error": "missing repository for download"}

    total_size = int(inspect_data.get("total_size") or 0)
    if not _should_download_large(total_size, image_name, console):
        return {"status": "skipped", "size": total_size, "error": "download not confirmed"}

    target_dir = os.path.join(
        download_dir,
        _safe_slug(host),
        _safe_slug(image_name),
    )
    os.makedirs(target_dir, exist_ok=True)

    manifest_raw = str(inspect_data.get("manifest_raw") or "")
    if manifest_raw:
        with open(os.path.join(target_dir, "manifest.json"), "w", encoding="utf-8") as fh:
            fh.write(manifest_raw)

    config_blob = inspect_data.get("config_blob")
    if isinstance(config_blob, dict):
        with open(os.path.join(target_dir, "config.json"), "w", encoding="utf-8") as fh:
            json.dump(config_blob, fh, ensure_ascii=False, indent=2)
            fh.write("\n")

    downloaded_bytes = 0
    config_digest = str(inspect_data.get("config_digest") or "").strip()
    if config_digest:
        config_name = _safe_slug(config_digest) + ".blob"
        config_path = os.path.join(target_dir, config_name)
        status, size, error = _http_download(
            host,
            port,
            f"/v2/{_quote_repo(repository)}/blobs/{_quote_ref(config_digest)}",
            timeout,
            config_path,
            headers=headers,
        )
        if error:
            return {"status": "fail", "size": downloaded_bytes, "error": error}
        if status != 200:
            return {"status": "fail", "size": downloaded_bytes, "error": f"config blob returned status {status}"}
        downloaded_bytes += size

    layers = inspect_data.get("layers")
    if isinstance(layers, list):
        for layer in layers:
            if not isinstance(layer, dict):
                continue
            digest = str(layer.get("digest") or "").strip()
            if not digest:
                continue
            layer_name = _safe_slug(digest) + ".layer"
            layer_path = os.path.join(target_dir, layer_name)
            status, size, error = _http_download(
                host,
                port,
                f"/v2/{_quote_repo(repository)}/blobs/{_quote_ref(digest)}",
                timeout,
                layer_path,
                headers=headers,
            )
            if error:
                return {"status": "fail", "path": target_dir, "size": downloaded_bytes, "error": error}
            if status != 200:
                return {
                    "status": "fail",
                    "path": target_dir,
                    "size": downloaded_bytes,
                    "error": f"layer {digest} returned status {status}",
                }
            downloaded_bytes += size

    return {
        "status": "ok",
        "path": target_dir,
        "size": downloaded_bytes,
        "declared_size": total_size,
        "files": len(os.listdir(target_dir)),
    }


def _fetch_harbor_info(
    host: str,
    port: int,
    timeout: float,
    *,
    headers: dict[str, str],
) -> tuple[dict[str, Any] | None, str | None]:
    status, body, _resp_headers, error = _http_request(
        host, port, "GET", "/api/v2.0/systeminfo", timeout, headers=headers
    )
    if error:
        return None, error
    if status in (401, 403):
        return None, "authentication required"
    if status == 404:
        return None, "not harbor"
    if status != 200:
        return None, f"/api/v2.0/systeminfo returned status {status}"
    try:
        payload = _json_loads_bytes(body)
    except json.JSONDecodeError:
        return None, "harbor systeminfo payload is invalid JSON"
    if not isinstance(payload, dict):
        return None, "harbor systeminfo payload is invalid"
    return payload, None


def _fetch_harbor_pages(
    host: str,
    port: int,
    base_path: str,
    timeout: float,
    *,
    headers: dict[str, str],
    page_size: int,
) -> tuple[list[Any] | None, str | None]:
    items: list[Any] = []
    parsed_base = urllib.parse.urlsplit(base_path)
    existing_query = urllib.parse.parse_qsl(parsed_base.query, keep_blank_values=True)
    for page in range(1, 31):
        query = urllib.parse.urlencode([("page", str(page)), ("page_size", str(page_size)), *existing_query])
        path = urllib.parse.urlunsplit(("", "", parsed_base.path, query, ""))
        status, body, response_headers, error = _http_request(
            host,
            port,
            "GET",
            path,
            timeout,
            headers=headers,
        )
        if error:
            return (items if items else None), f"partial: {error}" if items else error
        if status in {401, 403}:
            message = "authentication required"
            return (items if items else None), f"partial: {message}" if items else message
        if status != 200:
            message = f"{path} returned status {status}"
            return (items if items else None), f"partial: {message}" if items else message
        try:
            payload = _json_loads_bytes(body)
        except json.JSONDecodeError:
            message = f"{path} returned invalid JSON"
            return (items if items else None), f"partial: {message}" if items else message
        if not isinstance(payload, list):
            message = f"{path} payload is invalid"
            return (items if items else None), f"partial: {message}" if items else message
        items.extend(payload)
        total_raw = str(response_headers.get("x-total-count") or "").strip()
        total = int(total_raw) if total_raw.isdigit() else None
        if len(payload) < page_size or (total is not None and len(items) >= total):
            return items, None
    return items, "partial: harbor pagination limit exceeded"


def _fetch_harbor_projects(
    host: str,
    port: int,
    timeout: float,
    *,
    headers: dict[str, str],
) -> tuple[list[str] | None, str | None]:
    payload, page_error = _fetch_harbor_pages(
        host,
        port,
        "/api/v2.0/projects",
        timeout,
        headers=headers,
        page_size=200,
    )
    if payload is None:
        if page_error and "payload is invalid" in page_error:
            return None, "harbor projects payload is invalid"
        return None, page_error
    projects: list[str] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if name:
            projects.append(name)
    return sorted(set(projects)), page_error


def _fetch_harbor_repositories(
    host: str,
    port: int,
    project: str,
    timeout: float,
    *,
    headers: dict[str, str],
) -> tuple[list[str] | None, str | None]:
    quoted_project = urllib.parse.quote(project, safe="")
    path = f"/api/v2.0/projects/{quoted_project}/repositories"
    payload, page_error = _fetch_harbor_pages(host, port, path, timeout, headers=headers, page_size=200)
    if payload is None:
        return None, page_error
    repositories: list[str] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if name:
            repositories.append(name)
    return sorted(set(repositories)), page_error


def _fetch_harbor_artifacts(
    host: str,
    port: int,
    project: str,
    repository: str,
    timeout: float,
    *,
    headers: dict[str, str],
) -> tuple[list[str] | None, str | None]:
    quoted_project = urllib.parse.quote(project, safe="")
    quoted_repo = urllib.parse.quote(repository, safe="")
    path = f"/api/v2.0/projects/{quoted_project}/repositories/{quoted_repo}/artifacts?with_tag=true"
    payload, page_error = _fetch_harbor_pages(host, port, path, timeout, headers=headers, page_size=20)
    if payload is None:
        return None, page_error

    artifacts: list[str] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        digest = str(item.get("digest") or "").strip()
        tags_raw = item.get("tags")
        tags: list[str] = []
        if isinstance(tags_raw, list):
            for tag_item in tags_raw:
                if isinstance(tag_item, dict):
                    tag_name = str(tag_item.get("name") or "").strip()
                    if tag_name:
                        tags.append(tag_name)
        if tags:
            for tag in tags:
                artifacts.append(f"{repository}:{tag}@{digest}")
        elif digest:
            artifacts.append(f"{repository}@{digest}")
    return sorted(set(artifacts)), page_error


def _parse_www_authenticate(header_value: str) -> tuple[str, dict[str, str]]:
    raw = str(header_value or "").strip()
    if not raw:
        return "", {}

    if " " not in raw:
        return raw.lower(), {}

    scheme, params_raw = raw.split(" ", 1)
    params: dict[str, str] = {}
    for match in re.finditer(r'([A-Za-z][A-Za-z0-9_-]*)="([^"]*)"', params_raw):
        key = match.group(1).strip().lower()
        value = match.group(2).strip()
        if key:
            params[key] = value
    return scheme.strip().lower(), params


def _fetch_gitlab_info(
    host: str,
    port: int,
    www_authenticate: str,
    timeout: float,
    *,
    headers: dict[str, str],
    deep: bool,
) -> tuple[dict[str, Any] | None, str | None]:
    scheme, params = _parse_www_authenticate(www_authenticate)
    realm = str(params.get("realm") or "").strip()
    service = str(params.get("service") or "").strip()
    scope = str(params.get("scope") or "").strip()

    marker_raw = " ".join([scheme, realm, service, scope]).lower()
    header_is_gitlab = service == "container_registry" or "/jwt/auth" in realm.lower() or "gitlab" in marker_raw
    if not header_is_gitlab:
        # Fallback for flows where /v2/ returns 200 and omits WWW-Authenticate.
        probe_path = "/jwt/auth?service=container_registry&scope=registry:catalog:*"
        status, body, _probe_headers, error = _http_request(host, port, "GET", probe_path, timeout, headers=headers)
        if error:
            return None, error
        if status == 404:
            return None, "not gitlab"
        if status not in {200, 401, 403}:
            return None, "not gitlab"

        fallback_info: dict[str, Any] = {
            "scheme": "bearer",
            "realm": f"http://{host}:{port}/jwt/auth",
            "service": "container_registry",
            "scope": "registry:catalog:*",
            "detected_by": "jwt_auth_probe",
        }
        if not deep:
            return fallback_info, None

        fallback_info["token_probe_http_status"] = status
        if status in {401, 403}:
            fallback_info["token_probe_status"] = "authentication required"
            return fallback_info, None

        try:
            payload = _json_loads_bytes(body)
        except json.JSONDecodeError:
            fallback_info["token_probe_status"] = "failed"
            fallback_info["token_probe_error"] = "realm returned invalid JSON"
            return fallback_info, None

        if isinstance(payload, dict):
            fallback_info["token_probe_status"] = "ok"
            token = str(payload.get("token") or payload.get("access_token") or "").strip()
            fallback_info["token_received"] = bool(token)
            if "expires_in" in payload:
                fallback_info["token_expires_in"] = payload.get("expires_in")
            if "issued_at" in payload:
                fallback_info["token_issued_at"] = payload.get("issued_at")
            if "scope" in payload and payload.get("scope"):
                fallback_info["token_scope"] = payload.get("scope")
            return fallback_info, None

        fallback_info["token_probe_status"] = "failed"
        fallback_info["token_probe_error"] = "realm JSON payload is invalid"
        return fallback_info, None

    info: dict[str, Any] = {
        "scheme": scheme,
        "realm": realm or None,
        "service": service or None,
        "scope": scope or None,
        "detected_by": "www_authenticate",
    }

    if not deep or not realm:
        return info, None

    parsed = urllib.parse.urlsplit(realm)
    if parsed.scheme not in {"http", "https"}:
        info["token_probe_status"] = "skipped"
        info["token_probe_error"] = "unsupported realm URL scheme"
        return info, None

    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if service and "service" not in query:
        query["service"] = [service]
    if scope and "scope" not in query:
        query["scope"] = [scope]
    if "scope" not in query:
        query["scope"] = ["registry:catalog:*"]
    token_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query, doseq=True), parsed.fragment)
    )
    status, body, _headers, error = _http_request_url(token_url, "GET", timeout, headers=headers)
    if error:
        info["token_probe_status"] = "failed"
        info["token_probe_error"] = error
        return info, None

    info["token_probe_http_status"] = status
    if status in {401, 403}:
        info["token_probe_status"] = "authentication required"
        return info, None
    if status != 200:
        info["token_probe_status"] = "failed"
        info["token_probe_error"] = f"realm returned status {status}"
        return info, None

    try:
        payload = _json_loads_bytes(body)
    except json.JSONDecodeError:
        info["token_probe_status"] = "failed"
        info["token_probe_error"] = "realm returned invalid JSON"
        return info, None

    if isinstance(payload, dict):
        info["token_probe_status"] = "ok"
        token = str(payload.get("token") or payload.get("access_token") or "").strip()
        info["token_received"] = bool(token)
        if "expires_in" in payload:
            info["token_expires_in"] = payload.get("expires_in")
        if "issued_at" in payload:
            info["token_issued_at"] = payload.get("issued_at")
        if "scope" in payload and payload.get("scope"):
            info["token_scope"] = payload.get("scope")
        return info, None

    info["token_probe_status"] = "failed"
    info["token_probe_error"] = "realm JSON payload is invalid"
    return info, None


def _fetch_nexus_info(
    host: str,
    port: int,
    timeout: float,
    *,
    headers: dict[str, str],
) -> tuple[dict[str, Any] | None, str | None]:
    status, body, _resp_headers, error = _http_request(
        host, port, "GET", "/service/rest/v1/status", timeout, headers=headers
    )
    if error:
        return None, error
    if status in (401, 403):
        return None, "authentication required"
    if status == 404:
        return None, "not nexus"
    if status != 200:
        return None, f"/service/rest/v1/status returned status {status}"
    if not body.strip():
        # Newer Nexus versions can return 200 with an empty body on this endpoint.
        return {}, None
    try:
        payload = _json_loads_bytes(body)
    except json.JSONDecodeError:
        return None, "nexus status payload is invalid JSON"
    if not isinstance(payload, dict):
        return None, "nexus status payload is invalid"
    return payload, None


def _fetch_nexus_repositories(
    host: str,
    port: int,
    timeout: float,
    *,
    headers: dict[str, str],
) -> tuple[list[str] | None, str | None]:
    status, body, _resp_headers, error = _http_request(
        host,
        port,
        "GET",
        "/service/rest/v1/repositories",
        timeout,
        headers=headers,
    )
    if error:
        return None, error
    if status in (401, 403):
        return None, "authentication required"
    if status == 404:
        return None, "not nexus"
    if status != 200:
        return None, f"/service/rest/v1/repositories returned status {status}"
    try:
        payload = _json_loads_bytes(body)
    except json.JSONDecodeError:
        return None, "nexus repositories payload is invalid JSON"
    if not isinstance(payload, list):
        return None, "nexus repositories payload is invalid"

    repositories: list[str] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        fmt = str(item.get("format") or "").strip()
        repo_type = str(item.get("type") or "").strip()
        url = str(item.get("url") or "").strip()
        if not name:
            continue
        extra: list[str] = []
        if fmt:
            extra.append(f"format={fmt}")
        if repo_type:
            extra.append(f"type={repo_type}")
        if url:
            extra.append(f"url={url}")
        if extra:
            repositories.append(f"{name} ({', '.join(extra)})")
        else:
            repositories.append(name)
    return sorted(set(repositories)), None


def _fetch_nexus_repository_records(
    host: str,
    port: int,
    timeout: float,
    *,
    headers: dict[str, str],
) -> tuple[list[dict[str, Any]] | None, str | None]:
    status, body, _resp_headers, error = _http_request(
        host,
        port,
        "GET",
        "/service/rest/v1/repositories",
        timeout,
        headers=headers,
    )
    if error:
        return None, error
    if status in (401, 403):
        return None, "authentication required"
    if status == 404:
        return None, "not nexus"
    if status != 200:
        return None, f"/service/rest/v1/repositories returned status {status}"
    try:
        payload = _json_loads_bytes(body)
    except json.JSONDecodeError:
        return None, "nexus repositories payload is invalid JSON"
    if not isinstance(payload, list):
        return None, "nexus repositories payload is invalid"

    records: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        record: dict[str, Any] = {
            "name": name,
            "format": str(item.get("format") or "").strip() or None,
            "type": str(item.get("type") or "").strip() or None,
            "url": str(item.get("url") or "").strip() or None,
            "online": item.get("online") if isinstance(item.get("online"), bool) else None,
        }
        records.append(record)
    records.sort(key=lambda item: str(item.get("name") or ""))
    return records, None


def _fetch_nexus_components(
    host: str,
    port: int,
    repository: str,
    timeout: float,
    *,
    headers: dict[str, str],
) -> tuple[list[dict[str, Any]] | None, str | None]:
    components: list[dict[str, Any]] = []
    continuation: str | None = None
    seen_tokens: set[str] = set()
    pages = 0

    while True:
        pages += 1
        if pages > 30:
            return components, "partial: nexus component pagination limit exceeded"
        query = {"repository": repository}
        if continuation:
            query["continuationToken"] = continuation
        path = "/service/rest/v1/components?" + urllib.parse.urlencode(query)
        status, body, _resp_headers, error = _http_request(host, port, "GET", path, timeout, headers=headers)
        if error:
            return (components if components else None), f"partial: {error}" if components else error
        if status in (401, 403):
            message = "authentication required"
            return (components if components else None), f"partial: {message}" if components else message
        if status == 404:
            message = "nexus components API unavailable"
            return (components if components else None), f"partial: {message}" if components else message
        if status != 200:
            message = f"{path} returned status {status}"
            return (components if components else None), f"partial: {message}" if components else message
        try:
            payload = _json_loads_bytes(body)
        except json.JSONDecodeError:
            message = f"{path} returned invalid JSON"
            return (components if components else None), f"partial: {message}" if components else message
        if not isinstance(payload, dict):
            message = f"{path} payload is invalid"
            return (components if components else None), f"partial: {message}" if components else message

        items = payload.get("items")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    components.append(item)

        token_raw = payload.get("continuationToken")
        continuation = str(token_raw).strip() if token_raw not in (None, "") else None
        if not continuation:
            break
        if continuation in seen_tokens:
            return components, "partial: nexus component pagination loop detected"
        seen_tokens.add(continuation)

    return components, None


def _extract_nexus_assets(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    for component in components:
        comp_name = str(component.get("name") or "").strip() or None
        comp_version = str(component.get("version") or "").strip() or None
        assets_raw = component.get("assets")
        if not isinstance(assets_raw, list):
            continue
        for asset in assets_raw:
            if not isinstance(asset, dict):
                continue
            checksum_raw = asset.get("checksum")
            checksums: dict[str, str] = {}
            if isinstance(checksum_raw, dict):
                for key, value in checksum_raw.items():
                    key_s = str(key).strip().lower()
                    val_s = str(value).strip()
                    if key_s and val_s:
                        checksums[key_s] = val_s
            assets.append(
                {
                    "component_name": comp_name,
                    "component_version": comp_version,
                    "path": str(asset.get("path") or "").strip() or None,
                    "download_url": str(asset.get("downloadUrl") or "").strip() or None,
                    "checksums": checksums,
                }
            )
    return assets


def _registry_lifecycle_payload(
    ctx: Any,
    options: Mapping[str, Any],
    *,
    status: str,
    is_registry: bool,
    is_nexus: bool | None,
    auth_required: bool | None,
    probe_status: int | None,
    error: str | None,
) -> dict[str, Any]:
    credential = ctx.credential
    provided_credentials = credential.username is not None and credential.password is not None
    return {
        "timestamp": utc_now_iso(),
        "host": str(ctx.host),
        "port": int(ctx.port),
        "is_registry": bool(is_registry),
        "is_harbor": None,
        "is_gitlab": None,
        "is_nexus": is_nexus,
        "status": status,
        "auth_required": auth_required,
        "provided_credentials": provided_credentials,
        "provided_username": credential.username,
        "provided_password": credential.password if provided_credentials else None,
        "token_provided": bool(credential.token),
        "debug": bool(getattr(ctx.args, "debug", False)),
        "show_images": bool(options["show_images"]),
        "docker": bool(options["docker"]),
        "show_tags": bool(options["show_tags"]),
        "repository": options["repository"],
        "tag": options["tag"],
        "metadata": bool(options["metadata"]),
        "harbor": bool(options["harbor"]),
        "gitlab": bool(options["gitlab"]),
        "nexus": bool(options["nexus"]),
        "assets": bool(options["assets"]),
        "inspect": bool(options["inspect"]),
        "image": options["image"],
        "download": bool(options["download"]),
        "image_count": None,
        "images": None,
        "images_error": None,
        "harbor_info": None,
        "harbor_projects": None,
        "harbor_repositories": None,
        "harbor_artifacts": None,
        "harbor_error": None,
        "gitlab_info": None,
        "gitlab_error": None,
        "gitlab_repositories": None,
        "gitlab_repository_details": None,
        "selected_repository_tags": None,
        "metadata_result": None,
        "nexus_info": None,
        "nexus_repositories": None,
        "nexus_repository_details": None,
        "nexus_assets": None,
        "nexus_error": None,
        "inspections": None,
        "inspection_error": None,
        "download_result": None,
        "elapsed_ms": None,
        "probe_status": probe_status,
        "error": error,
    }


def _registry_append_lifecycle_stage(
    payload: Mapping[str, Any],
    *,
    stage_name: str,
    attempt: int,
    duration_ms: int,
    result: str,
    error: str | None,
    max_attempts: int,
) -> dict[str, Any]:
    record = dict(payload)
    raw_stages = record.get("stages")
    stages = [dict(item) for item in raw_stages if isinstance(item, dict)] if isinstance(raw_stages, list) else []
    stage_attempt = max(1, int(attempt))
    stage_duration = max(0, int(duration_ms))
    stage_result = str(result or "ok")
    stage_error = str(error or "").strip() or None
    stages.append(
        {
            "stage_name": stage_name,
            "attempt": stage_attempt,
            "duration_ms": stage_duration,
            "result": stage_result,
            "error": stage_error,
        }
    )

    raw_durations = record.get("stage_durations_ms")
    stage_durations_ms = dict(raw_durations) if isinstance(raw_durations, dict) else {}
    stage_durations_ms[stage_name] = max(0, int(stage_durations_ms.get(stage_name, 0) or 0)) + stage_duration

    raw_attempts = record.get("stage_attempts")
    stage_attempts = dict(raw_attempts) if isinstance(raw_attempts, dict) else {}
    stage_attempts[stage_name] = max(int(stage_attempts.get(stage_name, 0) or 0), stage_attempt)

    stage_failed_at = str(record.get("stage_failed_at") or "").strip() or None
    if stage_failed_at is None and stage_result in {"fail", "timeout"}:
        stage_failed_at = stage_name

    raw_debug_events = record.get("debug_events")
    debug_events = list(raw_debug_events) if isinstance(raw_debug_events, list) else []
    record.update(
        {
            "attempts": max(int(record.get("attempts", 0) or 0), stage_attempt),
            "max_attempts": max(int(record.get("max_attempts", 0) or 0), max(1, int(max_attempts))),
            "stages": stages,
            "stage_failed_at": stage_failed_at,
            "stage_durations_ms": stage_durations_ms,
            "stage_attempts": stage_attempts,
            "debug_events": debug_events,
            "debug_events_streamed": bool(record.get("debug_events_streamed", False)),
        }
    )
    return record


def _registry_has_lifecycle_stage(payload: Mapping[str, Any], stage_name: str) -> bool:
    stages = payload.get("stages")
    return isinstance(stages, list) and any(
        isinstance(item, dict) and str(item.get("stage_name") or "") == stage_name for item in stages
    )


def _registry_probe_has_fingerprint(status: int, body: bytes, headers: Mapping[str, str]) -> bool:
    docker_header = str(headers.get("docker-distribution-api-version") or "").strip().lower()
    if "registry/2.0" in docker_header:
        return True
    if str(headers.get("x-redposture-bearer-exchanged") or "").lower() == "true":
        return True
    challenge = str(headers.get("www-authenticate") or "")
    challenge_scheme, challenge_params = _parse_www_authenticate(challenge)
    challenge_scope = str(challenge_params.get("scope") or "").lower()
    challenge_service = str(challenge_params.get("service") or "").lower()
    if challenge_scheme == "bearer" and (
        challenge_scope.startswith(("registry:", "repository:"))
        or "registry" in challenge_service
        or "registry" in str(challenge_params.get("realm") or "").lower()
    ):
        return True
    try:
        payload = _json_loads_bytes(body)
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict):
        return False
    errors = payload.get("errors")
    if isinstance(errors, list):
        for item in errors:
            if not isinstance(item, dict):
                continue
            code = str(item.get("code") or "").upper()
            if code in {"UNAUTHORIZED", "DENIED", "NAME_UNKNOWN", "MANIFEST_UNKNOWN"}:
                return True
    # Status alone is deliberately insufficient: generic reverse proxies and
    # login portals commonly return 200/401/403 at /v2/.
    return False


def _registry_probe_state(probe: _RegistryProbe) -> tuple[bool, str, bool | None]:
    status, body, headers, error = probe
    if error:
        return False, "fail", None
    body_text = body.decode("utf-8", errors="replace").strip().lower()
    unauthorized = "unauthorized" in body_text or "authentication required" in body_text
    is_registry = _registry_probe_has_fingerprint(status, body, headers)
    if not is_registry:
        return False, "not_registry", None
    if status == 200:
        return True, "open_no_auth", False
    if status == 401 or (status == 403 and unauthorized):
        return True, "auth_required", True
    return True, "unknown_auth", None


def _registry_error_is_retryable(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and any(
        marker in text
        for marker in (
            "connection timeout",
            "connection refused",
            "connection reset",
            "connection closed",
            "temporarily unavailable",
            "timed out",
            "unexpected eof",
            "status 408",
            "status 429",
            "status 500",
            "status 502",
            "status 503",
            "status 504",
        )
    )


def _registry_probe_is_retryable(probe: _RegistryProbe) -> bool:
    status, _body, _headers, error = probe
    return bool(error and _registry_error_is_retryable(error)) or status in {408, 429, 500, 502, 503, 504}


def detect_registry(ctx: Any, options: Mapping[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, RegistryLifecycleState):
        raise TypeError("registry lifecycle state is unavailable")
    _activate_registry_transport(state)

    started_at = time.monotonic()
    attempts = max(1, int(getattr(ctx.args, "retries", 0) or 0) + 1)
    attempts_used = 0
    probe: _RegistryProbe = (0, b"", {}, "connection failed")
    for attempt in range(attempts):
        attempts_used += 1
        probe = _http_request(
            str(ctx.host),
            int(ctx.port),
            "GET",
            "/v2/",
            float(getattr(ctx.args, "timeout", 5.0)),
            headers=None,
        )
        if probe[3] is None or attempt >= attempts - 1:
            break
        time.sleep(_retry_delay(attempt))
    state.anonymous_probe = probe
    is_registry, status, auth_required = _registry_probe_state(probe)
    is_nexus: bool | None = None
    nexus_info: dict[str, Any] | None = None
    nexus_error: str | None = None
    if bool(options["nexus"]) and not is_registry:
        nexus_info, nexus_error = _fetch_nexus_info(
            str(ctx.host),
            int(ctx.port),
            float(getattr(ctx.args, "timeout", 5.0)),
            headers={},
        )
        state.anonymous_nexus = (nexus_info, nexus_error)
        if nexus_info is not None:
            is_registry = True
            is_nexus = True
            status = "open_no_auth"
            auth_required = False
        elif nexus_error == "authentication required":
            is_registry = True
            is_nexus = True
            status = "auth_required"
            auth_required = True
    payload = _registry_lifecycle_payload(
        ctx,
        options,
        status=status,
        is_registry=is_registry,
        is_nexus=is_nexus,
        auth_required=auth_required,
        probe_status=probe[0] or None,
        error=probe[3] if status == "fail" else nexus_error if status == "not_registry" else None,
    )
    payload["nexus_info"] = nexus_info
    stage_result = status if status in {"fail", "not_registry"} else "ok"
    return _registry_append_lifecycle_stage(
        payload,
        stage_name=_STAGE_DETECT_PROTOCOL,
        attempt=attempts_used,
        duration_ms=int((time.monotonic() - started_at) * 1000),
        result=stage_result,
        error=str(payload.get("error") or "").strip() or None,
        max_attempts=attempts,
    )


def authenticate_registry(ctx: Any, detect_record: Any, options: Mapping[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, RegistryLifecycleState):
        raise TypeError("registry lifecycle state is unavailable")
    _activate_registry_transport(state)
    payload = dict(detect_record.to_dict() if hasattr(detect_record, "to_dict") else detect_record)
    credential = ctx.credential
    attempts = max(1, int(getattr(ctx.args, "retries", 0) or 0) + 1)
    started_at = time.monotonic()
    if credential.username is None and credential.password is None and credential.token is None:
        return _registry_append_lifecycle_stage(
            payload,
            stage_name=_STAGE_AUTH_INFERENCE,
            attempt=1,
            duration_ms=int((time.monotonic() - started_at) * 1000),
            result=str(payload.get("status") or "unknown_auth"),
            error=str(payload.get("error") or "").strip() or None,
            max_attempts=attempts,
        )

    key = (credential.username, credential.password, credential.token, str(credential.source))
    headers = _auth_headers(credential.username, credential.password, credential.token)
    transport_attempts = 0
    transient_exhausted = False
    definitive_rejection = False
    is_nexus_only = bool(payload.get("is_nexus")) and (
        state.anonymous_probe is None or not _registry_probe_state(state.anonymous_probe)[0]
    )
    if is_nexus_only:
        nexus_result: tuple[dict[str, Any] | None, str | None] = (None, "connection failed")
        for attempt in range(attempts):
            transport_attempts += 1
            nexus_result = _fetch_nexus_info(
                str(ctx.host),
                int(ctx.port),
                float(getattr(ctx.args, "timeout", 5.0)),
                headers=headers,
            )
            if nexus_result[0] is not None:
                break
            if not _registry_error_is_retryable(nexus_result[1]) or attempt >= attempts - 1:
                transient_exhausted = _registry_error_is_retryable(nexus_result[1])
                break
            time.sleep(_retry_delay(attempt))
        state.credential_nexus[key] = nexus_result
        ok = nexus_result[0] is not None
        anonymous_ok = state.anonymous_nexus is not None and state.anonymous_nexus[0] is not None
        error = nexus_result[1]
        definitive_rejection = error == "authentication required"
        probe_status = payload.get("probe_status")
    else:
        probe: _RegistryProbe = (0, b"", {}, "connection failed")
        for attempt in range(attempts):
            transport_attempts += 1
            probe = _http_request(
                str(ctx.host),
                int(ctx.port),
                "GET",
                "/v2/",
                float(getattr(ctx.args, "timeout", 5.0)),
                headers=headers,
            )
            if not _registry_probe_is_retryable(probe) or attempt >= attempts - 1:
                transient_exhausted = _registry_probe_is_retryable(probe)
                break
            time.sleep(_retry_delay(attempt))
        state.credential_probes[key] = probe
        _detected, probe_state, _auth_required = _registry_probe_state(probe)
        ok = probe_state == "open_no_auth"
        definitive_rejection = probe_state == "auth_required"
        anonymous_ok = state.anonymous_probe is not None and _registry_probe_state(state.anonymous_probe)[1] == (
            "open_no_auth"
        )
        error = probe[3]
        probe_status = probe[0] or None

    if transient_exhausted and not ok:
        status = "fail"
    elif ok and anonymous_ok:
        status = "invalid_credentials_anonymous"
    elif ok:
        status = "valid_credentials"
    elif definitive_rejection:
        status = "auth_required"
    else:
        status = "fail"
    payload.update(
        {
            "timestamp": utc_now_iso(),
            "status": status,
            "auth_required": False if anonymous_ok else True,
            "provided_credentials": credential.username is not None and credential.password is not None,
            "provided_username": credential.username,
            "provided_password": credential.password,
            "token_provided": bool(credential.token),
            "credentials_source": str(credential.source),
            "provided_credentials_ok": (
                None if transient_exhausted or not definitive_rejection and not ok else bool(ok and not anonymous_ok)
            ),
            "auth_transport_attempts": transport_attempts,
            "probe_status": probe_status,
            "error": None if ok else error or "authentication required",
        }
    )
    return _registry_append_lifecycle_stage(
        payload,
        stage_name=_STAGE_AUTH_INFERENCE,
        attempt=transport_attempts,
        duration_ms=int((time.monotonic() - started_at) * 1000),
        result=status,
        error=str(payload.get("error") or "").strip() or None,
        max_attempts=attempts,
    )


def collect_registry_data(ctx: Any, record: Any, options: Mapping[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if not isinstance(state, RegistryLifecycleState):
        raise TypeError("registry lifecycle state is unavailable")
    _activate_registry_transport(state)
    prior = dict(record.to_dict() if hasattr(record, "to_dict") else record)
    credential = ctx.credential
    key = (credential.username, credential.password, credential.token, str(credential.source))
    status = str(prior.get("status") or "")
    use_anonymous = status in {"open_no_auth", "invalid_credentials_anonymous"}
    username = None if use_anonymous else credential.username
    password = None if use_anonymous else credential.password
    token = None if use_anonymous else credential.token
    probe = state.anonymous_probe if use_anonymous else state.credential_probes.get(key)
    nexus_result = state.anonymous_nexus if use_anonymous else state.credential_nexus.get(key)
    if probe is None:
        probe = state.anonymous_probe

    attempts = max(1, int(getattr(ctx.args, "retries", 0) or 0) + 1)
    if not _registry_has_lifecycle_stage(prior, _STAGE_AUTH_INFERENCE):
        prior = _registry_append_lifecycle_stage(
            prior,
            stage_name=_STAGE_AUTH_INFERENCE,
            attempt=1,
            duration_ms=0,
            result=str(prior.get("status") or "unknown_auth"),
            error=str(prior.get("error") or "").strip() or None,
            max_attempts=attempts,
        )
    prior = _registry_append_lifecycle_stage(
        prior,
        stage_name=_STAGE_ACCESS_CAPABILITIES,
        attempt=1,
        duration_ms=0,
        result="ok",
        error=None,
        max_attempts=attempts,
    )
    data_started_at = time.monotonic()
    result: dict[str, Any] = {}
    data_attempts = 0
    for attempt in range(attempts):
        data_attempts += 1
        result = _audit_registry_host_core(
            str(ctx.host),
            int(ctx.port),
            float(getattr(ctx.args, "timeout", 5.0)),
            0,
            username=username,
            password=password,
            token=token,
            docker=bool(options["docker"]),
            show_images=bool(options["show_images"]),
            show_tags=bool(options["show_tags"]),
            repository=options["repository"],
            tag=options["tag"],
            metadata=bool(options["metadata"]),
            harbor=bool(options["harbor"]),
            gitlab=bool(options["gitlab"]),
            nexus=bool(options["nexus"]),
            assets=bool(options["assets"]),
            inspect=bool(options["inspect"]),
            image=options["image"],
            download=bool(options["download"]),
            download_dir=str(options["download_dir"]),
            console=options["console"],
            debug=bool(getattr(ctx.args, "debug", False)),
            detect_nexus=bool(options["nexus"]),
            initial_probe=probe,
            initial_nexus=nexus_result,
            anonymous_probe_status=state.anonymous_probe[0] if state.anonymous_probe is not None else None,
        )
        retry_errors = (
            result.get("error"),
            result.get("images_error"),
            result.get("harbor_error"),
            result.get("gitlab_error"),
            result.get("nexus_error"),
            result.get("inspection_error"),
        )
        retryable = any(_registry_error_is_retryable(value) for value in retry_errors)
        if not retryable or attempt >= attempts - 1:
            break
        time.sleep(_retry_delay(attempt))
    deep_status = str(result.get("status") or "fail")
    deep_error = str(result.get("error") or "").strip() or None
    result["data_transport_attempts"] = data_attempts
    if deep_status == "fail" and bool(prior.get("is_registry")):
        result["is_registry"] = True
        result["detection_preserved"] = True
        result["detected_status"] = str(prior.get("status") or "")
    for name in (
        "status",
        "auth_required",
        "provided_credentials",
        "provided_username",
        "provided_password",
        "token_provided",
        "credentials_source",
        "provided_credentials_ok",
        "auth_transport_attempts",
    ):
        if name in prior:
            result[name] = prior[name]
    for name in (
        "attempts",
        "max_attempts",
        "stages",
        "stage_failed_at",
        "stage_durations_ms",
        "stage_attempts",
        "debug_events",
        "debug_events_streamed",
    ):
        if name in prior:
            result[name] = prior[name]
    return _registry_append_lifecycle_stage(
        result,
        stage_name=_STAGE_DATA,
        attempt=data_attempts,
        duration_ms=int((time.monotonic() - data_started_at) * 1000),
        result="fail" if deep_status == "fail" else "ok",
        error=deep_error if deep_status == "fail" else None,
        max_attempts=attempts,
    )


def _audit_registry_host_core(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    username: str | None,
    password: str | None,
    token: str | None,
    docker: bool,
    show_images: bool,
    show_tags: bool,
    repository: str | None,
    tag: str | None,
    metadata: bool,
    harbor: bool,
    gitlab: bool,
    nexus: bool,
    assets: bool,
    inspect: bool,
    image: str | None,
    download: bool,
    download_dir: str,
    console: Console,
    debug: bool,
    detect_nexus: bool = False,
    initial_probe: _RegistryProbe | None = None,
    initial_nexus: tuple[dict[str, Any] | None, str | None] | None = None,
    anonymous_probe_status: int | None = None,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
    auth_headers = _auth_headers(username, password, token)
    provided_credentials = username is not None and password is not None
    token_provided = bool(token)
    image_raw = str(image or "").strip() or None
    repository_raw = str(repository or "").strip() or None
    tag_raw = str(tag or "").strip() or None

    for attempt in range(attempts):
        started = time.monotonic()
        try:
            if attempt == 0 and initial_probe is not None:
                status, body, resp_headers, error = initial_probe
            else:
                status, body, resp_headers, error = _http_request(
                    host,
                    port,
                    "GET",
                    "/v2/",
                    timeout,
                    headers=auth_headers,
                )
            if error:
                raise OSError(error)

            body_text = body.decode("utf-8", errors="replace").strip().lower()
            unauthorized_body = "unauthorized" in body_text or "authentication required" in body_text
            is_registry = _registry_probe_has_fingerprint(status, body, resp_headers)
            www_authenticate = str(resp_headers.get("www-authenticate") or "")

            gitlab_info, gitlab_error = _fetch_gitlab_info(
                host,
                port,
                www_authenticate,
                timeout,
                headers=auth_headers,
                deep=gitlab,
            )
            if gitlab_info is not None:
                is_gitlab: bool | None = True
            elif gitlab_error == "not gitlab":
                is_gitlab = False
                gitlab_error = None
            else:
                is_gitlab = None
            gitlab_repositories: list[str] | None = None

            harbor_info, harbor_error = _fetch_harbor_info(host, port, timeout, headers=auth_headers)
            if harbor_info is not None:
                is_harbor: bool | None = True
            elif harbor_error == "not harbor":
                is_harbor = False
                harbor_error = None
            else:
                is_harbor = None
            harbor_projects: list[str] | None = None
            harbor_repositories: list[str] | None = None
            harbor_artifacts: list[str] | None = None

            if attempt == 0 and initial_nexus is not None:
                nexus_info, nexus_error = initial_nexus
            else:
                nexus_info, nexus_error = _fetch_nexus_info(host, port, timeout, headers=auth_headers)
            if nexus_info is not None:
                is_nexus: bool | None = True
            elif nexus_error == "not nexus":
                is_nexus = False
                nexus_error = None
            else:
                is_nexus = None
            nexus_detected_service = bool((nexus or detect_nexus) and is_nexus is True)
            nexus_repositories: list[str] | None = None
            nexus_repository_details: list[dict[str, Any]] | None = None
            nexus_assets_list: list[dict[str, Any]] | None = None
            if nexus and is_nexus is True:
                nexus_repository_details, nexus_error_repositories = _fetch_nexus_repository_records(
                    host,
                    port,
                    timeout,
                    headers=auth_headers,
                )
                if nexus_error_repositories and nexus_error is None:
                    nexus_error = nexus_error_repositories
                nexus_repository_details = nexus_repository_details or []
                nexus_repositories = []
                for item in nexus_repository_details:
                    name = str(item.get("name") or "").strip()
                    if not name:
                        continue
                    extra: list[str] = []
                    fmt = str(item.get("format") or "").strip()
                    repo_type = str(item.get("type") or "").strip()
                    url = str(item.get("url") or "").strip()
                    if fmt:
                        extra.append(f"format={fmt}")
                    if repo_type:
                        extra.append(f"type={repo_type}")
                    if url:
                        extra.append(f"url={url}")
                    nexus_repositories.append(f"{name} ({', '.join(extra)})" if extra else name)

            gitlab_repository_details: list[dict[str, Any]] | None = None
            selected_repository_tags: list[str] | None = None
            metadata_result: dict[str, Any] | None = None

            if nexus and is_nexus is True and nexus_repository_details:
                component_counts: dict[str, int] = {}
                assets_accum: list[dict[str, Any]] = []
                repo_names = [str(item.get("name") or "").strip() for item in nexus_repository_details]
                repo_names = [name for name in repo_names if name]
                if repository_raw:
                    repo_names = [repository_raw]
                for repo_name in repo_names:
                    components, components_error = _fetch_nexus_components(
                        host,
                        port,
                        repo_name,
                        timeout,
                        headers=auth_headers,
                    )
                    if components_error and nexus_error is None:
                        nexus_error = components_error
                    if components is None:
                        continue
                    component_counts[repo_name] = len(components)
                    if assets:
                        assets_accum.extend(_extract_nexus_assets(components))
                for repo_item in nexus_repository_details:
                    repo_name = str(repo_item.get("name") or "").strip()
                    if repo_name:
                        repo_item["components"] = component_counts.get(repo_name)
                if assets:
                    nexus_assets_list = assets_accum

            if not is_registry and not nexus_detected_service:
                return {
                    "timestamp": utc_now_iso(),
                    "host": host,
                    "port": port,
                    "is_registry": False,
                    "is_harbor": is_harbor,
                    "is_gitlab": is_gitlab,
                    "is_nexus": is_nexus,
                    "status": "not_registry",
                    "auth_required": None,
                    "provided_credentials": provided_credentials,
                    "provided_username": username,
                    "provided_password": password if provided_credentials else None,
                    "token_provided": token_provided,
                    "debug": debug,
                    "show_images": show_images,
                    "docker": docker,
                    "show_tags": show_tags,
                    "repository": repository_raw,
                    "tag": tag_raw,
                    "metadata": metadata,
                    "harbor": harbor,
                    "gitlab": gitlab,
                    "nexus": nexus,
                    "assets": assets,
                    "inspect": inspect,
                    "image": image_raw,
                    "download": download,
                    "image_count": None,
                    "images": None,
                    "images_error": None,
                    "harbor_info": harbor_info,
                    "harbor_projects": harbor_projects,
                    "harbor_repositories": harbor_repositories,
                    "harbor_artifacts": harbor_artifacts,
                    "harbor_error": harbor_error,
                    "gitlab_info": gitlab_info,
                    "gitlab_error": gitlab_error,
                    "gitlab_repositories": gitlab_repositories,
                    "gitlab_repository_details": gitlab_repository_details,
                    "selected_repository_tags": selected_repository_tags,
                    "metadata_result": metadata_result,
                    "nexus_info": nexus_info,
                    "nexus_repositories": nexus_repositories,
                    "nexus_repository_details": nexus_repository_details,
                    "nexus_assets": nexus_assets_list,
                    "nexus_error": nexus_error,
                    "inspections": None,
                    "inspection_error": None,
                    "download_result": None,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "probe_status": status,
                    "error": None,
                }

            if nexus_detected_service and not is_registry:
                auth_required = False
                nexus_anonymous = not (provided_credentials or token_provided)
                if not nexus_anonymous:
                    anonymous_info, _anonymous_error = _fetch_nexus_info(host, port, timeout, headers={})
                    nexus_anonymous = anonymous_info is not None
                state = "open_no_auth" if nexus_anonymous else "valid_credentials"
            else:
                auth_required = status == 401 or (status == 403 and unauthorized_body)
                anon_probe_status: int | None = None
                if status == 200 and (provided_credentials or token_provided):
                    # Re-probe /v2/ without credentials to distinguish "valid creds" from
                    # "server is anonymous and never checked what we sent". Without this
                    # distinction any bogus --username/--password against Docker Hub would
                    # be misreported as valid_credentials.
                    if anonymous_probe_status is not None:
                        anon_probe_status = int(anonymous_probe_status)
                    else:
                        anon_status, _anon_body, _anon_headers, anon_error = _http_request(
                            host, port, "GET", "/v2/", timeout, headers=None
                        )
                        if anon_error is None:
                            anon_probe_status = anon_status
                if status == 200 and not (provided_credentials or token_provided):
                    state = "open_no_auth"
                elif status == 200 and anon_probe_status == 200:
                    state = "open_no_auth"
                elif status == 200:
                    state = "valid_credentials"
                elif auth_required:
                    state = "auth_required"
                else:
                    state = "unknown_auth"

            repos: list[str] | None = None
            repo_tags_map: dict[str, list[str]] = {}
            image_refs: list[str] | None = None
            images_error: str | None = None
            can_access_registry_data = bool(is_registry and status == 200)

            if show_images and not can_access_registry_data:
                images_error = "authentication required"

            # Catalog and per-repository tag enumeration can be very expensive
            # on production registries. Only perform it for actions that
            # explicitly need whole-registry inventory.
            need_catalog = can_access_registry_data and bool(
                show_images or gitlab or (inspect and image_raw is None) or (download and image_raw is None)
            )
            if need_catalog:
                repos, images_error = _fetch_registry_catalog(host, port, timeout, headers=auth_headers)
                if repos is None:
                    repos = []

            if can_access_registry_data:
                image_refs = []
                if repos:
                    for repo in repos:
                        tags_list, tag_error = _fetch_repository_tags(host, port, repo, timeout, headers=auth_headers)
                        if tags_list is None:
                            if images_error is None and tag_error:
                                images_error = f"{repo}: {tag_error}"
                            continue
                        if tag_error and images_error is None:
                            images_error = f"{repo}: {tag_error}"
                        repo_tags_map[repo] = list(tags_list)
                        if not tags_list:
                            image_refs.append(f"{repo}:<untagged>")
                            continue
                        for repo_tag in tags_list:
                            image_refs.append(_display_image(repo, repo_tag))
                image_refs = sorted(set(image_refs or []))
                if is_gitlab is True:
                    gitlab_repositories = sorted(set(repos or []))
                    last_pushed_by_repo: dict[str, str] = {}
                    if gitlab:
                        for repo_name in gitlab_repositories:
                            latest_tag = _pick_latest_tag(repo_tags_map.get(repo_name) or [])
                            if not latest_tag:
                                continue
                            inspected_latest = _inspect_image(
                                host, port, repo_name, latest_tag, timeout, headers=auth_headers
                            )
                            created_raw = str(inspected_latest.get("created") or "").strip()
                            if created_raw:
                                last_pushed_by_repo[repo_name] = created_raw
                    gitlab_repository_details = _build_gitlab_repository_summaries(
                        gitlab_repositories,
                        repo_tags_map,
                        last_pushed_by_repo,
                    )

                if repository_raw:
                    if repository_raw in repo_tags_map:
                        selected_repository_tags = sorted(set(repo_tags_map.get(repository_raw) or []))
                    else:
                        tags_list, tag_error = _fetch_repository_tags(
                            host, port, repository_raw, timeout, headers=auth_headers
                        )
                        if tags_list is None:
                            if images_error is None and tag_error:
                                images_error = f"{repository_raw}: {tag_error}"
                        else:
                            selected_repository_tags = sorted(set(tags_list))
                            if tag_error and images_error is None:
                                images_error = f"{repository_raw}: {tag_error}"

                if metadata and repository_raw and tag_raw:
                    metadata_result = _inspect_image(host, port, repository_raw, tag_raw, timeout, headers=auth_headers)
            elif show_tags and repository_raw:
                selected_repository_tags = None
            if metadata and repository_raw and tag_raw and not can_access_registry_data:
                metadata_result = {
                    "image": _display_image(repository_raw, tag_raw),
                    "repository": repository_raw,
                    "reference": tag_raw,
                    "error": "cannot fetch metadata without registry access",
                }

            # Deep Harbor parsing is enabled only with --harbor.
            if harbor and is_harbor is True:
                harbor_projects, harbor_error_projects = _fetch_harbor_projects(
                    host, port, timeout, headers=auth_headers
                )
                if harbor_error_projects and harbor_error is None:
                    harbor_error = harbor_error_projects
                harbor_projects = harbor_projects or []

                repos_accum: list[str] = []
                artifacts_accum: list[str] = []
                for project_name in harbor_projects:
                    project_repos, project_error = _fetch_harbor_repositories(
                        host,
                        port,
                        project_name,
                        timeout,
                        headers=auth_headers,
                    )
                    if project_error and harbor_error is None:
                        harbor_error = project_error
                    for repo_name in project_repos or []:
                        repos_accum.append(repo_name)
                        artifacts, artifacts_error = _fetch_harbor_artifacts(
                            host,
                            port,
                            project_name,
                            repo_name,
                            timeout,
                            headers=auth_headers,
                        )
                        if artifacts_error and harbor_error is None:
                            harbor_error = artifacts_error
                        artifacts_accum.extend(artifacts or [])
                harbor_repositories = sorted(set(repos_accum))
                harbor_artifacts = sorted(set(artifacts_accum))

            inspections: list[dict[str, Any]] | None = None
            inspection_error: str | None = None
            inspect_needed = inspect or bool(download)
            if inspect_needed:
                if not can_access_registry_data:
                    inspection_error = "cannot inspect images without registry access"
                else:
                    inspect_targets: list[tuple[str, str]] = []
                    if image_raw:
                        repo, ref = _split_image_reference(image_raw)
                        if not repo or not ref:
                            inspection_error = f"invalid --image value: {image_raw}"
                        else:
                            inspect_targets.append((repo, ref))
                    else:
                        if not image_refs:
                            inspection_error = "no images discovered for inspection"
                        else:
                            for image_ref in image_refs[:_REGISTRY_MAX_INSPECT_IMAGES]:
                                repo, ref = _split_image_reference(image_ref)
                                if repo and ref:
                                    inspect_targets.append((repo, ref))
                            if len(image_refs) > _REGISTRY_MAX_INSPECT_IMAGES and inspection_error is None:
                                inspection_error = (
                                    f"inspect list truncated to first {_REGISTRY_MAX_INSPECT_IMAGES} images "
                                    f"(found {len(image_refs)})"
                                )

                    inspections = []
                    for repo, ref in inspect_targets:
                        inspected = _inspect_image(host, port, repo, ref, timeout, headers=auth_headers)
                        inspections.append(inspected)

            download_result: dict[str, Any] | None = None
            if download:
                if not image_raw:
                    download_result = {"status": "fail", "error": "--download requires --image"}
                elif not can_access_registry_data:
                    download_result = {"status": "fail", "error": "registry access denied"}
                else:
                    selected_inspect: dict[str, Any] | None = None
                    if inspections:
                        selected_inspect = inspections[0]
                    elif image_raw:
                        repo, ref = _split_image_reference(image_raw)
                        if repo and ref:
                            selected_inspect = _inspect_image(host, port, repo, ref, timeout, headers=auth_headers)
                    if selected_inspect is None:
                        download_result = {"status": "fail", "error": "failed to prepare image metadata"}
                    elif selected_inspect.get("error"):
                        download_result = {"status": "fail", "error": str(selected_inspect.get("error"))}
                    else:
                        download_result = _download_image(
                            host,
                            port,
                            timeout,
                            headers=auth_headers,
                            inspect_data=selected_inspect,
                            download_dir=download_dir,
                            console=console,
                        )

            return {
                "timestamp": utc_now_iso(),
                "host": host,
                "port": port,
                "is_registry": bool(is_registry or nexus_detected_service),
                "is_harbor": is_harbor,
                "is_gitlab": is_gitlab,
                "is_nexus": is_nexus,
                "status": state,
                "auth_required": auth_required if state != "unknown_auth" else None,
                "provided_credentials": provided_credentials,
                "provided_username": username,
                "provided_password": password if provided_credentials else None,
                "token_provided": token_provided,
                "debug": debug,
                "show_images": show_images,
                "docker": docker,
                "show_tags": show_tags,
                "repository": repository_raw,
                "tag": tag_raw,
                "metadata": metadata,
                "harbor": harbor,
                "gitlab": gitlab,
                "nexus": nexus,
                "assets": assets,
                "inspect": inspect,
                "image": image_raw,
                "download": download,
                "image_count": len(image_refs or []) if need_catalog else None,
                # Keep full list only when it may be rendered/used directly.
                "images": image_refs if (show_images or inspect or (download and image_raw is None)) else None,
                "images_error": images_error,
                "harbor_info": harbor_info,
                "harbor_projects": harbor_projects,
                "harbor_repositories": harbor_repositories,
                "harbor_artifacts": harbor_artifacts,
                "harbor_error": harbor_error,
                "gitlab_info": gitlab_info,
                "gitlab_error": gitlab_error,
                "gitlab_repositories": gitlab_repositories,
                "gitlab_repository_details": gitlab_repository_details,
                "selected_repository_tags": selected_repository_tags,
                "metadata_result": metadata_result,
                "nexus_info": nexus_info,
                "nexus_repositories": nexus_repositories,
                "nexus_repository_details": nexus_repository_details,
                "nexus_assets": nexus_assets_list,
                "nexus_error": nexus_error,
                "inspections": inspections,
                "inspection_error": inspection_error,
                "download_result": download_result,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "probe_status": status,
                "error": None
                if state in {"open_no_auth", "valid_credentials"}
                else ("authentication required" if state == "auth_required" else None),
            }
        except (OSError, TimeoutError, ValueError) as exc:
            last_error = _friendly_error_from_exception(exc)
            if attempt >= attempts - 1:
                break
            time.sleep(_retry_delay(attempt))

    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "port": port,
        "is_registry": False,
        "is_harbor": None,
        "is_gitlab": None,
        "is_nexus": None,
        "status": "fail",
        "auth_required": None,
        "provided_credentials": provided_credentials,
        "provided_username": username,
        "provided_password": password if provided_credentials else None,
        "token_provided": token_provided,
        "debug": debug,
        "show_images": show_images,
        "docker": docker,
        "show_tags": show_tags,
        "repository": repository_raw,
        "tag": tag_raw,
        "metadata": metadata,
        "harbor": harbor,
        "gitlab": gitlab,
        "nexus": nexus,
        "assets": assets,
        "inspect": inspect,
        "image": image_raw,
        "download": download,
        "image_count": None,
        "images": None,
        "images_error": None,
        "harbor_info": None,
        "harbor_projects": None,
        "harbor_repositories": None,
        "harbor_artifacts": None,
        "harbor_error": None,
        "gitlab_info": None,
        "gitlab_error": None,
        "gitlab_repositories": None,
        "gitlab_repository_details": None,
        "selected_repository_tags": None,
        "metadata_result": None,
        "nexus_info": None,
        "nexus_repositories": None,
        "nexus_repository_details": None,
        "nexus_assets": None,
        "nexus_error": None,
        "inspections": None,
        "inspection_error": None,
        "download_result": None,
        "elapsed_ms": None,
        "probe_status": None,
        "error": last_error or "connection failed",
    }


def _call_audit_registry_host_with_thread_debug(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    username: str | None,
    password: str | None,
    token: str | None,
    docker: bool,
    show_images: bool,
    show_tags: bool,
    repository: str | None,
    tag: str | None,
    metadata: bool,
    harbor: bool,
    gitlab: bool,
    nexus: bool,
    assets: bool,
    inspect: bool,
    image: str | None,
    download: bool,
    download_dir: str,
    console: Console,
    debug: bool,
    run_deep_checks: bool,
    debug_emit: Callable[[str], None] | None,
) -> dict[str, Any]:
    def _invoke() -> dict[str, Any]:
        try:
            return _audit_registry_host(
                host,
                port,
                timeout,
                retries,
                username=username,
                password=password,
                token=token,
                docker=docker,
                show_images=show_images,
                show_tags=show_tags,
                repository=repository,
                tag=tag,
                metadata=metadata,
                harbor=harbor,
                gitlab=gitlab,
                nexus=nexus,
                assets=assets,
                inspect=inspect,
                image=image,
                download=download,
                download_dir=download_dir,
                console=console,
                debug=debug,
                run_deep_checks=run_deep_checks,
            )
        except TypeError as exc:
            if not is_signature_compat_typeerror(exc, expected_keywords={"debug", "run_deep_checks"}):
                raise
            return _audit_registry_host(
                host,
                port,
                timeout,
                retries,
                username=username,
                password=password,
                token=token,
                docker=docker,
                show_images=show_images,
                show_tags=show_tags,
                repository=repository,
                tag=tag,
                metadata=metadata,
                harbor=harbor,
                gitlab=gitlab,
                nexus=nexus,
                assets=assets,
                inspect=inspect,
                image=image,
                download=download,
                download_dir=download_dir,
                console=console,
                debug=debug,
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


def _audit_registry_host(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    username: str | None,
    password: str | None,
    token: str | None,
    docker: bool,
    show_images: bool,
    show_tags: bool,
    repository: str | None,
    tag: str | None,
    metadata: bool,
    harbor: bool,
    gitlab: bool,
    nexus: bool,
    assets: bool,
    inspect: bool,
    image: str | None,
    download: bool,
    download_dir: str,
    console: Console,
    debug: bool,
    run_deep_checks: bool = True,
) -> dict[str, Any]:
    attempts = max(1, retries + 1)
    last_error: str | None = None
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
        debug_line = f"{host}:{port} {message}"
        debug_events.append(debug_line)
        emitter = _get_thread_debug_emitter()
        if emitter is not None:
            emitter(debug_line)
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
                status=str(payload.get("status") or "fail"),
                attempts_done=attempts_done,
                max_attempts=max_attempts,
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
        return record

    for attempt in range(attempts):
        _debug(f"attempt={attempt + 1}/{attempts} start timeout={timeout}s")
        stage1_started = time.monotonic()
        detect_record = _audit_registry_host_core(
            host,
            port,
            timeout,
            0,
            username=username,
            password=password,
            token=token,
            docker=False,
            show_images=False,
            show_tags=False,
            repository=repository,
            tag=tag,
            metadata=False,
            harbor=False,
            gitlab=False,
            nexus=False,
            assets=False,
            inspect=False,
            image=image,
            download=False,
            download_dir=download_dir,
            console=console,
            debug=debug,
            detect_nexus=nexus,
        )
        status = str(detect_record.get("status") or "fail")
        if status in {"fail", "not_registry"}:
            _stage_trace(
                _STAGE_DETECT_PROTOCOL,
                attempt=attempt + 1,
                started_at=stage1_started,
                result=status,
                error=str(detect_record.get("error") or "").strip() or None,
            )
            if status == "fail":
                last_error = str(detect_record.get("error") or "connection failed")
                if attempt < attempts - 1:
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
            return _record(detect_record, attempts_done=attempt + 1, max_attempts=attempts)
        _stage_trace(
            _STAGE_DETECT_PROTOCOL,
            attempt=attempt + 1,
            started_at=stage1_started,
            result="ok",
            error=None,
        )

        stage2_started = time.monotonic()
        _stage_trace(
            _STAGE_AUTH_INFERENCE,
            attempt=attempt + 1,
            started_at=stage2_started,
            result=status,
            error=str(detect_record.get("error") or "").strip() or None,
        )

        if not run_deep_checks:
            _debug(f"attempt={attempt + 1}/{attempts} detect-only result={status}")
            return _record(detect_record, attempts_done=attempt + 1, max_attempts=attempts)

        if status not in {"open_no_auth", "valid_credentials"}:
            return _record(detect_record, attempts_done=attempt + 1, max_attempts=attempts)

        stage3_started = time.monotonic()
        _stage_trace(
            _STAGE_ACCESS_CAPABILITIES,
            attempt=attempt + 1,
            started_at=stage3_started,
            result="ok",
            error=None,
        )

        stage4_started = time.monotonic()
        deep_record = _audit_registry_host_core(
            host,
            port,
            timeout,
            0,
            username=username,
            password=password,
            token=token,
            docker=docker,
            show_images=show_images,
            show_tags=show_tags,
            repository=repository,
            tag=tag,
            metadata=metadata,
            harbor=harbor,
            gitlab=gitlab,
            nexus=nexus,
            assets=assets,
            inspect=inspect,
            image=image,
            download=download,
            download_dir=download_dir,
            console=console,
            debug=debug,
        )
        deep_status = str(deep_record.get("status") or "fail")
        deep_error = str(deep_record.get("error") or "").strip() or None
        if deep_status == "fail":
            _stage_trace(
                _STAGE_DATA,
                attempt=attempt + 1,
                started_at=stage4_started,
                result="fail",
                error=deep_error,
            )
            last_error = deep_error or "deep stage failed"
            if attempt < attempts - 1:
                delay = _retry_delay(attempt)
                _debug_retry_decision(
                    _STAGE_DATA,
                    attempt=attempt + 1,
                    max_attempts=attempts,
                    delay_s=delay,
                    reason=last_error,
                )
                time.sleep(delay)
                continue
            return _record(deep_record, attempts_done=attempt + 1, max_attempts=attempts)

        _stage_trace(
            _STAGE_DATA,
            attempt=attempt + 1,
            started_at=stage4_started,
            result="ok",
            error=None,
        )
        return _record(deep_record, attempts_done=attempt + 1, max_attempts=attempts)

    return _record(
        {
            "timestamp": utc_now_iso(),
            "host": host,
            "port": port,
            "is_registry": False,
            "is_harbor": None,
            "is_gitlab": None,
            "is_nexus": None,
            "status": "fail",
            "auth_required": None,
            "provided_credentials": username is not None and password is not None,
            "provided_username": username,
            "provided_password": password if username is not None and password is not None else None,
            "token_provided": bool(token),
            "debug": debug,
            "show_images": show_images,
            "docker": docker,
            "show_tags": show_tags,
            "repository": str(repository or "").strip() or None,
            "tag": str(tag or "").strip() or None,
            "metadata": metadata,
            "harbor": harbor,
            "gitlab": gitlab,
            "nexus": nexus,
            "assets": assets,
            "inspect": inspect,
            "image": str(image or "").strip() or None,
            "download": download,
            "image_count": None,
            "images": None,
            "images_error": None,
            "harbor_info": None,
            "harbor_projects": None,
            "harbor_repositories": None,
            "harbor_artifacts": None,
            "harbor_error": None,
            "gitlab_info": None,
            "gitlab_error": None,
            "gitlab_repositories": None,
            "gitlab_repository_details": None,
            "selected_repository_tags": None,
            "metadata_result": None,
            "nexus_info": None,
            "nexus_repositories": None,
            "nexus_repository_details": None,
            "nexus_assets": None,
            "nexus_error": None,
            "inspections": None,
            "inspection_error": None,
            "download_result": None,
            "elapsed_ms": None,
            "probe_status": None,
            "error": _friendly_error_text(last_error or "connection failed"),
        },
        attempts_done=attempts,
        max_attempts=attempts,
    )


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
        "image_count",
        "images",
        "images_error",
        "harbor_info",
        "harbor_projects",
        "harbor_repositories",
        "harbor_artifacts",
        "harbor_error",
        "gitlab_info",
        "gitlab_error",
        "gitlab_repositories",
        "gitlab_repository_details",
        "selected_repository_tags",
        "metadata_result",
        "nexus_info",
        "nexus_repositories",
        "nexus_repository_details",
        "nexus_assets",
        "nexus_error",
        "inspections",
        "inspection_error",
        "download_result",
        "elapsed_ms",
        "probe_status",
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
    return merged


def _nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(str(record.get("host") or "-"), 64)
    port = str(record.get("port") or "-")
    return f"{'REGISTRY':<12}\t{host}\t{port}\t"


def _with_optional_images(record: dict[str, Any], message: str) -> str:
    return f"{message} (images:{format_count_value(record.get('image_count'))})"


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
                "service": "registry",
                "detected": bool(record.get("is_registry")),
                "auth_required": auth_required_value,
            },
            ensure_ascii=False,
        )
    service_label = "Docker Registry Service"
    if record.get("is_gitlab") is True:
        service_label = "GitLab Container Registry (Docker Registry v2)"
    elif record.get("is_harbor") is True:
        service_label = "Harbor Registry (Docker Registry v2)"
    elif record.get("is_nexus") is True:
        service_label = "Nexus Docker Registry (Docker Registry v2)"
    return f"{_nxc_prefix(record)} [*] {service_label} (auth required:{auth_required_text})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    prefix = _nxc_prefix(record)
    status = str(record.get("status") or "fail")
    err = _clip(str(record.get("error") or "-"), 96)

    if status == "open_no_auth":
        return ""

    if status == "valid_credentials":
        if record.get("token_provided"):
            return _with_optional_images(record, f"{prefix} [+] token auth")
        username = str(record.get("provided_username") or "user").strip() or "user"
        provided_password = record.get("provided_password")
        password_text = "<empty>" if provided_password == "" else str(provided_password or "")
        return _with_optional_images(record, f"{prefix} [+] {username}:{password_text}")

    if status == "auth_required":
        if record.get("token_provided"):
            line = f"{prefix} [-] token auth"
        elif record.get("provided_credentials"):
            username = str(record.get("provided_username") or "user").strip() or "user"
            provided_password = record.get("provided_password")
            password_text = "<empty>" if provided_password == "" else str(provided_password or "")
            line = f"{prefix} [-] {username}:{password_text}"
        else:
            line = f"{prefix} [-] authentication required"
        return line

    if status == "not_registry":
        line = f"{prefix} [-] not a Docker Registry v2 endpoint"
        probe_status = record.get("probe_status")
        if isinstance(probe_status, int) and probe_status > 0:
            return f"{line} (status:{probe_status})"
        return line

    if status == "unknown_auth":
        line = f"{prefix} [!] auth status unknown"
        if err != "-":
            return f"{line} err={err}"
        return line

    line = f"{prefix} [!] connection failed"
    if err != "-":
        return f"{line} err={err}"
    return line


def _format_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    debug = bool(record.get("debug"))
    is_registry = bool(record.get("is_registry"))
    show_images = bool(record.get("show_images")) and is_registry
    show_tags = bool(record.get("show_tags")) and is_registry
    repository_raw = str(record.get("repository") or "").strip()
    tag_raw = str(record.get("tag") or "").strip()
    metadata_enabled = bool(record.get("metadata")) and is_registry
    harbor = bool(record.get("harbor"))
    gitlab = bool(record.get("gitlab"))
    nexus = bool(record.get("nexus"))
    assets_enabled = bool(record.get("assets")) and bool(record.get("nexus"))
    inspect = bool(record.get("inspect"))
    download = bool(record.get("download"))
    image_raw = str(record.get("image") or "").strip()
    targeted_repo_lookup = bool(repository_raw and (show_tags or metadata_enabled))
    targeted_image_lookup = bool(image_raw and (inspect or download))
    suppress_vendor_inventory = targeted_repo_lookup or targeted_image_lookup

    images_raw = record.get("images")
    images = [str(item) for item in images_raw] if isinstance(images_raw, list) else []
    images_error = str(record.get("images_error") or "").strip()

    harbor_info = record.get("harbor_info")
    harbor_projects_raw = record.get("harbor_projects")
    harbor_repositories_raw = record.get("harbor_repositories")
    harbor_artifacts_raw = record.get("harbor_artifacts")
    harbor_projects = [str(item) for item in harbor_projects_raw] if isinstance(harbor_projects_raw, list) else []
    harbor_repositories = (
        [str(item) for item in harbor_repositories_raw] if isinstance(harbor_repositories_raw, list) else []
    )
    harbor_artifacts = [str(item) for item in harbor_artifacts_raw] if isinstance(harbor_artifacts_raw, list) else []
    harbor_error = str(record.get("harbor_error") or "").strip()
    is_harbor = record.get("is_harbor")
    gitlab_info = record.get("gitlab_info")
    gitlab_error = str(record.get("gitlab_error") or "").strip()
    gitlab_repositories_raw = record.get("gitlab_repositories")
    gitlab_repositories = (
        [str(item) for item in gitlab_repositories_raw] if isinstance(gitlab_repositories_raw, list) else []
    )
    gitlab_repository_details_raw = record.get("gitlab_repository_details")
    gitlab_repository_details = (
        [item for item in gitlab_repository_details_raw if isinstance(item, dict)]
        if isinstance(gitlab_repository_details_raw, list)
        else []
    )
    selected_repository_tags_raw = record.get("selected_repository_tags")
    selected_repository_tags = (
        [str(item) for item in selected_repository_tags_raw] if isinstance(selected_repository_tags_raw, list) else []
    )
    metadata_result = record.get("metadata_result") if isinstance(record.get("metadata_result"), dict) else None
    is_gitlab = record.get("is_gitlab")
    nexus_info = record.get("nexus_info")
    nexus_repositories_raw = record.get("nexus_repositories")
    nexus_repositories = (
        [str(item) for item in nexus_repositories_raw] if isinstance(nexus_repositories_raw, list) else []
    )
    nexus_repository_details_raw = record.get("nexus_repository_details")
    nexus_repository_details = (
        [item for item in nexus_repository_details_raw if isinstance(item, dict)]
        if isinstance(nexus_repository_details_raw, list)
        else []
    )
    nexus_assets_raw = record.get("nexus_assets")
    nexus_assets = (
        [item for item in nexus_assets_raw if isinstance(item, dict)] if isinstance(nexus_assets_raw, list) else []
    )
    nexus_error = str(record.get("nexus_error") or "").strip()
    is_nexus = record.get("is_nexus")

    inspections_raw = record.get("inspections")
    inspections = (
        [item for item in inspections_raw if isinstance(item, dict)] if isinstance(inspections_raw, list) else []
    )
    inspection_error = str(record.get("inspection_error") or "").strip()

    download_result = record.get("download_result") if isinstance(record.get("download_result"), dict) else None

    if output_format == "json":
        payloads: list[str] = []
        if show_images:
            payloads.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "images",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "images": images,
                        "error": images_error or None,
                    },
                    ensure_ascii=False,
                )
            )
        payloads.append(
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "harbor",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "is_harbor": is_harbor,
                    "deep": harbor,
                    "info": harbor_info,
                    "projects": harbor_projects,
                    "repositories": harbor_repositories,
                    "artifacts": harbor_artifacts,
                    "error": harbor_error or None,
                },
                ensure_ascii=False,
            )
        )
        payloads.append(
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "gitlab",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "is_gitlab": is_gitlab,
                    "deep": gitlab,
                    "info": gitlab_info,
                    "repositories": gitlab_repositories,
                    "repository_details": gitlab_repository_details,
                    "selected_repository_tags": selected_repository_tags if show_tags else None,
                    "metadata": metadata_result if metadata_enabled else None,
                    "error": gitlab_error or None,
                },
                ensure_ascii=False,
            )
        )
        payloads.append(
            json.dumps(
                {
                    "timestamp": record.get("timestamp"),
                    "type": "nexus",
                    "host": record.get("host"),
                    "port": record.get("port"),
                    "is_nexus": is_nexus,
                    "deep": nexus,
                    "info": nexus_info,
                    "repositories": nexus_repositories,
                    "repository_details": nexus_repository_details,
                    "assets": nexus_assets if assets_enabled else None,
                    "error": nexus_error or None,
                },
                ensure_ascii=False,
            )
        )
        if inspect:
            payloads.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "inspect",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "image": image_raw or None,
                        "inspections": inspections,
                        "error": inspection_error or None,
                    },
                    ensure_ascii=False,
                )
            )
        if download and download_result is not None:
            payloads.append(
                json.dumps(
                    {
                        "timestamp": record.get("timestamp"),
                        "type": "download",
                        "host": record.get("host"),
                        "port": record.get("port"),
                        "result": download_result,
                    },
                    ensure_ascii=False,
                )
            )
        return payloads

    prefix = _nxc_prefix(record)
    lines: list[str] = []

    if show_images:
        lines.append(f"{prefix} [*] Show Images")
        if images:
            for item in images:
                lines.append(f"{prefix} {item}")
        elif images_error:
            lines.append(f"{prefix} [-] {images_error}")
        else:
            lines.append(f"{prefix} <no images>")

    show_harbor_presence = bool(harbor or (debug and (is_registry or is_harbor is True or harbor_error)))
    if show_harbor_presence and is_harbor is True:
        version = ""
        if isinstance(harbor_info, dict):
            version = str(harbor_info.get("harbor_version") or harbor_info.get("version") or "").strip()
        if version:
            lines.append(f"{prefix} [*] Harbor detected version={version}")
        else:
            lines.append(f"{prefix} [*] Harbor detected")
        if harbor and not suppress_vendor_inventory:
            if harbor_projects:
                lines.append(f"{prefix} [*] Harbor Projects")
                for item in harbor_projects:
                    lines.append(f"{prefix} {item}")
            if harbor_repositories:
                lines.append(f"{prefix} [*] Harbor Repositories")
                for item in harbor_repositories:
                    lines.append(f"{prefix} {item}")
            if harbor_artifacts:
                lines.append(f"{prefix} [*] Harbor Artifacts")
                for item in harbor_artifacts:
                    lines.append(f"{prefix} {item}")
        if harbor and harbor_error:
            lines.append(f"{prefix} [-] {harbor_error}")
    elif show_harbor_presence and is_harbor is False:
        if debug:
            lines.append(f"{prefix} [*] Harbor API not detected")
    elif show_harbor_presence and harbor_error:
        lines.append(f"{prefix} [!] Harbor presence unknown: {harbor_error}")

    show_gitlab_presence = bool(gitlab or (debug and (is_registry or is_gitlab is True or gitlab_error)))
    if show_gitlab_presence and is_gitlab is True:
        challenge_parts: list[str] = []
        if isinstance(gitlab_info, dict):
            service = str(gitlab_info.get("service") or "").strip()
            realm = str(gitlab_info.get("realm") or "").strip()
            if service:
                challenge_parts.append(f"service={service}")
            if realm:
                challenge_parts.append(f"realm={realm}")
        if challenge_parts:
            lines.append(f"{prefix} [*] GitLab Container Registry detected ({', '.join(challenge_parts)})")
        else:
            lines.append(f"{prefix} [*] GitLab Container Registry detected")
        if gitlab and isinstance(gitlab_info, dict):
            probe_status = str(gitlab_info.get("token_probe_status") or "").strip()
            if probe_status:
                extra = ""
                probe_http_status = gitlab_info.get("token_probe_http_status")
                if isinstance(probe_http_status, int):
                    extra = f" http={probe_http_status}"
                lines.append(f"{prefix} [*] GitLab token probe status={probe_status}{extra}")
            probe_error = str(gitlab_info.get("token_probe_error") or "").strip()
            if probe_error:
                lines.append(f"{prefix} [-] {probe_error}")
            if not suppress_vendor_inventory and gitlab_repository_details:
                lines.append(f"{prefix} [*] GitLab Repositories")
                for gitlab_repo in gitlab_repository_details:
                    repo_name = str(gitlab_repo.get("repository") or "").strip() or "-"
                    tags_count = gitlab_repo.get("tags_count")
                    latest_tag = str(gitlab_repo.get("latest_tag") or "").strip() or "-"
                    last_pushed = str(gitlab_repo.get("last_pushed") or "").strip() or "-"
                    tags_count_text = format_count_value(tags_count)
                    lines.append(
                        f"{prefix} {repo_name} (tags:{tags_count_text}) (latest:{latest_tag}) (last pushed:{last_pushed})"
                    )
            elif not suppress_vendor_inventory and gitlab_repositories:
                lines.append(f"{prefix} [*] GitLab Repositories")
                for item in gitlab_repositories:
                    lines.append(f"{prefix} {item}")
            elif not suppress_vendor_inventory and images_error:
                lines.append(f"{prefix} [-] GitLab repositories unavailable: {images_error}")
            elif not suppress_vendor_inventory:
                lines.append(f"{prefix} [*] GitLab Repositories")
                lines.append(f"{prefix} <no repositories>")
    elif show_gitlab_presence and is_gitlab is False:
        if debug:
            lines.append(f"{prefix} [*] GitLab Container Registry not detected")
    elif show_gitlab_presence and gitlab_error:
        lines.append(f"{prefix} [!] GitLab presence unknown: {gitlab_error}")

    if show_tags and repository_raw:
        lines.append(f"{prefix} [*] Show Tags {repository_raw}")
        if selected_repository_tags:
            for item in selected_repository_tags:
                lines.append(f"{prefix} {item}")
        elif images_error:
            lines.append(f"{prefix} [-] {repository_raw}: {images_error}")
        else:
            lines.append(f"{prefix} <no tags>")

    if metadata_enabled and repository_raw and tag_raw:
        image_display = _display_image(repository_raw, tag_raw)
        if metadata_result is None:
            lines.append(f"{prefix} [-] Metadata unavailable for {image_display}")
        else:
            metadata_error = str(metadata_result.get("error") or "").strip()
            if metadata_error:
                lines.append(f"{prefix} [-] Metadata {image_display} err={metadata_error}")
            else:
                lines.append(f"{prefix} [*] Metadata {image_display}")
                env_values = metadata_result.get("env")
                if isinstance(env_values, list):
                    lines.append(f"{prefix} [*] ENV")
                    for env_item in env_values:
                        lines.append(f"{prefix} {env_item}")
                labels = metadata_result.get("labels")
                if isinstance(labels, list):
                    lines.append(f"{prefix} [*] Labels")
                    for label_item in labels:
                        lines.append(f"{prefix} {label_item}")
                cmd_items = metadata_result.get("cmd")
                if isinstance(cmd_items, list):
                    lines.append(f"{prefix} [*] CMD")
                    if cmd_items:
                        lines.append(f"{prefix} {' '.join(str(item) for item in cmd_items)}")
                    else:
                        lines.append(f"{prefix} <empty>")
                suspicious = metadata_result.get("suspicious")
                if isinstance(suspicious, list) and suspicious:
                    lines.append(f"{prefix} [!] Possible Secret Indicators")
                    for suspicious_item in suspicious:
                        lines.append(f"{prefix} {suspicious_item}")

    show_nexus_presence = bool(nexus or (debug and (is_registry or is_nexus is True or nexus_error)))
    if show_nexus_presence and is_nexus is True:
        nexus_version = ""
        if isinstance(nexus_info, dict):
            nexus_version = str(
                nexus_info.get("version") or nexus_info.get("release") or nexus_info.get("editionLong") or ""
            ).strip()
        if nexus_version:
            lines.append(f"{prefix} [*] Nexus Repository detected version={nexus_version}")
        else:
            lines.append(f"{prefix} [*] Nexus Repository detected")
        if nexus:
            if not suppress_vendor_inventory and nexus_repository_details:
                lines.append(f"{prefix} [*] Nexus Repositories")
                for nexus_repo in nexus_repository_details:
                    repo_name = str(nexus_repo.get("name") or "").strip() or "-"
                    repo_type = str(nexus_repo.get("type") or "").strip() or "-"
                    online_raw = nexus_repo.get("online")
                    online_text = "True" if online_raw is True else "False" if online_raw is False else "unknown"
                    components_raw = nexus_repo.get("components")
                    components_text = format_count_value(components_raw)
                    lines.append(
                        f"{prefix} {repo_name} (type:{repo_type}) (online:{online_text}) (components:{components_text})"
                    )
            elif not suppress_vendor_inventory and nexus_repositories:
                lines.append(f"{prefix} [*] Nexus Repositories")
                for item in nexus_repositories:
                    lines.append(f"{prefix} {item}")
            if assets_enabled:
                lines.append(f"{prefix} [*] Nexus Assets")
                if nexus_assets:
                    for asset in nexus_assets:
                        url = str(asset.get("download_url") or "").strip() or "-"
                        checksums = asset.get("checksums")
                        checksum_text = "-"
                        if isinstance(checksums, dict) and checksums:
                            for algo in ("sha256", "sha1", "md5"):
                                value = str(checksums.get(algo) or "").strip()
                                if value:
                                    checksum_text = f"{algo}:{value}"
                                    break
                            if checksum_text == "-":
                                first_key = sorted(checksums.keys())[0]
                                checksum_text = f"{first_key}:{checksums[first_key]}"
                        lines.append(f"{prefix} downloadUrl={url} checksum={checksum_text}")
                else:
                    lines.append(f"{prefix} <no assets>")
            if nexus_error:
                lines.append(f"{prefix} [-] {nexus_error}")
    elif show_nexus_presence and is_nexus is False:
        if debug:
            lines.append(f"{prefix} [*] Nexus Repository not detected")
    elif show_nexus_presence and nexus_error:
        lines.append(f"{prefix} [!] Nexus presence unknown: {nexus_error}")

    if inspect and is_registry:
        if inspection_error:
            lines.append(f"{prefix} [-] {inspection_error}")
        if inspections:
            for inspection in inspections:
                image_name = str(inspection.get("image") or image_raw or "-")
                error = str(inspection.get("error") or "").strip()
                if error:
                    lines.append(f"{prefix} [-] Inspect {image_name} err={error}")
                    continue

                layer_count = int(inspection.get("layer_count") or 0)
                total_size = _human_bytes(int(inspection.get("total_size") or 0))
                lines.append(f"{prefix} [*] Inspect {image_name} (layers:{layer_count}) (size:{total_size})")

                env_values = inspection.get("env")
                if isinstance(env_values, list):
                    lines.append(f"{prefix} [*] ENV")
                    for env_item in env_values:
                        lines.append(f"{prefix} {env_item}")

                exposed_ports = inspection.get("exposed_ports")
                if isinstance(exposed_ports, list):
                    lines.append(f"{prefix} [*] Exposed Ports")
                    for port_item in exposed_ports:
                        lines.append(f"{prefix} {port_item}")

                labels = inspection.get("labels")
                if isinstance(labels, list):
                    lines.append(f"{prefix} [*] Labels")
                    for label_item in labels:
                        lines.append(f"{prefix} {label_item}")

                cmd_items = inspection.get("cmd")
                if isinstance(cmd_items, list):
                    lines.append(f"{prefix} [*] CMD")
                    if cmd_items:
                        lines.append(f"{prefix} {' '.join(str(part) for part in cmd_items)}")
                    else:
                        lines.append(f"{prefix} <empty>")

                history = inspection.get("history")
                if isinstance(history, list):
                    lines.append(f"{prefix} [*] History")
                    for history_item in history:
                        lines.append(f"{prefix} {history_item}")

                suspicious = inspection.get("suspicious")
                if isinstance(suspicious, list) and suspicious:
                    lines.append(f"{prefix} [!] Possible Secret Indicators")
                    for suspicious_item in suspicious:
                        lines.append(f"{prefix} {suspicious_item}")

    if download and is_registry and download_result is not None:
        status = str(download_result.get("status") or "").strip()
        if status == "ok":
            path = str(download_result.get("path") or "-")
            size = _human_bytes(int(download_result.get("size") or 0))
            lines.append(f"{prefix} [+] Download complete path={path} size={size}")
        elif status == "skipped":
            err = str(download_result.get("error") or "download skipped")
            size = _human_bytes(int(download_result.get("size") or 0))
            lines.append(f"{prefix} [-] Download skipped size={size} reason={err}")
        else:
            err = str(download_result.get("error") or "download failed")
            lines.append(f"{prefix} [!] Download failed err={err}")

    return lines


def _render_colored_registry_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(
        console,
        line,
        tag="REGISTRY",
        counts=(CountColorRule("images", "red"),),
    ):
        return True
    if line.startswith("REGISTRY") and "\t" in line:
        return render_tagged_detail_line(console, line, tag="REGISTRY", default_color="orange")
    return False


def _render_plain_registry_line(console: Console, line: str, *, suspicious: bool = False) -> bool:
    color = "orange" if suspicious else "white"
    return console.render_tagged_payload_line(line, "REGISTRY", payload_color=color)


def _looks_like_registry_image_ref(line: str) -> bool:
    parts = line.split("\t", 3)
    if len(parts) < 4:
        return False
    value = parts[3].strip()
    if not value or " " in value or "/" not in value:
        return False
    if value.endswith(":<untagged>"):
        return True
    if "@sha256:" in value:
        return True
    return ":" in value


def _looks_like_registry_data_row(line: str) -> bool:
    parts = line.split("\t", 3)
    if len(parts) < 4:
        return False
    value = parts[3].strip()
    if not value or value.startswith("<"):
        return False
    if value.startswith(("downloadUrl=", "checksum=")):
        return True
    if value.startswith(("COPY ", "RUN ", "CMD ", "ENTRYPOINT ", "WORKDIR ", "EXPOSE ")):
        return True
    if value.startswith("/") and " " in value:
        return True
    if "=" in value and not value.startswith("["):
        return True
    if "(tags:" in value and "(latest:" in value:
        return True
    if "(type:" in value and "(online:" in value:
        return True
    # Plain repository names (e.g. gitlab/project-api) should also be highlighted.
    if "/" in value and " " not in value and "(" not in value and not value.startswith("["):
        return True
    # Plain tags (e.g. 1.0.0, latest, v16.11.0) are data rows too.
    if " " not in value and not value.startswith("[") and re.fullmatch(r"[A-Za-z0-9._:@+-]+", value):
        return True
    return False


# Typed runner boundary -----------------------------------------------------
host_stage = _call_audit_registry_host_with_thread_debug
