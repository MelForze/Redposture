"""Product-specific, read-only probes for management UIs paired with audit modules.

The UI is an independent security principal.  Nothing in this file treats a
successful UI login as a credential for the database or engine behind it.
"""

from __future__ import annotations

import base64
import html
import json
import os
import re
import secrets
import time
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlencode, urlsplit

from .clients.http_api import HttpResponse, infer_http_base_path
from .clients.http_session import HttpSessionPool
from .rendering import CountColorRule, RegexColorRule, render_colored_marker_line, render_tagged_detail_line

UI_PORTS: dict[str, tuple[int, ...]] = {
    "docker": (9443, 9000),
    "mongodb": (8081,),
    "elastic": (5601,),
    "redis": (5540,),
    "postgres": (80, 443),
    "kubeapi": (8443, 9090),
    "minio": (9001,),
}
UI_PRODUCTS = {
    "portainer": "Portainer",
    "mongo_express": "mongo-express",
    "kibana": "Kibana",
    "opensearch_dashboards": "OpenSearch Dashboards",
    "redis_insight": "Redis Insight",
    "pgadmin": "pgAdmin 4",
    "minio_console": "MinIO Console",
    "kubernetes_dashboard": "Kubernetes Dashboard",
    "postgrest": "PostgREST",
}
MODULE_PRODUCTS: dict[str, tuple[str, ...]] = {
    "docker": ("portainer",),
    "mongodb": ("mongo_express",),
    "elastic": ("kibana", "opensearch_dashboards"),
    "redis": ("redis_insight",),
    "postgres": ("pgadmin", "postgrest"),
    "kubeapi": ("kubernetes_dashboard",),
    "minio": ("minio_console",),
}
_ANONYMOUS_PROBES = {
    "portainer": "/api/endpoints",
    "mongo_express": "/",
    "kibana": "/api/spaces/space",
    "opensearch_dashboards": "/api/saved_objects/_find?type=dashboard&per_page=1",
    "redis_insight": "/api/databases",
    "pgadmin": "/browser/",
    "minio_console": "/api/v1/buckets",
    "kubernetes_dashboard": "/",
    "postgrest": "/",
}
_SUFFIXES = (
    "/api/system/status",
    "/api/status",
    "/api/info",
    "/api/health/",
    "/api/docs",
    "/misc/ping",
    "/login",
    "/db",
    "/api/v1/login/status",
)
_VERSION = re.compile(r"\b\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9._-]+)?\b")
_CSRF = re.compile(r"name=['\"](?:csrf_token|_csrf)['\"][^>]*value=['\"]([^'\"]+)", re.I)
_PGADMIN_CSRF = re.compile(r'"csrfToken"\s*:\s*"([^"\\]+)"')
_LOCK = ("captcha", "account locked", "too many attempts", "too many requests")
_DUMP_ITEMS = 10_000
_DUMP_BYTES = 64 * 1024 * 1024
_DUMP_SECONDS = 300.0
_DUMP_COLLECTIONS = 2_000
_DEFAULT_PAIRS: dict[str, tuple[tuple[str, str], ...]] = {
    "portainer": (("admin", "admin"), ("admin", "password"), ("admin", "12345678")),
    "mongo_express": (("admin", "pass"), ("admin", "admin"), ("admin", "password")),
    "kibana": (("elastic", "changeme"), ("elastic", "elastic"), ("kibana", "kibana")),
    "opensearch_dashboards": (("admin", "admin"), ("admin", "password")),
    "redis_insight": (("redis", "password"), ("admin", "admin")),
    "pgadmin": (("admin@example.com", "admin"), ("admin@admin.com", "admin")),
    "minio_console": (("minioadmin", "minioadmin"), ("admin", "admin")),
}


def default_pairs(product: str) -> tuple[tuple[str, str], ...]:
    """Small heuristic catalog, not a claim about factory-installed passwords."""
    return _DEFAULT_PAIRS.get(product, ())


def _header(response: HttpResponse, name: str) -> str:
    return next((str(value) for key, value in response.headers.items() if key.lower() == name.lower()), "")


def _json(response: HttpResponse) -> Any:
    if response.error or response.truncated or response.status != 200:
        return None
    try:
        return response.json()
    except (ValueError, UnicodeError):
        return None


def _get(
    pool: HttpSessionPool,
    base: str,
    path: str,
    *,
    headers: Mapping[str, str] | None = None,
    response_size_cap: int = 128 * 1024,
) -> HttpResponse:
    return pool.request(
        "GET",
        base + path,
        headers=dict(headers or {}),
        response_size_cap=response_size_cap,
        allow_cross_origin_redirects=False,
        preserve_authorization_on_cross_origin=False,
    )


def _post(
    pool: HttpSessionPool,
    base: str,
    path: str,
    body: bytes,
    headers: Mapping[str, str],
    *,
    response_size_cap: int = 128 * 1024,
) -> HttpResponse:
    return pool.request_once("POST", base + path, body=body, headers=dict(headers), response_size_cap=response_size_cap)


def _base(ctx: Any, scheme: str) -> str:
    target = getattr(ctx, "target", None)
    path = str(getattr(target, "path", "") or "")
    prefix = infer_http_base_path(path, _SUFFIXES).rstrip("/")
    host = f"[{ctx.host}]" if ":" in str(ctx.host) else str(ctx.host)
    return f"{scheme}://{host}:{ctx.port}{prefix}"


def _response_contains(response: HttpResponse, *markers: str) -> bool:
    if response.error or response.truncated or response.status != 200:
        return False
    text = response.text[:32768].lower()
    return all(marker.lower() in text for marker in markers)


def _version(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = _VERSION.search(value)
    return match.group(0) if match else None


def _fingerprints(module: str, pool: HttpSessionPool, base: str) -> tuple[str, str | None, list[str]] | None:
    """Require two product-specific signals; never confirm a generic page/status."""
    if module == "docker":
        status = _get(pool, base, "/api/system/status")
        info = _json(status)
        home = _get(pool, base, "/")
        if (
            isinstance(info, dict)
            and isinstance(info.get("Version"), str)
            and ("InstanceID" in info or "Edition" in info or "DatabaseVersion" in info)
            and _response_contains(home, "portainer")
        ):
            return "portainer", _version(info["Version"]), ["portainer_system_status", "portainer_page"]
    elif module == "mongodb":
        home = _get(pool, base, "/")
        logo = _get(pool, base, "/public/img/mongo-express-logo.png")
        if (
            _response_contains(home, "<title", "mongo express")
            and "/public/img/mongo-express-logo.png" in home.text
            and logo.status == 200
            and _header(logo, "content-type").lower().startswith("image/png")
        ):
            return "mongo_express", None, ["mongo_express_page", "mongo_express_logo"]
    elif module == "elastic":
        status = _get(pool, base, "/api/status")
        info = _json(status)
        if status.status == 401 and _header(status, "osd-name"):
            login = _get(pool, base, "/app/login")
            if _header(login, "osd-name") and _response_contains(login, "<title>opensearch dashboards</title>"):
                return "opensearch_dashboards", None, ["opensearch_auth_challenge", "opensearch_login_page"]
        if status.status == 401 and _header(status, "kbn-name"):
            login = _get(pool, base, "/login")
            if _header(login, "kbn-name") and _response_contains(login, "kibana"):
                return "kibana", None, ["kibana_auth_challenge", "kibana_login_page"]
        if (
            isinstance(info, dict)
            and isinstance(info.get("version"), dict)
            and isinstance(info["version"].get("number"), str)
        ):
            version = _version(info["version"]["number"])
            spaces = _get(pool, base, "/api/spaces/space")
            spaces_info = _json(spaces)
            if (
                _header(status, "kbn-name")
                and isinstance(spaces_info, list)
                and all(isinstance(item, dict) and isinstance(item.get("id"), str) for item in spaces_info[:3])
                and _header(spaces, "kbn-name")
            ):
                return "kibana", version, ["kibana_status", "kibana_spaces"]
            saved = _get(pool, base, "/api/saved_objects/_find?type=dashboard&per_page=1")
            saved_info = _json(saved)
            if (
                _header(status, "osd-name")
                and _header(saved, "osd-name")
                and isinstance(saved_info, dict)
                and isinstance(saved_info.get("saved_objects"), list)
            ):
                return "opensearch_dashboards", version, ["opensearch_status", "opensearch_saved_objects"]
    elif module == "redis":
        home = _get(pool, base, "/")
        info = _json(_get(pool, base, "/api/info"))
        if (
            _response_contains(home, "<title>redis insight</title>")
            and isinstance(info, dict)
            and info.get("appType") == "DOCKER"
            and info.get("buildType") == "DOCKER_ON_PREMISE"
        ):
            return "redis_insight", _version(info.get("appVersion")), ["redis_insight_page", "redis_insight_info"]
    elif module == "postgres":
        login = _get(pool, base, "/login")
        ping = _get(pool, base, "/misc/ping")
        if _response_contains(login, "pgadmin") and ping.status == 200 and ping.text.strip().upper() == "PING":
            return "pgadmin", None, ["pgadmin_login", "pgadmin_ping"]
        root = _get(pool, base, "/", headers={"Accept": "application/openapi+json"})
        spec = _json(root)
        if (
            _header(root, "server").lower().startswith("postgrest/")
            and "application/openapi+json" in _header(root, "content-type").lower()
            and isinstance(spec, dict)
            and spec.get("swagger") == "2.0"
            and isinstance(spec.get("paths"), dict)
        ):
            return "postgrest", _version(_header(root, "server")), ["postgrest_server", "postgrest_openapi"]
    elif module == "kubeapi":
        home = _get(pool, base, "/")
        if _response_contains(home, "<title>kubernetes dashboard</title>", "<kd-root"):
            return "kubernetes_dashboard", None, ["dashboard_title", "dashboard_angular_root"]
    elif module == "minio":
        home = _get(pool, base, "/")
        session = _get(pool, base, "/api/v1/session")
        session_info = None
        if session.status == 403:
            try:
                session_info = session.json()
            except (ValueError, UnicodeError):
                pass
        if (
            _response_contains(home, "<title", "minio console")
            and _header(session, "server").lower() == "minio console"
            and isinstance(session_info, dict)
            and session_info.get("message") == "invalid session"
        ):
            return "minio_console", None, ["minio_console_title", "minio_console_page"]
    return None


def _candidate(ctx: Any, module: str) -> bool:
    if module not in MODULE_PRODUCTS:
        return False
    target = getattr(ctx, "target", None)
    return (
        int(ctx.port) in UI_PORTS[module]
        or getattr(target, "scheme", None) in {"http", "https"}
        or getattr(target, "explicit_port", None) is not None
        or getattr(ctx.args, "port", None) is not None
        or bool(getattr(ctx.args, "ports", None))
    )


def detect_panel(module: str, ctx: Any) -> dict[str, Any] | None:
    if not _candidate(ctx, module):
        return None
    scheme = str(getattr(getattr(ctx, "target", None), "scheme", "") or "").lower()
    schemes = (
        (scheme,)
        if scheme in {"http", "https"}
        else (("https", "http") if int(ctx.port) in {443, 9443} else ("http", "https"))
    )
    with closing(
        HttpSessionPool(
            timeout=min(3.0, max(0.2, float(getattr(ctx.args, "timeout", 5.0) or 5.0))),
            insecure=not bool(getattr(ctx.args, "secure", False)),
            proxy=getattr(ctx.args, "_proxy_config", None),
            retries=0,
        )
    ) as pool:
        for candidate_scheme in schemes:
            base = _base(ctx, candidate_scheme)
            fingerprint = _fingerprints(module, pool, base)
            if fingerprint is None:
                continue
            product, version, signals = fingerprint
            probe_path = _ANONYMOUS_PROBES[product]
            if product == "mongo_express":
                home = _get(pool, base, "/")
                databases = _mongo_links(home.text, r'href=["\']/db/([^/"\']+)/["\']')
                if databases:
                    probe_path = f"/db/{quote(databases[0], safe='')}/"
            access = _get(pool, base, probe_path)
            auth_required = False if access.status == 200 else True if access.status in {401, 403} else None
            anonymous_read: bool | None = None
            if product == "kubernetes_dashboard":
                # A public login page proves neither anonymous API access nor login.
                auth_required = None
            if product == "postgrest":
                spec = _json(_get(pool, base, "/", headers={"Accept": "application/openapi+json"}))
                paths = spec.get("paths") if isinstance(spec, dict) else None
                table_paths = [
                    name
                    for name, methods in (paths.items() if isinstance(paths, dict) else ())
                    if isinstance(name, str)
                    and name.startswith("/")
                    and name != "/"
                    and isinstance(methods, dict)
                    and "get" in methods
                ]
                if table_paths:
                    probe_path = sorted(table_paths)[0]
                    table = _get(pool, base, probe_path + "?limit=1")
                    anonymous_read = table.status == 200 and isinstance(_json(table), list)
                    auth_required = False if anonymous_read else True if table.status in {401, 403} else None
            if product == "pgadmin" and access.status == 200:
                auth_required = urlsplit(access.final_url or "").path != urlsplit(base + "/browser/").path
            return {
                "host": str(ctx.host),
                "port": int(ctx.port),
                "module": module,
                "service": module,
                "status": "open_no_auth"
                if auth_required is False
                else "auth_required"
                if auth_required is True
                else "unknown_auth",
                "auth_required": auth_required,
                "surface": "ui",
                "ui_product": product,
                "ui": {
                    "product": product,
                    "version": version,
                    "endpoint": base,
                    "auth_required": auth_required,
                    "credential_state": "unverified",
                    "inventory": {},
                    "credential_probe_path": probe_path if product == "mongo_express" else None,
                    "anonymous_read": anonymous_read,
                },
                "version": version,
                "is_ui": True,
                "detection_status": "confirmed",
                "detection_signals": signals,
                "credential_verification_status": (
                    "available"
                    if auth_required is True
                    and product not in {"postgrest", "kubernetes_dashboard"}
                    and (
                        product != "redis_insight"
                        or (access.status == 401 and "basic" in _header(access, "www-authenticate").lower())
                    )
                    else "unavailable"
                ),
            }
    return None


def _cookie(response: HttpResponse) -> str:
    raw = _header(response, "set-cookie")
    return raw.split(";", 1)[0] if "=" in raw else ""


def _basic(username: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode("ascii")


def _blocked(response: HttpResponse) -> bool:
    return response.status == 429 or any(marker in response.text[:4096].lower() for marker in _LOCK)


def _names(items: Any, *fields: str, limit: int = 20) -> list[str]:
    if not isinstance(items, list):
        return []
    names: list[str] = []
    for item in items[:limit]:
        if isinstance(item, str):
            name = item
        elif isinstance(item, dict):
            name = next((item[key] for key in fields if isinstance(item.get(key), str)), "")
        else:
            name = ""
        if name and str(name) not in names:
            names.append(str(name)[:160])
    return names


def _list_result(items: Any, *fields: str) -> dict[str, Any]:
    if not isinstance(items, list):
        return {"status": "unavailable"}
    names = _names(items, *fields)
    return {"count": len(items), "items": names}


def _bounded_records(items: Any, *fields: str, limit: int = 100) -> dict[str, Any]:
    """Retain useful UI records while making an incomplete page explicit."""
    if not isinstance(items, list):
        return {"status": "unavailable"}
    selected = items[:limit]
    return {
        "count": len(selected),
        "items": _names(selected, *fields, limit=limit),
        "records": selected,
        "partial": len(items) > limit,
    }


def _pgadmin_nodes(response: HttpResponse, *, limit: int = 20) -> list[dict[str, Any]] | None:
    value = _json(response)
    if not isinstance(value, dict) or value.get("success") != 1:
        return None
    nodes = value.get("data") if isinstance(value.get("data"), list) else value.get("result")
    return [item for item in nodes if isinstance(item, dict)][:limit] if isinstance(nodes, list) else None


def _pgadmin_view_rows(
    pool: HttpSessionPool,
    base: str,
    headers: Mapping[str, str],
    group_id: int,
    server_id: int,
    database_id: int,
    table_id: int,
    *,
    limit: int,
    max_bytes: int = _DUMP_BYTES,
) -> dict[str, Any]:
    """Read rows through pgAdmin's read-only View All Rows cursor and close it."""
    transaction_id = secrets.randbelow(1_000_000_000) + 1
    prefix = f"/sqleditor/initialize/viewdata/{transaction_id}/3/table/{group_id}/{server_id}/{database_id}/{table_id}"
    initialized = _post(
        pool,
        base,
        prefix,
        b'{"server_cursor":true}',
        {**headers, "Content-Type": "application/json"},
    )
    init_data = _json(initialized)
    if not isinstance(init_data, dict) or init_data.get("success") != 1:
        return _response_status(initialized)
    try:
        started = _json(_get(pool, base, f"/sqleditor/view_data/start/{transaction_id}", headers=headers))
        if not isinstance(started, dict) or started.get("success") != 1:
            return {"status": "unavailable"}
        for _ in range(10):
            polled = _json(_get(pool, base, f"/sqleditor/poll/{transaction_id}", headers=headers))
            data = polled.get("data") if isinstance(polled, dict) else None
            if not isinstance(data, dict):
                return {"status": "unavailable"}
            if data.get("status") == "Busy":
                time.sleep(0.05)
                continue
            if data.get("status") != "Success" or not isinstance(data.get("result"), list):
                return {"status": "unavailable"}
            rows: list[Any] = []
            next_page = (data.get("pagination") or {}).get("next_page")
            start = len(data["result"])
            partial = len(data["result"]) > limit
            bytes_used = 0
            for row in data["result"][:limit]:
                size = len(json.dumps(row, ensure_ascii=False).encode())
                if bytes_used + size > max_bytes:
                    partial = True
                    break
                rows.append(row)
                bytes_used += size
            deadline = time.monotonic() + _DUMP_SECONDS
            while (
                next_page
                and len(rows) < limit
                and bytes_used < max_bytes
                and time.monotonic() < deadline
                and not partial
            ):
                window = _json(
                    _get(
                        pool,
                        base,
                        f"/sqleditor/fetch_window/{transaction_id}/{start + 1}/{start + min(100, limit - len(rows))}",
                        headers=headers,
                    )
                )
                page_data = window.get("data") if isinstance(window, dict) else None
                if not isinstance(page_data, dict) or not isinstance(page_data.get("result"), list):
                    partial = True
                    break
                page_rows = page_data["result"]
                if not page_rows:
                    break
                for row in page_rows[: limit - len(rows)]:
                    size = len(json.dumps(row, ensure_ascii=False).encode())
                    if bytes_used + size > max_bytes:
                        partial = True
                        break
                    rows.append(row)
                    bytes_used += size
                if partial:
                    break
                start += len(page_rows)
                next_page = (page_data.get("pagination") or {}).get("next_page")
            if next_page:
                partial = True
            return {
                "count": len(rows),
                "items": [json.dumps(row, ensure_ascii=False)[:512] for row in rows],
                "records": rows,
                "partial": partial,
                "bytes_read": bytes_used,
            }
        return {"status": "timeout"}
    finally:
        try:
            pool.request_once(
                "DELETE",
                base + f"/sqleditor/close/{transaction_id}",
                headers=dict(headers),
                response_size_cap=4096,
            )
        except Exception:  # noqa: BLE001 - cleanup must not mask the read result
            pass


def _response_status(response: HttpResponse) -> dict[str, str]:
    if response.status in {401, 403}:
        return {"status": "access_denied"}
    return {"status": "unavailable"}


def _mongo_links(source: str, pattern: str, *, limit: int = 20) -> list[str]:
    names = [html.unescape(unquote(value)) for value in re.findall(pattern, source, re.I)]
    return list(dict.fromkeys(name[:160] for name in names if name))[:limit]


def _mongo_document_paths(source: str) -> list[str]:
    paths = re.findall(r"loadDocument\(['\"]([^'\"]+)['\"]\)", source)
    return list(dict.fromkeys(html.unescape(path).split("?", 1)[0] for path in paths if path.startswith("/db/")))


def _mongo_document(source: str) -> str | None:
    match = re.search(r'<textarea[^>]*id=["\']document["\'][^>]*>(.*?)</textarea>', source, re.I | re.S)
    return html.unescape(match.group(1).strip()) if match else None


def _mongo_page_size_and_count(source: str) -> tuple[int, int] | None:
    size = re.search(r"\blimit:\s*['\"](\d+)['\"]", source)
    count = re.search(r"\btotalPages:\s*Math\.round\(['\"](\d+)['\"]\s*/", source)
    if not size or not count:
        return None
    page_size = int(size.group(1))
    return (page_size, int(count.group(1))) if 0 < page_size <= 1000 else None


def _write_ui_object(bucket: str, key: str, body: bytes) -> str | None:
    """Create a new local file for a Console download without overwriting files."""
    if "/" in bucket or "\\" in bucket:
        return None
    parts = (bucket, *key.split("/"))
    if any(part in {"", ".", ".."} or "\\" in part or "\x00" in part for part in parts):
        return None
    destination = Path.cwd().joinpath(*parts)
    try:
        current = Path.cwd()
        for part in parts[:-1]:
            current = current / part
            if current.is_symlink():
                return None
            current.mkdir(mode=0o700, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(destination, flags, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
    except OSError:
        return None
    return str(destination.relative_to(Path.cwd()))


def _redis_insight_value(
    pool: HttpSessionPool,
    base: str,
    headers: Mapping[str, str],
    entry: dict[str, Any],
    *,
    byte_budget: int,
    deadline: float,
) -> tuple[Any, str | None, int, bool]:
    """Read a configured Redis key through its typed browser route only."""
    routes: dict[str, tuple[str, dict[str, Any]]] = {
        "string": ("string/get-value", {"start": 0, "end": 4095}),
        "hash": ("hash/get-fields", {"cursor": 0, "count": 100}),
        "list": ("list/get-elements", {"offset": 0, "count": 100}),
        "set": ("set/get-members", {"cursor": 0, "count": 100}),
        "zset": ("zSet/get-members", {"offset": 0, "count": 100, "sortOrder": "ASC"}),
        "stream": ("streams/entries/get", {"count": 100, "sortOrder": "ASC"}),
        "ReJSON-RL": ("rejson-rl/get", {}),
        "json": ("rejson-rl/get", {}),
    }
    route = routes.get(str(entry.get("type")))
    if route is None:
        return None, "unsupported_type", 0, True
    suffix, options = route
    options = dict(options)
    path = f"/api/databases/{quote(str(entry['database_id']), safe='')}/{suffix}?encoding=utf8"
    pages: list[Any] = []
    seen_cursors: set[str] = set()
    bytes_used = 0
    for _ in range(_DUMP_ITEMS):
        if bytes_used >= byte_budget or time.monotonic() >= deadline:
            return pages, "budget_reached", bytes_used, True
        request_body = {"keyName": entry["key"], **options}
        answer = _post(
            pool,
            base,
            path,
            json.dumps(request_body).encode(),
            {**headers, "Content-Type": "application/json"},
            response_size_cap=min(8 * 1024 * 1024, byte_budget - bytes_used),
        )
        bytes_used += len(answer.body or b"")
        data = _json(answer)
        if data is None:
            return pages, str(_response_status(answer).get("status", "unavailable")), bytes_used, True
        pages.append(data)
        if not isinstance(data, dict):
            return pages[0] if len(pages) == 1 else pages, None, bytes_used, False
        if suffix == "rejson-rl/get" and data.get("downloaded") is False:
            return pages, "json_not_downloaded", bytes_used, True
        if suffix == "rejson-rl/get" and not isinstance(data.get("data"), list):
            return pages, "invalid_json_response", bytes_used, True
        if suffix == "string/get-value" and not isinstance(data.get("value"), str):
            return pages, "invalid_string_response", bytes_used, True
        if suffix == "hash/get-fields" and not isinstance(data.get("fields"), list):
            return pages, "invalid_hash_response", bytes_used, True
        if suffix == "set/get-members" and not isinstance(data.get("members"), list):
            return pages, "invalid_set_response", bytes_used, True
        next_cursor = data.get("nextCursor", data.get("cursor"))
        if next_cursor is not None and str(next_cursor) != "0":
            cursor = str(next_cursor)
            if cursor in seen_cursors:
                return pages, "repeated_cursor", bytes_used, True
            seen_cursors.add(cursor)
            options["cursor"] = next_cursor
            continue
        if "cursor" in options and next_cursor is None:
            return pages, "missing_cursor", bytes_used, True
        if "offset" in options:
            elements = next(
                (data.get(key) for key in ("elements", "members", "items") if isinstance(data.get(key), list)), None
            )
            total = data.get("total", data.get("totalCount"))
            if isinstance(elements, list) and type(total) is int and options["offset"] + len(elements) < total:
                if not elements:
                    return pages, "stalled_page", bytes_used, True
                options["offset"] += len(elements)
                continue
            if isinstance(elements, list) and len(elements) >= options["count"] and type(total) is not int:
                return pages, "unknown_next_page", bytes_used, True
        if suffix == "streams/entries/get":
            entries = data.get("entries")
            total = data.get("total")
            received = sum(
                len(page.get("entries", []))
                for page in pages
                if isinstance(page, dict) and isinstance(page.get("entries"), list)
            )
            if not isinstance(entries, list) or (type(total) is int and received < total and not entries):
                return pages, "stalled_page", bytes_used, True
            if type(total) is int and received < total:
                last = entries[-1] if entries else None
                last_id = last.get("id") if isinstance(last, dict) else None
                if not isinstance(last_id, str) or not last_id:
                    return pages, "missing_stream_id", bytes_used, True
                options["start"] = "(" + last_id
                continue
            if type(total) is not int and len(entries) >= options["count"]:
                return pages, "unknown_next_page", bytes_used, True
        if suffix == "string/get-value" and isinstance(data.get("value"), str):
            chunk = data["value"]
            if len(chunk.encode("utf-8")) >= options["end"] - options["start"] + 1:
                options["start"] = options["end"] + 1
                options["end"] += 4096
                continue
        return pages[0] if len(pages) == 1 else pages, None, bytes_used, False
    return pages, "page_limit_reached", bytes_used, True


def _auth_result(record: dict[str, Any], state: str, *, proof: str, cookie: str = "") -> dict[str, Any]:
    result = dict(record)
    ui = dict(result["ui"])
    ui["credential_state"] = state
    ui["credential_proof"] = proof
    if cookie:
        ui["session_cookie"] = cookie
    result["ui"] = ui
    result["credential_state"] = state
    result["provided_credentials_ok"] = True if state == "valid" else False if state == "invalid" else None
    result["status"] = (
        "valid_credentials" if state == "valid" else "invalid_credentials" if state == "invalid" else state
    )
    return result


def authenticate_panel(ctx: Any, record: dict[str, Any]) -> dict[str, Any]:
    product = str(record.get("ui_product") or "")
    base = str((record.get("ui") or {}).get("endpoint") or "")
    username = getattr(ctx.credential, "username", None)
    password = getattr(ctx.credential, "password", None)
    if username is None or password is None:
        return record
    username, password = str(username), str(password)
    with closing(
        HttpSessionPool(
            timeout=max(0.2, float(getattr(ctx.args, "timeout", 5.0) or 5.0)),
            insecure=not bool(getattr(ctx.args, "secure", False)),
            proxy=getattr(ctx.args, "_proxy_config", None),
            retries=0,
        )
    ) as pool:
        if product == "portainer":
            response = _post(
                pool,
                base,
                "/api/auth",
                json.dumps({"Username": username, "Password": password}).encode(),
                {"Content-Type": "application/json"},
            )
            if _blocked(response):
                return _auth_result(record, "rate_limited", proof="Portainer blocked login")
            if response.status in {401, 403} or (
                response.status == 422 and "invalid credentials" in response.text[:4096].lower()
            ):
                return _auth_result(record, "invalid", proof="Portainer rejected login")
            try:
                token = response.json().get("jwt") if response.status == 200 else None
            except (ValueError, AttributeError):
                token = None
            if isinstance(token, str) and token:
                who = _get(pool, base, "/api/users/me", headers={"Authorization": f"Bearer {token}"})
                info = _json(who)
                if isinstance(info, dict) and info.get("Username") == username:
                    result = _auth_result(record, "valid", proof="Portainer identity endpoint")
                    result["ui"]["session_token"] = token
                    return result
        elif product == "mongo_express":
            path = str(record.get("ui", {}).get("credential_probe_path") or "/")
            if path == "/":
                return _auth_result(record, "unsupported", proof="no protected mongo-express database route")
            response = _get(pool, base, path, headers={"Authorization": _basic(username, password)})
            if _blocked(response):
                return _auth_result(record, "rate_limited", proof="mongo-express blocked login")
            if response.status == 401 and "basic" in _header(response, "www-authenticate").lower():
                return _auth_result(record, "invalid", proof="mongo-express Basic rejected")
            if _response_contains(response, "mongo express", "/public/img/mongo-express-logo.png"):
                anonymous = _get(pool, base, path)
                if anonymous.status == 401:
                    return _auth_result(record, "valid", proof="mongo-express protected route")
        elif product in {"kibana", "opensearch_dashboards"}:
            path = "/api/security/v1/me" if product == "kibana" else "/api/v1/configuration/account"
            headers = {"Authorization": _basic(username, password)}
            if product == "kibana":
                headers.update({"kbn-xsrf": "true", "x-elastic-internal-origin": "Kibana"})
            else:
                headers["osd-xsrf"] = "true"
            response = _get(pool, base, path, headers=headers)
            if _blocked(response):
                return _auth_result(record, "rate_limited", proof="UI blocked login")
            info = _json(response)
            identity = info.get("data") if isinstance(info, dict) and isinstance(info.get("data"), dict) else info
            if isinstance(identity, dict) and (
                identity.get("username") == username or identity.get("user_name") == username
            ):
                result = _auth_result(record, "valid", proof="UI identity endpoint")
                result["ui"]["session_authorization"] = headers["Authorization"]
                status_response = _get(pool, base, "/api/status", headers=headers)
                status_data = _json(status_response)
                status_version = (
                    status_data.get("version", {}).get("number")
                    if isinstance(status_data, dict) and isinstance(status_data.get("version"), dict)
                    else None
                )
                if exact_version := _version(status_version):
                    result["ui"]["version"] = exact_version
                    result["version"] = exact_version
                return result
            if response.status == 401 and (
                "basic" in _header(response, "www-authenticate").lower()
                or "authentication exception" in response.text[:4096].lower()
            ):
                return _auth_result(record, "invalid", proof="UI Basic rejected")
        elif product == "pgadmin":
            login = _get(pool, base, "/login")
            csrf = _CSRF.search(login.text) or _PGADMIN_CSRF.search(login.text)
            cookie = _cookie(login)
            if csrf:
                fields = {
                    "email": username,
                    "password": password,
                    "csrf_token": html.unescape(csrf.group(1)),
                    "language": "en",
                    "internal_button": "Login",
                }
                response = _post(
                    pool,
                    base,
                    "/authenticate/login",
                    urlencode(fields).encode(),
                    {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
                )
                if _blocked(response):
                    return _auth_result(record, "rate_limited", proof="pgAdmin blocked login")
                session = _cookie(response) or cookie
                browser = _get(pool, base, "/browser/", headers={"Cookie": session})
                if (
                    browser.status == 200
                    and urlsplit(browser.final_url or "").path == "/browser/"
                    and ("pgadmin.browser" in browser.text[:32768] and "login_user" not in browser.text[:32768])
                ):
                    return _auth_result(record, "valid", proof="pgAdmin authenticated browser", cookie=session)
                if response.status in {401, 403} or (
                    response.status == 302 and _header(response, "location").startswith("/login")
                ):
                    return _auth_result(record, "invalid", proof="pgAdmin rejected login")
        elif product == "minio_console":
            response = _post(
                pool,
                base,
                "/api/v1/login",
                json.dumps({"accessKey": username, "secretKey": password}).encode(),
                {"Content-Type": "application/json"},
            )
            if _blocked(response):
                return _auth_result(record, "rate_limited", proof="MinIO Console blocked login")
            cookie = _cookie(response)
            if cookie:
                session_response = _get(pool, base, "/api/v1/session", headers={"Cookie": cookie})
                info = _json(session_response)
                if isinstance(info, dict) and (info.get("status") == "ok" or info.get("accessKey") == username):
                    return _auth_result(record, "valid", proof="MinIO Console session", cookie=cookie)
            if response.status in {401, 403}:
                return _auth_result(record, "invalid", proof="MinIO Console rejected login")
        elif product == "redis_insight":
            # Redis Insight has no product login. A verified proxy Basic
            # challenge is reported separately from Redis AUTH.
            response = _get(pool, base, "/api/databases", headers={"Authorization": _basic(username, password)})
            anonymous = _get(pool, base, "/api/databases")
            if anonymous.status == 401 and response.status == 200 and isinstance(_json(response), list):
                result = _auth_result(record, "valid", proof="reverse proxy Basic accepted")
                result["ui"]["auth_boundary"] = "reverse_proxy"
                return result
            if anonymous.status == 401 and response.status == 401:
                result = _auth_result(record, "invalid", proof="reverse proxy Basic rejected")
                result["ui"]["auth_boundary"] = "reverse_proxy"
                return result
    return _auth_result(record, "unverified", proof="no authenticated identity or protected resource proof")


def enumerate_panel(ctx: Any, record: dict[str, Any]) -> dict[str, Any]:
    """Bounded read-only inventory, only for requested existing CLI flags."""
    product = str(record.get("ui_product") or "")
    from .web_panel_export import export_panel, standard_export_selection

    if getattr(ctx.args, "_ui_standard_export", False):
        export_categories = standard_export_selection(ctx.args, product)
        if export_categories:
            return export_panel(ctx, record, export_categories)
    ui = dict(record.get("ui") or {})
    base = str(ui.get("endpoint") or "")
    flags = {
        name
        for name in (
            "containers",
            "images",
            "networks",
            "volumes",
            "system",
            "show_databases",
            "show_collections",
            "show_indexes",
            "cluster",
            "discover",
            "show_keys",
            "show_tables",
            "show_columns",
            "show_buckets",
            "show_objects",
            "dump",
            "download",
            "query",
            "endpoints",
            "plugins",
            "user",
            "nosql_cmd",
            "nosql_shell",
            "os_shell",
            "privesc_check",
        )
        if getattr(ctx.args, name, False)
    }
    if not flags:
        return record
    auth_headers: dict[str, str] = {}
    if ui.get("session_cookie"):
        auth_headers["Cookie"] = str(ui["session_cookie"])
    if ui.get("session_token"):
        auth_headers["Authorization"] = "Bearer " + str(ui["session_token"])
    if ui.get("session_authorization"):
        auth_headers["Authorization"] = str(ui["session_authorization"])
    results: dict[str, Any] = {}
    with closing(
        HttpSessionPool(
            timeout=max(0.2, float(getattr(ctx.args, "timeout", 5.0) or 5.0)),
            insecure=not bool(getattr(ctx.args, "secure", False)),
            proxy=getattr(ctx.args, "_proxy_config", None),
            retries=0,
        )
    ) as pool:

        def get(path: str, *, response_size_cap: int = 128 * 1024) -> HttpResponse:
            return _get(pool, base, path, headers=auth_headers, response_size_cap=response_size_cap)

        if product == "portainer":
            endpoints: list[dict[str, Any]] = []
            endpoint_ids_seen: set[int] = set()
            endpoint_partial = False
            endpoint_deadline = time.monotonic() + _DUMP_SECONDS
            endpoints_response = get("/api/endpoints?start=0&limit=100", response_size_cap=8 * 1024 * 1024)
            first_page = _json(endpoints_response)
            if not isinstance(first_page, list) and endpoints_response.status in {400, 404}:
                endpoints_response = get("/api/endpoints", response_size_cap=8 * 1024 * 1024)
                first_page = _json(endpoints_response)
            if isinstance(first_page, list):
                page_items = first_page
                while True:
                    new_ids = 0
                    for item in page_items:
                        endpoint_id = item.get("Id") if isinstance(item, dict) else None
                        if type(endpoint_id) is not int or endpoint_id in endpoint_ids_seen:
                            continue
                        endpoint_ids_seen.add(endpoint_id)
                        endpoints.append(item)
                        new_ids += 1
                        if len(endpoints) >= _DUMP_COLLECTIONS:
                            endpoint_partial = True
                            break
                    if len(endpoints) >= _DUMP_COLLECTIONS or len(page_items) < 100:
                        break
                    if not new_ids or time.monotonic() >= endpoint_deadline:
                        endpoint_partial = True
                        break
                    next_response = get(
                        "/api/endpoints?" + urlencode({"start": len(endpoints), "limit": 100}),
                        response_size_cap=8 * 1024 * 1024,
                    )
                    next_page = _json(next_response)
                    if not isinstance(next_page, list):
                        endpoint_partial = True
                        break
                    page_items = next_page
                results["environments"] = {
                    "count": len(endpoints),
                    "items": _names(endpoints, "Name", limit=_DUMP_COLLECTIONS),
                    "records": endpoints,
                    "partial": endpoint_partial,
                }
                endpoint_ids = [
                    item["Id"] for item in endpoints if isinstance(item, dict) and type(item.get("Id")) is int
                ]
                paths = {
                    "containers": "containers/json",
                    "images": "images/json",
                    "networks": "networks",
                    "volumes": "volumes",
                    "system": "info",
                }
                for flag, path in paths.items():
                    if flag not in flags:
                        continue
                    if not endpoint_ids:
                        results[flag] = {"count": 0, "items": []}
                        continue
                    found: list[str] = []
                    records: list[dict[str, Any]] = []
                    failed = False
                    bytes_used = 0
                    for endpoint_id in endpoint_ids:
                        if (
                            time.monotonic() >= endpoint_deadline
                            or len(records) >= _DUMP_ITEMS
                            or bytes_used >= _DUMP_BYTES
                        ):
                            failed = True
                            break
                        response = get(f"/api/endpoints/{endpoint_id}/docker/{path}", response_size_cap=8 * 1024 * 1024)
                        value = _json(response)
                        if flag == "volumes" and isinstance(value, dict):
                            value = value.get("Volumes")
                        if flag == "system" and isinstance(value, dict):
                            found.append(
                                f"environment:{endpoint_id} server:{str(value.get('ServerVersion') or 'unknown')[:80]}"
                            )
                            records.append({"environment": endpoint_id, "info": value})
                            bytes_used += len(response.body or b"")
                            disk_response = get(
                                f"/api/endpoints/{endpoint_id}/docker/system/df", response_size_cap=8 * 1024 * 1024
                            )
                            disk = _json(disk_response)
                            if isinstance(disk, dict):
                                records[-1]["disk_usage"] = disk
                                bytes_used += len(disk_response.body or b"")
                            else:
                                failed = True
                        elif isinstance(value, list):
                            available = max(0, _DUMP_ITEMS - len(records))
                            selected = value[:available]
                            found.extend(
                                f"environment:{endpoint_id} {name}"
                                for name in _names(selected, "Name", "Id", "ID", limit=available)
                            )
                            records.extend(
                                {"environment": endpoint_id, **item} for item in selected if isinstance(item, dict)
                            )
                            bytes_used += len(response.body or b"")
                            failed = failed or len(value) > available
                        else:
                            failed = True
                    results[flag] = (
                        {
                            "count": len(records),
                            "items": found,
                            "records": records,
                            "partial": failed or endpoint_partial or bytes_used >= _DUMP_BYTES,
                        }
                        if found or not failed
                        else {"status": "unavailable", "partial": True}
                    )
            else:
                results["environments"] = _response_status(endpoints_response)
                for flag in flags:
                    results[flag] = _response_status(endpoints_response)
        elif product == "mongo_express":
            home = get("/")
            if home.status != 200 or "mongo express" not in home.text.lower():
                for flag in flags:
                    results[flag] = _response_status(home)
            else:
                databases = _mongo_links(
                    home.text,
                    r'href=["\']/db/([^/"\']+)/["\']',
                    limit=_DUMP_COLLECTIONS + 1,
                )
                enumeration_partial = len(databases) > _DUMP_COLLECTIONS
                databases = databases[:_DUMP_COLLECTIONS]
                if "show_databases" in flags:
                    results["show_databases"] = {
                        "count": len(databases),
                        "items": databases,
                        "partial": enumeration_partial,
                    }
                collections: list[str] = []
                if flags & {"show_collections", "show_indexes", "dump", "query"}:
                    selected_database = getattr(ctx.args, "database", None)
                    selected_databases = [db for db in databases if not selected_database or db == selected_database]
                    enumeration_deadline = time.monotonic() + _DUMP_SECONDS
                    wide_walk = True
                    for database in selected_databases:
                        if wide_walk and (
                            time.monotonic() >= enumeration_deadline or len(collections) >= _DUMP_COLLECTIONS
                        ):
                            enumeration_partial = True
                            break
                        page = get(f"/db/{quote(database, safe='')}/")
                        if page.status != 200 or page.truncated:
                            enumeration_partial = True
                            continue
                        for name in _mongo_links(
                            page.text,
                            rf'href=["\']/db/{re.escape(quote(database, safe=""))}/([^/"\']+)["\']',
                            limit=_DUMP_COLLECTIONS + 1 if wide_walk else 20,
                        ):
                            if wide_walk and len(collections) >= _DUMP_COLLECTIONS:
                                enumeration_partial = True
                                break
                            candidate = f"{database}/{name}"
                            if candidate not in collections:
                                collections.append(candidate)
                    if "show_collections" in flags:
                        results["show_collections"] = {
                            "count": len(collections),
                            "items": collections,
                            "partial": enumeration_partial,
                        }
                if "show_indexes" in flags:
                    indexes: list[str] = []
                    index_partial = enumeration_partial
                    index_deadline = enumeration_deadline
                    for item in collections:
                        if len(indexes) >= _DUMP_ITEMS or time.monotonic() >= index_deadline:
                            index_partial = True
                            break
                        database, collection = item.split("/", 1)
                        page = get(f"/db/{quote(database, safe='')}/{quote(collection, safe='')}")
                        if page.status != 200 or page.truncated:
                            index_partial = True
                            continue
                        names = _mongo_links(page.text, r'dropIndex/[^?"\']+\?name=([^&"\']+)', limit=_DUMP_ITEMS + 1)
                        available = max(0, _DUMP_ITEMS - len(indexes))
                        index_partial = index_partial or len(names) > available
                        for name in names[:available]:
                            indexes.append(f"{item}/{name}")
                    results["show_indexes"] = {"count": len(indexes), "items": indexes, "partial": index_partial}
                if flags & {"dump", "query"}:
                    raw_query = getattr(ctx.args, "query", None)
                    try:
                        query_value = json.loads(raw_query) if isinstance(raw_query, str) else {}
                    except ValueError:
                        query_value = None
                    if not isinstance(query_value, dict):
                        for flag in flags & {"dump", "query"}:
                            results[flag] = {"status": "invalid_query"}
                    else:
                        selected_collections = getattr(ctx.args, "collections", None)
                        requested = [part.strip() for item in (selected_collections or []) for part in item.split(",")]
                        mongo_targets = [
                            item
                            for item in collections
                            if not requested or item in requested or item.split("/", 1)[-1] in requested
                        ][: _DUMP_COLLECTIONS if "dump" in flags else 20]
                        dump_value = getattr(ctx.args, "dump", False)
                        cap = (
                            min(_DUMP_ITEMS, dump_value if type(dump_value) is int else _DUMP_ITEMS)
                            if "dump" in flags
                            else 20
                        )
                        documents: list[dict[str, str]] = []
                        failed = False
                        bytes_used = 0
                        deadline = enumeration_deadline
                        for target in mongo_targets:
                            if len(documents) >= cap or time.monotonic() >= deadline or bytes_used >= _DUMP_BYTES:
                                failed = True
                                break
                            database, collection = target.split("/", 1)
                            path = f"/db/{quote(database, safe='')}/{quote(collection, safe='')}"
                            if raw_query:
                                path += "?" + urlencode({"query": json.dumps(query_value, separators=(",", ":"))})
                            skip = 0
                            while True:
                                page_path = (
                                    path + ("&" if "?" in path else "?") + urlencode({"skip": skip}) if skip else path
                                )
                                page = get(page_path)
                                if page.status != 200 or page.truncated:
                                    failed = True
                                    break
                                document_paths = _mongo_document_paths(page.text)
                                page_info = _mongo_page_size_and_count(page.text)
                                for document_path in document_paths:
                                    if (
                                        len(documents) >= cap
                                        or time.monotonic() >= deadline
                                        or bytes_used >= _DUMP_BYTES
                                    ):
                                        failed = True
                                        break
                                    document = get(document_path)
                                    document_text = (
                                        _mongo_document(document.text)
                                        if document.status == 200 and not document.truncated
                                        else None
                                    )
                                    if document_text is None:
                                        bytes_used += len(document.body or b"")
                                        failed = True
                                        continue
                                    encoded_size = len(document_text.encode("utf-8"))
                                    if bytes_used + encoded_size > _DUMP_BYTES:
                                        failed = True
                                        break
                                    bytes_used += encoded_size
                                    documents.append({"collection": target, "content": document_text})
                                if failed and (
                                    len(documents) >= cap or bytes_used >= _DUMP_BYTES or time.monotonic() >= deadline
                                ):
                                    break
                                if not page_info:
                                    if document_paths:
                                        failed = True
                                    break
                                page_size, total = page_info
                                skip += page_size
                                if skip >= total:
                                    break
                            if len(documents) >= cap or bytes_used >= _DUMP_BYTES or time.monotonic() >= deadline:
                                failed = True
                                break
                        value = {
                            "count": len(documents),
                            "items": [f"{entry['collection']} {entry['content'][:512]}" for entry in documents],
                            "records": documents,
                            "partial": failed or enumeration_partial or len(mongo_targets) < len(collections),
                        }
                        for flag in flags & {"dump", "query"}:
                            results[flag] = value
        elif product in {"kibana", "opensearch_dashboards"}:
            # The Dev Tools proxy executes only a fixed list of upstream GETs.
            # The UI's own backend principal is independent of supplied credentials.
            def proxy_get(path: str, *, response_size_cap: int = 128 * 1024) -> HttpResponse:
                headers = {**auth_headers, "Content-Type": "application/json"}
                headers["kbn-xsrf" if product == "kibana" else "osd-xsrf"] = "redposture"
                return _post(
                    pool,
                    base,
                    "/api/console/proxy?" + urlencode({"path": path, "method": "GET"}),
                    b"",
                    headers,
                    response_size_cap=response_size_cap,
                )

            routes = {
                "cluster": "/_cluster/health",
                "endpoints": "/_cat/nodes?format=json",
                "plugins": "/_cat/plugins?format=json",
                "user": "/_security/user" if product == "kibana" else "/_plugins/_security/api/internalusers",
            }
            for flag, path in routes.items():
                if flag not in flags:
                    continue
                response = proxy_get(path)
                value = _json(response)
                if isinstance(value, dict) and (
                    "error" in value or (type(value.get("status")) is int and value["status"] >= 400)
                ):
                    results[flag] = {
                        "status": "unavailable",
                        "reason": str(value.get("error") or value.get("status"))[:256],
                    }
                elif isinstance(value, list):
                    results[flag] = _bounded_records(value, "name", "id", "ip", limit=100)
                elif isinstance(value, dict):
                    results[flag] = {
                        "count": len(value) if flag == "user" else 1,
                        "items": list(value)[:100] if flag == "user" else [json.dumps(value, ensure_ascii=False)[:512]],
                        "records": value,
                        "partial": len(value) > 100,
                    }
                else:
                    results[flag] = _response_status(response)
            if "discover" in flags:
                response = proxy_get(
                    "/_cat/indices?format=json&h=index,health,docs.count", response_size_cap=8 * 1024 * 1024
                )
                value = _json(response)
                if isinstance(value, list):
                    indices = [
                        row["index"]
                        for row in value
                        if isinstance(row, dict)
                        and isinstance(row.get("index"), str)
                        and not row["index"].startswith(".")
                    ]
                    hits: list[dict[str, Any]] = []
                    failed = len(indices) > _DUMP_COLLECTIONS
                    bytes_used = len(response.body or b"")
                    deadline = time.monotonic() + _DUMP_SECONDS
                    for index in indices[:_DUMP_COLLECTIONS]:
                        offset = 0
                        seen_pages: set[str] = set()
                        while True:
                            if len(hits) >= _DUMP_ITEMS or bytes_used >= _DUMP_BYTES or time.monotonic() >= deadline:
                                failed = True
                                break
                            page_size = min(100, _DUMP_ITEMS - len(hits))
                            search = proxy_get(
                                f"/{quote(index, safe='')}/_search?"
                                + urlencode(
                                    {"size": page_size, "from": offset, "track_total_hits": "true", "sort": "_doc"}
                                ),
                                response_size_cap=min(8 * 1024 * 1024, _DUMP_BYTES - bytes_used),
                            )
                            bytes_used += len(search.body or b"")
                            page = _json(search)
                            hit_data = page.get("hits") if isinstance(page, dict) else None
                            rows = hit_data.get("hits") if isinstance(hit_data, dict) else None
                            if (
                                not isinstance(hit_data, dict)
                                or not isinstance(rows, list)
                                or any(not isinstance(row, dict) for row in rows)
                            ):
                                failed = True
                                break
                            signature = json.dumps([rows[0], rows[-1]], sort_keys=True) if rows else ""
                            if signature and signature in seen_pages:
                                failed = True
                                break
                            if signature:
                                seen_pages.add(signature)
                            hits.extend({"index": index, "hit": row} for row in rows)
                            offset += len(rows)
                            total_data = hit_data.get("total")
                            total_hits = total_data.get("value") if isinstance(total_data, dict) else total_data
                            total_exact = not isinstance(total_data, dict) or total_data.get("relation", "eq") == "eq"
                            if type(total_hits) is int and offset >= total_hits and total_exact:
                                break
                            if len(rows) < page_size:
                                if type(total_hits) is int and offset < total_hits:
                                    failed = True
                                if not total_exact:
                                    failed = True
                                break
                            if offset >= _DUMP_ITEMS or offset >= 10_000:
                                failed = True
                                break
                        if failed and (
                            len(hits) >= _DUMP_ITEMS or bytes_used >= _DUMP_BYTES or time.monotonic() >= deadline
                        ):
                            break
                    results["discover"] = {
                        "count": len(hits),
                        "items": [f"{row['index']} {json.dumps(row['hit'], ensure_ascii=False)[:512]}" for row in hits],
                        "records": hits,
                        "partial": failed,
                    }
                else:
                    results["discover"] = _response_status(response)
        elif product == "redis_insight":
            if flags & {"show_keys", "dump"}:
                response = get("/api/databases", response_size_cap=8 * 1024 * 1024)
                value = _json(response)
                configured_databases = (
                    value if isinstance(value, list) else value.get("data") if isinstance(value, dict) else None
                )
                if isinstance(configured_databases, list):
                    results["connections"] = _bounded_records(configured_databases, "name", limit=_DUMP_COLLECTIONS)
                    keys: list[str] = []
                    seen_keys: set[str] = set()
                    key_records: list[dict[str, Any]] = []
                    failed = len(configured_databases) > _DUMP_COLLECTIONS
                    deadline = time.monotonic() + _DUMP_SECONDS
                    key_request = getattr(ctx.args, "show_keys", False)
                    cap = min(_DUMP_ITEMS, key_request if type(key_request) is int else _DUMP_ITEMS)
                    for database_index, database in enumerate(configured_databases[:_DUMP_COLLECTIONS]):
                        if len(keys) >= cap:
                            failed = True
                            break
                        if time.monotonic() >= deadline:
                            failed = True
                            break
                        if not isinstance(database, dict) or not isinstance(database.get("id"), str):
                            failed = True
                            continue
                        # This Redis Insight POST is a read-only cursor query
                        # (KeysController_getKeys), not a create/update action.
                        path = f"/api/databases/{quote(database['id'], safe='')}/keys?encoding=utf8"
                        cursor = "0"
                        seen_cursors: set[str] = set()
                        while True:
                            if cursor in seen_cursors or len(keys) >= cap or time.monotonic() >= deadline:
                                failed = failed or cursor in seen_cursors or time.monotonic() >= deadline
                                break
                            seen_cursors.add(cursor)
                            page_failed = False
                            key_response = _post(
                                pool,
                                base,
                                path,
                                json.dumps(
                                    {"cursor": cursor, "count": min(100, cap - len(keys)), "keysInfo": "dump" in flags}
                                ).encode(),
                                {**auth_headers, "Content-Type": "application/json"},
                                response_size_cap=8 * 1024 * 1024,
                            )
                            key_data = _json(key_response)
                            pages = [key_data] if isinstance(key_data, dict) else key_data
                            if not isinstance(pages, list) or not pages:
                                failed = True
                                break
                            next_cursor = "0"
                            for page in pages:
                                if not isinstance(page, dict) or not isinstance(page.get("keys"), list):
                                    failed = True
                                    page_failed = True
                                    break
                                for item_index, item in enumerate(page["keys"]):
                                    if len(keys) >= cap:
                                        failed = failed or item_index < len(page["keys"])
                                        break
                                    if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                                        continue
                                    name = item["name"]
                                    label = f"{str(database.get('name') or database['id'])[:80]}/{name}"
                                    if label not in seen_keys:
                                        seen_keys.add(label)
                                        keys.append(label)
                                        key_records.append(
                                            {"database_id": database["id"], "key": name, "type": item.get("type")}
                                        )
                                next_cursor = str(page.get("cursor", page.get("nextCursor", "0")))
                                if len(keys) >= cap and (
                                    next_cursor != "0" or database_index + 1 < len(configured_databases)
                                ):
                                    failed = True
                            if page_failed or next_cursor == "0":
                                break
                            cursor = next_cursor
                    if "show_keys" in flags:
                        results["show_keys"] = (
                            {"count": len(keys), "items": keys, "partial": failed}
                            if keys or not failed
                            else {"status": "unavailable"}
                        )
                    if "dump" in flags:
                        requested_dump = getattr(ctx.args, "dump", False)
                        dump_cap = min(_DUMP_ITEMS, requested_dump if type(requested_dump) is int else _DUMP_ITEMS)
                        redis_dumps: list[dict[str, Any]] = []
                        value_bytes = 0
                        value_partial = failed
                        for entry in key_records[:dump_cap]:
                            if value_bytes >= _DUMP_BYTES or time.monotonic() >= deadline:
                                value_partial = True
                                break
                            data, error, used, partial = _redis_insight_value(
                                pool,
                                base,
                                auth_headers,
                                entry,
                                byte_budget=_DUMP_BYTES - value_bytes,
                                deadline=deadline,
                            )
                            value_bytes += used
                            value_partial = value_partial or partial
                            redis_dumps.append(
                                {**entry, "value": data, "partial": partial}
                                if data is not None
                                else {**entry, "status": error or "unavailable", "partial": True}
                            )
                        results["dump"] = {
                            "count": len(redis_dumps),
                            "items": [
                                f"{entry['key']} = {json.dumps(entry['value'], ensure_ascii=False)[:512]}"
                                if "value" in entry
                                else f"{entry['key']} ({entry.get('status', 'unavailable')})"
                                for entry in redis_dumps
                            ],
                            "records": redis_dumps,
                            "partial": value_partial
                            or len(key_records) > dump_cap
                            or len(redis_dumps) < min(len(key_records), dump_cap),
                        }
                else:
                    for flag in flags & {"show_keys", "dump"}:
                        results[flag] = _response_status(response)
        elif product == "pgadmin":
            if flags & {"show_databases", "show_tables", "show_columns", "dump", "privesc_check"}:
                utils = get("/browser/js/utils.js")
                header = re.search(r"csrf_token_header'\] = '([^']+)'", utils.text)
                token = re.search(r"csrf_token'\] = '([^']+)'", utils.text)
                if header and token:
                    auth_headers[header.group(1)] = token.group(1)
                    auth_headers["X-Requested-With"] = "XMLHttpRequest"
                response = get("/browser/nodes/")
                groups = _pgadmin_nodes(response, limit=_DUMP_COLLECTIONS if flags & {"dump", "privesc_check"} else 20)
                if groups is not None:
                    servers: list[dict[str, Any]] = []
                    dump_deadline = time.monotonic() + _DUMP_SECONDS
                    for group in groups[: _DUMP_COLLECTIONS if flags & {"dump", "privesc_check"} else 5]:
                        if time.monotonic() >= dump_deadline:
                            break
                        if group.get("_type") != "server_group":
                            continue
                        group_id = group.get("_id")
                        if not str(group_id).isdigit():
                            continue
                        child_response = get(f"/browser/server/nodes/{group_id}/")
                        children = _pgadmin_nodes(
                            child_response, limit=_DUMP_COLLECTIONS if flags & {"dump", "privesc_check"} else 20
                        )
                        if children is not None:
                            servers.extend(
                                {**item, "_group_id": group_id} for item in children if item.get("_type") == "server"
                            )
                    results["servers"] = _list_result(servers, "label", "name")
                    pg_databases: list[str] = []
                    pg_tables: list[str] = []
                    pg_columns: list[str] = []
                    pg_dump_rows: list[dict[str, Any]] = []
                    pg_dump_bytes = 0
                    pg_role_records: list[dict[str, Any]] = []
                    pg_role_partial = False
                    pg_grant_records: list[dict[str, Any]] = []
                    pg_grant_partial = False
                    pg_grant_bytes = 0
                    inaccessible = False
                    dump_partial = False
                    dump_limit = min(
                        _DUMP_ITEMS, ctx.args.dump if type(getattr(ctx.args, "dump", False)) is int else _DUMP_ITEMS
                    )
                    table_filters = {
                        part.strip()
                        for value in (getattr(ctx.args, "tables", None) or [])
                        for part in value.split(",")
                        if part.strip()
                    }
                    connected_databases = 0

                    def read_grants(kind: str, label: str, path: str) -> None:
                        nonlocal pg_grant_partial, pg_grant_bytes
                        if (
                            len(pg_grant_records) >= _DUMP_COLLECTIONS
                            or pg_grant_bytes >= _DUMP_BYTES
                            or time.monotonic() >= dump_deadline
                        ):
                            pg_grant_partial = True
                            return
                        answer = get(path, response_size_cap=min(8 * 1024 * 1024, _DUMP_BYTES - pg_grant_bytes))
                        pg_grant_bytes += len(answer.body or b"")
                        value = _json(answer)
                        value = (
                            value.get("data")
                            if isinstance(value, dict) and isinstance(value.get("data"), dict)
                            else value
                        )
                        if answer.status != 200 or answer.truncated or not isinstance(value, dict):
                            pg_grant_partial = True
                            return
                        fields = {
                            key: field
                            for key, field in value.items()
                            if "acl" in key.lower() or "privilege" in key.lower()
                        }
                        if not fields:
                            # pgAdmin omits ACL keys for objects without explicit grants.
                            return
                        pg_grant_records.append({"object_type": kind, "object": label, "acl_fields": fields})

                    def read_acl_children(kind: str, label: str, path: str) -> None:
                        nonlocal pg_grant_partial
                        if time.monotonic() >= dump_deadline or len(pg_grant_records) >= _DUMP_COLLECTIONS:
                            pg_grant_partial = True
                            return
                        response = get(f"/browser/{kind}/nodes/{path}/")
                        children = _pgadmin_nodes(response, limit=_DUMP_COLLECTIONS + 1)
                        if children is None:
                            pg_grant_partial = True
                            return
                        if len(children) > _DUMP_COLLECTIONS:
                            pg_grant_partial = True
                        for child in children[:_DUMP_COLLECTIONS]:
                            child_id = child.get("_id")
                            if child.get("_type") != kind or not str(child_id).isdigit():
                                continue
                            if time.monotonic() >= dump_deadline or len(pg_grant_records) >= _DUMP_COLLECTIONS:
                                pg_grant_partial = True
                                break
                            child_label = f"{label}/{str(child.get('label') or child_id)[:80]}"
                            read_grants(kind, child_label, f"/browser/{kind}/obj/{path}/{child_id}")

                    wide_pg_walk = bool(flags & {"dump", "privesc_check"})
                    for server in servers[: _DUMP_COLLECTIONS if wide_pg_walk else 5]:
                        if time.monotonic() >= dump_deadline or len(pg_tables) >= _DUMP_COLLECTIONS:
                            dump_partial = True
                            break
                        server_id = server.get("_id")
                        group_id = server.get("_group_id")
                        if not str(server_id).isdigit() or not str(group_id).isdigit():
                            continue
                        server_password = getattr(ctx.args, "pgadmin_server_password", None)
                        if server_password and not server.get("connected"):
                            connect = _post(
                                pool,
                                base,
                                f"/browser/server/connect/{group_id}/{server_id}",
                                json.dumps({"password": str(server_password), "save_password": False}).encode(),
                                {**auth_headers, "Content-Type": "application/json"},
                            )
                            if refreshed_cookie := _cookie(connect):
                                auth_headers["Cookie"] = refreshed_cookie
                            connection = _json(connect)
                            identity = connection.get("data", {}).get("user") if isinstance(connection, dict) else None
                            if isinstance(identity, dict):
                                results.setdefault("backend_identities", {"count": 0, "items": [], "records": []})
                                identities = results["backend_identities"]
                                identities["count"] += 1
                                identities["items"].append(
                                    f"{server.get('label') or server_id}: {identity.get('name') or 'unknown'}"
                                )
                                identities["records"].append({"server": server.get("label"), "identity": identity})
                                if "privesc_check" in flags:
                                    results["privesc_check"] = {
                                        "count": 1,
                                        "items": [
                                            f"{identity.get('name') or 'unknown'} superuser:{identity.get('is_superuser')} "
                                            f"create_role:{identity.get('can_create_role')} create_db:{identity.get('can_create_db')}"
                                        ],
                                        "records": [identity],
                                    }
                        if "privesc_check" in flags:
                            role_response = get(
                                f"/browser/role/obj/{group_id}/{server_id}/",
                                response_size_cap=8 * 1024 * 1024,
                            )
                            role_payload = _json(role_response)
                            role_data = role_payload.get("data") if isinstance(role_payload, dict) else role_payload
                            if isinstance(role_data, list):
                                for role in role_data:
                                    if len(pg_role_records) >= _DUMP_COLLECTIONS or time.monotonic() >= dump_deadline:
                                        pg_role_partial = True
                                        break
                                    if not isinstance(role, dict):
                                        continue
                                    pg_role_records.append(
                                        {
                                            "server": server.get("label") or server_id,
                                            **{key: value for key, value in role.items() if key != "rolpassword"},
                                        }
                                    )
                                pg_role_partial = pg_role_partial or len(role_data) > _DUMP_COLLECTIONS
                            else:
                                pg_role_partial = True
                        db_response = get(f"/browser/database/nodes/{group_id}/{server_id}/")
                        db_nodes = _pgadmin_nodes(db_response, limit=_DUMP_COLLECTIONS if wide_pg_walk else 20)
                        if db_nodes is None:
                            inaccessible = True
                            continue
                        for db_node in db_nodes[: _DUMP_COLLECTIONS if wide_pg_walk else 5]:
                            if time.monotonic() >= dump_deadline or len(pg_tables) >= _DUMP_COLLECTIONS:
                                dump_partial = True
                                break
                            if db_node.get("_type") != "database" or not str(db_node.get("_id")).isdigit():
                                continue
                            database_id = db_node["_id"]
                            requested_database = getattr(ctx.args, "database", None)
                            if requested_database and db_node.get("label") != requested_database:
                                continue
                            database_label = f"{str(server.get('label') or server_id)[:80]}/{str(db_node.get('label') or database_id)[:80]}"
                            pg_databases.append(database_label)
                            if not db_node.get("connected"):
                                inaccessible = True
                                continue
                            connected_databases += 1
                            if "privesc_check" in flags:
                                read_grants(
                                    "database",
                                    database_label,
                                    f"/browser/database/obj/{group_id}/{server_id}/{database_id}",
                                )
                            if not flags & {"show_tables", "show_columns", "dump", "privesc_check"}:
                                continue
                            schema_response = get(f"/browser/schema/nodes/{group_id}/{server_id}/{database_id}/")
                            schemas = _pgadmin_nodes(schema_response, limit=_DUMP_COLLECTIONS if wide_pg_walk else 20)
                            if schemas is None:
                                inaccessible = True
                                continue
                            for schema in schemas[: _DUMP_COLLECTIONS if wide_pg_walk else 5]:
                                if time.monotonic() >= dump_deadline or len(pg_tables) >= _DUMP_COLLECTIONS:
                                    dump_partial = True
                                    break
                                if schema.get("_type") != "schema" or not str(schema.get("_id")).isdigit():
                                    continue
                                schema_id = schema["_id"]
                                if "privesc_check" in flags:
                                    read_grants(
                                        "schema",
                                        f"{database_label}/{str(schema.get('label') or schema_id)[:80]}",
                                        f"/browser/schema/obj/{group_id}/{server_id}/{database_id}/{schema_id}",
                                    )
                                    schema_path = f"{group_id}/{server_id}/{database_id}/{schema_id}"
                                    schema_label = f"{database_label}/{str(schema.get('label') or schema_id)[:80]}"
                                    read_acl_children("sequence", schema_label, schema_path)
                                    read_acl_children("function", schema_label, schema_path)
                                table_response = get(
                                    f"/browser/table/nodes/{group_id}/{server_id}/{database_id}/{schema_id}/"
                                )
                                tables = _pgadmin_nodes(table_response, limit=_DUMP_COLLECTIONS if wide_pg_walk else 20)
                                if tables is None:
                                    inaccessible = True
                                    continue
                                for table in tables[: _DUMP_COLLECTIONS if wide_pg_walk else 5]:
                                    if time.monotonic() >= dump_deadline or len(pg_tables) >= _DUMP_COLLECTIONS:
                                        dump_partial = True
                                        break
                                    if table.get("_type") != "table" or not str(table.get("_id")).isdigit():
                                        continue
                                    table_id = table["_id"]
                                    table_label = f"{database_label}/{str(schema.get('label') or schema_id)[:80]}/{str(table.get('label') or table_id)[:80]}"
                                    pg_tables.append(table_label)
                                    if "privesc_check" in flags:
                                        read_grants(
                                            "table",
                                            table_label,
                                            f"/browser/table/obj/{group_id}/{server_id}/{database_id}/{schema_id}/{table_id}",
                                        )
                                        read_acl_children(
                                            "column",
                                            table_label,
                                            f"{group_id}/{server_id}/{database_id}/{schema_id}/{table_id}",
                                        )
                                    table_name = str(table.get("label") or "")
                                    schema_name = str(schema.get("label") or "")
                                    matches_dump_filter = (
                                        not table_filters
                                        or table_name in table_filters
                                        or f"{schema_name}.{table_name}" in table_filters
                                    )
                                    if (
                                        "dump" in flags
                                        and len(pg_dump_rows) < dump_limit
                                        and pg_dump_bytes < _DUMP_BYTES
                                        and matches_dump_filter
                                    ):
                                        viewed = _pgadmin_view_rows(
                                            pool,
                                            base,
                                            auth_headers,
                                            int(str(group_id)),
                                            int(str(server_id)),
                                            int(database_id),
                                            int(table_id),
                                            limit=dump_limit - len(pg_dump_rows),
                                            max_bytes=_DUMP_BYTES - pg_dump_bytes,
                                        )
                                        if isinstance(viewed.get("records"), list):
                                            pg_dump_bytes += int(viewed.get("bytes_read") or 0)
                                            pg_dump_rows.extend(
                                                {"table": table_label, "row": row} for row in viewed["records"]
                                            )
                                            dump_partial = dump_partial or bool(viewed.get("partial"))
                                        else:
                                            dump_partial = True
                                    elif "dump" in flags and matches_dump_filter:
                                        dump_partial = True
                                    if "show_columns" in flags:
                                        column_response = get(
                                            f"/browser/column/nodes/{group_id}/{server_id}/{database_id}/{schema_id}/{table_id}/"
                                        )
                                        columns = _pgadmin_nodes(column_response)
                                        if columns is None:
                                            inaccessible = True
                                        else:
                                            pg_columns.extend(
                                                f"{table_label}/{str(item.get('label') or item.get('_id') or '')[:80]}"
                                                for item in columns[:20]
                                                if item.get("_type") == "column"
                                            )
                    if "show_databases" in flags:
                        results["show_databases"] = (
                            {"count": len(pg_databases), "items": pg_databases[:20]}
                            if pg_databases or not inaccessible
                            else {"status": "backend_not_connected"}
                        )
                    if "privesc_check" in flags:
                        existing = results.get("privesc_check", {})
                        identities = existing.get("records", []) if isinstance(existing, dict) else []
                        identity_items = existing.get("items", []) if isinstance(existing, dict) else []
                        results["privesc_check"] = {
                            "count": len(identities) + len(pg_role_records) + len(pg_grant_records),
                            "items": identity_items
                            + [
                                f"{role.get('server')}/{role.get('rolname')} superuser:{role.get('rolsuper')} "
                                f"create_role:{role.get('rolcreaterole')} create_db:{role.get('rolcreatedb')}"
                                for role in pg_role_records
                            ]
                            + [
                                f"{grant['object_type']} {grant['object']} "
                                f"{json.dumps(grant['acl_fields'], ensure_ascii=False)[:512]}"
                                for grant in pg_grant_records
                            ],
                            "records": identities + pg_role_records + pg_grant_records,
                            "backend_identities": identities,
                            "partial": pg_role_partial or pg_grant_partial or inaccessible or dump_partial,
                        }
                    if "show_tables" in flags:
                        results["show_tables"] = (
                            {"count": len(pg_tables), "items": pg_tables[:20]}
                            if pg_tables or connected_databases or not inaccessible
                            else {"status": "backend_not_connected"}
                        )
                    if "show_columns" in flags:
                        results["show_columns"] = (
                            {"count": len(pg_columns), "items": pg_columns[:20]}
                            if pg_columns or connected_databases or not inaccessible
                            else {"status": "backend_not_connected"}
                        )
                    if "dump" in flags:
                        results["dump"] = (
                            {
                                "count": len(pg_dump_rows),
                                "items": [
                                    f"{entry['table']} {json.dumps(entry['row'], ensure_ascii=False)[:512]}"
                                    for entry in pg_dump_rows
                                ],
                                "records": pg_dump_rows,
                                "partial": dump_partial or inaccessible,
                            }
                            if pg_dump_rows or connected_databases or not inaccessible
                            else {"status": "backend_not_connected"}
                        )
                else:
                    results["servers"] = _response_status(response)
                    for flag in flags & {"show_databases", "show_tables", "show_columns", "dump", "privesc_check"}:
                        results[flag] = _response_status(response)
        elif product == "minio_console":
            if flags & {"show_buckets", "show_objects", "dump", "download", "discover"}:
                object_ref = getattr(ctx.args, "object", None)
                response = get(
                    "/api/v1/buckets", response_size_cap=8 * 1024 * 1024 if flags & {"dump", "download"} else 128 * 1024
                )
                value = _json(response)
                buckets = value.get("buckets") if isinstance(value, dict) else None
                synthetic_buckets = not isinstance(buckets, list)
                if not isinstance(buckets, list) and isinstance(object_ref, str) and "/" in object_ref:
                    # A caller may have GetObject permission without ListBuckets.
                    buckets = [{"name": object_ref.split("/", 1)[0]}]
                if isinstance(buckets, list):
                    if "show_buckets" in flags:
                        results["show_buckets"] = (
                            _response_status(response)
                            if synthetic_buckets
                            else _bounded_records(buckets, "name", "Name")
                        )
                    if flags & {"show_objects", "dump", "download", "discover"}:
                        objects: list[str] = []
                        seen_objects: set[str] = set()
                        failed = False
                        selected_bucket = getattr(ctx.args, "bucket", None)
                        if object_ref and "/" in str(object_ref):
                            selected_bucket = str(object_ref).split("/", 1)[0]
                        selected = [
                            bucket
                            for bucket in buckets
                            if not selected_bucket
                            or (
                                isinstance(bucket, dict)
                                and (bucket.get("name") == selected_bucket or bucket.get("Name") == selected_bucket)
                            )
                        ]
                        if selected_bucket and not selected and object_ref:
                            selected = [{"name": selected_bucket}]
                        walk_limit = _DUMP_COLLECTIONS
                        deadline = time.monotonic() + _DUMP_SECONDS
                        for bucket in selected[:walk_limit]:
                            if time.monotonic() >= deadline or len(objects) >= _DUMP_ITEMS:
                                failed = True
                                break
                            if object_ref and not flags & {"show_objects", "discover"}:
                                break
                            if not isinstance(bucket, dict):
                                continue
                            bucket_name = bucket.get("name") or bucket.get("Name")
                            if not isinstance(bucket_name, str) or not bucket_name:
                                continue
                            pending_prefixes = [""]
                            seen_prefixes: set[str] = set()
                            while pending_prefixes:
                                if (
                                    len(seen_prefixes) >= _DUMP_COLLECTIONS
                                    or len(objects) >= _DUMP_ITEMS
                                    or time.monotonic() >= deadline
                                ):
                                    failed = True
                                    break
                                prefix = pending_prefixes.pop(0)
                                if prefix in seen_prefixes:
                                    failed = True
                                    continue
                                seen_prefixes.add(prefix)
                                marker = ""
                                seen_markers: set[str] = set()
                                while True:
                                    page_limit = _DUMP_ITEMS + 1
                                    query: dict[str, int | str] = {"limit": page_limit}
                                    if prefix:
                                        query["prefix"] = prefix
                                    if marker:
                                        query["marker"] = marker
                                    object_response = get(
                                        f"/api/v1/buckets/{quote(bucket_name, safe='')}/objects?" + urlencode(query),
                                        response_size_cap=8 * 1024 * 1024,
                                    )
                                    object_data = _json(object_response)
                                    object_list = object_data.get("objects") if isinstance(object_data, dict) else None
                                    if (
                                        object_response.status == 200
                                        and isinstance(object_data, dict)
                                        and "objects" in object_data
                                        and object_list is None
                                    ):
                                        object_list = []
                                    if not isinstance(object_list, list):
                                        failed = True
                                        break
                                    page_names: list[str] = []
                                    for item in object_list:
                                        if not isinstance(item, dict):
                                            failed = True
                                            continue
                                        object_name = item.get("name") or item.get("Name")
                                        if not isinstance(object_name, str) or not object_name:
                                            failed = True
                                            continue
                                        page_names.append(object_name)
                                        if object_name.endswith("/") and not item.get("etag") and "size" not in item:
                                            if (
                                                object_name != prefix
                                                and object_name not in seen_prefixes
                                                and object_name not in pending_prefixes
                                            ):
                                                pending_prefixes.append(object_name)
                                            continue
                                        full_name = f"{bucket_name}/{object_name}"
                                        if full_name not in seen_objects and len(objects) < _DUMP_ITEMS:
                                            seen_objects.add(full_name)
                                            objects.append(full_name)
                                    next_marker = object_data.get("nextMarker") or object_data.get("next_marker")
                                    truncated = bool(object_data.get("isTruncated") or object_data.get("is_truncated"))
                                    if not truncated and not next_marker:
                                        if len(object_list) >= page_limit:
                                            failed = True
                                        break
                                    if not next_marker and page_names:
                                        next_marker = page_names[-1]
                                    if (
                                        not isinstance(next_marker, str)
                                        or not next_marker
                                        or next_marker in seen_markers
                                        or time.monotonic() >= deadline
                                        or len(objects) >= _DUMP_ITEMS
                                    ):
                                        failed = True
                                        break
                                    seen_markers.add(next_marker)
                                    marker = next_marker
                        if "show_objects" in flags:
                            results["show_objects"] = (
                                {
                                    "count": len(objects),
                                    "items": objects,
                                    "partial": failed or len(selected) > walk_limit,
                                }
                                if objects or not failed
                                else {"status": "unavailable"}
                            )
                        if flags & {"dump", "download", "discover"}:
                            explicit_object = str(object_ref) if object_ref else None
                            if explicit_object and "/" not in explicit_object:
                                object_targets: list[str] = []
                            elif explicit_object:
                                object_targets = [explicit_object]
                            elif selected_bucket or flags & {"discover", "dump", "download"}:
                                object_targets = objects if flags & {"dump", "download"} else objects[:100]
                            else:
                                object_targets = []
                            if (
                                not object_targets
                                and not (selected_bucket or flags & {"discover", "dump", "download"})
                                and flags
                                & {
                                    "dump",
                                    "download",
                                }
                            ):
                                for flag in flags & {"dump", "download"}:
                                    results[flag] = {"status": "object_or_bucket_required"}
                            object_dumps: list[dict[str, Any]] = []
                            downloads: list[dict[str, Any]] = []
                            findings: list[dict[str, Any]] = []
                            from .modules.minio.discover import is_candidate_key
                            from .secret_detection import mask_secret, scan_value

                            bytes_used = 0
                            budget = (
                                _DUMP_BYTES
                                if flags & {"dump", "download"}
                                else min(
                                    50 * 1024 * 1024,
                                    int(getattr(ctx.args, "discover_max_bytes", 50 * 1024 * 1024) or 0),
                                )
                            )
                            partial = failed or ("discover" in flags and len(object_targets) >= 100)
                            for target in object_targets:
                                if time.monotonic() >= deadline or bytes_used >= budget:
                                    partial = True
                                    break
                                bucket_name, key = target.split("/", 1)
                                if (
                                    "discover" in flags
                                    and not flags & {"dump", "download"}
                                    and not is_candidate_key(key)
                                ):
                                    continue
                                if "discover" in flags and bytes_used >= budget:
                                    partial = True
                                    break
                                path = f"/api/v1/buckets/{quote(bucket_name, safe='')}/objects/download?" + urlencode(
                                    {"prefix": key}
                                )
                                object_response = get(
                                    path,
                                    response_size_cap=(
                                        min(_DUMP_BYTES, budget - bytes_used)
                                        if flags & {"dump", "download"}
                                        else 128 * 1024
                                    ),
                                )
                                if object_response.status != 200 or object_response.error or object_response.truncated:
                                    bytes_used += len(object_response.body or b"")
                                    partial = True
                                    continue
                                object_body = object_response.body or b""
                                if bytes_used + len(object_body) > budget:
                                    partial = True
                                    break
                                bytes_used += len(object_body)
                                if "dump" in flags:
                                    try:
                                        content = object_body.decode("utf-8")
                                        if "\x00" in content:
                                            raise UnicodeDecodeError("utf-8", object_body, 0, 1, "binary NUL")
                                    except UnicodeDecodeError:
                                        object_dumps.append(
                                            {"object": target, "base64": base64.b64encode(object_body).decode()}
                                        )
                                    else:
                                        object_dumps.append({"object": target, "content": content})
                                if "download" in flags:
                                    destination = _write_ui_object(bucket_name, key, object_body)
                                    if destination:
                                        downloads.append(
                                            {"object": target, "path": destination, "size": len(object_body)}
                                        )
                                    else:
                                        partial = True
                                if "discover" in flags:
                                    for match in scan_value(
                                        object_body.decode("utf-8", errors="replace"), object_path="$", enabled=None
                                    ):
                                        findings.append(
                                            {
                                                "object": target,
                                                "type": match.detector,
                                                "masked_value": mask_secret(match.value),
                                                "object_path": match.object_path,
                                            }
                                        )
                            if "dump" in flags and "dump" not in results:
                                results["dump"] = {
                                    "count": len(object_dumps),
                                    "items": [
                                        f"{entry['object']} {str(entry.get('content') or entry.get('base64'))[:512]}"
                                        for entry in object_dumps
                                    ],
                                    "records": object_dumps,
                                    "partial": partial,
                                }
                            if "download" in flags and "download" not in results:
                                results["download"] = {
                                    "count": len(downloads),
                                    "items": [entry["path"] for entry in downloads],
                                    "records": downloads,
                                    "partial": partial,
                                }
                            if "discover" in flags:
                                results["discover"] = {
                                    "count": len(findings),
                                    "items": [
                                        f"{entry['object']} {entry['type']} {entry['masked_value']}"
                                        for entry in findings
                                    ],
                                    "records": findings,
                                    "bytes_read": bytes_used,
                                    "partial": partial or bytes_used > budget,
                                }
                else:
                    for flag in flags & {"show_buckets", "show_objects", "dump", "download", "discover"}:
                        results[flag] = _response_status(response)
        for flag in flags:
            results.setdefault(flag, {"status": "unsupported_by_ui"})
    ui["inventory"] = results
    payload = dict(record)
    payload["ui"] = ui
    return payload


def _render_grouped_panel_inventory(prefix: str, product: str, inventory: dict[str, Any]) -> tuple[list[str], set[str]]:
    """Keep UI object values beside their listed resource without changing JSON."""
    hierarchy = {
        "minio_console": ("show_buckets", "show_objects"),
        "mongo_express": ("show_databases", "show_collections"),
        "pgadmin": ("show_databases", "show_tables"),
        "redis_insight": (None, "show_keys"),
    }.get(product)
    if hierarchy is None:
        return [], set()
    parent_key, child_key = hierarchy
    child = inventory.get(child_key)
    parent = inventory.get(parent_key) if parent_key else None
    dump = inventory.get("dump")
    if (
        not isinstance(child, dict)
        or not isinstance(child.get("count"), int)
        or not isinstance(child.get("items"), list)
    ):
        return [], set()
    if not isinstance(parent, dict) and not (
        isinstance(dump, dict) and isinstance(dump.get("count"), int) and isinstance(dump.get("records"), list)
    ):
        return [], set()

    consumed = {child_key}
    if (
        parent_key is not None
        and isinstance(parent, dict)
        and isinstance(parent.get("count"), int)
        and isinstance(parent.get("items"), list)
    ):
        consumed.add(parent_key)
    else:
        parent = None
    if isinstance(dump, dict) and isinstance(dump.get("count"), int) and isinstance(dump.get("records"), list):
        consumed.add("dump")
    else:
        dump = None
    lines: list[str] = []

    def clean(value: Any) -> str:
        return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", str(value)).replace("\r", "\\r").replace("\n", "\\n")

    for key in (parent_key, child_key, "dump"):
        if key is None or key not in consumed:
            continue
        section = inventory[key]
        lines.append(f"{prefix} [*] {key.replace('_', ' ').title()} Enumeration (count:{section.get('count', 0)})")

    child_items = [str(item) for item in child["items"][:200]]
    emitted_children: set[int] = set()
    dump_rows = dump.get("records", []) if dump is not None else []
    emitted_dumps: set[int] = set()
    dumps_by_child: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    redis_targets: dict[str, str | None] = {}
    for dump_index, entry in enumerate(dump_rows):
        if not isinstance(entry, dict):
            continue
        if product == "minio_console":
            target = str(entry.get("object") or "")
        elif product == "mongo_express":
            target = str(entry.get("collection") or "")
        elif product == "pgadmin":
            target = str(entry.get("table") or "")
        else:
            key = str(entry.get("key") or "")
            if key not in redis_targets:
                matches = [item for item in child_items if item == key or item.endswith("/" + key)]
                redis_targets[key] = matches[0] if len(matches) == 1 else None
            target = redis_targets[key] or ""
        if target:
            dumps_by_child.setdefault(target, []).append((dump_index, entry))

    def append_dump(entry: dict[str, Any]) -> None:
        if product == "minio_console":
            content = (
                f"base64:{entry['base64']}"
                if "base64" in entry
                else json.dumps(entry.get("content", ""), ensure_ascii=False)
            )
            shown = f"{entry.get('object', '')} {content}"
        elif product == "mongo_express":
            shown = f"{entry.get('collection', '')} {json.dumps(entry.get('content', ''), ensure_ascii=False)}"
        elif product == "pgadmin":
            shown = f"{entry.get('table', '')} {json.dumps(entry.get('row'), ensure_ascii=False)}"
        else:
            shown = (
                f"{entry.get('key', '')} = {json.dumps(entry['value'], ensure_ascii=False)}"
                if "value" in entry
                else f"{entry.get('key', '')} ({entry.get('status', 'unavailable')})"
            )
        lines.append(f"{prefix} [+] {clean(shown)}")

    def append_child(index: int, item: str) -> None:
        emitted_children.add(index)
        lines.append(f"{prefix} {clean(item)[:512]}")
        for dump_index, entry in dumps_by_child.get(item, []):
            if dump_index not in emitted_dumps:
                append_dump(entry)
                emitted_dumps.add(dump_index)

    if parent is not None:
        for parent_item in parent["items"][:200]:
            name = str(parent_item)
            lines.append(f"{prefix} {clean(name)[:512]}")
            for index, item in enumerate(child_items):
                if index not in emitted_children and item.startswith(name + "/"):
                    append_child(index, item)
    for index, item in enumerate(child_items):
        if index not in emitted_children:
            append_child(index, item)
    for index, entry in enumerate(dump_rows):
        if index not in emitted_dumps and isinstance(entry, dict):
            append_dump(entry)
    for key in (parent_key, child_key, "dump"):
        if key is None or key not in consumed:
            continue
        section = inventory[key]
        if section.get("partial"):
            reason = clean(section.get("reason") or "")
            suffix = f" (reason:{reason[:256]})" if reason else ""
            lines.append(f"{prefix} [*] {key.replace('_', ' ')} coverage:partial{suffix}")
    return lines, consumed


def render_panel(record: dict[str, Any], label: str) -> list[str]:
    ui = record.get("ui") or {}
    product = str(record.get("ui_product") or "")
    name = UI_PRODUCTS.get(product, product)
    auth = ui.get("auth_required")
    auth_text = "True" if auth is True else "False" if auth is False else "unknown"
    version = ui.get("version") or "unknown"
    prefix = f"{label}\t{record.get('host') or '?'}\t{int(record.get('port') or 0)}\t"
    lines = [f"{prefix} [*] {name} (auth required:{auth_text}) (version:{version})"]
    if product == "postgrest" and ui.get("anonymous_read") is True:
        lines.append(f"{prefix} [+] Anonymous READ available through PostgREST")
    attempts = record.get("attempted_credentials")
    if not isinstance(attempts, list):
        attempts = [record]
    shown: set[tuple[str, str]] = set()
    blocked = False
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        user = attempt.get("username", attempt.get("provided_username"))
        password = attempt.get("password", attempt.get("provided_password"))
        state = str(attempt.get("credential_state") or attempt.get("status") or "")
        if state in {"rate_limited", "account_locked", "captcha"}:
            blocked = True
            continue
        if (
            user is None
            or password is None
            or state
            not in {
                "valid",
                "invalid",
                "valid_credentials",
                "invalid_credentials",
            }
        ):
            continue
        key = str(user), str(password)
        if key in shown:
            continue
        shown.add(key)
        marker = "[+]" if state in {"valid", "valid_credentials"} else "[-]"
        lines.append(f"{prefix} {marker} {user}:{password} (UI)")
    if blocked:
        lines.append(f"{prefix} [!] Credential attempts stopped: panel rate limit or lockout")
    inventory = ui.get("inventory") or {}
    grouped_lines, grouped_keys = _render_grouped_panel_inventory(prefix, product, inventory)
    lines.extend(grouped_lines)
    for key, value in inventory.items():
        if key in grouped_keys:
            continue
        if isinstance(value, dict) and isinstance(value.get("count"), int):
            lines.append(f"{prefix} [*] {key.replace('_', ' ').title()} Enumeration (count:{value['count']})")
            items = value.get("items", [])
            if key == "dump" and isinstance(value.get("records"), list):
                records = value["records"]
                if product == "minio_console":
                    items = [
                        f"{entry['object']} "
                        + (
                            f"base64:{entry['base64']}"
                            if "base64" in entry
                            else json.dumps(entry.get("content", ""), ensure_ascii=False)
                        )
                        for entry in records
                        if isinstance(entry, dict) and "object" in entry
                    ]
                elif product == "mongo_express":
                    items = [
                        f"{entry['collection']} {json.dumps(entry.get('content', ''), ensure_ascii=False)}"
                        for entry in records
                        if isinstance(entry, dict) and "collection" in entry
                    ]
                elif product == "pgadmin":
                    items = [
                        f"{entry['table']} {json.dumps(entry.get('row'), ensure_ascii=False)}"
                        for entry in records
                        if isinstance(entry, dict) and "table" in entry
                    ]
            for item in items if key == "dump" else items[:200]:
                clean = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", str(item)).replace("\r", "\\r").replace("\n", "\\n")
                if key in {"dump", "discover"}:
                    lines.append(f"{prefix} [+] {clean if key == 'dump' else clean[:1024]}")
                else:
                    lines.append(f"{prefix} {clean[:512]}")
            if value.get("partial"):
                reason = str(value.get("reason") or "")
                reason = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", reason).replace("\r", " ").replace("\n", " ")
                suffix = f" (reason:{reason[:256]})" if reason else ""
                lines.append(f"{prefix} [*] {key.replace('_', ' ')} coverage:partial{suffix}")
        elif isinstance(value, dict):
            status = str(value.get("status") or "unavailable")
            reason = str(value.get("reason") or "") if key == "export" else ""
            reason = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", reason).replace("\r", " ").replace("\n", " ")
            suffix = f" (reason:{reason[:256]})" if reason else ""
            lines.append(f"{prefix} [-] {key.replace('_', ' ')} {status}{suffix}")
    return lines


def colorize_panel_line(console: Any, line: str, label: str) -> bool:
    """Airflow-style emphasis for UI lines; backend renderers keep their rules."""
    payload = line.split("\t", 3)[-1]
    if payload.startswith(" ") and not payload.lstrip().startswith("["):
        return render_tagged_detail_line(console, line, tag=label, default_color="orange")
    if not (
        any(f"[*] {name} " in payload for name in UI_PRODUCTS.values())
        or " Enumeration (count:" in payload
        or payload.rstrip().endswith(" (UI)")
        or payload.startswith(" [+] ")
        or payload.startswith(" [-] export ")
        or "coverage:partial" in payload
    ):
        return False

    def credential_spans(marker: str, right: str) -> list[tuple[int, int, str]]:
        match = re.match(r"\S+:\S+", right)
        if marker != "[+]":
            return []
        if right.endswith(" (UI)") and match:
            return [(match.start(), match.end(), "red")]
        if right.startswith("Anonymous READ"):
            return [(0, len(right), "red")]
        return [(0, len(right), "true_red")]

    return render_colored_marker_line(
        console,
        line,
        tag=label,
        regexes=(
            RegexColorRule(r"\(version:[^)]+\)", "orange"),
            RegexColorRule(r"coverage:partial", "orange"),
            RegexColorRule(r"\(reason:[^)]+\)", "orange"),
        ),
        counts=(CountColorRule("count", "red", unknown_color="orange", zero_color="bright_green"),),
        extra_spans=credential_spans,
    )
