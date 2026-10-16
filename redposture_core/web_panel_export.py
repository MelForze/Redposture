"""Explicit full, resumable read-only exports through confirmed web panels."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import sqlite3
import time
from collections.abc import Iterator
from contextlib import closing
from typing import Any
from urllib.parse import quote, urlencode

from . import web_panels as wp
from .clients.http_api import HttpResponse
from .clients.http_session import HttpSessionPool
from .ui_export import UIExport

_PAGE = 100
_RESPONSE_BYTES = 8 * 1024 * 1024
_MINIO_LIST_LIMIT = 65_536


class _Incomplete(Exception):
    """A UI page cannot be continued or proved complete."""


def standard_export_selection(args: Any, product: str) -> set[str]:
    """Map unbounded standard inventory flags to their UI collections."""
    if product == "minio_console" and getattr(args, "dump", False) is True and getattr(args, "object", None):
        return set()
    if (
        product == "mongo_express"
        and getattr(args, "dump", False) is True
        and any(getattr(args, name, None) for name in ("document", "query", "projection"))
    ):
        return set()
    if product == "pgadmin" and getattr(args, "dump", False) is True and getattr(args, "columns", None):
        return set()
    selected: set[str] = set()
    if product == "portainer":
        selected.update(
            name
            for name in ("containers", "images", "networks", "volumes", "system")
            if getattr(args, name, False) is True
        )
    elif product == "mongo_express":
        if getattr(args, "show_databases", False) is True:
            selected.add("databases")
        if getattr(args, "show_collections", False) is True:
            selected.add("collections")
        if getattr(args, "dump", False) is True and not any(
            getattr(args, name, None) for name in ("document", "query", "projection")
        ):
            selected.add("documents")
    elif product == "redis_insight":
        if getattr(args, "show_keys", False) is True:
            selected.add("keys")
        if getattr(args, "dump", False) is True:
            selected.add("values")
    elif product == "minio_console":
        if getattr(args, "show_buckets", False) is True:
            selected.add("buckets")
        if getattr(args, "show_objects", False) is True:
            selected.add("objects")
        if getattr(args, "dump", False) is True and not getattr(args, "object", None):
            selected.add("content")
    elif product in {"kibana", "opensearch_dashboards"}:
        if getattr(args, "discover", False) is True:
            selected.add("documents")
    elif product == "pgadmin":
        if getattr(args, "show_databases", False) is True:
            selected.add("databases")
        if getattr(args, "show_tables", False) is True:
            selected.add("tables")
        if getattr(args, "show_columns", False) is True:
            selected.add("columns")
        if getattr(args, "dump", False) is True and not getattr(args, "columns", None):
            selected.add("rows")
    return selected


def _json_page(response: HttpResponse, source: str) -> Any:
    if response.error or response.truncated or response.status != 200:
        detail = response.error or ("truncated" if response.truncated else "unavailable")
        raise _Incomplete(f"{source}: HTTP {response.status}; {detail}")
    value = wp._json(response)
    if value is None:
        raise _Incomplete(f"{source}: invalid JSON")
    return value


def _get(pool: HttpSessionPool, base: str, path: str, headers: dict[str, str]) -> HttpResponse:
    return wp._get(pool, base, path, headers=headers, response_size_cap=_RESPONSE_BYTES)


def _post(pool: HttpSessionPool, base: str, path: str, body: dict[str, Any], headers: dict[str, str]) -> HttpResponse:
    return wp._post(
        pool,
        base,
        path,
        json.dumps(body, ensure_ascii=False).encode(),
        {**headers, "Content-Type": "application/json"},
        response_size_cap=_RESPONSE_BYTES,
    )


def _portainer(
    pool: HttpSessionPool, base: str, headers: dict[str, str], selected: set[str] | None = None
) -> Iterator[tuple[str, str, Any]]:
    start = 0
    seen_pages: set[tuple[int, ...]] = set()
    while True:
        response = _get(pool, base, f"/api/endpoints?start={start}&limit={_PAGE}", headers)
        if start == 0 and response.status in {400, 404}:
            response = _get(pool, base, "/api/endpoints", headers)
        endpoints = _json_page(response, "Portainer environments")
        if not isinstance(endpoints, list):
            raise _Incomplete("Portainer environments: invalid list")
        if any(not isinstance(item, dict) or type(item.get("Id")) is not int for item in endpoints):
            raise _Incomplete("Portainer environments: invalid environment entry")
        ids = tuple(item["Id"] for item in endpoints if isinstance(item, dict) and type(item.get("Id")) is int)
        if ids in seen_pages:
            raise _Incomplete("Portainer environments: repeated page")
        seen_pages.add(ids)
        for endpoint in endpoints:
            assert isinstance(endpoint, dict)
            endpoint_id = endpoint["Id"]
            yield f"environment:{endpoint_id}", "environments", endpoint
            for category, route in (
                ("containers", "containers/json"),
                ("images", "images/json"),
                ("networks", "networks"),
                ("volumes", "volumes"),
                ("system", "info"),
            ):
                if selected is not None and category not in selected:
                    continue
                data = _json_page(
                    _get(pool, base, f"/api/endpoints/{endpoint_id}/docker/{route}", headers),
                    f"Portainer {category} in environment {endpoint_id}",
                )
                if category == "system":
                    if not isinstance(data, dict):
                        raise _Incomplete(f"Portainer {category}: invalid object")
                    yield f"{endpoint_id}:system", category, {"environment": endpoint_id, "info": data}
                    disk = _json_page(
                        _get(pool, base, f"/api/endpoints/{endpoint_id}/docker/system/df", headers),
                        f"Portainer disk usage in environment {endpoint_id}",
                    )
                    yield f"{endpoint_id}:disk", "disk_usage", {"environment": endpoint_id, "usage": disk}
                    continue
                values = data.get("Volumes") if category == "volumes" and isinstance(data, dict) else data
                if not isinstance(values, list):
                    raise _Incomplete(f"Portainer {category}: invalid list")
                for index, value in enumerate(values):
                    if not isinstance(value, dict):
                        raise _Incomplete(f"Portainer {category}: invalid entry in environment {endpoint_id}")
                    identity = value.get("Id") or value.get("ID") or value.get("Name") or index
                    yield f"{endpoint_id}:{category}:{identity}", category, {"environment": endpoint_id, **value}
        if len(endpoints) < _PAGE:
            return
        start += len(endpoints)


def _mongo(
    pool: HttpSessionPool, base: str, headers: dict[str, str], args: Any, selected: set[str] | None = None
) -> Iterator[tuple[str, str, Any]]:
    home = _get(pool, base, "/", headers)
    if home.status != 200 or home.truncated or "mongo express" not in home.text.lower():
        raise _Incomplete("mongo-express home unavailable")
    databases = wp._mongo_links(home.text, r'href=["\']/db/([^/"\']+)/["\']', limit=1_000_000)
    selected_database = getattr(args, "database", None)
    selected_collections = {
        part.strip()
        for value in (getattr(args, "collections", None) or [])
        for part in value.split(",")
        if part.strip()
    }
    for database in databases:
        if selected_database and database != selected_database:
            continue
        yield f"database:{database}", "databases", {"name": database}
        if selected is not None and not selected & {"collections", "documents"}:
            continue
        page = _get(pool, base, f"/db/{quote(database, safe='')}/", headers)
        if page.status != 200 or page.truncated:
            raise _Incomplete(f"mongo-express database {database}: page unavailable")
        names = wp._mongo_links(
            page.text,
            rf'href=["\']/db/{re.escape(quote(database, safe=""))}/([^/"\']+)["\']',
            limit=1_000_000,
        )
        for name in names:
            if (
                selected_collections
                and name not in selected_collections
                and f"{database}/{name}" not in selected_collections
            ):
                continue
            identity = f"{database}/{name}"
            yield f"collection:{identity}", "collections", {"database": database, "name": name}
            if selected is not None and "documents" not in selected:
                continue
            path = f"/db/{quote(database, safe='')}/{quote(name, safe='')}"
            skip = 0
            seen_pages: set[tuple[str, ...]] = set()
            while True:
                response = _get(pool, base, path + ("?" + urlencode({"skip": skip}) if skip else ""), headers)
                if response.status != 200 or response.truncated:
                    raise _Incomplete(f"mongo-express {identity}: page unavailable at skip {skip}")
                paths = wp._mongo_document_paths(response.text)
                signature = tuple(paths)
                if signature in seen_pages:
                    raise _Incomplete(f"mongo-express {identity}: repeated document page")
                seen_pages.add(signature)
                for document_path in paths:
                    document = _get(pool, base, document_path, headers)
                    content = (
                        wp._mongo_document(document.text) if document.status == 200 and not document.truncated else None
                    )
                    if content is None:
                        raise _Incomplete(f"mongo-express {identity}: document unavailable")
                    yield f"document:{document_path}", "documents", {"collection": identity, "content": content}
                page_info = wp._mongo_page_size_and_count(response.text)
                if page_info is None:
                    if paths:
                        raise _Incomplete(f"mongo-express {identity}: pagination unavailable")
                    break
                page_size, total = page_info
                skip += page_size
                if skip >= total:
                    break


def _redis(
    pool: HttpSessionPool,
    base: str,
    headers: dict[str, str],
    writer: UIExport,
    selected: set[str] | None = None,
) -> Iterator[tuple[str, str, Any]]:
    value = _json_page(_get(pool, base, "/api/databases", headers), "Redis Insight databases")
    databases = value if isinstance(value, list) else value.get("data") if isinstance(value, dict) else None
    if not isinstance(databases, list):
        raise _Incomplete("Redis Insight databases: invalid list")
    for database in databases:
        if not isinstance(database, dict) or not isinstance(database.get("id"), str):
            raise _Incomplete("Redis Insight databases: invalid database")
        database_id = database["id"]
        yield f"database:{database_id}", "connections", database
        cursor = "0"
        seen_cursors: set[str] = set()
        while True:
            if cursor in seen_cursors:
                raise _Incomplete(f"Redis Insight {database_id}: repeated key cursor")
            seen_cursors.add(cursor)
            path = f"/api/databases/{quote(database_id, safe='')}/keys?encoding=utf8"
            response = _post(pool, base, path, {"cursor": cursor, "count": _PAGE, "keysInfo": True}, headers)
            value = _json_page(response, f"Redis Insight {database_id} keys")
            pages = [value] if isinstance(value, dict) else value
            if not isinstance(pages, list) or not pages:
                raise _Incomplete(f"Redis Insight {database_id}: invalid key page")
            next_cursor = "0"
            for page in pages:
                if not isinstance(page, dict) or not isinstance(page.get("keys"), list):
                    raise _Incomplete(f"Redis Insight {database_id}: invalid key page")
                for key in page["keys"]:
                    if not isinstance(key, dict) or not isinstance(key.get("name"), str):
                        raise _Incomplete(f"Redis Insight {database_id}: invalid key entry")
                    name = key["name"]
                    identity = f"{database_id}:{name}"
                    if writer.has(f"key:{identity}"):
                        continue
                    entry = {"database_id": database_id, "key": name, "type": key.get("type")}
                    if selected is not None and "values" not in selected:
                        yield f"key:{identity}", "keys", entry
                        continue
                    data, error, _used, partial = wp._redis_insight_value(
                        pool, base, headers, entry, byte_budget=64 * 1024 * 1024, deadline=float("inf")
                    )
                    if partial or data is None:
                        raise _Incomplete(f"Redis Insight {identity}: {error or 'value unavailable'}")
                    yield f"key:{identity}", "keys", {**entry, "value": data}
                next_cursor = str(page.get("cursor", page.get("nextCursor", "0")))
            if next_cursor == "0":
                break
            cursor = next_cursor


def _minio(
    pool: HttpSessionPool,
    base: str,
    headers: dict[str, str],
    writer: UIExport,
    args: Any,
    selected: set[str] | None = None,
) -> Iterator[tuple[str, str, Any]]:
    value = _json_page(_get(pool, base, "/api/v1/buckets", headers), "MinIO Console buckets")
    buckets = value.get("buckets") if isinstance(value, dict) else None
    if not isinstance(buckets, list):
        raise _Incomplete("MinIO Console bucket listing unavailable")
    selected_bucket = getattr(args, "bucket", None)
    for bucket in buckets:
        name = bucket.get("name") or bucket.get("Name") if isinstance(bucket, dict) else None
        if not isinstance(name, str) or (selected_bucket and name != selected_bucket):
            continue
        yield f"bucket:{name}", "buckets", bucket
        if selected is not None and not selected & {"objects", "content"}:
            continue
        # The Console ListObjects API exposes limit/prefix/recursive but no
        # cursor on the 2025 release. Grow a bounded request until the list
        # is shorter than requested. Already written objects are skipped on
        # each larger response. The 8 MiB response cap prevents unbounded
        # memory; reaching either cap is an explicit partial result.
        limit = _PAGE
        marker = ""
        seen_markers: set[str] = set()
        while True:
            query: dict[str, Any] = {"limit": limit, "recursive": "true"}
            if marker:
                query["marker"] = marker
            value = _json_page(
                _get(pool, base, f"/api/v1/buckets/{quote(name, safe='')}/objects?" + urlencode(query), headers),
                f"MinIO Console {name} object list",
            )
            objects = value.get("objects") if isinstance(value, dict) else None
            if not isinstance(objects, list):
                raise _Incomplete(f"MinIO Console {name}: invalid object list")
            for item in objects:
                if not isinstance(item, dict):
                    raise _Incomplete(f"MinIO Console {name}: invalid object entry")
                key = item.get("name") or item.get("Name")
                if not isinstance(key, str) or not key:
                    raise _Incomplete(f"MinIO Console {name}: object without a name")
                if key.endswith("/") and "size" not in item:
                    continue
                identity = f"{name}/{key}"
                if writer.has(f"object:{identity}"):
                    continue
                if selected is not None and "content" not in selected:
                    yield f"object:{identity}", "objects", {"object": identity, **item}
                    continue
                response = _get(
                    pool,
                    base,
                    f"/api/v1/buckets/{quote(name, safe='')}/objects/download?" + urlencode({"prefix": key}),
                    headers,
                )
                if response.status != 200 or response.truncated or response.error:
                    raise _Incomplete(f"MinIO Console {identity}: object unavailable")
                body = response.body or b""
                try:
                    content = body.decode("utf-8")
                    if "\x00" in content:
                        raise UnicodeDecodeError("utf-8", body, 0, 1, "binary NUL")
                except UnicodeDecodeError:
                    data = {"object": identity, "base64": base64.b64encode(body).decode()}
                else:
                    data = {"object": identity, "content": content}
                yield f"object:{identity}", "objects", data
            next_marker = value.get("nextMarker") or value.get("next_marker")
            if next_marker:
                if not isinstance(next_marker, str) or next_marker in seen_markers:
                    raise _Incomplete(f"MinIO Console {name}: repeated continuation marker")
                seen_markers.add(next_marker)
                marker = next_marker
                continue
            if len(objects) < limit:
                break
            if limit >= _MINIO_LIST_LIMIT:
                raise _Incomplete(f"MinIO Console {name}: no cursor and list limit {_MINIO_LIST_LIMIT} reached")
            limit = min(limit * 2, _MINIO_LIST_LIMIT)


def _elastic(
    pool: HttpSessionPool,
    base: str,
    headers: dict[str, str],
    product: str,
    selected: set[str] | None = None,
) -> Iterator[tuple[str, str, Any]]:
    proxy_headers = {**headers, "kbn-xsrf" if product == "kibana" else "osd-xsrf": "redposture"}

    def upstream(path: str) -> Any:
        response = wp._post(
            pool,
            base,
            "/api/console/proxy?" + urlencode({"path": path, "method": "GET"}),
            b"",
            proxy_headers,
            response_size_cap=_RESPONSE_BYTES,
        )
        value = _json_page(response, f"{product} Dev Tools {path.split('?', 1)[0]}")
        if isinstance(value, dict) and (
            "error" in value or type(value.get("status")) is int and value["status"] >= 400
        ):
            raise _Incomplete(f"{product} Dev Tools: {str(value.get('error') or value.get('status'))[:256]}")
        return value

    indices = upstream("/_cat/indices?format=json&h=index,health,docs.count")
    if not isinstance(indices, list):
        raise _Incomplete(f"{product} indices: invalid list")
    for index_info in indices:
        if not isinstance(index_info, dict) or not isinstance(index_info.get("index"), str):
            raise _Incomplete(f"{product} indices: invalid index entry")
        index = index_info["index"]
        if index.startswith("."):
            continue
        yield f"index:{index}", "indices", index_info
        if selected is not None and "documents" not in selected:
            continue
        # Scroll is the backend's stable, read-only page cursor. Its context
        # expires automatically; each subsequent GET renews the keepalive.
        path = f"/{quote(index, safe='')}/_search?" + urlencode({"size": _PAGE, "scroll": "1m", "sort": "_doc"})
        seen_pages: set[tuple[str, str]] = set()
        while True:
            page = upstream(path)
            rows = page.get("hits", {}).get("hits") if isinstance(page, dict) else None
            scroll_id = page.get("_scroll_id") if isinstance(page, dict) else None
            if not isinstance(rows, list) or not isinstance(scroll_id, str) or not scroll_id:
                raise _Incomplete(f"{product} {index}: scroll response has no continuation proof")
            if not rows:
                break
            signature = (str(rows[0].get("_id")), str(rows[-1].get("_id")))
            if signature in seen_pages:
                raise _Incomplete(f"{product} {index}: repeated scroll page")
            seen_pages.add(signature)
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get("_id"), str):
                    raise _Incomplete(f"{product} {index}: invalid hit")
                yield f"document:{index}:{row['_id']}", "documents", {"index": index, "hit": row}
            path = "/_search/scroll?" + urlencode({"scroll": "1m", "scroll_id": scroll_id})


def _pgadmin_rows(
    pool: HttpSessionPool,
    base: str,
    headers: dict[str, str],
    group_id: int,
    server_id: int,
    database_id: int,
    table_id: int,
) -> Iterator[Any]:
    transaction_id = secrets.randbelow(1_000_000_000) + 1
    prefix = f"/sqleditor/initialize/viewdata/{transaction_id}/3/table/{group_id}/{server_id}/{database_id}/{table_id}"
    response = _post(pool, base, prefix, {"server_cursor": True}, headers)
    value = _json_page(response, "pgAdmin viewdata initialize")
    if not isinstance(value, dict) or value.get("success") != 1:
        raise _Incomplete("pgAdmin viewdata initialize rejected")
    try:
        started = _json_page(
            _get(pool, base, f"/sqleditor/view_data/start/{transaction_id}", headers), "pgAdmin viewdata start"
        )
        if not isinstance(started, dict) or started.get("success") != 1:
            raise _Incomplete("pgAdmin viewdata start rejected")
        polled: Any = None
        for _ in range(30):
            polled = _json_page(_get(pool, base, f"/sqleditor/poll/{transaction_id}", headers), "pgAdmin viewdata poll")
            data = polled.get("data") if isinstance(polled, dict) else None
            if isinstance(data, dict) and data.get("status") == "Busy":
                time.sleep(0.05)
                continue
            break
        data = polled.get("data") if isinstance(polled, dict) else None
        if not isinstance(data, dict) or data.get("status") != "Success" or not isinstance(data.get("result"), list):
            raise _Incomplete("pgAdmin viewdata did not complete")
        rows = data["result"]
        count = 0
        for row in rows:
            yield row
            count += 1
        next_page = (data.get("pagination") or {}).get("next_page")
        while next_page:
            window = _json_page(
                _get(pool, base, f"/sqleditor/fetch_window/{transaction_id}/{count + 1}/{count + _PAGE}", headers),
                "pgAdmin viewdata window",
            )
            page = window.get("data") if isinstance(window, dict) else None
            if not isinstance(page, dict) or not isinstance(page.get("result"), list):
                raise _Incomplete("pgAdmin viewdata window invalid")
            rows = page["result"]
            if not rows:
                raise _Incomplete("pgAdmin viewdata window empty before final page")
            for row in rows:
                yield row
                count += 1
            next_page = (page.get("pagination") or {}).get("next_page")
    finally:
        try:
            pool.request_once(
                "DELETE",
                base + f"/sqleditor/close/{transaction_id}",
                headers=headers,
                response_size_cap=4096,
            )
        except Exception:  # noqa: BLE001 - cleanup cannot mask the read result
            pass


def _pgadmin(
    pool: HttpSessionPool,
    base: str,
    headers: dict[str, str],
    args: Any,
    selected: set[str] | None = None,
) -> Iterator[tuple[str, str, Any]]:
    utils = _get(pool, base, "/browser/js/utils.js", headers)
    header = re.search(r"csrf_token_header'\] = '([^']+)'", utils.text)
    token = re.search(r"csrf_token'\] = '([^']+)'", utils.text)
    if header and token:
        headers[header.group(1)] = token.group(1)
        headers["X-Requested-With"] = "XMLHttpRequest"

    def nodes(path: str) -> list[dict[str, Any]]:
        response = _get(pool, base, path, headers)
        parsed = wp._pgadmin_nodes(response, limit=1_000_000)
        if parsed is None or response.truncated:
            raise _Incomplete(f"pgAdmin nodes unavailable: {path}")
        return parsed

    filters = {
        part.strip() for value in (getattr(args, "tables", None) or []) for part in value.split(",") if part.strip()
    }
    for group in nodes("/browser/nodes/"):
        if group.get("_type") != "server_group" or not str(group.get("_id")).isdigit():
            continue
        group_id = int(group["_id"])
        for server in nodes(f"/browser/server/nodes/{group_id}/"):
            if server.get("_type") != "server" or not str(server.get("_id")).isdigit():
                continue
            server_id = int(server["_id"])
            server_name = str(server.get("label") or server_id)
            yield f"server:{group_id}:{server_id}", "servers", server
            if selected is not None and not selected & {"databases", "tables", "columns", "rows"}:
                continue
            password = getattr(args, "pgadmin_server_password", None)
            if password and not server.get("connected"):
                response = _post(
                    pool,
                    base,
                    f"/browser/server/connect/{group_id}/{server_id}",
                    {"password": str(password), "save_password": False},
                    headers,
                )
                if cookie := wp._cookie(response):
                    headers["Cookie"] = cookie
            for database in nodes(f"/browser/database/nodes/{group_id}/{server_id}/"):
                if database.get("_type") != "database" or not str(database.get("_id")).isdigit():
                    continue
                database_id = int(database["_id"])
                database_name = str(database.get("label") or database_id)
                if getattr(args, "database", None) and args.database != database_name:
                    continue
                label = f"{server_name}/{database_name}"
                yield f"database:{group_id}:{server_id}:{database_id}", "databases", {"server": server_name, **database}
                if selected is not None and not selected & {"tables", "columns", "rows"}:
                    continue
                if not database.get("connected"):
                    raise _Incomplete(f"pgAdmin backend database not connected: {label}")
                for schema in nodes(f"/browser/schema/nodes/{group_id}/{server_id}/{database_id}/"):
                    if schema.get("_type") != "schema" or not str(schema.get("_id")).isdigit():
                        continue
                    schema_id = int(schema["_id"])
                    schema_name = str(schema.get("label") or schema_id)
                    for table in nodes(f"/browser/table/nodes/{group_id}/{server_id}/{database_id}/{schema_id}/"):
                        if table.get("_type") != "table" or not str(table.get("_id")).isdigit():
                            continue
                        table_id = int(table["_id"])
                        table_name = str(table.get("label") or table_id)
                        if filters and table_name not in filters and f"{schema_name}.{table_name}" not in filters:
                            continue
                        table_key = f"{group_id}:{server_id}:{database_id}:{schema_id}:{table_id}"
                        yield f"table:{table_key}", "tables", {"database": label, "schema": schema_name, **table}
                        if selected is None or "columns" in selected:
                            for column in nodes(
                                f"/browser/column/nodes/{group_id}/{server_id}/{database_id}/{schema_id}/{table_id}/"
                            ):
                                if column.get("_type") == "column":
                                    yield (
                                        f"column:{table_key}:{column.get('_id')}",
                                        "columns",
                                        {"table": f"{label}/{schema_name}/{table_name}", **column},
                                    )
                        if selected is not None and "rows" not in selected:
                            continue
                        for ordinal, row in enumerate(
                            _pgadmin_rows(pool, base, headers, group_id, server_id, database_id, table_id)
                        ):
                            yield (
                                f"row:{table_key}:{ordinal}",
                                "rows",
                                {"table": f"{label}/{schema_name}/{table_name}", "row": row},
                            )


def export_panel(ctx: Any, record: dict[str, Any], selected: set[str] | None = None) -> dict[str, Any]:
    """Export selected UI records to a private JSONL file and checkpoint."""
    product = str(record.get("ui_product") or "")
    ui = dict(record.get("ui") or {})
    base = str(ui.get("endpoint") or "")
    headers: dict[str, str] = {}
    if ui.get("session_cookie"):
        headers["Cookie"] = str(ui["session_cookie"])
    if ui.get("session_token"):
        headers["Authorization"] = "Bearer " + str(ui["session_token"])
    if ui.get("session_authorization"):
        headers["Authorization"] = str(ui["session_authorization"])
    credential = getattr(ctx, "credential", None)
    username = getattr(credential, "username", None) or getattr(ctx.args, "username", None)
    password = getattr(credential, "password", None) or getattr(ctx.args, "password", None)
    identity = {
        "username": username,
        "password": password,
        "token": getattr(ctx.args, "token", None) or getattr(ctx.args, "apitoken", None),
        "pgadmin_server_password": getattr(ctx.args, "pgadmin_server_password", None),
    }
    scope = {
        "username": str(username or ""),
        "identity": hashlib.sha256(json.dumps(identity, sort_keys=True, default=str).encode()).hexdigest()[:16],
        "database": getattr(ctx.args, "database", None),
        "bucket": getattr(ctx.args, "bucket", None),
        "object": getattr(ctx.args, "object", None),
        "collections": getattr(ctx.args, "collections", None),
        "document": getattr(ctx.args, "document", None),
        "tables": getattr(ctx.args, "tables", None),
        "columns": getattr(ctx.args, "columns", None),
        "query": getattr(ctx.args, "query", None),
        "selected": sorted(selected) if selected is not None else None,
    }
    result: dict[str, Any]
    try:
        with UIExport(
            ".redposture/ui-exports",
            base,
            product,
            resume=None,
            scope=scope,
        ) as writer:
            with closing(
                HttpSessionPool(
                    timeout=max(0.2, float(getattr(ctx.args, "timeout", 5.0) or 5.0)),
                    insecure=not bool(getattr(ctx.args, "secure", False)),
                    proxy=getattr(ctx.args, "_proxy_config", None),
                    retries=0,
                )
            ) as pool:
                try:
                    if product == "portainer":
                        records = (
                            _portainer(pool, base, headers, selected)
                            if selected is not None
                            else _portainer(pool, base, headers)
                        )
                    elif product == "mongo_express":
                        records = (
                            _mongo(pool, base, headers, ctx.args, selected)
                            if selected is not None
                            else _mongo(pool, base, headers, ctx.args)
                        )
                    elif product == "redis_insight":
                        records = (
                            _redis(pool, base, headers, writer, selected)
                            if selected is not None
                            else _redis(pool, base, headers, writer)
                        )
                    elif product == "minio_console":
                        records = (
                            _minio(pool, base, headers, writer, ctx.args, selected)
                            if selected is not None
                            else _minio(pool, base, headers, writer, ctx.args)
                        )
                    elif product in {"kibana", "opensearch_dashboards"}:
                        records = (
                            _elastic(pool, base, headers, product, selected)
                            if selected is not None
                            else _elastic(pool, base, headers, product)
                        )
                    elif product == "pgadmin":
                        records = (
                            _pgadmin(pool, base, headers, ctx.args, selected)
                            if selected is not None
                            else _pgadmin(pool, base, headers, ctx.args)
                        )
                    else:
                        raise _Incomplete(f"full UI export is not implemented for {product}")
                    for key, collection, value in records:
                        if writer.add(key, collection, value) and writer.new_count % 100 == 0:
                            emit = getattr(ctx, "live_emit", None)
                            if callable(emit):
                                label = str(record.get("module") or product).upper()
                                emit(
                                    [
                                        f"{label}\t{ctx.host}\t{ctx.port}\t [*] UI Export Enumeration (count:{writer.count})"
                                    ]
                                )
                except (KeyboardInterrupt, _Incomplete) as exc:
                    result = writer.finish(complete=False, reason=str(exc) or "interrupted")
                else:
                    result = writer.finish(complete=True)
    except (OSError, ValueError, sqlite3.Error) as exc:
        result = {"status": "unavailable", "partial": True, "reason": str(exc)}
    ui["inventory"] = {"export": result}
    payload = dict(record)
    payload["ui"] = ui
    return payload
