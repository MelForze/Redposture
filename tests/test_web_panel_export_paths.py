"""Product-level full UI export paths and incomplete-page regressions."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core import web_panel_export as export
from redposture_core.clients.http_api import HttpResponse
from redposture_core.ui_export import UIExport


def response(value: object, status: int = 200) -> HttpResponse:
    return HttpResponse(status=status, body=json.dumps(value).encode(), headers={})


def test_mongo_full_walk_reads_documents_and_rejects_unprovable_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    pages: list[str] = []

    def get(_pool: object, _base: str, path: str, _headers: dict[str, str]) -> HttpResponse:
        pages.append(path)
        if path == "/":
            body = '<h1>mongo express</h1><a href="/db/qa/">qa</a>'
        elif path == "/db/qa/":
            body = '<a href="/db/qa/orders">orders</a>'
        elif path == "/db/qa/orders":
            body = "loadDocument('/db/qa/orders/one') limit: '10' totalPages: Math.round('1' /"
        elif path == "/db/qa/orders/one":
            body = '<textarea id="document">{"order": 1}</textarea>'
        else:
            raise AssertionError(path)
        return HttpResponse(status=200, body=body.encode(), headers={})

    monkeypatch.setattr(export, "_get", get)
    args = SimpleNamespace(database="qa", collections=["orders"])
    rows = list(export._mongo(object(), "http://qa", {}, args, {"documents"}))
    assert [category for _key, category, _value in rows] == ["databases", "collections", "documents"]
    assert rows[-1][2]["content"] == '{"order": 1}'
    assert pages == ["/", "/db/qa/", "/db/qa/orders", "/db/qa/orders/one"]

    def no_pagination(_pool: object, _base: str, path: str, headers: dict[str, str]) -> HttpResponse:
        value = get(_pool, _base, path, headers)
        if path == "/db/qa/orders":
            return HttpResponse(status=200, body=b"loadDocument('/db/qa/orders/one')", headers={})
        return value

    monkeypatch.setattr(export, "_get", no_pagination)
    with pytest.raises(export._Incomplete, match="pagination unavailable"):
        list(export._mongo(object(), "http://qa", {}, args, {"documents"}))


def test_redis_full_scan_cursors_and_value_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(export, "_get", lambda *_args: response([{"id": "qa", "name": "QA"}]))
    cursors: list[str] = []

    def post(_pool: object, _base: str, _path: str, body: dict[str, object], _headers: dict[str, str]) -> HttpResponse:
        cursor = str(body["cursor"])
        cursors.append(cursor)
        return response(
            {
                "keys": [{"name": "first" if cursor == "0" else "second", "type": "string"}],
                "cursor": "7" if cursor == "0" else "0",
            }
        )

    monkeypatch.setattr(export, "_post", post)
    monkeypatch.setattr(export.wp, "_redis_insight_value", lambda *_args, **_kw: ({"value": "ok"}, None, 2, False))
    with UIExport(str(tmp_path), "http://qa", "redis_insight", resume=False) as writer:
        rows = list(export._redis(object(), "http://qa", {}, writer, {"values"}))
    assert cursors == ["0", "7"]
    assert [row[2]["value"] for row in rows[1:]] == [{"value": "ok"}, {"value": "ok"}]

    monkeypatch.setattr(export.wp, "_redis_insight_value", lambda *_args, **_kw: (None, "denied", 0, True))
    with UIExport(str(tmp_path / "failure"), "http://qa", "redis_insight", resume=False) as writer:
        with pytest.raises(export._Incomplete, match="denied"):
            list(export._redis(object(), "http://qa", {}, writer, {"values"}))


@pytest.mark.parametrize("product,xsrf", [("kibana", "kbn-xsrf"), ("opensearch_dashboards", "osd-xsrf")])
def test_elastic_ui_scroll_reads_all_pages_and_rejects_repeats(
    monkeypatch: pytest.MonkeyPatch, product: str, xsrf: str
) -> None:
    paths: list[str] = []

    def post(
        _pool: object, _base: str, path: str, _body: bytes, headers: dict[str, str], **_kw: object
    ) -> HttpResponse:
        assert headers[xsrf] == "redposture"
        upstream = parse_qs(urlsplit(path).query)["path"][0]
        paths.append(upstream)
        if upstream.startswith("/_cat/indices"):
            return response([{"index": ".hidden"}, {"index": "orders"}])
        if upstream.startswith("/orders/_search"):
            return response({"_scroll_id": "cursor", "hits": {"hits": [{"_id": "1", "_source": {"total": 3}}]}})
        if upstream.startswith("/_search/scroll"):
            return response({"_scroll_id": "cursor2", "hits": {"hits": []}})
        raise AssertionError(upstream)

    monkeypatch.setattr(export.wp, "_post", post)
    rows = list(export._elastic(object(), "http://qa", {}, product, {"documents"}))
    assert [kind for _key, kind, _value in rows] == ["indices", "documents"]
    assert len(paths) == 3

    def repeated(
        _pool: object, _base: str, path: str, _body: bytes, _headers: dict[str, str], **_kw: object
    ) -> HttpResponse:
        upstream = parse_qs(urlsplit(path).query)["path"][0]
        if upstream.startswith("/_cat/indices"):
            return response([{"index": "orders"}])
        return response({"_scroll_id": "cursor", "hits": {"hits": [{"_id": "1"}]}})

    monkeypatch.setattr(export.wp, "_post", repeated)
    with pytest.raises(export._Incomplete, match="repeated scroll page"):
        list(export._elastic(object(), "http://qa", {}, product, {"documents"}))


def test_pgadmin_walks_servers_databases_columns_and_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    def get(_pool: object, _base: str, path: str, _headers: dict[str, str]) -> HttpResponse:
        routes: dict[str, object] = {
            "/browser/nodes/": [{"_type": "server_group", "_id": 1}],
            "/browser/server/nodes/1/": [{"_type": "server", "_id": 2, "label": "server", "connected": True}],
            "/browser/database/nodes/1/2/": [{"_type": "database", "_id": 3, "label": "db", "connected": True}],
            "/browser/schema/nodes/1/2/3/": [{"_type": "schema", "_id": 4, "label": "public"}],
            "/browser/table/nodes/1/2/3/4/": [{"_type": "table", "_id": 5, "label": "orders"}],
            "/browser/column/nodes/1/2/3/4/5/": [{"_type": "column", "_id": 6, "label": "id"}],
        }
        if path == "/browser/js/utils.js":
            return HttpResponse(status=200, body=b"csrf_token_header'] = 'X-CSRF'; csrf_token'] = 'token'", headers={})
        return response({"success": 1, "data": routes[path]})

    monkeypatch.setattr(export, "_get", get)
    monkeypatch.setattr(export, "_pgadmin_rows", lambda *_args: iter([[1, "paid"]]))
    rows = list(
        export._pgadmin(
            object(), "http://qa", {}, SimpleNamespace(database="db", tables=["public.orders"]), {"rows", "columns"}
        )
    )
    assert [kind for _key, kind, _value in rows] == ["servers", "databases", "tables", "columns", "rows"]
    assert rows[-1][2]["row"] == [1, "paid"]

    def disconnected(_pool: object, _base: str, path: str, headers: dict[str, str]) -> HttpResponse:
        value = get(_pool, _base, path, headers)
        if path == "/browser/database/nodes/1/2/":
            return response({"success": 1, "data": [{"_type": "database", "_id": 3, "label": "db"}]})
        return value

    monkeypatch.setattr(export, "_get", disconnected)
    with pytest.raises(export._Incomplete, match="not connected"):
        list(export._pgadmin(object(), "http://qa", {}, SimpleNamespace(database="db", tables=[]), {"rows"}))


def test_minio_binary_content_and_marker_completion(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    paths: list[str] = []

    def get(_pool: object, _base: str, path: str, _headers: dict[str, str]) -> HttpResponse:
        paths.append(path)
        if path == "/api/v1/buckets":
            return response({"buckets": [{"name": "qa"}]})
        if "/objects/download?" in path:
            return HttpResponse(status=200, body=b"\x00\xff", headers={})
        marker = parse_qs(urlsplit(path).query).get("marker")
        if marker:
            return response({"objects": [{"name": "binary", "size": 2}]})
        return response({"objects": [], "nextMarker": "next"})

    monkeypatch.setattr(export, "_get", get)
    with UIExport(str(tmp_path), "http://qa", "minio_console", resume=False) as writer:
        rows = list(export._minio(object(), "http://qa", {}, writer, SimpleNamespace(bucket="qa"), {"content"}))
    assert rows[-1][2] == {"object": "qa/binary", "base64": "AP8="}
    assert any("marker=next" in path for path in paths)
