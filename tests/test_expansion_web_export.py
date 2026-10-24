"""Additional full-export contracts for malformed, selected and interrupted reads."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core import web_panel_export as export
from redposture_core.clients.http_api import HttpResponse
from redposture_core.ui_export import UIExport


def response(value: Any, *, status: int = 200, **extra: Any) -> HttpResponse:
    return HttpResponse(status=status, body=json.dumps(value).encode(), headers={}, **extra)


@pytest.mark.parametrize(
    ("product", "flags"),
    [
        ("minio_console", {"dump": True, "object": "secret"}),
        ("mongo_express", {"dump": True, "document": "id"}),
        ("mongo_express", {"dump": True, "query": "{}"}),
        ("mongo_express", {"dump": True, "projection": "{id:1}"}),
        ("pgadmin", {"dump": True, "columns": ["id"]}),
    ],
)
def test_explicit_selectors_do_not_trigger_unbounded_export(product: str, flags: dict[str, Any]) -> None:
    assert export.standard_export_selection(SimpleNamespace(**flags), product) == set()


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (response({}, status=403), "HTTP 403; unavailable"),
        (response({}, error="reset"), "HTTP 200; reset"),
        (response({}, truncated=True), "HTTP 200; truncated"),
        (HttpResponse(status=200, body=b"not-json", headers={}), "invalid JSON"),
    ],
)
def test_json_page_never_treats_failed_or_truncated_response_as_complete(answer: HttpResponse, reason: str) -> None:
    with pytest.raises(export._Incomplete, match=reason):
        export._json_page(answer, "inventory")


@pytest.mark.parametrize(
    ("endpoints", "reason"),
    [({}, "invalid list"), ([None], "invalid environment entry"), ([{"Id": True}], "invalid environment entry")],
)
def test_portainer_rejects_invalid_environment_pages(
    monkeypatch: pytest.MonkeyPatch, endpoints: Any, reason: str
) -> None:
    monkeypatch.setattr(export, "_get", lambda *_args: response(endpoints))
    with pytest.raises(export._Incomplete, match=reason):
        list(export._portainer(object(), "http://panel", {}, {"containers"}))


@pytest.mark.parametrize(
    ("category", "value", "reason"),
    [("containers", {}, "invalid list"), ("images", [None], "invalid entry"), ("system", [], "invalid object")],
)
def test_portainer_partial_iterator_retains_environment_before_inventory_error(
    monkeypatch: pytest.MonkeyPatch, category: str, value: Any, reason: str
) -> None:
    paths: list[str] = []

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        paths.append(path)
        return response([{"Id": 7}]) if path.startswith("/api/endpoints?") else response(value)

    monkeypatch.setattr(export, "_get", get)
    records = export._portainer(object(), "http://panel", {}, {category})
    assert next(records) == ("environment:7", "environments", {"Id": 7})
    with pytest.raises(export._Incomplete, match=reason):
        next(records)
    route = {"containers": "containers/json?all=1", "images": "images/json", "system": "info"}[category]
    assert paths == ["/api/endpoints?start=0&limit=100", f"/api/endpoints/7/docker/{route}"]


def test_portainer_legacy_endpoint_fallback_and_null_volumes(monkeypatch: pytest.MonkeyPatch) -> None:
    paths: list[str] = []
    answers = iter([response({}, status=404), response([{"Id": 3}]), response({"Volumes": None})])

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        paths.append(path)
        return next(answers)

    monkeypatch.setattr(export, "_get", get)
    assert list(export._portainer(object(), "http://panel", {}, {"volumes"})) == [
        ("environment:3", "environments", {"Id": 3})
    ]
    assert paths == ["/api/endpoints?start=0&limit=100", "/api/endpoints", "/api/endpoints/3/docker/volumes"]


@pytest.mark.parametrize(
    ("database", "page", "reason"),
    [
        ({}, None, "invalid list"),
        ([{}], None, "invalid database"),
        ([{"id": "db"}], [], "invalid key page"),
        ([{"id": "db"}], [None], "invalid key page"),
        ([{"id": "db"}], {"keys": [None]}, "invalid key entry"),
        ([{"id": "db"}], {"keys": [{"name": 5}]}, "invalid key entry"),
    ],
)
def test_redis_export_requires_typed_database_and_key_pages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, database: Any, page: Any, reason: str
) -> None:
    monkeypatch.setattr(export, "_get", lambda *_args: response(database))
    monkeypatch.setattr(export, "_post", lambda *_args: response(page))
    with UIExport(str(tmp_path), "http://panel", "redis_insight", resume=False) as writer:
        with pytest.raises(export._Incomplete, match=reason):
            list(export._redis(object(), "http://panel", {}, writer, {"keys"}))


def test_redis_export_skips_checkpointed_keys_and_detects_stalled_cursor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cursors: list[str] = []
    monkeypatch.setattr(export, "_get", lambda *_args: response({"data": [{"id": "db/1"}]}))

    def post(_pool: Any, _base: str, path: str, body: dict[str, Any], _headers: Any) -> HttpResponse:
        assert path == "/api/databases/db%2F1/keys?encoding=utf8"
        cursors.append(body["cursor"])
        return response({"keys": [{"name": "saved", "type": "string"}], "cursor": "7"})

    monkeypatch.setattr(export, "_post", post)
    with UIExport(str(tmp_path), "http://panel", "redis_insight", resume=False) as writer:
        writer.add("key:db/1:saved", "keys", {"key": "saved"})
        records = export._redis(object(), "http://panel", {}, writer, {"keys"})
        assert next(records) == ("database:db/1", "connections", {"id": "db/1"})
        with pytest.raises(export._Incomplete, match="repeated key cursor"):
            next(records)
    assert cursors == ["0", "7"]


@pytest.mark.parametrize("value", [{}, {"objects": False}, {"objects": [None]}, {"objects": [{"size": 4}]}])
def test_minio_export_rejects_unprovable_object_lists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: Any
) -> None:
    monkeypatch.setattr(
        export,
        "_get",
        lambda _pool, _base, path, _headers: (
            response({"buckets": [{"name": "qa"}]}) if path == "/api/v1/buckets" else response(value)
        ),
    )
    with UIExport(str(tmp_path), "http://panel", "minio_console", resume=False) as writer:
        with pytest.raises(export._Incomplete, match="invalid object|object without a name"):
            list(export._minio(object(), "http://panel", {}, writer, SimpleNamespace(), {"objects"}))


def test_minio_real_empty_bucket_does_not_abort_remaining_buckets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Console returns {objects: null} for a valid empty bucket on the real fixture."""
    paths: list[str] = []

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        paths.append(path)
        if path == "/api/v1/buckets":
            return response({"buckets": [{"name": "empty"}, {"name": "populated"}]})
        if path.startswith("/api/v1/buckets/empty/objects?"):
            return response({"objects": None})
        assert path.startswith("/api/v1/buckets/populated/objects?")
        return response({"objects": [{"name": "report.json", "size": 2}]})

    monkeypatch.setattr(export, "_get", get)
    with UIExport(str(tmp_path), "http://panel", "minio_console", resume=False) as writer:
        rows = list(export._minio(object(), "http://panel", {}, writer, SimpleNamespace(), {"objects"}))
    assert [identity for identity, _kind, _value in rows] == [
        "bucket:empty",
        "bucket:populated",
        "object:populated/report.json",
    ]
    assert len(paths) == 3


@pytest.mark.parametrize("value", [{"error": "forbidden"}, {"status": 503}, {}, [None], [{"index": 1}]])
def test_dashboard_export_rejects_upstream_errors_and_invalid_indices(
    monkeypatch: pytest.MonkeyPatch, value: Any
) -> None:
    calls: list[str] = []

    def post(_pool: Any, _base: str, path: str, body: bytes, headers: Any, **kwargs: Any) -> HttpResponse:
        calls.append(path)
        assert body == b""
        assert headers == {"osd-xsrf": "redposture"}
        assert parse_qs(urlsplit(path).query)["method"] == ["GET"]
        assert kwargs["response_size_cap"] == 8 * 1024 * 1024
        return response(value)

    monkeypatch.setattr(export.wp, "_post", post)
    with pytest.raises(export._Incomplete):
        list(export._elastic(object(), "http://panel", {}, "opensearch_dashboards", {"indices"}))
    assert len(calls) == 1


@pytest.mark.parametrize("page", [{}, {"hits": {"hits": []}}, {"_scroll_id": "", "hits": {"hits": []}}])
def test_dashboard_export_requires_scroll_proof(monkeypatch: pytest.MonkeyPatch, page: Any) -> None:
    answers = iter([response([{"index": "orders"}]), response(page)])
    monkeypatch.setattr(export.wp, "_post", lambda *_args, **_kwargs: next(answers))
    records = export._elastic(object(), "http://panel", {}, "kibana", {"documents"})
    assert next(records) == ("index:orders", "indices", {"index": "orders"})
    with pytest.raises(export._Incomplete, match="continuation proof"):
        next(records)


def test_dashboard_malformed_scroll_hit_reports_incomplete_instead_of_crashing(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = iter([response([{"index": "orders"}]), response({"_scroll_id": "s", "hits": {"hits": [None]}})])
    monkeypatch.setattr(export.wp, "_post", lambda *_args, **_kwargs: next(answers))
    with pytest.raises(export._Incomplete, match="invalid hit"):
        list(export._elastic(object(), "http://panel", {}, "kibana", {"documents"}))


@pytest.mark.parametrize(
    ("start", "poll", "window", "reason"),
    [
        ({"success": 0}, None, None, "start rejected"),
        ({"success": 1}, {"data": {"status": "Error"}}, None, "did not complete"),
        (
            {"success": 1},
            {"data": {"status": "Success", "result": [[1]], "pagination": {"next_page": True}}},
            {},
            "window invalid",
        ),
        (
            {"success": 1},
            {"data": {"status": "Success", "result": [[1]], "pagination": {"next_page": True}}},
            {"data": {"result": []}},
            "window empty",
        ),
    ],
)
def test_pgadmin_export_closes_read_only_cursor_after_failure(
    monkeypatch: pytest.MonkeyPatch, start: Any, poll: Any, window: Any, reason: str
) -> None:
    monkeypatch.setattr(export.secrets, "randbelow", lambda _limit: 9)
    requests: list[str] = []
    monkeypatch.setattr(export, "_post", lambda *_args: response({"success": 1}))

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        requests.append(path)
        if "/start/" in path:
            return response(start)
        if "/poll/" in path:
            return response(poll)
        assert path == "/sqleditor/fetch_window/10/2/101"
        return response(window)

    class Pool:
        def request_once(self, method: str, url: str, **kwargs: Any) -> None:
            assert (method, url, kwargs) == (
                "DELETE",
                "http://panel/sqleditor/close/10",
                {"headers": {"Cookie": "sid=1"}, "response_size_cap": 4096},
            )
            requests.append("closed")
            raise OSError("cleanup failure must not replace read error")

    monkeypatch.setattr(export, "_get", get)
    records = export._pgadmin_rows(Pool(), "http://panel", {"Cookie": "sid=1"}, 1, 2, 3, 4)
    with pytest.raises(export._Incomplete, match=reason):
        list(records)
    assert requests[-1] == "closed"
    assert requests[0] == "/sqleditor/view_data/start/10"


def test_pgadmin_busy_poll_exhaustion_is_incomplete_and_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(export, "_post", lambda *_args: response({"success": 1}))
    paths: list[str] = []
    sleeps: list[float] = []

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        paths.append(path)
        return response({"success": 1}) if "/start/" in path else response({"data": {"status": "Busy"}})

    class Pool:
        def request_once(self, method: str, url: str, **_kwargs: Any) -> None:
            assert method == "DELETE"
            paths.append(url)

    monkeypatch.setattr(export, "_get", get)
    monkeypatch.setattr(export.time, "sleep", sleeps.append)
    with pytest.raises(export._Incomplete, match="did not complete"):
        list(export._pgadmin_rows(Pool(), "http://panel", {}, 1, 2, 3, 4))
    assert len(sleeps) == 30
    assert sleeps == [0.05] * 30
    assert len([path for path in paths if "/poll/" in path]) == 30
    assert "/sqleditor/close/" in paths[-1]


@pytest.mark.parametrize("product", ["mongo_express", "redis_insight", "minio_console", "kibana", "pgadmin"])
def test_export_dispatches_selected_reader_and_preserves_partial_checkpoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, product: str
) -> None:
    monkeypatch.chdir(tmp_path)
    headers_seen: list[dict[str, str]] = []
    reader = {
        "mongo_express": "_mongo",
        "redis_insight": "_redis",
        "minio_console": "_minio",
        "kibana": "_elastic",
        "pgadmin": "_pgadmin",
    }[product]

    def records(_pool: Any, base: str, headers: dict[str, str], *args: Any) -> Any:
        assert base == "http://panel/prefix"
        assert args[-1] == {"requested"}
        headers_seen.append(headers)
        yield "item:1", "requested", {"name": "saved"}
        raise export._Incomplete("next page denied")

    class Pool:
        def __init__(self, **kwargs: Any) -> None:
            assert kwargs["retries"] == 0

        def close(self) -> None:
            pass

    monkeypatch.setattr(export, reader, records)
    monkeypatch.setattr(export, "HttpSessionPool", Pool)
    record = {
        "ui_product": product,
        "ui": {
            "endpoint": "http://panel/prefix",
            "session_cookie": "sid=1",
            "session_token": "token",
            "session_authorization": "Basic final",
        },
    }
    result = export.export_panel(SimpleNamespace(args=SimpleNamespace()), record, {"requested"})
    outcome = result["ui"]["inventory"]["export"]
    assert outcome["partial"] is True
    assert outcome["count"] == 1
    assert outcome["reason"] == "next page denied"
    assert headers_seen == [{"Cookie": "sid=1", "Authorization": "Basic final"}]
    assert "inventory" not in record["ui"]
    text = Path(outcome["path"]).read_text()
    assert json.loads(text)["value"] == {"name": "saved"}
    assert "\x1b" not in text


@pytest.mark.parametrize(
    ("stage", "answer", "reason"),
    [
        ("home", response("not mongo"), "home unavailable"),
        ("database", response({}, status=403), "page unavailable"),
        ("collection", response({}, status=403), "page unavailable at skip 0"),
        ("document", response({}, status=403), "document unavailable"),
    ],
)
def test_mongo_export_reports_stage_of_read_failure(
    monkeypatch: pytest.MonkeyPatch, stage: str, answer: HttpResponse, reason: str
) -> None:
    calls: list[str] = []
    normal = {
        "/": HttpResponse(status=200, body=b'mongo express <a href="/db/qa/">qa</a>', headers={}),
        "/db/qa/": HttpResponse(status=200, body=b'<a href="/db/qa/orders">orders</a>', headers={}),
        "/db/qa/orders": HttpResponse(status=200, body=b"loadDocument('/db/qa/orders/1')", headers={}),
    }
    bad_path = {"home": "/", "database": "/db/qa/", "collection": "/db/qa/orders", "document": "/db/qa/orders/1"}[stage]

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        calls.append(path)
        return answer if path == bad_path else normal[path]

    monkeypatch.setattr(export, "_get", get)
    with pytest.raises(export._Incomplete, match=reason):
        list(export._mongo(object(), "http://panel", {}, SimpleNamespace(), {"documents"}))
    assert calls[-1] == bad_path
    expected_paths = list(normal)[: len(calls)] if stage != "document" else [*normal, bad_path]
    assert calls == expected_paths


@pytest.mark.parametrize("selected", [{"collections"}, {"documents"}])
def test_mongo_export_filters_database_and_collection_before_opening_pages(
    monkeypatch: pytest.MonkeyPatch, selected: set[str]
) -> None:
    paths: list[str] = []

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        paths.append(path)
        pages = {
            "/": 'mongo express <a href="/db/skip/">skip</a><a href="/db/qa/">qa</a>',
            "/db/qa/": '<a href="/db/qa/skip">skip</a><a href="/db/qa/orders">orders</a>',
            "/db/qa/orders": "limit: '100', totalPages: Math.round('0' / 100)",
        }
        return HttpResponse(status=200, body=pages[path].encode(), headers={})

    monkeypatch.setattr(export, "_get", get)
    assert list(
        export._mongo(
            object(), "http://panel", {}, SimpleNamespace(database="qa", collections=[" qa/orders,other "]), selected
        )
    ) == [
        ("database:qa", "databases", {"name": "qa"}),
        ("collection:qa/orders", "collections", {"database": "qa", "name": "orders"}),
    ]
    assert paths == ["/", "/db/qa/"] + (["/db/qa/orders"] if "documents" in selected else [])


def test_mongo_export_repeated_document_page_retains_prior_record(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    pages = {
        "/": 'mongo express <a href="/db/qa/">qa</a>',
        "/db/qa/": '<a href="/db/qa/orders">orders</a>',
        "/db/qa/orders": "loadDocument('/db/qa/orders/1'); limit: '1', totalPages: Math.round('2' / 1)",
        "/db/qa/orders?skip=1": "loadDocument('/db/qa/orders/1'); limit: '1', totalPages: Math.round('2' / 1)",
        "/db/qa/orders/1": '<textarea id="document">{"value":3}</textarea>',
    }

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        calls.append(path)
        return HttpResponse(status=200, body=pages[path].encode(), headers={})

    monkeypatch.setattr(export, "_get", get)
    records = export._mongo(object(), "http://panel", {}, SimpleNamespace(), {"documents"})
    assert next(records)[1] == "databases"
    assert next(records)[1] == "collections"
    assert next(records) == (
        "document:/db/qa/orders/1",
        "documents",
        {"collection": "qa/orders", "content": '{"value":3}'},
    )
    with pytest.raises(export._Incomplete, match="repeated document page"):
        next(records)
    assert calls[-1] == "/db/qa/orders?skip=1"
    assert calls.count("/db/qa/orders/1") == 1


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (response({}, status=403), "object unavailable"),
        (response({}, truncated=True), "object unavailable"),
        (response({}, error="reset"), "object unavailable"),
    ],
)
def test_minio_download_failure_is_partial_not_an_empty_object(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: HttpResponse, reason: str
) -> None:
    paths: list[str] = []

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        paths.append(path)
        if path == "/api/v1/buckets":
            return response({"buckets": [{"name": "qa /"}]})
        if "/objects/download?" in path:
            return answer
        return response({"objects": [{"name": "folder/"}, {"name": "secret+key", "size": 1}]})

    monkeypatch.setattr(export, "_get", get)
    with UIExport(str(tmp_path), "http://panel", "minio_console", resume=False) as writer:
        records = export._minio(object(), "http://panel", {}, writer, SimpleNamespace(), {"content"})
        assert next(records)[0] == "bucket:qa /"
        with pytest.raises(export._Incomplete, match=reason):
            next(records)
    assert paths == [
        "/api/v1/buckets",
        "/api/v1/buckets/qa%20%2F/objects?limit=100&recursive=true",
        "/api/v1/buckets/qa%20%2F/objects/download?prefix=secret%2Bkey",
    ]


@pytest.mark.parametrize("marker", ["again", 3])
def test_minio_rejects_invalid_or_repeated_continuation_marker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, marker: Any
) -> None:
    paths: list[str] = []

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        paths.append(path)
        return (
            response({"buckets": [{"name": "qa"}]})
            if path == "/api/v1/buckets"
            else response({"objects": [], "nextMarker": marker})
        )

    monkeypatch.setattr(export, "_get", get)
    with UIExport(str(tmp_path), "http://panel", "minio_console", resume=False) as writer:
        with pytest.raises(export._Incomplete, match="repeated continuation marker"):
            list(export._minio(object(), "http://panel", {}, writer, SimpleNamespace(), {"objects"}))
    assert paths[1] == "/api/v1/buckets/qa/objects?limit=100&recursive=true"
    assert len(paths) == (3 if marker == "again" else 2)
    if marker == "again":
        assert paths[2].endswith("&marker=again")


@pytest.mark.parametrize("selected", [{"buckets"}, {"objects"}])
def test_minio_bucket_selection_skips_unselected_and_checkpointed_data(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, selected: set[str]
) -> None:
    calls: list[str] = []

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        calls.append(path)
        return (
            response({"buckets": [None, {"name": "skip"}, {"Name": "qa"}]})
            if path == "/api/v1/buckets"
            else response({"objects": [{"name": "saved", "size": 1}]})
        )

    monkeypatch.setattr(export, "_get", get)
    with UIExport(str(tmp_path), "http://panel", "minio_console", resume=False) as writer:
        writer.add("object:qa/saved", "objects", {"object": "qa/saved"})
        assert list(export._minio(object(), "http://panel", {}, writer, SimpleNamespace(bucket="qa"), selected)) == [
            ("bucket:qa", "buckets", {"Name": "qa"})
        ]
    assert calls == ["/api/v1/buckets"] + (
        ["/api/v1/buckets/qa/objects?limit=100&recursive=true"] if "objects" in selected else []
    )


@pytest.mark.parametrize("failure", ["nodes", "disconnected"])
def test_pgadmin_node_failure_cannot_be_reported_as_empty_complete_inventory(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    calls: list[str] = []
    pages = {
        "/browser/nodes/": [{"_type": "server_group", "_id": 1}],
        "/browser/server/nodes/1/": [{"_type": "server", "_id": 2}],
        "/browser/database/nodes/1/2/": [{"_type": "database", "_id": 3, "label": "qa", "connected": False}],
    }

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        calls.append(path)
        if path == "/browser/js/utils.js":
            return response("")
        if failure == "nodes":
            return response({"success": 0})
        return response({"success": 1, "data": pages[path]})

    monkeypatch.setattr(export, "_get", get)
    with pytest.raises(
        export._Incomplete, match="nodes unavailable" if failure == "nodes" else "backend database not connected"
    ):
        list(export._pgadmin(object(), "http://panel", {}, SimpleNamespace(), {"rows"}))
    assert calls[-1] == ("/browser/nodes/" if failure == "nodes" else "/browser/database/nodes/1/2/")


@pytest.mark.parametrize("selected", [{"servers"}, {"databases"}, {"tables"}, {"columns"}])
def test_pgadmin_filters_each_hierarchy_level_and_connects_without_saving_password(
    monkeypatch: pytest.MonkeyPatch, selected: set[str]
) -> None:
    calls: list[str] = []
    headers: dict[str, str] = {}
    pages = {
        "/browser/nodes/": [
            {"_type": "other", "_id": 0},
            {"_type": "server_group", "_id": "bad"},
            {"_type": "server_group", "_id": 1},
        ],
        "/browser/server/nodes/1/": [
            {"_type": "other", "_id": 0},
            {"_type": "server", "_id": "bad"},
            {"_type": "server", "_id": 2, "label": "backend"},
        ],
        "/browser/database/nodes/1/2/": [
            {"_type": "other"},
            {"_type": "database", "_id": 5, "label": "skip"},
            {"_type": "database", "_id": 3, "label": "qa", "connected": True},
        ],
        "/browser/schema/nodes/1/2/3/": [{"_type": "other"}, {"_type": "schema", "_id": 4, "label": "public"}],
        "/browser/table/nodes/1/2/3/4/": [
            {"_type": "other"},
            {"_type": "table", "_id": 9, "label": "skip"},
            {"_type": "table", "_id": 6, "label": "orders"},
        ],
        "/browser/column/nodes/1/2/3/4/6/": [{"_type": "other"}, {"_type": "column", "_id": 7, "label": "id"}],
    }

    def get(_pool: Any, _base: str, path: str, actual_headers: Any) -> HttpResponse:
        assert actual_headers is headers
        calls.append(path)
        if path == "/browser/js/utils.js":
            return response("")
        return response({"success": 1, "data": pages[path]})

    def post(_pool: Any, _base: str, path: str, body: Any, actual_headers: Any) -> HttpResponse:
        assert path == "/browser/server/connect/1/2"
        assert body == {"password": "secret", "save_password": False}
        assert actual_headers is headers
        return HttpResponse(status=200, body=b"{}", headers={"Set-Cookie": "backend=1; HttpOnly"})

    monkeypatch.setattr(export, "_get", get)
    monkeypatch.setattr(export, "_post", post)
    result = list(
        export._pgadmin(
            object(),
            "http://panel",
            headers,
            SimpleNamespace(database="qa", tables=["public.orders"], pgadmin_server_password="secret"),
            selected,
        )
    )
    expected_kinds = {
        "servers": ["servers"],
        "databases": ["servers", "databases"],
        "tables": ["servers", "databases", "tables"],
        "columns": ["servers", "databases", "tables", "columns"],
    }[next(iter(selected))]
    assert [row[1] for row in result] == expected_kinds
    if selected != {"servers"}:
        assert headers["Cookie"] == "backend=1"
    assert not any("skip" in str(row[2]) for row in result)
    depth = {"servers": 2, "databases": 3, "tables": 5, "columns": 6}[next(iter(selected))]
    assert calls == ["/browser/js/utils.js", *list(pages)[:depth]]


def test_export_http_wrappers_apply_json_encoding_headers_and_response_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Any, ...]] = []
    answer = response({})

    def get(*args: Any, **kwargs: Any) -> HttpResponse:
        calls.append((args, kwargs))
        return answer

    monkeypatch.setattr(export.wp, "_get", get)
    monkeypatch.setattr(export.wp, "_post", get)
    pool = object()
    assert export._get(pool, "http://panel", "/read", {"Cookie": "sid=1"}) is answer
    assert export._post(pool, "http://panel", "/read", {"key": "ключ"}, {"Cookie": "sid=1"}) is answer
    assert calls == [
        ((pool, "http://panel", "/read"), {"headers": {"Cookie": "sid=1"}, "response_size_cap": 8 * 1024 * 1024}),
        (
            (
                pool,
                "http://panel",
                "/read",
                '{"key": "ключ"}'.encode(),
                {"Cookie": "sid=1", "Content-Type": "application/json"},
            ),
            {"response_size_cap": 8 * 1024 * 1024},
        ),
    ]


@pytest.mark.parametrize("value", [{}, {"buckets": None}, {"buckets": {}}])
def test_minio_export_does_not_confuse_invalid_buckets_with_empty_list(
    monkeypatch: pytest.MonkeyPatch, value: Any
) -> None:
    monkeypatch.setattr(export, "_get", lambda *_args: response(value))
    with pytest.raises(export._Incomplete, match="bucket listing unavailable"):
        list(export._minio(object(), "http://panel", {}, object(), SimpleNamespace(), {"buckets"}))


def test_elastic_indices_only_never_opens_scroll_and_skips_internal_indices(monkeypatch: pytest.MonkeyPatch) -> None:
    paths: list[str] = []

    def post(_pool: Any, _base: str, path: str, *_args: Any, **_kwargs: Any) -> HttpResponse:
        paths.append(path)
        return response([{"index": ".system"}, {"index": "orders"}])

    monkeypatch.setattr(export.wp, "_post", post)
    assert list(export._elastic(object(), "http://panel", {}, "kibana", {"indices"})) == [
        ("index:orders", "indices", {"index": "orders"})
    ]
    assert len(paths) == 1
    assert parse_qs(urlsplit(paths[0]).query)["path"] == ["/_cat/indices?format=json&h=index,health,docs.count"]


def test_elastic_scroll_rejects_missing_hit_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = iter(
        [response([{"index": "orders"}]), response({"_scroll_id": "s", "hits": {"hits": [{"_source": {}}]}})]
    )
    monkeypatch.setattr(export.wp, "_post", lambda *_args, **_kwargs: next(answers))
    with pytest.raises(export._Incomplete, match="invalid hit"):
        list(export._elastic(object(), "http://panel", {}, "kibana", {"documents"}))


def test_pgadmin_initialization_rejection_does_not_start_or_close_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, Any]] = []

    def post(_pool: Any, _base: str, path: str, body: Any, _headers: Any) -> HttpResponse:
        calls.append((path, body))
        return response({"success": 0})

    monkeypatch.setattr(export, "_post", post)
    monkeypatch.setattr(export.secrets, "randbelow", lambda _limit: 0)
    with pytest.raises(export._Incomplete, match="initialize rejected"):
        list(export._pgadmin_rows(object(), "http://panel", {}, 1, 2, 3, 4))
    assert calls == [("/sqleditor/initialize/viewdata/1/3/table/1/2/3/4", {"server_cursor": True})]


@pytest.mark.parametrize("product", ["unknown", "portainer"])
def test_export_storage_failure_and_unsupported_product_are_explicit_partial(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, product: str
) -> None:
    monkeypatch.chdir(tmp_path)
    if product == "portainer":

        def fail(*_args: Any, **_kwargs: Any) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(export, "UIExport", fail)
    result = export.export_panel(
        SimpleNamespace(args=SimpleNamespace()), {"ui_product": product, "ui": {"endpoint": "http://panel"}}
    )
    result = result["ui"]["inventory"]["export"]
    assert result["partial"] is True
    assert result["reason"] == (
        "disk full" if product == "portainer" else "full UI export is not implemented for unknown"
    )
    if product == "portainer":
        assert result["status"] == "unavailable"
    else:
        assert result["count"] == 0
        assert Path(result["path"]).read_bytes() == b""
