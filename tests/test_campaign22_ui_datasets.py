"""Synthetic UI API emulators with exact, independently generated JSONL oracles.

These exercise the real export dispatcher, pagination, readers, and SQLite writer;
no browser, Docker service, or real backend is implied by this test coverage.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core import web_panel_export as export
from redposture_core.clients.http_api import HttpResponse

N = 1307
BASE = "http://campaign22-emulator.invalid/prefix"


def response(value: Any) -> HttpResponse:
    return HttpResponse(status=200, body=json.dumps(value, ensure_ascii=False).encode(), headers={})


def text_response(value: str) -> HttpResponse:
    return HttpResponse(status=200, body=value.encode(), headers={})


def payload(number: int) -> dict[str, Any]:
    # Deliberately preserve falsy values and non-ASCII content across serialization.
    return {"id": number, "text": f"Строка-{number}-值", "empty": {}, "nullable": None, "enabled": False, "zero": 0}


def run_export(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    product: str,
    selected: set[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    monkeypatch.chdir(tmp_path)
    record = {"ui_product": product, "ui": {"endpoint": BASE}}
    outcome = export.export_panel(SimpleNamespace(args=SimpleNamespace()), record, selected)["ui"]["inventory"][
        "export"
    ]
    assert outcome["partial"] is False, outcome
    assert outcome["reason"] is None
    raw = Path(outcome["path"]).read_text(encoding="utf-8")
    assert "\x1b" not in raw
    rows = [json.loads(line) for line in raw.splitlines()]
    assert outcome["count"] == len(rows)
    assert all(row["target"] == BASE and row["ui_product"] == product for row in rows)
    assert Path(outcome["path"]).stat().st_mode & 0o777 == 0o600
    return outcome, rows


def expected(collection: str, value: Any, product: str) -> dict[str, Any]:
    return {"target": BASE, "ui_product": product, "collection": collection, "value": value}


@pytest.mark.parametrize("product", ["kibana", "opensearch_dashboards"])
def test_dashboard_1307_documents_exact_export_and_empty_index_between_populated(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    product: str,
) -> None:
    names = ["before", "empty", "after"]
    datasets = {"before": [payload(i) for i in range(N)], "empty": [], "after": [payload(9001)]}
    offsets = {name: 0 for name in names}
    pages: list[tuple[str, int]] = []

    def post(_pool: Any, base: str, path: str, body: bytes, headers: dict[str, str], **kwargs: Any) -> HttpResponse:
        assert base == BASE and body == b""
        assert headers["kbn-xsrf" if product == "kibana" else "osd-xsrf"] == "redposture"
        assert kwargs["response_size_cap"] == 8 * 1024 * 1024
        upstream = parse_qs(urlsplit(path).query)["path"][0]
        if upstream.startswith("/_cat/"):
            return response([{"index": name} for name in names])
        query = parse_qs(urlsplit(upstream).query)
        name = query["scroll_id"][0] if upstream.startswith("/_search/scroll") else upstream.split("/")[1]
        offset = offsets[name]
        pages.append((name, offset))
        values = datasets[name][offset : offset + 100]
        offsets[name] += len(values)
        return response(
            {
                "_scroll_id": name,
                "hits": {"hits": [{"_index": name, "_id": str(value["id"]), "_source": value} for value in values]},
            }
        )

    monkeypatch.setattr(export.wp, "_post", post)
    _, rows = run_export(monkeypatch, tmp_path, product, {"documents"})
    oracle = []
    for name in names:
        oracle.append(expected("indices", {"index": name}, product))
        oracle.extend(
            expected(
                "documents",
                {
                    "index": name,
                    "hit": {
                        "_index": name,
                        "_id": str(value["id"]),
                        "_source": value,
                    },
                },
                product,
            )
            for value in datasets[name]
        )
    assert_typed_rows(rows, oracle)
    assert pages == [("before", i) for i in [*range(0, N, 100), N]] + [("empty", 0), ("after", 0), ("after", 1)]


@pytest.mark.parametrize("mode", ["growing-limit", "marker"])
def test_minio_1307_objects_exact_content_with_zero_byte_object_and_empty_bucket_between(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: str,
) -> None:
    buckets = ["before", "empty", "after"]
    objects = {
        "before": [
            (f"key-{i:04}", b"" if i == 654 else json.dumps(payload(i), ensure_ascii=False).encode()) for i in range(N)
        ],
        "empty": [],
        "after": [("last", b"last-value")],
    }
    listings: list[tuple[str, int, int]] = []
    downloads: list[str] = []

    def get(_pool: Any, base: str, path: str, _headers: Any) -> HttpResponse:
        assert base == BASE
        if path == "/api/v1/buckets":
            return response({"buckets": [{"name": name} for name in buckets]})
        name = path.split("/")[4]
        query = parse_qs(urlsplit(path).query)
        if "/download?" in path:
            key = query["prefix"][0]
            downloads.append(f"{name}/{key}")
            return HttpResponse(status=200, body=dict(objects[name])[key], headers={})
        limit = int(query["limit"][0])
        offset = int(query.get("marker", ["0"])[0])
        listings.append((name, offset, limit))
        page = objects[name][offset : offset + limit]
        value: dict[str, Any] = {"objects": [{"name": key, "size": len(body)} for key, body in page]}
        if mode == "marker" and offset + len(page) < len(objects[name]):
            value["nextMarker"] = str(offset + len(page))
        return response(value)

    monkeypatch.setattr(export, "_get", get)
    _, rows = run_export(monkeypatch, tmp_path, "minio_console", {"content"})
    oracle = []
    for name in buckets:
        oracle.append(expected("buckets", {"name": name}, "minio_console"))
        oracle.extend(
            expected("objects", {"object": f"{name}/{key}", "content": body.decode()}, "minio_console")
            for key, body in objects[name]
        )
    assert_typed_rows(rows, oracle)
    assert downloads == [f"{name}/{key}" for name in buckets for key, _body in objects[name]]
    assert len(downloads) == len(set(downloads)) == N + 1
    assert ("empty", 0, 100) in listings and ("after", 0, 100) in listings
    assert len([item for item in listings if item[0] == "before"]) == (5 if mode == "growing-limit" else 14)


def test_redis_1307_keys_exact_values_and_empty_connection_between(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    databases = ["before", "empty", "after"]
    counts = {"before": N, "empty": 0, "after": 1}
    pages: list[tuple[str, int]] = []
    reads: list[tuple[str, str]] = []

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        assert path == "/api/databases"
        return response([{"id": name} for name in databases])

    def post(_pool: Any, _base: str, path: str, body: dict[str, Any], _headers: Any) -> HttpResponse:
        name = path.split("/")[3]
        offset = int(body["cursor"])
        assert body["count"] == 100
        pages.append((name, offset))
        stop = min(offset + 100, counts[name])
        return response(
            {
                "keys": [{"name": f"key-{i}", "type": "string"} for i in range(offset, stop)],
                "cursor": str(stop) if stop < counts[name] else "0",
            }
        )

    def read(_pool: Any, _base: str, _headers: Any, entry: dict[str, Any], **_kwargs: Any) -> Any:
        reads.append((entry["database_id"], entry["key"]))
        return payload(int(entry["key"].split("-")[1])), None, 1, False

    monkeypatch.setattr(export, "_get", get)
    monkeypatch.setattr(export, "_post", post)
    monkeypatch.setattr(export.wp, "_redis_insight_value", read)
    _, rows = run_export(monkeypatch, tmp_path, "redis_insight", {"values"})
    oracle = []
    for name in databases:
        oracle.append(expected("connections", {"id": name}, "redis_insight"))
        oracle.extend(
            expected(
                "keys", {"database_id": name, "key": f"key-{i}", "type": "string", "value": payload(i)}, "redis_insight"
            )
            for i in range(counts[name])
        )
    assert_typed_rows(rows, oracle)
    assert len(reads) == len(set(reads)) == N + 1
    assert pages == [("before", i) for i in range(0, N, 100)] + [("empty", 0), ("after", 0)]


def test_mongo_1307_documents_exact_unicode_payload_and_empty_collection_between(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    collections = ["before", "empty", "after"]
    counts = {"before": N, "empty": 0, "after": 1}
    skips: list[tuple[str, int]] = []
    documents: list[str] = []

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        if path == "/":
            return text_response('mongo express <a href="/db/qa/">qa</a>')
        if path == "/db/qa/":
            return text_response("".join(f'<a href="/db/qa/{name}">{name}</a>' for name in collections))
        parts = urlsplit(path).path.split("/")
        name = parts[3]
        if len(parts) == 5:
            documents.append(path)
            return text_response(
                '<textarea id="document">'
                + html.escape(json.dumps(payload(int(parts[4])), ensure_ascii=False))
                + "</textarea>"
            )
        offset = int(parse_qs(urlsplit(path).query).get("skip", ["0"])[0])
        skips.append((name, offset))
        links = "".join(f"loadDocument('/db/qa/{name}/{i}');" for i in range(offset, min(offset + 100, counts[name])))
        return text_response(links + f"limit: '100', totalPages: Math.round('{counts[name]}' / 100)")

    monkeypatch.setattr(export, "_get", get)
    _, rows = run_export(monkeypatch, tmp_path, "mongo_express", {"documents"})
    oracle = [expected("databases", {"name": "qa"}, "mongo_express")]
    for name in collections:
        oracle.append(expected("collections", {"database": "qa", "name": name}, "mongo_express"))
        oracle.extend(
            expected(
                "documents",
                {"collection": f"qa/{name}", "content": json.dumps(payload(i), ensure_ascii=False)},
                "mongo_express",
            )
            for i in range(counts[name])
        )
    assert_typed_rows(rows, oracle)
    assert len(documents) == len(set(documents)) == N + 1
    assert skips == [("before", i) for i in range(0, N, 100)] + [("empty", 0), ("after", 0)]


def test_portainer_1307_environments_exact_inventory_and_empty_environment_between(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pages: list[int] = []
    inventory: list[int] = []

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        if path.startswith("/api/endpoints?"):
            offset = int(parse_qs(urlsplit(path).query)["start"][0])
            pages.append(offset)
            return response([{"Id": i, "Name": f"env-{i}"} for i in range(offset, min(offset + 100, N))])
        number = int(path.split("/")[3])
        inventory.append(number)
        assert path.endswith("/docker/containers/json?all=1")
        return response([] if number == 654 else [{"Id": f"container-{number}", **payload(number)}])

    monkeypatch.setattr(export, "_get", get)
    _, rows = run_export(monkeypatch, tmp_path, "portainer", {"containers"})
    oracle = []
    for i in range(N):
        oracle.append(expected("environments", {"Id": i, "Name": f"env-{i}"}, "portainer"))
        if i != 654:
            oracle.append(expected("containers", {"environment": i, "Id": f"container-{i}", **payload(i)}, "portainer"))
    assert_typed_rows(rows, oracle)
    assert pages == list(range(0, N, 100))
    assert inventory == list(range(N))


def test_pgadmin_1307_rows_exact_export_and_empty_table_between_populated(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    table_ids = [5, 6, 7]
    counts = {5: N, 6: 0, 7: 1}
    transaction_tables: dict[int, int] = {}
    windows: list[tuple[int, int, int]] = []
    closed: list[int] = []
    counter = iter(range(50, 60))
    monkeypatch.setattr(export.secrets, "randbelow", lambda _limit: next(counter))
    server = {"_type": "server", "_id": 2, "label": "backend", "connected": True}
    database = {"_type": "database", "_id": 3, "label": "qa", "connected": True}

    def result(table: int, start: int, stop: int, *, initial: bool = False) -> HttpResponse:
        data: dict[str, Any] = {
            "result": [payload(i) for i in range(start, min(stop, counts[table]))],
            "pagination": {"next_page": stop < counts[table]},
        }
        if initial:
            data["status"] = "Success"
        return response({"data": data})

    def get(_pool: Any, _base: str, path: str, _headers: Any) -> HttpResponse:
        if path == "/browser/js/utils.js":
            return text_response("")
        nodes: dict[str, Any] = {
            "/browser/nodes/": [{"_type": "server_group", "_id": 1}],
            "/browser/server/nodes/1/": [server],
            "/browser/database/nodes/1/2/": [database],
            "/browser/schema/nodes/1/2/3/": [{"_type": "schema", "_id": 4, "label": "public"}],
            "/browser/table/nodes/1/2/3/4/": [{"_type": "table", "_id": i, "label": f"table-{i}"} for i in table_ids],
        }
        if path in nodes:
            return response({"success": 1, "data": nodes[path]})
        if "/start/" in path:
            return response({"success": 1})
        parts = path.split("/")
        transaction = int(parts[3])
        table = transaction_tables[transaction]
        if "/poll/" in path:
            return result(table, 0, 100, initial=True)
        assert "/fetch_window/" in path
        start, stop = int(parts[4]) - 1, int(parts[5])
        windows.append((table, start, stop))
        return result(table, start, stop)

    def post(_pool: Any, _base: str, path: str, body: Any, _headers: Any) -> HttpResponse:
        assert body == {"server_cursor": True}
        parts = path.split("/")
        transaction_tables[int(parts[4])] = int(parts[-1])
        return response({"success": 1})

    class Pool:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def request_once(self, method: str, url: str, **_kwargs: Any) -> None:
            assert method == "DELETE"
            closed.append(transaction_tables[int(url.rsplit("/", 1)[1])])

        def close(self) -> None:
            pass

    monkeypatch.setattr(export, "HttpSessionPool", Pool)
    monkeypatch.setattr(export, "_get", get)
    monkeypatch.setattr(export, "_post", post)
    _, rows = run_export(monkeypatch, tmp_path, "pgadmin", {"rows"})
    oracle = [
        expected("servers", server, "pgadmin"),
        expected("databases", {"server": "backend", **database}, "pgadmin"),
    ]
    for table in table_ids:
        oracle.append(
            expected(
                "tables",
                {
                    "database": "backend/qa",
                    "schema": "public",
                    "_type": "table",
                    "_id": table,
                    "label": f"table-{table}",
                },
                "pgadmin",
            )
        )
        oracle.extend(
            expected("rows", {"table": f"backend/qa/public/table-{table}", "row": payload(i)}, "pgadmin")
            for i in range(counts[table])
        )
    assert_typed_rows(rows, oracle)
    assert windows == [(5, i, i + 100) for i in range(100, N, 100)]
    assert closed == table_ids


def assert_typed_rows(actual: list[dict[str, Any]], oracle: list[dict[str, Any]]) -> None:
    # Python equality conflates False with 0; canonical JSON keeps these distinct.
    assert json.dumps(actual, sort_keys=True, ensure_ascii=False) == json.dumps(
        oracle, sort_keys=True, ensure_ascii=False
    )


@pytest.mark.parametrize(("actual", "expected_value"), [(False, 0), (0, False), (None, ""), ("0", 0)])
def test_exact_dataset_oracle_rejects_falsy_type_coercion(actual: Any, expected_value: Any) -> None:
    with pytest.raises(AssertionError):
        assert_typed_rows([{"value": actual}], [{"value": expected_value}])
