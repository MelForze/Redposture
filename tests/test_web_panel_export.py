"""Full UI readers must continue beyond bounded audit limits."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core import web_panel_export as export
from redposture_core import web_panels
from redposture_core.cli_args import build_parser
from redposture_core.clients.http_api import HttpResponse
from redposture_core.ui_export import UIExport


def _response(value: object, status: int = 200) -> HttpResponse:
    return HttpResponse(status=status, body=json.dumps(value).encode(), headers={})


@pytest.mark.parametrize(
    ("product", "flags", "expected"),
    [
        ("portainer", {"containers": True}, {"containers"}),
        ("mongo_express", {"show_collections": True}, {"collections"}),
        ("mongo_express", {"dump": True}, {"documents"}),
        ("redis_insight", {"show_keys": True}, {"keys"}),
        ("redis_insight", {"dump": True}, {"values"}),
        ("minio_console", {"show_buckets": True}, {"buckets"}),
        ("minio_console", {"show_objects": True}, {"objects"}),
        ("minio_console", {"dump": True}, {"content"}),
        ("kibana", {"discover": True}, set()),
        ("pgadmin", {"show_tables": True}, {"tables"}),
        ("pgadmin", {"dump": True}, {"rows"}),
    ],
)
def test_standard_flags_select_only_requested_ui_data(
    product: str, flags: dict[str, object], expected: set[str]
) -> None:
    assert export.standard_export_selection(SimpleNamespace(**flags), product) == expected
    assert export.standard_export_selection(SimpleNamespace(**{key: 3 for key in flags}), product) == set()


def test_standard_ui_flag_routes_to_export_without_extra_cli_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    selected: list[set[str]] = []

    def fake_export(_ctx: object, record: dict[str, object], categories: set[str]) -> dict[str, object]:
        selected.append(categories)
        return record

    monkeypatch.setattr(export, "export_panel", fake_export)
    ctx = SimpleNamespace(args=SimpleNamespace(_ui_standard_export=True, show_objects=True))
    record = {"ui_product": "minio_console", "ui": {"endpoint": "http://qa"}}
    assert web_panels.enumerate_panel(ctx, record) == record
    assert selected == [{"objects"}]


@pytest.mark.parametrize("module", ["minio", "docker", "mongodb", "elastic", "redis", "postgres", "kafka"])
def test_ui_only_export_flags_are_absent_from_help(module: str) -> None:
    parser = build_parser()
    subcommands = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    help_text = subcommands.choices[module].format_help()
    assert "--ui-full" not in help_text
    assert "--ui-export-dir" not in help_text
    assert "--ui-resume" not in help_text
    if module != "kafka":
        assert subcommands.choices[module].get_default("_ui_standard_export") is True


def test_minio_console_full_export_reads_more_than_bounded_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    names = [f"record-{n:05d}" for n in range(10_050)]

    def get(_pool: object, _base: str, path: str, _headers: dict[str, str]) -> HttpResponse:
        parsed = urlsplit(path)
        query = parse_qs(parsed.query)
        if parsed.path == "/api/v1/buckets":
            return _response({"buckets": [{"name": "qa"}]})
        if parsed.path.endswith("/objects/download"):
            return HttpResponse(status=200, body=query["prefix"][0].encode(), headers={})
        limit = int(query["limit"][0])
        return _response({"objects": [{"name": name, "size": 1} for name in names[:limit]]})

    monkeypatch.setattr(export, "_get", get)
    with UIExport(str(tmp_path), "http://qa", "minio_console", resume=False) as writer:
        for key, collection, value in export._minio(object(), "http://qa", {}, writer, SimpleNamespace(bucket=None)):
            writer.add(key, collection, value)
        result = writer.finish(complete=True)
    assert result["count"] == 10_051
    assert result["partial"] is False


def test_minio_show_objects_does_not_download_values(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    paths: list[str] = []

    def get(_pool: object, _base: str, path: str, _headers: dict[str, str]) -> HttpResponse:
        paths.append(path)
        if path == "/api/v1/buckets":
            return _response({"buckets": [{"name": "qa"}]})
        assert "objects/download" not in path
        return _response({"objects": [{"name": "one", "size": 2}]})

    monkeypatch.setattr(export, "_get", get)
    with UIExport(str(tmp_path), "http://qa", "minio_console", resume=False) as writer:
        records = list(export._minio(object(), "http://qa", {}, writer, SimpleNamespace(bucket=None), {"objects"}))
    assert [record[1] for record in records] == ["buckets", "objects"]
    assert len(paths) == 2


def test_mongo_show_databases_does_not_open_collections(monkeypatch: pytest.MonkeyPatch) -> None:
    paths: list[str] = []

    def get(_pool: object, _base: str, path: str, _headers: dict[str, str]) -> HttpResponse:
        paths.append(path)
        return HttpResponse(status=200, body=b'<h1>mongo express</h1><a href="/db/qa/">qa</a>', headers={})

    monkeypatch.setattr(export, "_get", get)
    records = list(export._mongo(object(), "http://qa", {}, SimpleNamespace(database=None), {"databases"}))
    assert [record[1] for record in records] == ["databases"]
    assert paths == ["/"]


def test_portainer_full_export_continues_environment_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    def get(_pool: object, _base: str, path: str, _headers: dict[str, str]) -> HttpResponse:
        parsed = urlsplit(path)
        if parsed.path == "/api/endpoints":
            start = int(parse_qs(parsed.query).get("start", ["0"])[0])
            return _response([{"Id": i, "Name": f"env-{i}"} for i in range(start + 1, min(start + 101, 2002))])
        if parsed.path.endswith("/info") or parsed.path.endswith("/system/df"):
            return _response({"name": "qa"})
        if parsed.path.endswith("/volumes"):
            return _response({"Volumes": []})
        return _response([])

    monkeypatch.setattr(export, "_get", get)
    items = list(export._portainer(object(), "http://qa", {}))
    environments = [item for item in items if item[1] == "environments"]
    assert len(environments) == 2001
    assert environments[-1][0] == "environment:2001"


def test_minio_without_continuation_reports_limit_as_partial(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(export, "_MINIO_LIST_LIMIT", 200)

    def get(_pool: object, _base: str, path: str, _headers: dict[str, str]) -> HttpResponse:
        if path == "/api/v1/buckets":
            return _response({"buckets": [{"name": "qa"}]})
        if "objects/download" in path:
            return HttpResponse(status=200, body=b"qa", headers={})
        limit = int(parse_qs(urlsplit(path).query)["limit"][0])
        return _response({"objects": [{"name": f"key-{i}", "size": 2} for i in range(limit)]})

    monkeypatch.setattr(export, "_get", get)
    with UIExport(str(tmp_path), "http://qa", "minio_console", resume=False) as writer:
        with pytest.raises(export._Incomplete, match="no cursor and list limit 200 reached"):
            for key, collection, value in export._minio(
                object(), "http://qa", {}, writer, SimpleNamespace(bucket=None)
            ):
                writer.add(key, collection, value)
        assert writer.count == 201


def test_pgadmin_viewdata_reads_more_than_bounded_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [[i, str(i)] for i in range(10_050)]

    def get(_pool: object, _base: str, path: str, _headers: dict[str, str]) -> HttpResponse:
        if "/view_data/start/" in path:
            return _response({"success": 1})
        if "/poll/" in path:
            return _response({"data": {"status": "Success", "result": rows[:100], "pagination": {"next_page": True}}})
        if "/fetch_window/" in path:
            parts = path.rsplit("/", 2)
            start, stop = int(parts[1]) - 1, int(parts[2])
            return _response({"data": {"result": rows[start:stop], "pagination": {"next_page": stop < len(rows)}}})
        raise AssertionError(path)

    monkeypatch.setattr(export, "_get", get)
    monkeypatch.setattr(export, "_post", lambda *_args: _response({"success": 1}))
    pool = SimpleNamespace(request_once=lambda *_args, **_kwargs: _response({"success": 1}))
    actual = list(export._pgadmin_rows(pool, "http://qa", {}, 1, 1, 1, 1))
    assert actual == rows


def test_redis_insight_full_scan_reads_more_than_bounded_limit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def get(_pool: object, _base: str, _path: str, _headers: dict[str, str]) -> HttpResponse:
        return _response([{"id": "qa", "name": "qa"}])

    def post(_pool: object, _base: str, _path: str, body: dict[str, object], _headers: dict[str, str]) -> HttpResponse:
        start = int(str(body["cursor"]))
        names = [f"key-{i:05d}" for i in range(start, min(start + 100, 10_050))]
        cursor = str(start + len(names)) if start + len(names) < 10_050 else "0"
        return _response({"keys": [{"name": name, "type": "string"} for name in names], "cursor": cursor})

    monkeypatch.setattr(export, "_get", get)
    monkeypatch.setattr(export, "_post", post)
    monkeypatch.setattr(export.wp, "_redis_insight_value", lambda *_args, **_kw: ({"value": "qa"}, None, 2, False))
    with UIExport(str(tmp_path), "http://qa", "redis_insight", resume=False) as writer:
        for key, collection, value in export._redis(object(), "http://qa", {}, writer):
            writer.add(key, collection, value)
        result = writer.finish(complete=True)
    assert result["count"] == 10_051
    assert result["partial"] is False


def test_repeated_page_is_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    def get(_pool: object, _base: str, path: str, _headers: dict[str, str]) -> HttpResponse:
        if path.startswith("/api/endpoints?"):
            return _response([{"Id": i} for i in range(100)])
        if path.endswith("/info") or path.endswith("/system/df"):
            return _response({})
        if path.endswith("/volumes"):
            return _response({"Volumes": []})
        return _response([])

    monkeypatch.setattr(export, "_get", get)
    with pytest.raises(export._Incomplete, match="repeated page"):
        list(export._portainer(object(), "http://qa", {}))


def test_full_export_reports_partial_then_resumes_without_duplicate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Pool:
        def close(self) -> None:
            pass

    monkeypatch.setattr(export, "HttpSessionPool", lambda **_kw: Pool())
    monkeypatch.chdir(tmp_path)
    state = {"fail": True}

    def entries(_pool: object, _base: str, _headers: dict[str, str]):
        yield "environment:1", "environments", {"Id": 1}
        if state["fail"]:
            raise export._Incomplete("Portainer environments: HTTP 429; rate limited")
        yield "environment:2", "environments", {"Id": 2}

    monkeypatch.setattr(export, "_portainer", entries)
    args = SimpleNamespace(
        username="qa",
        database=None,
        bucket=None,
        collections=None,
        tables=None,
        timeout=1,
        secure=False,
        _proxy_config=None,
    )
    ctx = SimpleNamespace(args=args, host="qa", port=9000)
    record = {"module": "docker", "ui_product": "portainer", "ui": {"endpoint": "http://qa", "inventory": {}}}
    first = export.export_panel(ctx, record)["ui"]["inventory"]["export"]
    assert first["count"] == 1
    assert first["partial"] is True
    assert "429" in first["reason"]
    state["fail"] = False
    second = export.export_panel(ctx, record)["ui"]["inventory"]["export"]
    assert second["count"] == 2
    assert second["partial"] is False
    assert len(Path(second["path"]).read_text().splitlines()) == 2
    assert "\x1b[" not in json.dumps(second)


def test_full_export_emits_colored_style_progress_every_100_new_records(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(export, "HttpSessionPool", lambda **_kw: SimpleNamespace(close=lambda: None))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        export,
        "_portainer",
        lambda *_args: ((f"environment:{i}", "environments", {"Id": i}) for i in range(100)),
    )
    lines: list[str] = []
    args = SimpleNamespace(
        username=None,
        database=None,
        bucket=None,
        collections=None,
        tables=None,
        timeout=1,
        secure=False,
        _proxy_config=None,
    )
    ctx = SimpleNamespace(args=args, host="qa", port=9443, live_emit=lambda chunk: lines.extend(chunk))
    export.export_panel(ctx, {"module": "docker", "ui_product": "portainer", "ui": {"endpoint": "http://qa"}})
    assert lines == ["DOCKER\tqa\t9443\t [*] UI Export Enumeration (count:100)"]
