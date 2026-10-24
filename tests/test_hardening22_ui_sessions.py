"""Session expiry and resume through real readers; product APIs are emulated."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core import web_panel_export as export
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.kafka import ui as kafka_ui


def response(value: Any, status: int = 200) -> HttpResponse:
    return HttpResponse(status, json.dumps(value).encode(), {})


@pytest.mark.parametrize("fault", [401, 403, "login-html"])
@pytest.mark.parametrize(
    "product",
    ["portainer", "minio_console", "redis_insight", "mongo_express", "kibana", "opensearch_dashboards", "pgadmin"],
)
def test_expired_ui_session_keeps_prefix_and_fresh_session_resumes_without_duplicates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, product: str, fault: int | str
) -> None:
    monkeypatch.chdir(tmp_path)
    fresh = False
    calls: list[tuple[str, str, dict[str, str]]] = []
    page_number = 0
    selected = {
        "portainer": set(),
        "minio_console": {"objects"},
        "redis_insight": {"keys"},
        "mongo_express": {"collections"},
        "kibana": {"documents"},
        "opensearch_dashboards": {"documents"},
        "pgadmin": {"databases"},
    }[product]

    def unavailable() -> HttpResponse:
        return (
            HttpResponse(200, b"<html>Sign in again</html>", {"Content-Type": "text/html"})
            if fault == "login-html"
            else response({"error": "session expired"}, int(fault))
        )

    def request(method: str, path: str, headers: dict[str, str]) -> HttpResponse:
        nonlocal page_number
        calls.append((method, path, dict(headers)))
        assert headers.get("Cookie") == ("sid=fresh" if fresh else "sid=expired")
        assert headers.get("Authorization") == "Bearer " + ("fresh-jwt" if fresh else "expired-jwt")
        parsed = urlsplit(path)
        query = parse_qs(parsed.query)
        if product == "portainer":
            start = int(query["start"][0])
            if start == 0:
                return response([{"Id": i} for i in range(100)])
            return response([{"Id": 100}]) if fresh else unavailable()
        if product == "minio_console":
            if path == "/api/v1/buckets":
                return response({"buckets": [{"name": "qa"}]})
            if not query.get("marker"):
                return response({"objects": [{"name": "one"}], "nextMarker": "next"})
            return response({"objects": [{"name": "two"}]}) if fresh else unavailable()
        if product == "redis_insight":
            if method == "GET":
                return response([{"id": "db", "name": "qa"}])
            page_number += 1
            if page_number == 1:
                return response({"keys": [{"name": "one", "type": "string"}], "cursor": "next"})
            return response({"keys": [{"name": "two", "type": "string"}], "cursor": "0"}) if fresh else unavailable()
        if product == "mongo_express":
            if path == "/":
                return HttpResponse(200, b'<title>Mongo Express</title><a href="/db/qa/">qa</a>', {})
            return HttpResponse(200, b'<a href="/db/qa/values">values</a>', {}) if fresh else unavailable()
        if product in {"kibana", "opensearch_dashboards"}:
            upstream = query["path"][0]
            if upstream.startswith("/_cat/"):
                return response([{"index": "qa"}])
            page_number += 1
            if page_number == 1:
                return response({"_scroll_id": "scroll", "hits": {"hits": [{"_id": "one", "_source": {"value": 1}}]}})
            if not fresh:
                return unavailable()
            return response(
                {
                    "_scroll_id": "scroll",
                    "hits": {"hits": [] if page_number > 2 else [{"_id": "two", "_source": {"value": 2}}]},
                }
            )
        if path.endswith("utils.js"):
            return HttpResponse(200, b"csrf_token_header'] = 'X-CSRFToken'; csrf_token'] = 'csrf-current';", {})
        assert headers["X-CSRFToken"] == "csrf-current"
        if path == "/browser/nodes/":
            nodes = [{"_type": "server_group", "_id": 1}]
        elif path == "/browser/server/nodes/1/":
            nodes = [{"_type": "server", "_id": 1, "label": "qa"}]
        elif fresh:
            nodes = [{"_type": "database", "_id": 1, "label": "qa", "connected": True}]
        else:
            return unavailable()
        return response({"success": 1, "data": nodes})

    def get(_pool: Any, _base: str, path: str, **kw: Any) -> HttpResponse:
        return request("GET", path, kw["headers"])

    def post(_pool: Any, _base: str, path: str, body: Any, headers: dict[str, str], **kw: Any) -> HttpResponse:
        return request("POST", path, headers)

    monkeypatch.setattr(export.wp, "_get", get)
    monkeypatch.setattr(export.wp, "_post", post)
    record = {
        "surface": "ui",
        "ui_product": product,
        "ui": {"endpoint": "http://127.0.0.1/prefix", "session_cookie": "sid=expired", "session_token": "expired-jwt"},
    }
    ctx = SimpleNamespace(args=SimpleNamespace(username="reader", password="same-password"))
    first = export.export_panel(ctx, record, selected)["ui"]["inventory"]["export"]
    assert first["partial"] is True and first["reason"], first
    prefix = Path(first["path"]).read_text()
    assert first["count"] > 0 and prefix
    fresh = True
    page_number = 0
    record["ui"].update(session_cookie="sid=fresh", session_token="fresh-jwt")
    final = export.export_panel(ctx, record, selected)["ui"]["inventory"]["export"]
    assert final["partial"] is False, final
    assert final["checkpoint"] == first["checkpoint"]
    rows = Path(final["path"]).read_text().splitlines()
    assert len(rows) == final["count"] == len(set(rows))
    assert all(line in rows for line in prefix.splitlines())
    expected_count = {
        "portainer": 101,
        "minio_console": 3,
        "redis_insight": 3,
        "mongo_express": 2,
        "kibana": 3,
        "opensearch_dashboards": 3,
        "pgadmin": 2,
    }[product]
    assert final["count"] == expected_count
    assert not any(secret in "\n".join(rows) for secret in ("sid=", "-jwt", "same-password", "\x1b"))
    assert calls and record.get("is_backend") is not True


@pytest.mark.parametrize("section", ["clusters", "brokers"])
@pytest.mark.parametrize("fault", [401, 403])
def test_kafka_inventory_session_expiry_is_explicit_partial(
    monkeypatch: pytest.MonkeyPatch, section: str, fault: int
) -> None:
    def get(_pool: Any, _base: str, path: str, **kw: Any) -> HttpResponse:
        if path.endswith("/" + section):
            return response({"error": "session expired"}, fault)
        if path == "/api/clusters":
            return response([{"name": "qa", "status": "online"}])
        return response([])

    monkeypatch.setattr(kafka_ui, "_get", get)
    state = SimpleNamespace(ui_base="http://qa", ui_http=object(), ui_cookie="sid=expired")
    result = kafka_ui.collect_ui(
        SimpleNamespace(), {"status": "valid_credentials"}, state, {"show_brokers": True, "show_topics": True}
    )
    assert result.get("ui_brokers_partial") is True, result
    assert result.get("ui_brokers_error") or result.get("error"), result
