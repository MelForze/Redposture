"""Full Kafka UI export pagination, checkpoint and partial-result paths."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.kafka import ui


def response(value: object, status: int = 200) -> HttpResponse:
    return HttpResponse(status=status, body=json.dumps(value).encode(), headers={})


def state(vendor: str = "kafbat") -> SimpleNamespace:
    return SimpleNamespace(ui_base="http://qa", ui_http=object(), ui_cookie="", ui_vendor=vendor)


def context() -> SimpleNamespace:
    return SimpleNamespace(
        host="qa",
        port=8080,
        args=SimpleNamespace(username=None, password=None),
        live_emit=lambda _lines: None,
    )


def test_full_export_walks_topic_pages_and_cursors_without_repeating(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    fetched: list[str] = []

    def get(_pool: object, _base: str, path: str, **_kwargs: object) -> HttpResponse:
        fetched.append(path)
        if path == "/api/clusters":
            return response([{"name": "qa", "status": "online"}])
        if path.endswith("/topics?page=1&perPage=200"):
            return response([{"name": f"topic-{number}"} for number in range(200)])
        if path.endswith("/topics?page=2&perPage=200"):
            return response([{"name": "last"}])
        raise AssertionError(path)

    monkeypatch.setattr(ui, "_get", get)
    calls: list[tuple[str, str | None]] = []

    def read(_pool: object, _base: str, _cluster: str, topic: str, **kwargs: object):
        cursor = kwargs.get("cursor")
        calls.append((topic, cursor if isinstance(cursor, str) else None))
        if topic == "topic-0" and cursor is None:
            return ([{"partition": 0, "offset": 0, "value": "first"}], True, None, "next", True)
        if topic == "topic-0":
            return ([{"partition": 0, "offset": 1, "value": "second"}], True, None, None, True)
        return ([], True, None, None, True)

    monkeypatch.setattr(ui, "_read_ui_messages", read)
    record = ui.collect_ui(context(), {"status": "open_no_auth"}, state(), {"ui_dump_all": True})
    export = record["ui_export"]
    assert export["partial"] is False
    assert export["count"] == 2
    assert len(calls) == 202
    assert calls[:2] == [("topic-0", None), ("topic-0", "next")]
    assert len([path for path in fetched if "/topics?page=" in path]) == 2
    assert [json.loads(line)["value"]["value"] for line in Path(export["path"]).read_text().splitlines()] == [
        "first",
        "second",
    ]


def test_full_export_keeps_partial_checkpoint_and_resumes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)

    def get(_pool: object, _base: str, path: str, **_kwargs: object) -> HttpResponse:
        assert path == "/api/clusters"
        return response([{"name": "qa", "status": "online"}])

    monkeypatch.setattr(ui, "_get", get)
    attempts = 0

    def read(_pool: object, _base: str, _cluster: str, _topic: str, **kwargs: object):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return ([{"partition": 0, "offset": 0, "value": "first"}], True, None, "next", True)
        if attempts == 2:
            return ([], False, "HTTP 503", None, True)
        assert kwargs.get("cursor") == "next"
        return ([{"partition": 0, "offset": 1, "value": "second"}], True, None, None, True)

    monkeypatch.setattr(ui, "_read_ui_messages", read)
    options = {"ui_dump_all": True, "query_topic": "orders"}
    first = ui.collect_ui(context(), {"status": "open_no_auth"}, state(), options)["ui_export"]
    assert first["partial"] is True
    assert "HTTP 503" in first["reason"]
    second = ui.collect_ui(context(), {"status": "open_no_auth"}, state(), options)["ui_export"]
    assert second["partial"] is False
    assert second["count"] == 2
    assert len(Path(second["path"]).read_text().splitlines()) == 2


@pytest.mark.parametrize(
    "body,fragment", [({"topics": 1}, "topics unavailable"), ([{"name": "qa"}], "topics unavailable")]
)
def test_full_export_rejects_unknown_topic_page(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, body: object, fragment: str
) -> None:
    monkeypatch.chdir(tmp_path)

    def get(_pool: object, _base: str, path: str, **_kwargs: object) -> HttpResponse:
        if path == "/api/clusters":
            return response([{"name": "qa", "status": "online"}])
        return response(body, 500 if isinstance(body, list) else 200)

    monkeypatch.setattr(ui, "_get", get)
    result = ui.collect_ui(context(), {"status": "open_no_auth"}, state(), {"ui_dump_all": True})
    assert result["ui_export"]["partial"] is True
    assert fragment in result["ui_export"]["reason"]
