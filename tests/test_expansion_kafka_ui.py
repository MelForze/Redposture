"""Kafka UI failure framing, read-only routes and login outcome contracts."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.kafka import ui


def response(value: Any, status: int = 200, **extra: Any) -> HttpResponse:
    body = value.encode() if isinstance(value, str) else json.dumps(value).encode()
    return HttpResponse(status=status, body=body, headers=extra.pop("headers", {}), **extra)


def events(*items: Any, **extra: Any) -> HttpResponse:
    return response(
        "\n".join("data: " + json.dumps(item) for item in items), headers={"Content-Type": "text/event-stream"}, **extra
    )


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (response("", error="reset"), "reset"),
        (response("", status=403), "HTTP 403 from Kafka UI message API"),
        (response({}), "Kafka UI message API did not return an event stream"),
        (events([]), "invalid Kafka UI message event"),
        (events({"type": "ERROR"}), "Kafka UI message stream reported an error"),
        (events({"type": "MESSAGE", "message": []}), "invalid Kafka UI message payload"),
        (events({"type": "MESSAGE", "message": {"value": 3}}), "invalid Kafka UI message value"),
        (
            events({"type": "MESSAGE", "message": {"value": "x", "partition": "0", "offset": 1}}),
            "invalid Kafka UI message position",
        ),
        (events({"type": "DONE"}, truncated=True), "Kafka UI message response exceeded 8 MiB"),
        (events({"type": "PROGRESS"}), "Kafka UI message stream ended without completion"),
    ],
)
def test_message_stream_errors_have_no_completion_or_cursor(answer: HttpResponse, reason: str) -> None:
    assert ui._parse_message_events_page(answer, limit=3) == ([], False, reason, None)


def test_message_limit_preserves_requested_positions_without_false_completion() -> None:
    answer = events(
        *[{"type": "MESSAGE", "message": {"content": f"value-{i}", "partition": 2, "offset": i}} for i in range(3)],
        {"type": "DONE", "cursor": {"id": "cursor"}},
    )
    rows, done, error, cursor = ui._parse_message_events_page(answer, limit=2)
    assert rows == [
        {"partition": 2, "offset": i, "timestamp": None, "key": None, "value": f"value-{i}", "headers": None}
        for i in range(2)
    ]
    assert (done, error, cursor) == (False, "Kafka UI returned more messages than requested", None)


@pytest.mark.parametrize(
    "partitions",
    [
        None,
        [],
        [None],
        [{"partition": True, "offsetMin": 0, "offsetMax": 1}],
        [{"partition": 0, "offsetMin": 5, "offsetMax": 4}],
        [{"partition": 0, "offsetMin": 0, "offsetMax": 1}] * 2,
    ],
)
def test_legacy_offsets_reject_unknown_or_inconsistent_snapshots(
    monkeypatch: pytest.MonkeyPatch, partitions: Any
) -> None:
    seen: list[tuple[Any, ...]] = []

    def get(_pool: Any, base: str, path: str, **kwargs: Any) -> HttpResponse:
        seen.append((base, path, kwargs))
        return response({"partitions": partitions})

    monkeypatch.setattr(ui, "_get", get)
    assert ui._legacy_topic_offsets(object(), "http://panel", "cluster/1", "topic/1", cookie="sid=1") is None
    assert seen == [("http://panel", "/api/clusters/cluster%2F1/topics/topic%2F1", {"cookie": "sid=1"})]


def test_legacy_message_seek_uses_ordered_partition_snapshot_and_read_only_get() -> None:
    calls: list[str] = []

    class Pool:
        def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
            assert method == "GET"
            assert kwargs["headers"] == {"Accept": "text/event-stream", "Cookie": "sid=1"}
            assert kwargs["allow_cross_origin_redirects"] is False
            assert kwargs["preserve_authorization_on_cross_origin"] is False
            calls.append(url)
            return events({"type": "DONE"})

    assert ui._read_ui_messages(
        Pool(), "http://panel", "c/1", "t/1", vendor="provectus", cookie="sid=1", limit=700, offsets={2: 5, 0: 3}
    ) == ([], True, None, None, False)
    parsed = urlsplit(calls[0])
    assert parsed.path == "/api/clusters/c%2F1/topics/t%2F1/messages"
    assert parse_qs(parsed.query) == {"limit": ["500"], "seekType": ["OFFSET"], "seekTo": ["0::3", "2::5"]}
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("post", "identity", "source", "status", "ok"),
    [
        (response("", status=429), None, "provided", "rate_limited", None),
        (response("CAPTCHA required"), None, "provided", "rate_limited", None),
        (
            response("", status=302, headers={"Location": "/login?error"}),
            None,
            "provided",
            "invalid_credentials",
            False,
        ),
        (response("", status=403), None, "provided", "unknown_auth", None),
        (response("", status=302), {"userInfo": {"username": "other"}}, "provided", "unknown_auth", None),
        (response("", status=302), {"userInfo": {"username": "user"}}, "default", "weak_default_creds", None),
    ],
)
def test_login_outcomes_require_identity_and_keep_default_credentials_separate(
    post: HttpResponse, identity: Any, source: str, status: str, ok: bool | None
) -> None:
    calls: list[tuple[str, str]] = []

    class Pool:
        def request_once(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
            calls.append((method, url))
            if method == "GET":
                return response('<input name="_csrf" value="a&amp;b">', headers={"Set-Cookie": "sid=1; Path=/"})
            assert parse_qs(kwargs["body"].decode()) == {"username": ["user"], "password": ["pass"], "_csrf": ["a&b"]}
            assert kwargs["headers"]["Cookie"] == "sid=1"
            return post

        def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
            calls.append((method, url))
            assert kwargs["headers"]["Cookie"] == "sid=1"
            return (
                response(identity)
                if url.endswith("/api/authorization")
                else response({"build": {"commitId": "abc", "version": "1.0.0", "name": "kafbat"}})
            )

    state = SimpleNamespace(ui_base="http://panel/prefix", ui_http=Pool(), ui_auth_type="LOGIN_FORM", ui_cookie="")
    result = ui.authenticate_ui(
        SimpleNamespace(credential=SimpleNamespace(username="user", password="pass", source=source)),
        {"is_kafka_ui": True, "is_kafka": False},
        state,
    )
    assert result["status"] == status
    assert result["provided_credentials_ok"] is ok
    assert result["is_kafka"] is False
    assert result["credential_attempts"][0]["default"] is (source == "default")
    assert calls[:2] == [("GET", "http://panel/prefix/login"), ("POST", "http://panel/prefix/login")]
    assert len(calls) == (4 if status == "weak_default_creds" else 3 if identity is not None else 2)
    assert state.ui_cookie == ("sid=1" if status == "weak_default_creds" else "")


@pytest.mark.parametrize("field", ["partition", "offset"])
def test_message_stream_rejects_boolean_positions(field: str) -> None:
    message = {"value": "data", "partition": 0, "offset": 1, field: True}
    answer = events({"type": "MESSAGE", "message": message}, {"type": "DONE"})
    assert ui._parse_message_events_page(answer, limit=10) == ([], False, "invalid Kafka UI message position", None)


@pytest.mark.parametrize(
    ("mode", "vendor", "reason"),
    [
        ("message-error", "kafbat", "Kafka UI c/t: denied"),
        ("message-incomplete", "kafbat", "Kafka UI c/t: incomplete message page"),
        ("legacy-missing", "provectus", "legacy Kafka UI c/t: end offsets unavailable"),
        ("legacy-fallback-missing", "kafbat", "legacy Kafka UI c/t: end offsets unavailable"),
        ("legacy-stalled", "provectus", "legacy Kafka UI c/t: no offset progress"),
        ("repeated-cursor", "kafbat", "Kafka UI c/t: repeated cursor"),
    ],
)
def test_full_export_failure_retains_partial_checkpoint_and_does_not_claim_completion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, mode: str, vendor: str, reason: str
) -> None:
    monkeypatch.chdir(tmp_path)
    paths: list[str] = []
    calls: list[Any] = []

    def get(_pool: Any, _base: str, path: str, **kwargs: Any) -> HttpResponse:
        paths.append(path)
        assert kwargs == {"cookie": "sid=1"}
        return response([{"name": "c", "status": "online"}])

    def snapshot(*_args: Any, **_kwargs: Any) -> Any:
        return None if "missing" in mode else ({0: 0}, {0: 2})

    def read(*_args: Any, **kwargs: Any) -> Any:
        calls.append(kwargs)
        if mode == "message-error":
            return [], False, "denied", None, True
        if mode == "message-incomplete":
            return [], False, None, None, True
        if mode == "repeated-cursor":
            return [{"partition": 0, "offset": 0, "value": "once"}], True, None, "same", True
        return [], True, None, None, False

    monkeypatch.setattr(ui, "_get", get)
    monkeypatch.setattr(ui, "_legacy_topic_offsets", snapshot)
    monkeypatch.setattr(ui, "_read_ui_messages", read)
    result = ui._collect_ui_full(
        SimpleNamespace(args=SimpleNamespace()),
        {"status": "valid_credentials", "is_kafka": False},
        SimpleNamespace(ui_base="http://panel", ui_http=object(), ui_cookie="sid=1", ui_vendor=vendor),
        {"query_topic": "t"},
    )
    outcome = result["ui_export"]
    assert outcome["partial"] is True
    assert outcome["reason"] == reason
    assert outcome["count"] == (1 if mode == "repeated-cursor" else 0)
    assert paths == ["/api/clusters"]
    assert len(calls) == (0 if mode == "legacy-missing" else 2 if mode == "repeated-cursor" else 1)
    if calls:
        assert calls[0]["cursor"] is None
        assert calls[0]["limit"] == 500
    if mode == "repeated-cursor":
        assert calls[1]["cursor"] == "same"
        saved = json.loads(tmp_path.joinpath(outcome["path"]).read_text())
        assert saved["value"] == {"cluster": "c", "topic": "t", "partition": 0, "offset": 0, "value": "once"}


@pytest.mark.parametrize(
    ("mode", "expected", "messages"),
    [
        ("oversized", "Kafka UI dump byte budget reached", []),
        ("legacy-missing", "legacy Kafka UI topic end offsets unavailable", [{"partition": 0, "offset": 0}]),
        ("legacy-stalled", "legacy Kafka UI made no offset progress before topic end", []),
        ("incomplete", "denied", [{"partition": 0, "offset": 0}]),
    ],
)
def test_bounded_dump_failure_preserves_only_verified_or_explicit_partial_rows(
    monkeypatch: pytest.MonkeyPatch, mode: str, expected: str, messages: list[Any]
) -> None:
    monkeypatch.setattr(ui, "_get", lambda *_args, **_kwargs: response([{"name": "c", "status": "online"}]))
    monkeypatch.setattr(ui, "_MAX_DUMP_BYTES", 1 if mode == "oversized" else 1000)
    monkeypatch.setattr(
        ui, "_legacy_topic_offsets", lambda *_args, **_kwargs: None if mode == "legacy-missing" else ({0: 0}, {0: 5})
    )
    page = [] if mode == "legacy-stalled" else [{"partition": 0, "offset": 0}]
    monkeypatch.setattr(
        ui,
        "_read_ui_messages",
        lambda *_args, **_kwargs: (
            page,
            mode != "incomplete",
            "denied" if mode == "incomplete" else None,
            None,
            mode not in {"legacy-stalled", "legacy-missing"},
        ),
    )
    result = ui.collect_ui(
        SimpleNamespace(args=SimpleNamespace()),
        {"is_kafka_ui": True, "is_kafka": False},
        SimpleNamespace(ui_base="http://panel", ui_http=object(), ui_cookie="", ui_vendor="kafbat"),
        {"dump": True, "query_topic": "t"},
    )
    assert result["ui_dump_partial"] is True
    assert result["ui_dump_records"] == [
        {"cluster": "c", "topic": "t", "messages": messages, "complete": False, "error": expected}
    ]
    assert result["is_kafka"] is False


@pytest.mark.parametrize("groups", [{}, [{"groupId": "g"}] * 100])
def test_consumer_group_invalid_or_stalled_page_marks_partial(monkeypatch: pytest.MonkeyPatch, groups: Any) -> None:
    paths: list[str] = []

    def get(_pool: Any, _base: str, path: str, **_kwargs: Any) -> HttpResponse:
        paths.append(path)
        return response([{"name": "c", "status": "online"}]) if path == "/api/clusters" else response(groups)

    monkeypatch.setattr(ui, "_get", get)
    result = ui.collect_ui(
        SimpleNamespace(),
        {},
        SimpleNamespace(ui_base="http://panel", ui_http=object(), ui_cookie=""),
        {"show_consumer_groups": True},
    )
    assert result["ui_consumer_groups_partial"] is True
    assert result["ui_consumer_groups"] == ([{"cluster": "c", "name": "g"}] if isinstance(groups, list) else [])
    assert paths == ["/api/clusters", "/api/clusters/c/consumer-groups/paged?page=1&perPage=100"] + (
        ["/api/clusters/c/consumer-groups/paged?page=2&perPage=100"] if isinstance(groups, list) else []
    )
