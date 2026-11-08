"""Kafka UI discovery must preserve completed messages across SSE failures."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.kafka.discovery import read_events


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
def test_denied_sse_body_cannot_publish_messages_or_early_findings(status: int) -> None:
    observed: list[dict] = []
    response, messages, complete, error, _cursor = read_events(
        _stream(
            {"type": "MESSAGE", "message": {"partition": 0, "offset": 0, "value": 'password="denied-body!42"'}},
            {"type": "DONE"},
            status=status,
        ),
        "http://ui/messages",
        cookie="session=qa",
        deadline=time.monotonic() + 30,
        limit=2,
        on_message=observed.append,
    )
    assert response.status == status and not complete and error
    assert not observed and not messages


def _stream(*events: dict, content_type: str = "text/event-stream", status: int = 200):
    body = b"\n".join(b"data:" + json.dumps(event).encode() for event in events) + b"\n"

    class Pool:
        def request_stream(self, _method, _url, **kwargs):
            kwargs["on_response"](status, {"Content-Type": content_type})
            for offset in range(0, len(body), 17):
                kwargs["on_chunk"](body[offset : offset + 17])
            return SimpleNamespace(status=status, error=None)

    return Pool()


def test_kafka_ui_sse_keeps_long_message_and_done_cursor() -> None:
    value = "qa-token-" + "A" * 120_000
    observed: list[dict] = []
    response, messages, complete, error, cursor = read_events(
        _stream(
            {"type": "MESSAGE", "message": {"partition": 0, "offset": 4, "value": value}},
            {"type": "DONE", "cursor": {"id": "next-5"}},
        ),
        "http://ui/messages",
        cookie="session=qa",
        deadline=time.monotonic() + 30,
        limit=2,
        on_message=observed.append,
    )
    assert response.status == 200
    assert complete and error is None and cursor == "next-5"
    assert len(messages) == len(observed) == 1
    assert isinstance(messages[0]["value"], DiskBackedText)
    assert "".join(messages[0]["value"].iter_text_chunks()) == value


def test_kafka_ui_sse_invalid_position_preserves_prior_message() -> None:
    _response, messages, complete, error, _cursor = read_events(
        _stream(
            {"type": "MESSAGE", "message": {"partition": 0, "offset": 4, "value": "first"}},
            {"type": "MESSAGE", "message": {"partition": True, "offset": 5, "value": "bad"}},
        ),
        "http://ui/messages",
        cookie="",
        deadline=time.monotonic() + 30,
        limit=2,
    )
    assert not complete and "invalid Kafka UI message position" in str(error)
    assert [(item["partition"], item["offset"]) for item in messages] == [(0, 4)]


def test_kafka_ui_sse_wrong_media_type_and_unfinished_stream_are_not_complete() -> None:
    for pool, expected in (
        (_stream({"type": "DONE"}, content_type="application/json"), "event stream"),
        (_stream({"type": "MESSAGE", "message": {"partition": 0, "offset": 1}}), "without completion"),
    ):
        _response, messages, complete, error, _cursor = read_events(
            pool, "http://ui/messages", cookie="", deadline=time.monotonic() + 30, limit=1
        )
        assert not complete and expected in str(error)
        assert not messages or messages[0]["offset"] == 1
