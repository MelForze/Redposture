"""Native and UI bare-dump parity: independently seeded messages through lifecycle."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.modules.kafka import actions, stage
from redposture_core.stage_runtime import AuditCredentialRun


def collect(monkeypatch: pytest.MonkeyPatch, *, size: int, count: int | bool) -> tuple[dict[str, Any], list[str]]:
    args = SimpleNamespace(dump=count, max_messages=None, timeout=1, debug=False)
    options = stage._build_kafka_lifecycle_options(args)
    dataset = [f"p0@{i} seed-{i}" for i in range(size)]
    state = actions.KafkaLifecycleState(
        is_kafka=True, auth_required=False, transport_mode="plaintext", anonymous_metadata={"topic_map": {"events": 1}}
    )
    ctx = SimpleNamespace(
        host="kafka-fixture.invalid",
        port=9092,
        args=args,
        lifecycle_state=state,
        credential=AuditCredentialRun(source="anonymous"),
    )

    def read(**kwargs: Any) -> tuple[dict[str, list[str]], dict[str, str]]:
        assert kwargs["topics"] == ["events"]
        limit = kwargs["max_messages"]
        return {"events": dataset[:limit]}, {}

    monkeypatch.setattr(actions, "_read_dump_topics", read)
    monkeypatch.setattr(actions, "_probe_kafka_acl_state", lambda **kwargs: ({"events": {"read": True}}, {}))
    try:
        return actions.collect_kafka_data(ctx, {"status": "open_no_auth"}, options), dataset
    finally:
        state.close()


@pytest.mark.parametrize("count", [1, 10, 1205])
def test_native_explicit_limit_matches_exact_seed_dataset(monkeypatch: pytest.MonkeyPatch, count: int) -> None:
    record, dataset = collect(monkeypatch, size=1307, count=count)
    assert record["dump_results"] == {"events": dataset[:count]}
    assert record["max_messages_explicit"] is True
    assert record["error"] is None


@pytest.mark.parametrize("size", [11, 1205])
def test_native_bare_dump_must_not_silently_cap_at_ten_and_claim_complete(
    monkeypatch: pytest.MonkeyPatch, size: int
) -> None:
    record, dataset = collect(monkeypatch, size=size, count=True)
    assert record["max_messages_explicit"] is False
    assert record["dump_results"] == {"events": dataset}, (
        f"bare dump lost {size - len(record['dump_results']['events'])} messages; coverage={record['dump_coverage']}"
    )


@pytest.mark.parametrize("full", [False, True])
@pytest.mark.parametrize(
    ("option", "field", "expected"),
    [
        ("show_topics", "ui_topics", [{"cluster": "qa22", "name": "empty"}]),
        ("show_brokers", "ui_brokers", [{"cluster": "qa22", "id": 1, "host": "broker"}]),
        ("show_consumer_groups", "ui_consumer_groups", [{"cluster": "qa22", "name": "qa-consumer"}]),
    ],
)
def test_ui_full_dump_preserves_requested_inventory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    option: str,
    full: bool,
    field: str,
    expected: list[dict[str, Any]],
) -> None:
    import json

    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.modules.kafka import ui

    def get(_pool: Any, _base: str, path: str, **kwargs: Any) -> HttpResponse:
        if path == "/api/clusters":
            value: Any = [{"name": "qa22", "status": "online"}]
        elif "/topics" in path:
            value = [{"name": "empty"}]
        elif "/brokers" in path:
            value = [{"id": 1, "host": "broker", "port": 9092}]
        elif "/consumer-groups" in path:
            value = [{"groupId": "qa-consumer"}]
        else:
            pytest.fail(f"unexpected route {path}")
        return HttpResponse(200, json.dumps(value).encode(), {})

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ui, "_get", get)
    monkeypatch.setattr(ui, "_read_ui_messages", lambda *a, **kw: ([], True, None, None, True))
    state = SimpleNamespace(ui_base="http://qa22", ui_http=object(), ui_cookie="", ui_vendor="kafbat")
    ctx = SimpleNamespace(args=SimpleNamespace())
    result = ui.collect_ui(ctx, {"status": "open_no_auth"}, state, {option: True, "dump": True, "ui_dump_all": full})
    if full:
        assert result["ui_export"]["partial"] is False
    assert result.get(field) == expected, "bare --dump bypasses requested inventory"


@pytest.mark.parametrize("full", [False, True])
def test_ui_interrupted_sse_page_preserves_already_decoded_messages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, full: bool
) -> None:
    """A valid immutable message remains useful even when its page has no DONE."""
    import json
    from pathlib import Path
    from urllib.parse import urlsplit

    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.modules.kafka import ui

    class Pool:
        def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse:
            assert method == "GET"
            path = urlsplit(url).path
            if path == "/api/clusters":
                return HttpResponse(200, b'[{"name":"qa22","status":"online"}]', {})
            assert path == "/api/clusters/qa22/topics/events/messages/v2", path
            message = {"type": "MESSAGE", "message": {"partition": 0, "offset": 0, "value": "received-before-break"}}
            # HTTP framing is intact, but the upstream SSE stream ended before DONE.
            return HttpResponse(
                200, ("data: " + json.dumps(message) + "\n\n").encode(), {"Content-Type": "text/event-stream"}
            )

    monkeypatch.chdir(tmp_path)
    args = SimpleNamespace(dump=True if full else 10, max_messages=None, topic="events")
    options = stage._build_kafka_lifecycle_options(args)
    state = SimpleNamespace(ui_base="http://qa22", ui_http=Pool(), ui_cookie="", ui_vendor="kafbat")
    result = ui.collect_ui(SimpleNamespace(args=args), {"status": "open_no_auth"}, state, options)
    reason = "Kafka UI message stream ended without completion"
    if full:
        outcome = result["ui_export"]
        assert outcome["partial"] is True and reason in outcome["reason"]
        rows = [json.loads(line)["value"] for line in Path(outcome["path"]).read_text().splitlines()]
    else:
        assert result["ui_dump_partial"] is True
        outcome = result["ui_dump_records"][0]
        assert reason in outcome["error"] and outcome["complete"] is False
        rows = outcome["messages"]
    assert [(row["partition"], row["offset"], row["value"]) for row in rows] == [(0, 0, "received-before-break")]
