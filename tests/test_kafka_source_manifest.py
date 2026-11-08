"""Broker and UI sources count completed reads, not only detected values."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from redposture_core.modules.kafka import actions, ui
from redposture_core.modules.kafka.discovery import read_events
from redposture_core.scheduler import NestedSchedulerCancelled
from tests.test_kafka_ui_discovery_stream import _stream
from tests.test_kafka_ui_full_export_paths import response


@pytest.mark.parametrize("denied", [False, True])
@pytest.mark.parametrize("capped", [False, True])
def test_native_topic_metadata_and_empty_read_have_independent_evidence(monkeypatch, denied, capped):
    state = actions.KafkaLifecycleState(anonymous_metadata={"topic_map": {"events": {0: 1}}})
    ctx = SimpleNamespace(
        host="qa",
        port=9092,
        args=SimpleNamespace(discover=True, discover_time=30, timeout=1, debug=False),
        lifecycle_state=state,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
        debug_emit=None,
    )
    monkeypatch.setattr(
        actions,
        "_read_dump_topics",
        lambda **kw: (
            ({}, {"events": "TOPIC_AUTHORIZATION_FAILED"})
            if denied
            else ({"events": ["first", "second"] if capped else []}, {})
        ),
    )
    monkeypatch.setattr(actions, "_probe_kafka_acl_state", lambda **kw: ({}, {}))
    result = actions.collect_kafka_data(
        ctx,
        {"status": "open_no_auth"},
        {
            "dump": True,
            "show_topics": False,
            "max_messages": 2 if capped else None,
            "probe_write": False,
            "max_messages_explicit": False,
        },
    )["content_discovery"]
    rows = {r["id"]: r for r in result["sources"]}
    assert rows["kafka.broker_topic_metadata"]["read"] == 1
    row = rows["kafka.broker_message_walks"]
    assert row["requested"] == 1 and row["read"] == int(not denied and not capped)
    assert row["denied"] == int(denied) and row["complete"] == (not denied and not capped)
    assert not result["findings"]
    if capped and not denied:
        assert result["status"] == "partial"
        assert any("message_limit" in reason for reason in result["partial_reasons"])


@pytest.mark.parametrize("full", [True, False])
@pytest.mark.parametrize("denied", [False, True])
def test_ui_selected_topic_sources_and_fresh_repeat(monkeypatch, tmp_path, full, denied):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ui, "_get", lambda *a, **kw: response([{"name": "qa", "status": "online"}]))
    monkeypatch.setattr(ui, "_collect_cluster_inventory", lambda *a, **kw: None)
    monkeypatch.setattr(
        ui,
        "_read_ui_messages",
        lambda *a, **kw: ([], not denied, "HTTP 403 from Kafka UI message API" if denied else None, None, True),
    )
    for _ in range(2):
        ctx = SimpleNamespace(
            host="qa",
            port=8080,
            args=SimpleNamespace(discover=True, discover_time=30, _discover_implicit_dump=True),
            live_emit=lambda lines: None,
        )
        state = SimpleNamespace(ui_base="http://qa", ui_http=object(), ui_vendor="kafbat", ui_cookie="")
        result = ui.collect_ui(
            ctx, {"status": "open_no_auth"}, state, {"ui_dump_all": full, "query_topic": "events", "dump": True}
        )
        rows = {r["id"]: r for r in result["discover_sources"]}
        assert rows["kafka.ui_cluster_catalog"]["read"] == 1
        assert rows["kafka.ui_topic_catalog"]["requested"] == 0
        row = rows["kafka.ui_message_walks"]
        assert row["requested"] == 1 and row["read"] == int(not denied)
        assert row["denied"] == int(denied) and row["complete"] == (not denied)


def test_sse_does_not_swallow_scheduler_cancellation_as_runtime_error():
    with pytest.raises(NestedSchedulerCancelled):
        read_events(
            _stream({"type": "MESSAGE", "message": {"partition": 0, "offset": 0, "value": "safe"}}),
            "http://qa",
            cookie="",
            deadline=time.monotonic() + 30,
            limit=2,
            on_message=lambda message: (_ for _ in ()).throw(NestedSchedulerCancelled("stop")),
        )


@pytest.mark.parametrize("vendor", ["kafbat", "provectus"])
def test_bounded_ui_discover_can_count_a_disk_backed_message_without_materializing_json(monkeypatch, vendor):
    from redposture_core.data_discovery import inspect_record
    from redposture_core.discovery_values import DiskBackedText

    secret = "inactive-bounded-" + "Ab0_" * 30_000
    with DiskBackedText() as value:
        value.append_text('{"password":' + json.dumps(secret) + "}")
        value.finish()
        monkeypatch.setattr(ui, "_get", lambda *a, **kw: response([{"name": "qa", "status": "online"}]))
        monkeypatch.setattr(ui, "_collect_cluster_inventory", lambda *a, **kw: None)
        monkeypatch.setattr(
            ui,
            "_read_ui_messages",
            lambda *a, **kw: ([{"partition": 0, "offset": 0, "value": value}], True, None, None, True),
        )
        ctx = SimpleNamespace(
            host="qa", port=8080, args=SimpleNamespace(discover=True, discover_time=30, _discover_implicit_dump=True)
        )
        state = SimpleNamespace(ui_base="http://qa", ui_http=object(), ui_vendor=vendor, ui_cookie="")
        result = ui.collect_ui(
            ctx,
            {"status": "open_no_auth"},
            state,
            {
                "dump": True,
                "ui_dump_all": False,
                "query_topic": "events",
                "max_messages": 1,
                "max_messages_explicit": True,
            },
        )
        assert result["ui_dump_records"][0]["messages"][0]["value"] is value
        report = inspect_record("kafka", result)
        found = [f["value"] for f in report["findings"]]
        assert [("".join(v.iter_text_chunks()) if isinstance(v, DiskBackedText) else v) for v in found] == [secret]
