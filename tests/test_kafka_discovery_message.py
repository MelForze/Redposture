"""Broker discovery scans raw values before their UI display prefix."""

from __future__ import annotations

import time
from types import SimpleNamespace

from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.kafka import actions
from redposture_core.storage_discovery import DiscoveryCollector


def test_broker_discovery_callback_reaches_native_dump_reader(monkeypatch):
    received = {}

    def reader(*, on_message=None, **kwargs):
        received.update(kwargs)
        received["on_message"] = on_message
        return {}, {}

    monkeypatch.setattr(actions, "_CLIENT_READ_DUMP_TOPICS", reader)

    def callback(*_args: object) -> None:
        pass

    actions._read_dump_topics(
        host="qa",
        port=9092,
        timeout=1.0,
        topics=["events"],
        max_messages=None,
        username=None,
        password=None,
        on_message=callback,
    )
    assert received["on_message"] is callback


def test_broker_message_discovers_large_json_value_before_next_fetch():
    emitted = []
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover_time=30),
        discovery_started_at=time.monotonic(),
        host="qa",
        port=9092,
        live_emit=emitted.append,
        live_discovery_value=lambda *args, **kwargs: emitted.append((args, kwargs)),
    )
    collector = DiscoveryCollector("kafka", ctx, {"status": "open_no_auth"})
    value = DiskBackedText()
    value.append_text('{"password":"' + "LargeExactTokenABC" * 10000 + '"}')
    value.finish()
    actions._scan_broker_message(collector, "events", 0, 7, value)
    result = collector.result()
    assert result["status"] == "complete"
    assert len(result["findings"]) == 1
    found = result["findings"][0]["value"]
    assert "".join(found.iter_text_chunks()) == "LargeExactTokenABC" * 10000
    assert len(emitted) == 1


def test_broker_explicit_dump_spools_full_value_to_txt(tmp_path):
    from redposture_core.discovery_spool import SpoolingValues

    value = DiskBackedText()
    value.append_text("p0@7 " + "long-secret-123" * 20000)
    value.finish()
    rows = SpoolingValues()
    rows.append(value)
    record = {
        "host": "qa",
        "port": 9092,
        "dump_topics": ["events"],
        "dump_results": {"events": rows},
        "dump_errors": {},
        "dump_coverage": {"topics": [{"topic": "events", "status": "complete"}]},
    }
    result = actions._spool_kafka_dump_details(record)
    text = open(result, encoding="utf-8").read()
    assert "long-secret-123" * 20000 in text
    assert "DiskBackedText" not in text
