"""Kafka parser, unique cursor quotas, and durable incomplete-page boundaries."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.clients import kafka
from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.kafka import ui


def test_unlimited_native_dump_does_not_use_compressed_bytes_as_message_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    zstandard = pytest.importorskip("zstandard")
    count = 10_000

    def positive_varint(value: int) -> bytes:
        value <<= 1  # Kafka's signed varint uses zigzag encoding.
        encoded = bytearray()
        while value > 127:
            encoded.append((value & 127) | 128)
            value >>= 7
        return bytes([*encoded, value])

    records = []
    for offset in range(count):
        # Attributes=0, timestamp delta=0, unique offset delta, null key,
        # one-byte value x, and zero record headers.
        record = b"\x00\x00" + positive_varint(offset) + b"\x01\x02x\x00"
        records.append(positive_varint(len(record)) + record)
    suffix = struct.pack(">hiqqqhii", 4, count - 1, 0, 0, -1, -1, -1, count)
    suffix += zstandard.ZstdCompressor().compress(b"".join(records))
    batch = struct.pack(">ibI", 0, 2, kafka._crc32c(suffix)) + suffix
    message_set = struct.pack(">qi", 0, len(batch)) + batch
    fetch_offsets = []

    def send(_sock: Any, **kwargs: Any) -> bytes:
        correlation = kwargs["correlation_id"]
        topic = kafka._encode_kafka_string("events")
        if kwargs["api_key"] == kafka.KAFKA_LIST_OFFSETS:
            return struct.pack(">ii", correlation, 1) + topic + struct.pack(">iihiq", 1, 0, 0, 1, 0)
        reader = kafka._KafkaReader(kwargs["body"])
        reader._read(4 + 4 + 4 + 4 + 1 + 4 + 4 + 4)
        reader.read_string(nullable=False)
        reader.read_i32()
        reader.read_i32()
        reader.read_i32()
        fetch_offsets.append(reader.read_i64())
        assert len(fetch_offsets) <= 2, "snapshot reader did not make bounded progress"
        wire = (
            struct.pack(">iihii", correlation, 0, 0, 0, 1)
            + topic
            + struct.pack(">iihqqqii", 1, 0, 0, count, count, 0, -1, len(message_set))
            + message_set
        )
        assert len(wire) < count, "fixture must contain more messages than compressed wire bytes"
        return wire

    monkeypatch.setattr(kafka, "_send_kafka_request", send)
    messages, _correlation, error = kafka._read_partition_messages_on_leader(None, 1, "events", 0, None)
    assert error is None
    assert len(messages) == count
    assert messages == [f"p0@{offset} x" for offset in range(count)]
    assert fetch_offsets == [0]


@pytest.mark.parametrize("count", [-1, -2, 2**31 - 1])
def test_apiversions_requires_valid_nonnullable_array(count: int) -> None:
    result = kafka._parse_apiversions_response(struct.pack(">ihi", 7, 0, count), 7)
    assert not result.ok and result.error


@pytest.mark.parametrize("field", ["partition", "offset"])
def test_ui_rejects_negative_message_positions(field: str) -> None:
    message = {"partition": 0, "offset": 0, "value": "x", field: -1}
    body = "\n".join(
        "data: " + json.dumps(event) for event in [{"type": "MESSAGE", "message": message}, {"type": "DONE"}]
    )
    rows, done, error, cursor = ui._parse_message_events_page(
        HttpResponse(200, body.encode(), {"Content-Type": "text/event-stream"}), limit=10
    )
    assert rows == [] and not done and error == "invalid Kafka UI message position" and cursor is None


@pytest.mark.parametrize("mode", ["quota", "repeat", "error-prefix"])
def test_cursor_quota_counts_only_unique_positions(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    monkeypatch.setattr(ui, "_get", lambda *a, **kw: HttpResponse(200, b'[{"name":"qa","status":"online"}]', {}))
    calls = []

    def read(*args: Any, **kwargs: Any) -> Any:
        calls.append(kwargs["cursor"])
        assert len(calls) <= 3
        positions = [0, 1] if len(calls) == 1 else [1] if mode == "repeat" else [1, 2]
        rows = [{"partition": 0, "offset": x, "value": str(x)} for x in positions]
        if len(calls) == 1:
            return rows, True, None, "next", True
        return (
            rows,
            mode != "error-prefix",
            "broken page" if mode == "error-prefix" else None,
            "further" if mode == "repeat" else None,
            True,
        )

    monkeypatch.setattr(ui, "_read_ui_messages", read)
    state = SimpleNamespace(ui_base="http://qa", ui_http=object(), ui_cookie="", ui_vendor="kafbat")
    result = ui.collect_ui(
        SimpleNamespace(),
        {},
        state,
        {"query_topic": "orders", "dump": True, "max_messages": 3, "max_messages_explicit": True},
    )
    dumped = result["ui_dump_records"][0]
    assert [m["offset"] for m in dumped["messages"]] == ([0, 1] if mode == "repeat" else [0, 1, 2])
    assert dumped["complete"] is (mode == "quota")
    if mode == "repeat":
        assert "progress" in dumped["error"]
    if mode == "error-prefix":
        assert dumped["error"] == "broken page"
    assert len(calls) == 2


def test_full_incomplete_prefix_replays_without_advancing_checkpoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ui, "_get", lambda *a, **kw: HttpResponse(200, b'[{"name":"qa","status":"online"}]', {}))
    calls = []

    def read(*args: Any, **kwargs: Any) -> Any:
        calls.append(kwargs["cursor"])
        assert kwargs["cursor"] is None
        positions = [0] if len(calls) == 1 else [0, 1]
        return (
            [{"partition": 0, "offset": p, "value": str(p)} for p in positions],
            len(calls) != 1,
            "incomplete" if len(calls) == 1 else None,
            "must-not-commit" if len(calls) == 1 else None,
            True,
        )

    monkeypatch.setattr(ui, "_read_ui_messages", read)
    state = SimpleNamespace(ui_base="http://qa", ui_http=object(), ui_cookie="", ui_vendor="kafbat")
    ctx = SimpleNamespace(args=SimpleNamespace())
    options = {"ui_dump_all": True, "query_topic": "orders"}
    first = ui.collect_ui(ctx, {}, state, options)["ui_export"]
    assert first["partial"] and first["count"] == 1
    assert [json.loads(line)["value"]["offset"] for line in Path(first["path"]).read_text().splitlines()] == [0]
    second = ui.collect_ui(ctx, {}, state, options)["ui_export"]
    assert not second["partial"] and second["count"] == 2
    assert [json.loads(line)["value"]["offset"] for line in Path(second["path"]).read_text().splitlines()] == [0, 1]
