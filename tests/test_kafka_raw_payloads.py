"""Discovery receives broker bytes before inventory's UTF8 rendering."""

from __future__ import annotations

import gzip
import struct
import time
from types import SimpleNamespace

import pytest

from redposture_core.clients import kafka
from redposture_core.discovery_bytes import SpoolBytes
from redposture_core.discovery_values import DiskBackedText
from redposture_core.modules.kafka.actions import _scan_broker_message
from redposture_core.storage_discovery import DiscoveryCollector
from tests.test_clients_kafka import _kstr, _varint


def records(raw, modern):
    if modern:
        record = b"\0" + _varint(0) + _varint(0) + _varint(-1) + _varint(len(raw)) + raw + _varint(0)
        body = struct.pack(">ibi hiqqqhii".replace(" ", ""), 0, 2, 0, 0, 0, 0, 0, -1, -1, -1, 1)
        body += _varint(len(record)) + record
    else:
        body = bytes(6) + struct.pack(">ii", -1, len(raw)) + raw
    return struct.pack(">qi", 0, len(body)) + body


@pytest.mark.parametrize("kind", ["utf8", "utf16", "gzip", "binary"])
@pytest.mark.parametrize("modern", [False, True])
@pytest.mark.parametrize("spooled", [False, True])
def test_broker_wire_payload_is_classified_before_text_replacement(monkeypatch, kind, modern, spooled):
    password = "qa-broker-raw-format-password"
    body = f'password="{password}"\n'
    raw = {
        "utf8": body.encode(),
        "utf16": body.encode("utf-16"),
        "gzip": gzip.compress(body.encode()),
        "binary": b"\xff\0unknown",
    }[kind]
    data = records(raw, modern)
    fetch = struct.pack(">iihii", 2, 0, 0, 0, 1) + _kstr("events")
    fetch += struct.pack(">iihqqqii", 1, 0, 0, 1, 1, 0, 0, len(data)) + data
    seen = []

    def send(_sock, **kwargs):
        seen.append(kwargs["api_key"])
        if kwargs["api_key"] == kafka.KAFKA_LIST_OFFSETS:
            return b"offset-reply"
        assert kwargs["correlation_id"] == 2
        if spooled:
            value = SpoolBytes()
            value.write(fetch)
            return value
        return fetch

    monkeypatch.setattr(kafka, "_send_kafka_request", send)
    monkeypatch.setattr(kafka, "_parse_list_offsets_response", lambda *a: (0, None))
    collector = DiscoveryCollector(
        "kafka",
        SimpleNamespace(
            args=SimpleNamespace(discover_time=30),
            host="qa",
            port=9092,
        ),
        {"status": "open_no_auth"},
    )
    items, _, error = kafka._read_partition_messages_on_leader(
        object(),
        1,
        "events",
        0,
        None,
        deadline=time.monotonic() + 30,
        budget=kafka.KafkaDiscoveryReadBudget(2**63 - 1, time.monotonic() + 30),
        on_message=lambda offset, value: _scan_broker_message(collector, "events", 0, offset, value),
    )
    assert error is None
    assert len(items) == 1
    assert seen == [kafka.KAFKA_LIST_OFFSETS, kafka.KAFKA_FETCH]
    result = collector.result()
    values = {
        "".join(r["value"].iter_text_chunks()) if isinstance(r["value"], DiskBackedText) else r["value"]
        for r in result["findings"]
    }
    if kind == "binary":
        assert result["status"] == "partial"
        assert not values
    else:
        assert result["status"] == "complete", result["partial_reasons"]
        assert values == {password}
        assert len(result["findings"]) == 1
        assert "partition.0.offset.0" in result["findings"][0]["object_path"]
