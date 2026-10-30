"""Discovery reads large Kafka wire frames without a frame-size rejection."""

from __future__ import annotations

import hashlib
import importlib
import socket
import struct
import threading
import time

import pytest

from redposture_core.clients import kafka
from redposture_core.discovery_values import DiskBackedText


def test_discovery_frame_spools_large_body_and_round_trips_utf8(monkeypatch):
    left, right = socket.socketpair()
    body = ("prefix\r\nсекрет" * 100000).encode()
    monkeypatch.setattr(kafka, "KAFKA_MAX_FRAME", 1024)

    def writer():
        right.sendall(struct.pack(">i", len(body)) + body)
        right.close()

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        budget = kafka.KafkaDiscoveryReadBudget(remaining=1024, deadline=time.monotonic() + 10)
        frame = kafka._recv_kafka_frame(left, budget=budget)
        assert len(frame) == len(body)
        decoded = frame.decode("utf-8", errors="replace")
        assert isinstance(decoded, DiskBackedText)
        assert decoded.digest == hashlib.sha256(body).hexdigest()
    finally:
        left.close()
        thread.join()


def test_discovery_gzip_batch_decompresses_past_legacy_cap(monkeypatch):
    import gzip

    from redposture_core.discovery_bytes import SpoolBytes

    source = b"record-secret-123\r\n" * 100000
    compressed = SpoolBytes()
    compressed.write(gzip.compress(source))
    monkeypatch.setattr(kafka, "KAFKA_MAX_DECOMPRESSED_BYTES", 1024)
    result = kafka._decompress_kafka_records(1, compressed)
    assert isinstance(result, SpoolBytes)
    assert hashlib.sha256(b"".join(result.iter_chunks())).digest() == hashlib.sha256(source).digest()


@pytest.mark.parametrize("codec", [1, 3, 4])
def test_discovery_compression_large_across_optional_codecs(codec, monkeypatch):
    import gzip

    from redposture_core.discovery_bytes import SpoolBytes

    data = b'{"api_token":"real-token-123"}\n' * 40000
    if codec == 1:
        encoded = gzip.compress(data)
    elif codec == 3:
        encoded = importlib.import_module("lz4.frame").compress(data)
    else:
        import zstandard

        encoded = zstandard.ZstdCompressor().compress(data)
    wrapped = SpoolBytes()
    wrapped.write(encoded)
    monkeypatch.setattr(kafka, "KAFKA_MAX_DECOMPRESSED_BYTES", 1024)
    decoded = kafka._decompress_kafka_records(codec, wrapped)
    assert isinstance(decoded, SpoolBytes)
    assert hashlib.sha256(b"".join(decoded.iter_chunks())).digest() == hashlib.sha256(data).digest()


def test_discovery_snappy_raw_block_and_truncation():
    from redposture_core.discovery_bytes import SpoolBytes

    original = b"abcd" * 100
    # Raw Snappy: declared length 400, literal 4, then copy from 4 bytes back.
    encoded = bytearray(b"\x90\x03\x0c" + b"abcd")
    for size in [64] * 6 + [12]:
        encoded.extend(bytes([((size - 1) << 2) | 2, 4, 0]))
    wrapped = SpoolBytes()
    wrapped.write(bytes(encoded))
    assert b"".join(kafka._decompress_kafka_records(2, wrapped).iter_chunks()) == original
    broken = SpoolBytes()
    broken.write(bytes(encoded[:-1]))
    with pytest.raises(kafka.KafkaCompressionError):
        kafka._decompress_kafka_records(2, broken)


@pytest.mark.parametrize("codec", [1, 3, 4])
def test_discovery_compression_rejects_truncated_tail(codec):
    import gzip

    from redposture_core.discovery_bytes import SpoolBytes

    data = b"secret-value-" * 10000
    if codec == 1:
        encoded = gzip.compress(data)
    elif codec == 3:
        encoded = importlib.import_module("lz4.frame").compress(data)
    else:
        import zstandard

        encoded = zstandard.ZstdCompressor().compress(data)
    wrapped = SpoolBytes()
    wrapped.write(encoded[:-2])
    with pytest.raises(kafka.KafkaCompressionError):
        kafka._decompress_kafka_records(codec, wrapped)


def test_discovery_record_batch_preserves_large_json_value():
    from redposture_core.discovery_bytes import SpoolBytes

    value = b'{"password":"' + b"Z" * 1500000 + b'"}'
    batch = kafka._build_produce_probe_batch(value)
    wrapped = SpoolBytes()
    wrapped.write(batch)
    entries = kafka._parse_message_set_entries(wrapped, None)
    assert len(entries) == 1
    decoded = entries[0][1]
    assert isinstance(decoded, DiskBackedText)
    assert decoded.digest == hashlib.sha256(value).hexdigest()


def test_discovery_record_catalog_uses_disk_for_many_messages():
    from redposture_core.discovery_bytes import SpoolBytes
    from redposture_core.discovery_spool import SpoolingValues

    chunks = []
    for index in range(10000):
        batch = kafka._build_produce_probe_batch(f'{{"password":"secret-{index}"}}'.encode())
        chunks.append(batch)
    frame = SpoolBytes()
    for chunk in chunks:
        frame.write(chunk)
    entries = kafka._parse_message_set_entries(frame, None)
    assert isinstance(entries, SpoolingValues)
    assert len(entries) == 10000
    assert entries[9999][1] == '{"password":"secret-9999"}'


def test_discovery_partition_delivers_complete_messages_before_followup_fetch(monkeypatch):
    seen = []
    calls = []
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda _sock, **kw: calls.append(kw["api_key"]) or b"frame")
    monkeypatch.setattr(kafka, "_parse_list_offsets_response", lambda *_: (0, None))

    def parse(*_a, progress, **_kw):
        progress.update(high_watermark=2, next_offset=1 if calls.count(kafka.KAFKA_FETCH) == 1 else 2)
        if calls.count(kafka.KAFKA_FETCH) == 2:
            assert seen == [(0, '{"password":"first"}')]
            return [(1, '{"password":"second"}')], None
        return [(0, '{"password":"first"}')], None

    monkeypatch.setattr(kafka, "_parse_fetch_response", parse)
    result, *_ = kafka._read_partition_messages_on_leader(
        object(), 1, "events", 0, None, on_message=lambda offset, value: seen.append((offset, value))
    )
    assert len(result) == 2
    assert seen == [(0, '{"password":"first"}'), (1, '{"password":"second"}')]


def test_discovery_partition_keeps_earlier_message_when_next_fetch_is_corrupt(monkeypatch):
    seen = []
    calls = []
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda _sock, **kw: calls.append(kw["api_key"]) or b"frame")
    monkeypatch.setattr(kafka, "_parse_list_offsets_response", lambda *_: (0, None))

    def parse(*_args, progress, **_kwargs):
        if calls.count(kafka.KAFKA_FETCH) == 1:
            progress.update(high_watermark=2, next_offset=1)
            return [(0, '{"password":"first"}')], None
        return None, "invalid Fetch response: truncated gzip batch"

    monkeypatch.setattr(kafka, "_parse_fetch_response", parse)
    items, _correlation, error = kafka._read_partition_messages_on_leader(
        object(), 1, "events", 0, None, on_message=lambda offset, value: seen.append((offset, value))
    )
    assert seen == [(0, '{"password":"first"}')]
    assert items == ['p0@0 {"password":"first"}']
    assert error == "invalid Fetch response: truncated gzip batch"


def test_discovery_fetch_requests_can_receive_one_large_record(monkeypatch):
    requested = []
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda _sock, **_kw: b"frame")
    monkeypatch.setattr(kafka, "_parse_list_offsets_response", lambda *_: (0, None))

    def build(*_args, max_bytes, **_kwargs):
        requested.append(max_bytes)
        return b"fetch"

    monkeypatch.setattr(kafka, "_build_fetch_request_body", build)
    monkeypatch.setattr(kafka, "_parse_fetch_response", lambda *_a, progress, **_k: ([], None))
    budget = kafka.KafkaDiscoveryReadBudget(remaining=2**63 - 1, deadline=time.monotonic() + 10)
    kafka._read_partition_messages_on_leader(object(), 1, "events", 0, None, budget=budget)
    assert requested and requested[0] >= 10_000_000


def test_discovery_compressed_record_batch_scans_value_beyond_legacy_cap(monkeypatch):
    import gzip

    from redposture_core.discovery_bytes import SpoolBytes

    value = b'{"password":"' + b"Q" * 1200000 + b'"}'
    plain = kafka._build_produce_probe_batch(value)
    compressed = gzip.compress(plain[61:])
    batch = (
        plain[:8]
        + struct.pack(">i", 49 + len(compressed))
        + plain[12:21]
        + struct.pack(">h", 1)
        + plain[23:61]
        + compressed
    )
    wrapped = SpoolBytes()
    wrapped.write(batch)
    monkeypatch.setattr(kafka, "KAFKA_MAX_DECOMPRESSED_BYTES", 1024)
    entries = kafka._parse_message_set_entries(wrapped, None)
    assert len(entries) == 1
    decoded = entries[0][1]
    assert isinstance(decoded, DiskBackedText)
    assert decoded.digest == hashlib.sha256(value).hexdigest()
