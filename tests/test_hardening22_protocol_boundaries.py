"""Seeded wire truncations, compressed batches and control/offset boundaries."""

from __future__ import annotations

import gzip
import socket
import struct

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from redposture_core.clients import kafka


@settings(max_examples=50, deadline=None)
@given(payload=st.binary(min_size=1, max_size=512), missing=st.integers(min_value=1, max_value=32))
def test_actual_kafka_frame_truncations_never_produce_success(payload: bytes, missing: int) -> None:
    client, peer = socket.socketpair()
    client.settimeout(0.1)
    try:
        length = len(payload) + missing
        peer.sendall(struct.pack(">i", length) + payload)
        peer.close()
        with pytest.raises(ConnectionError, match="EOF"):
            kafka._recv_kafka_frame(client)
    finally:
        client.close()
        peer.close()


@settings(max_examples=35, deadline=None)
@given(payload=st.binary(min_size=0, max_size=256))
def test_gzip_records_roundtrip_then_every_footer_truncation_is_rejected(payload: bytes) -> None:
    encoded = gzip.compress(payload)
    assert kafka._decompress_kafka_records(1, encoded) == payload
    for cut in range(1, min(8, len(encoded)) + 1):
        with pytest.raises(kafka.KafkaCompressionError):
            kafka._decompress_kafka_records(1, encoded[:-cut])


@pytest.mark.parametrize("offset", [0, 1, 10, 2**31, 2**63 - 2])
def test_native_snapshot_parser_retains_noncontiguous_offsets(offset: int) -> None:
    # Independently encode two legacy message envelopes with a deliberate gap.
    values = [(offset, b"first"), (offset + 1 if offset > 2**63 - 10 else offset + 7, b"after-gap")]
    wire = b""
    for position, value in values:
        body = struct.pack(">Ibbii", 0, 0, 0, -1, len(value)) + value
        wire += struct.pack(">qi", position, len(body)) + body
    progress: dict[str, int] = {}
    assert kafka._parse_message_set_entries(wire, None, progress=progress) == [(i, v.decode()) for i, v in values]
    assert progress["next_offset"] == values[-1][0] + 1
