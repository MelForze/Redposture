from __future__ import annotations

import struct

import pytest

from redposture_core.clients import kafka


def _kstr(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack(">h", len(raw)) + raw


class _FrameSocket:
    def __init__(self, response_body: bytes | list[bytes] = b"") -> None:
        self.sent: list[bytes] = []
        frames = response_body if isinstance(response_body, list) else [response_body]
        self._payload = b"".join(struct.pack(">i", len(frame)) + frame for frame in frames)
        self._timeout = 1.0

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        chunk = self._payload[:size]
        self._payload = self._payload[size:]
        return chunk

    def gettimeout(self) -> float:
        return self._timeout

    def settimeout(self, timeout: float) -> None:
        self._timeout = timeout


def _message_set(offset: int, value: str, *, magic: int = 0) -> bytes:
    raw = value.encode("utf-8")
    message = struct.pack(">i", 0) + struct.pack(">b", magic) + struct.pack(">b", 0)
    if magic >= 1:
        message += struct.pack(">q", 123)
    message += struct.pack(">i", -1) + struct.pack(">i", len(raw)) + raw
    return struct.pack(">q", offset) + struct.pack(">i", len(message)) + message


def _uvarint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def _varint(value: int) -> bytes:
    return _uvarint((int(value) << 1) ^ (int(value) >> 63))


def test_kafka_reader_and_encode_error_branches() -> None:
    assert kafka._KafkaReader(struct.pack(">h", -1)).read_string(nullable=True) is None
    assert kafka._KafkaReader(struct.pack(">i", -1)).read_bytes(nullable=True) is None

    with pytest.raises(ValueError, match="non-nullable string"):
        kafka._KafkaReader(struct.pack(">h", -1)).read_string(nullable=False)
    with pytest.raises(ValueError, match="non-nullable bytes"):
        kafka._KafkaReader(struct.pack(">i", -1)).read_bytes(nullable=False)
    with pytest.raises(ValueError, match="unexpected EOF"):
        kafka._KafkaReader(b"\x00").read_i16()
    with pytest.raises(ValueError, match="negative read size"):
        kafka._KafkaReader(b"")._read(-1)  # noqa: SLF001
    with pytest.raises(ValueError, match="exceeds int16"):
        kafka._encode_kafka_string("x" * 32768)

    assert kafka._KafkaReader(struct.pack(">i", -1)).read_string_array() == []
    assert kafka._build_metadata_request_body(None) == struct.pack(">i", 0)
    assert kafka._build_metadata_request_body(["orders"]) == struct.pack(">i", 1) + _kstr("orders")


def test_parse_protocol_response_error_edges() -> None:
    ok, code, error = kafka._parse_apiversions_response(struct.pack(">ih", 2, 0), 1)
    assert ok is False
    assert code is None
    assert "unexpected correlation id" in str(error)

    ok, code, error = kafka._parse_apiversions_response(struct.pack(">ihi", 1, 0, 1) + b"\x00", 1)
    assert ok is False
    assert code == 0
    assert error == "invalid ApiVersions entry payload"

    metadata, error = kafka._parse_metadata_response(struct.pack(">ii", 1, -1), 1)
    assert metadata is None
    assert error == "invalid broker array size"

    metadata, error = kafka._parse_metadata_response(struct.pack(">ii", 1, 0) + struct.pack(">i", -1), 1)
    assert metadata is None
    assert error == "invalid topic metadata array size"

    offset, error = kafka._parse_list_offsets_response(struct.pack(">ii", 1, 0), 1)
    assert offset is None
    assert error == "ListOffsets returned empty topic list"

    offset, error = kafka._parse_list_offsets_response(
        struct.pack(">ii", 1, 1) + _kstr("orders") + struct.pack(">i", 0),
        1,
    )
    assert offset is None
    assert error == "ListOffsets returned empty partition list"

    offset, error = kafka._parse_list_offsets_response(
        struct.pack(">ii", 1, 1) + _kstr("orders") + struct.pack(">iihi", 1, 0, 7, 1) + struct.pack(">q", 5),
        1,
    )
    assert offset is None
    assert error == "ListOffsets failed: REQUEST_TIMED_OUT"


def test_varint_record_and_message_set_edges() -> None:
    with pytest.raises(ValueError, match="varint is too long"):
        kafka._read_unsigned_varint(kafka._KafkaReader(b"\x80" * 5))
    with pytest.raises(ValueError, match="varlong is too long"):
        kafka._read_varlong(kafka._KafkaReader(b"\x80" * 10))
    with pytest.raises(ValueError, match="varbytes"):
        kafka._read_var_bytes(kafka._KafkaReader(_varint(3) + b"ab"))
    with pytest.raises(ValueError, match="header count"):
        kafka._skip_record_headers(kafka._KafkaReader(_varint(-1)))
    with pytest.raises(ValueError, match="header key size"):
        kafka._skip_record_headers(kafka._KafkaReader(_varint(1) + _varint(2) + b"x"))

    assert kafka._parse_message_set_entries(_message_set(7, "alpha"), 10) == [(7, "alpha")]
    assert kafka._parse_message_set_entries(_message_set(8, "beta", magic=1), 10) == [(8, "beta")]
    assert kafka._parse_message_set_entries(struct.pack(">qi", 1, 999), 10) == []
    assert kafka._parse_record_batch_entries(0, b"short", 10) == []

    compressed_batch = (
        struct.pack(">i", 0)
        + struct.pack(">b", 2)
        + struct.pack(">i", 0)
        + struct.pack(">h", 1)
        + struct.pack(">i", 0)
        + struct.pack(">q", 0)
        + struct.pack(">q", 0)
        + struct.pack(">q", -1)
        + struct.pack(">h", -1)
        + struct.pack(">i", -1)
        + struct.pack(">i", 1)
    )
    assert kafka._parse_record_batch_entries(0, compressed_batch, 10) == []

    invalid_count_batch = compressed_batch[:9] + struct.pack(">h", 0) + compressed_batch[11:-4] + struct.pack(">i", -1)
    with pytest.raises(ValueError, match="record batch count"):
        kafka._parse_record_batch_entries(0, invalid_count_batch, 10)


def test_fetch_response_success_and_error_edges() -> None:
    message_set = _message_set(3, "payload")
    fetch_payload = (
        struct.pack(">ii", 4, 1) + _kstr("orders") + struct.pack(">iihqi", 1, 0, 0, 10, len(message_set)) + message_set
    )
    items, error = kafka._parse_fetch_response(fetch_payload, 4, expected_partition=0, max_messages=10)
    assert error is None
    assert items == [(3, "payload")]

    items, error = kafka._parse_fetch_response(struct.pack(">ii", 4, 0), 4, expected_partition=0, max_messages=10)
    assert items == []
    assert error is None

    bad_size = struct.pack(">ii", 4, 1) + _kstr("orders") + struct.pack(">iihqi", 1, 0, 0, 10, 99) + b"x"
    items, error = kafka._parse_fetch_response(bad_size, 4, expected_partition=0, max_messages=10)
    assert items is None
    assert error == "invalid Fetch message set size"

    fetch_error = struct.pack(">ii", 4, 1) + _kstr("orders") + struct.pack(">iihqi", 1, 0, 7, 10, 0)
    items, error = kafka._parse_fetch_response(fetch_error, 4, expected_partition=0, max_messages=10)
    assert items is None
    assert error == "Fetch failed: REQUEST_TIMED_OUT"

    items, error = kafka._parse_fetch_response(fetch_payload, 99, expected_partition=0, max_messages=10)
    assert items is None
    assert "unexpected correlation id" in str(error)


def test_send_request_and_sasl_error_paths() -> None:
    response = struct.pack(">ih", 9, 0)
    sock = _FrameSocket(response)
    payload = kafka._send_kafka_request(
        sock,
        api_key=kafka.KAFKA_API_VERSIONS,
        api_version=0,
        correlation_id=9,
        client_id="rp",
    )
    assert payload == response
    sent_size = struct.unpack(">i", sock.sent[0][:4])[0]
    assert sent_size == len(sock.sent[0]) - 4

    ok, next_corr, error = kafka._sasl_handshake_plain(
        _FrameSocket([struct.pack(">ih", 1, 35), struct.pack(">ih", 1, 35)]),
        1,
    )
    assert ok is False
    assert next_corr == 2
    assert error == "SASL handshake failed: UNSUPPORTED_VERSION"

    ok, next_corr, error = kafka._sasl_handshake_plain(_FrameSocket(struct.pack(">ih", 2, 0)), 1)
    assert ok is False
    assert next_corr == 2
    assert "unexpected correlation id" in str(error)

    auth_response = struct.pack(">ih", 3, 58) + struct.pack(">h", -1) + struct.pack(">i", -1)
    ok, next_corr, error = kafka._sasl_authenticate_plain(_FrameSocket(auth_response), 3, "user", "")
    assert ok is False
    assert next_corr == 4
    assert error == "SASL auth failed: SASL_AUTHENTICATION_FAILED"


def test_kafka_small_helpers_and_metadata_success_branches() -> None:
    assert kafka._clip("abcdef", 4) == "a..."
    assert kafka._retry_delay(0) == pytest.approx(0.20)
    assert kafka._retry_delay(8) == pytest.approx(1.50)
    assert kafka._kafka_error_name(999) == "ERR_999"
    assert kafka._is_probable_auth_error("SASL authentication failed") is True
    assert kafka._is_probable_auth_error(None, [58]) is True
    assert kafka._is_probable_auth_error("plain timeout") is False
    assert kafka._is_sasl_probe_candidate("unexpected EOF from broker") is True
    assert kafka._is_sasl_probe_candidate("") is False

    assert kafka._build_credential_runs("u", "", True) == [
        ("u", ""),
        ("admin", "admin"),
        ("kafka", "kafka"),
        ("kafka", "password"),
    ]
    assert kafka._build_credential_runs(None, None, False) == [(None, None)]

    metadata_payload = (
        struct.pack(">ii", 7, 1)
        + struct.pack(">i", 1)
        + _kstr("broker.local")
        + struct.pack(">i", 9092)
        + struct.pack(">i", 1)
        + struct.pack(">h", 29)
        + _kstr("orders")
        + struct.pack(">i", 1)
        + struct.pack(">hiii", 29, 0, 1, 0)
        + struct.pack(">i", -1)
        + struct.pack(">i", -1)
    )
    metadata, error = kafka._parse_metadata_response(metadata_payload, 7)
    assert error is None
    assert metadata is not None
    assert metadata["topics"] == ["orders"]
    assert metadata["topic_map"] == {"orders": 1}
    assert metadata["auth_required"] is True
    assert metadata["error_codes"] == [29, 29]
    # Partition-aware routing: the parser must retain the broker list and
    # per-partition leader map so `_read_topic_messages` can open a socket
    # per leader and avoid the classic NOT_LEADER_OR_FOLLOWER error.
    assert metadata["broker_map"] == {1: ("broker.local", 9092)}
    assert metadata["partition_leaders"] == {"orders": {0: 1}}

    offset_payload = struct.pack(">ii", 8, 1) + _kstr("orders") + struct.pack(">iihi", 1, 0, 0, 0)
    no_offset, no_offset_error = kafka._parse_list_offsets_response(offset_payload, 8)
    assert no_offset is None
    assert no_offset_error == "ListOffsets returned no offsets"

    good_offset_payload = struct.pack(">ii", 8, 1) + _kstr("orders") + struct.pack(">iihi", 1, 0, 0, 1)
    good_offset_payload += struct.pack(">q", 123)
    offset, offset_error = kafka._parse_list_offsets_response(good_offset_payload, 8)
    assert offset == 123
    assert offset_error is None


def test_kafka_record_batch_and_sasl_fallback_branches() -> None:
    record_payload = (
        struct.pack(">b", 0) + _varint(0) + _varint(2) + _varint(-1) + _varint(len(b"value")) + b"value" + _varint(0)
    )
    batch = (
        struct.pack(">i", 0)
        + struct.pack(">b", 2)
        + struct.pack(">i", 0)
        + struct.pack(">h", 0)
        + struct.pack(">i", 0)
        + struct.pack(">q", 0)
        + struct.pack(">q", 0)
        + struct.pack(">q", -1)
        + struct.pack(">h", -1)
        + struct.pack(">i", -1)
        + struct.pack(">i", 1)
        + _varint(len(record_payload))
        + record_payload
    )
    assert kafka._parse_record_batch_entries(10, batch, 10) == [(12, "value")]
    with pytest.raises(ValueError, match="invalid Kafka record size"):
        kafka._parse_record_batch_entries(10, batch[:49] + _varint(-1), 10)

    class LegacyAuthSocket:
        def __init__(self) -> None:
            self.sent: list[bytes] = []
            self.timeout = 1.0
            self.legacy_payload = struct.pack(">i", len(b"authentication failed")) + b"authentication failed"

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

        def recv(self, size: int) -> bytes:
            if len(self.sent) <= 1:
                return b""
            chunk = self.legacy_payload[:size]
            self.legacy_payload = self.legacy_payload[size:]
            return chunk

        def gettimeout(self) -> float:
            return self.timeout

        def settimeout(self, timeout: float) -> None:
            self.timeout = timeout

    sock = LegacyAuthSocket()
    ok, corr, error = kafka._sasl_authenticate_plain(sock, 3, "user", "secret")
    assert ok is False
    assert corr == 3
    assert error == "authentication failed"
    assert len(sock.sent) >= 2

    class BrokenSendSocket(LegacyAuthSocket):
        def sendall(self, _data: bytes) -> None:
            raise OSError("broken pipe")

    ok, corr, error = kafka._sasl_authenticate_plain(BrokenSendSocket(), 3, "user", "secret")
    assert ok is False
    assert corr == 3
    assert "broken pipe" in str(error)


# ---------------------------------------------------------------------------
# TLS auto-detection (regression tests for the SASL_SSL crash on port 9093)
# ---------------------------------------------------------------------------


def test_is_tls_record_prelude_recognizes_all_record_types() -> None:
    """The TLS record header always starts with a known type byte (0x14..0x17)
    followed by the TLS major version (0x03) and a minor version byte
    (0x00..0x04). Miscategorizing a real Kafka frame length as TLS would
    trigger a spurious retry, so this test pins the false-positive cases too.
    """
    assert kafka._is_tls_record_prelude(b"\x15\x03\x03\x00") is True  # TLS 1.2 Alert
    assert kafka._is_tls_record_prelude(b"\x16\x03\x01\x02") is True  # TLS 1.0 Handshake
    assert kafka._is_tls_record_prelude(b"\x14\x03\x03\x00") is True  # ChangeCipherSpec
    assert kafka._is_tls_record_prelude(b"\x17\x03\x04\x00") is True  # TLS 1.3 AppData

    # Not a TLS record: valid Kafka frame length like 0x00000140 (320 bytes).
    assert kafka._is_tls_record_prelude(b"\x00\x00\x01\x40") is False
    # Wrong first byte (0x18 not a TLS record type).
    assert kafka._is_tls_record_prelude(b"\x18\x03\x03\x00") is False
    # Wrong TLS major version (0x02 — SSLv2 predecessor, not TLS).
    assert kafka._is_tls_record_prelude(b"\x15\x02\x03\x00") is False
    # Wrong minor version (0x05 is beyond TLS 1.3 draft numbering).
    assert kafka._is_tls_record_prelude(b"\x15\x03\x05\x00") is False
    # Short buffer must never crash and must return False.
    assert kafka._is_tls_record_prelude(b"") is False
    assert kafka._is_tls_record_prelude(b"\x15") is False
    assert kafka._is_tls_record_prelude(b"\x15\x03") is False


def test_recv_kafka_frame_raises_tls_probe_error_on_alert() -> None:
    """`_recv_kafka_frame` on a plaintext socket connected to a TLS listener
    reads back a TLS Alert record. Historically this raised
    `ValueError('invalid Kafka frame size 352518912')`, causing the whole
    Kafka scan to log a misleading error. Now it must raise `_TlsProbeError`
    so the caller can catch it and retry with `wrap_socket`.
    """

    class _AlertSocket:
        def __init__(self) -> None:
            self._payload = b"\x15\x03\x03\x00"

        def recv(self, size: int) -> bytes:
            chunk = self._payload[:size]
            self._payload = self._payload[size:]
            return chunk

    with pytest.raises(kafka._TlsProbeError):
        kafka._recv_kafka_frame(_AlertSocket())

    # Sanity: a legit 4-byte length still parses (empty body).
    class _EmptyFrameSocket:
        def __init__(self) -> None:
            self._payload = b"\x00\x00\x00\x00"

        def recv(self, size: int) -> bytes:
            chunk = self._payload[:size]
            self._payload = self._payload[size:]
            return chunk

    # frame_size == 0 hits the existing "invalid Kafka frame size 0" branch,
    # not the TLS path — proves we still fail closed on genuinely bogus input.
    with pytest.raises(ValueError, match="invalid Kafka frame size 0"):
        kafka._recv_kafka_frame(_EmptyFrameSocket())


def test_open_kafka_socket_port_9093_prefers_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    """9093 = well-known SASL_SSL listener. `open_kafka_socket` with
    `use_tls=None` (the default) must attempt `wrap_socket` on the first
    pass — otherwise the caller pays the cost of one round-trip probe
    followed by a re-connect just to discover the well-known layout.
    """
    wrap_calls: list[tuple[str, int | None]] = []

    class _FakeBaseSocket:
        def __init__(self, host: str, port: int) -> None:
            self.host = host
            self.port = port
            self.closed = False
            self._timeout: float | None = None

        def settimeout(self, timeout: float | None) -> None:
            self._timeout = timeout

        def close(self) -> None:
            self.closed = True

    class _FakeWrappedSocket:
        def __init__(self, base: _FakeBaseSocket, server_hostname: str) -> None:
            self.base = base
            self.server_hostname = server_hostname
            self._timeout: float | None = None

        def settimeout(self, timeout: float | None) -> None:
            self._timeout = timeout

    class _FakeContext:
        def __init__(self) -> None:
            self.check_hostname = True
            self.verify_mode = 0

        def wrap_socket(self, sock, server_hostname):
            wrap_calls.append((server_hostname, getattr(sock, "port", None)))
            return _FakeWrappedSocket(sock, server_hostname)

    def _fake_create_connection(addr, timeout):
        host, port = addr
        return _FakeBaseSocket(host, port)

    monkeypatch.setattr(kafka.socket, "create_connection", _fake_create_connection)
    monkeypatch.setattr(kafka.ssl, "create_default_context", lambda: _FakeContext())

    # 9093 with use_tls=None -> TLS wrap is attempted.
    sock, transport_mode = kafka.open_kafka_socket("kafka.example.com", 9093, 1.0)
    assert transport_mode == "tls"
    assert wrap_calls == [("kafka.example.com", 9093)]
    assert isinstance(sock, _FakeWrappedSocket)

    # 9092 with use_tls=None -> plaintext, wrap_socket NOT called.
    wrap_calls.clear()
    sock, transport_mode = kafka.open_kafka_socket("kafka.example.com", 9092, 1.0)
    assert transport_mode == "plaintext"
    assert wrap_calls == []
    assert isinstance(sock, _FakeBaseSocket)

    # Explicit use_tls=False on 9093 forces plaintext (operator override).
    sock, transport_mode = kafka.open_kafka_socket("kafka.example.com", 9093, 1.0, use_tls=False)
    assert transport_mode == "plaintext"
    assert wrap_calls == []

    # Explicit use_tls=True on 9092 forces TLS.
    sock, transport_mode = kafka.open_kafka_socket("kafka.example.com", 9092, 1.0, use_tls=True)
    assert transport_mode == "tls"
    assert wrap_calls == [("kafka.example.com", 9092)]


def test_read_topic_messages_partition_aware_routes_to_leader_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    """Multi-broker Kafka clusters spread partition leaders across brokers.
    The fix: after Metadata, `_read_topic_messages` must open a fresh socket
    per leader broker instead of sending every ListOffsets to the bootstrap
    socket (which returns NOT_LEADER_OR_FOLLOWER for partitions it doesn't
    lead). This regression pins that routing.
    """

    class _StubSock:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def close(self):
            pass

        def settimeout(self, _t):
            pass

    open_calls: list[tuple[str, int]] = []

    def _fake_open(host, port, timeout, *, use_tls=None):
        _ = timeout, use_tls
        open_calls.append((host, port))
        return _StubSock(), "plaintext"

    monkeypatch.setattr(kafka, "open_kafka_socket", _fake_open)
    monkeypatch.setattr(kafka, "_probe_apiversions", lambda *_a, **_k: (True, None, None))
    monkeypatch.setattr(
        kafka,
        "_fetch_metadata",
        lambda *_a, **_k: (
            {
                "topic_map": {"multi": 2},
                "broker_map": {10: ("broker-a", 9092), 20: ("broker-b", 9092)},
                "partition_leaders": {"multi": {0: 10, 1: 20}},
            },
            None,
        ),
    )
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda *_a, **_k: b"x")

    offsets = iter([(100, None), (200, None)])
    fetches = iter([([(100, "a-msg")], None), ([(200, "b-msg")], None)])
    monkeypatch.setattr(kafka, "_parse_list_offsets_response", lambda *_a, **_k: next(offsets))
    monkeypatch.setattr(kafka, "_parse_fetch_response", lambda *_a, **_k: next(fetches))

    items, error, transport_mode = kafka._read_topic_messages("bootstrap", 9092, 1.0, "multi", 10)

    assert error is None
    assert transport_mode == "plaintext"
    # Both messages surface (one per partition, each fetched from its leader).
    assert sorted(items) == ["p0@100 a-msg", "p1@200 b-msg"]
    # Three sockets were opened: bootstrap + two leader brokers.
    assert ("bootstrap", 9092) in open_calls
    assert ("broker-a", 9092) in open_calls
    assert ("broker-b", 9092) in open_calls


def test_read_topic_messages_falls_back_to_bootstrap_when_leader_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the metadata-advertised leader hostname isn't reachable from the
    auditor's network (e.g. broker advertises `kafka-tls:9093` internal DNS),
    the client falls back to running the ListOffsets on the bootstrap socket.
    The broker will likely refuse (NOT_LEADER_OR_FOLLOWER), but the caller
    gets a per-partition error instead of a hard `ConnectionError`.
    """

    class _StubSock:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def close(self):
            pass

        def settimeout(self, _t):
            pass

    def _fake_open(host, port, timeout, *, use_tls=None):
        _ = timeout, use_tls
        if host == "unreachable-broker":
            raise ConnectionRefusedError("cannot resolve unreachable-broker")
        return _StubSock(), "plaintext"

    monkeypatch.setattr(kafka, "open_kafka_socket", _fake_open)
    monkeypatch.setattr(kafka, "_probe_apiversions", lambda *_a, **_k: (True, None, None))
    monkeypatch.setattr(
        kafka,
        "_fetch_metadata",
        lambda *_a, **_k: (
            {
                "topic_map": {"orders": 1},
                "broker_map": {5: ("unreachable-broker", 9092)},
                "partition_leaders": {"orders": {0: 5}},
            },
            None,
        ),
    )
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda *_a, **_k: b"x")
    monkeypatch.setattr(kafka, "_parse_list_offsets_response", lambda *_a, **_k: (50, None))
    monkeypatch.setattr(kafka, "_parse_fetch_response", lambda *_a, **_k: ([(50, "fallback-msg")], None))

    items, error, transport_mode = kafka._read_topic_messages("bootstrap", 9092, 1.0, "orders", 5)

    # Falls back to bootstrap socket, delivers the message (in the test —
    # in real life the broker would refuse with NOT_LEADER_OR_FOLLOWER,
    # but the point is we don't crash on unreachable leaders).
    assert error is None
    assert items == ["p0@50 fallback-msg"]
    assert transport_mode == "plaintext"
