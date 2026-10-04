"""Kafka protocol and policy contracts across malformed framed traffic."""

from __future__ import annotations

import argparse
import gzip
import socket
import struct
import threading
import time
from types import SimpleNamespace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.clients import kafka
from redposture_core.modules.kafka.policy import validate_args


class _Console:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"max_messages": 0}, "--max-messages"),
        ({"tls_cert": "client.pem"}, "--tls-cert and --tls-key"),
        ({"tls_key": "client.key"}, "--tls-cert and --tls-key"),
        ({"plaintext": True, "tls_ca": "ca.pem"}, "--plaintext cannot"),
        ({"plaintext": True, "tls_cert": "client.pem", "tls_key": "client.key"}, "--plaintext cannot"),
        ({"plaintext": True, "tls_server_name": "broker.example"}, "--plaintext cannot"),
    ],
)
def test_kafka_policy_rejects_conflicting_tls_and_budget_options(options: dict[str, object], message: str) -> None:
    values: dict[str, object] = {"targets": "127.0.0.1", "timeout": 1, "retries": 0}
    values.update(options)
    console = _Console()
    assert validate_args(argparse.Namespace(**values), console) == 2
    assert any(message in item for item in console.errors)


@given(st.binary(max_size=256), st.integers(0, 100))
def test_kafka_binary_parsers_never_escape_with_unexpected_exception(raw: bytes, correlation: int) -> None:
    parsers = (
        lambda: kafka._parse_apiversions_response(raw, correlation),
        lambda: kafka._parse_metadata_response(raw, correlation),
        lambda: kafka._parse_list_offsets_response(raw, correlation),
        lambda: kafka._parse_fetch_response(raw, correlation, expected_partition=0, max_messages=10),
        lambda: kafka._parse_message_set_entries(raw, 10),
        lambda: kafka._parse_record_batch_entries(0, raw, 10),
    )
    for parser in parsers:
        try:
            parser()
        except (ValueError, struct.error):
            pass


@pytest.mark.parametrize("status", [0, 3, 29, 31, 42])
def test_kafka_acl_probe_response_tristate_without_mutating_a_broker(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    def response(*_args: object, **kwargs: object) -> bytes:
        correlation = int(kwargs["correlation_id"])
        api_key = int(kwargs["api_key"])
        topic = kafka._encode_kafka_string("orders")
        if api_key == kafka.KAFKA_CREATE_TOPICS:
            return struct.pack(">iii", correlation, 0, 1) + topic + struct.pack(">h", status) + struct.pack(">h", -1)
        if api_key == kafka.KAFKA_DELETE_TOPICS:
            return struct.pack(">iii", correlation, 0, 1) + topic + struct.pack(">h", status)
        if api_key == kafka.KAFKA_PRODUCE:
            return struct.pack(">ii", correlation, 1) + topic + struct.pack(">iihqq", 1, 0, status, 0, 0)
        raise AssertionError(api_key)

    monkeypatch.setattr(kafka, "_send_kafka_request", response)
    sock = object()  # The fake send never reaches a socket or a broker.
    create, create_next = kafka._probe_create_topic_permission(sock, 17)
    delete, delete_next = kafka._probe_delete_topic_permission(sock, 18)
    write, write_next = kafka._probe_topic_write_permission(sock, 19, "orders")
    assert create_next == 18 and delete_next == 19 and write_next == 20
    assert create is ({0: True, 3: None, 29: False, 31: False, 42: None}[status])
    assert delete is ({0: True, 3: True, 29: False, 31: False, 42: None}[status])
    assert write is ({0: True, 3: None, 29: False, 31: None, 42: None}[status])


@pytest.mark.parametrize(
    ("frame", "error_type"),
    [
        (b"HTTP", ValueError),
        (b"SSH-", ValueError),
        (b"\x00\x00\x00\x00", ValueError),
        (b"\x7f\xff\xff\xff", ValueError),
        (b"\x16\x03\x03\x00", kafka._TlsProbeError),
    ],
)
def test_kafka_framed_socket_rejects_foreign_and_invalid_prefixes(frame: bytes, error_type: type[Exception]) -> None:
    reader, writer = socket.socketpair()
    try:
        writer.sendall(frame)
        writer.close()
        with pytest.raises(error_type):
            kafka._recv_kafka_frame(reader)
    finally:
        reader.close()
        writer.close()


def test_kafka_framed_socket_reassembles_fragmented_header_and_body() -> None:
    reader, writer = socket.socketpair()
    payload = struct.pack(">i", 6) + b"abcdef"

    def send_fragments() -> None:
        try:
            for piece in payload:
                writer.sendall(bytes([piece]))
                time.sleep(0.001)
        finally:
            writer.close()

    thread = threading.Thread(target=send_fragments, daemon=True)
    thread.start()
    try:
        reader.settimeout(1)
        assert kafka._recv_kafka_frame(reader) == b"abcdef"
    finally:
        reader.close()
        thread.join(timeout=1)
        assert not thread.is_alive()


def test_kafka_framed_socket_reports_partial_body_and_stalled_header() -> None:
    reader, writer = socket.socketpair()
    try:
        writer.sendall(struct.pack(">i", 6) + b"abc")
        writer.close()
        with pytest.raises(ConnectionError, match="EOF"):
            kafka._recv_kafka_frame(reader)
    finally:
        reader.close()
        writer.close()

    reader, writer = socket.socketpair()
    try:
        reader.settimeout(0.02)
        with pytest.raises(TimeoutError):
            kafka._recv_kafka_frame(reader)
    finally:
        reader.close()
        writer.close()


def test_kafka_framed_socket_surfaces_peer_tcp_reset() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    reader = socket.create_connection(listener.getsockname(), timeout=1)
    try:
        peer, _address = listener.accept()
        peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        peer.close()
        with pytest.raises(OSError):
            kafka._recv_kafka_frame(reader)
    finally:
        reader.close()
        listener.close()


@pytest.mark.parametrize("status", [0, 29, 6])
def test_kafka_fetch_acl_probe_uses_partition_error_without_reading_records(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    topic = kafka._encode_kafka_string("orders")
    payload = (
        struct.pack(">iihi", 7, 0, 0, 0)
        + struct.pack(">i", 1)
        + topic
        + struct.pack(">iihqqqi", 1, 0, status, 0, 0, 0, 0)
        + struct.pack(">i", 0)
    )
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda *_args, **_kwargs: payload)
    decision, next_id = kafka._probe_topic_read_permission(object(), 7, "orders", 0, fetch_api_version=10)
    assert (decision, next_id) == ({0: True, 29: False, 6: None}[status], 8)


@pytest.mark.parametrize("api_key", [kafka.KAFKA_CREATE_TOPICS, kafka.KAFKA_DELETE_TOPICS, kafka.KAFKA_PRODUCE])
def test_kafka_acl_probes_treat_truncation_as_inconclusive(monkeypatch: pytest.MonkeyPatch, api_key: int) -> None:
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda *_args, **_kwargs: b"\x00")
    if api_key == kafka.KAFKA_CREATE_TOPICS:
        result = kafka._probe_create_topic_permission(object(), 7)
    elif api_key == kafka.KAFKA_DELETE_TOPICS:
        result = kafka._probe_delete_topic_permission(object(), 7)
    else:
        result = kafka._probe_topic_write_permission(object(), 7, "orders")
    assert result == (None, 8)


def test_kafka_snappy_xerial_chunks_and_optional_codecs(monkeypatch: pytest.MonkeyPatch) -> None:
    chunk = b"abc"
    xerial = b"\x82SNAPPY\x00" + b"\x00" * 8 + len(chunk).to_bytes(4, "big") + chunk
    fake_snappy = SimpleNamespace(decompress=lambda raw: raw.upper())
    assert kafka._decode_xerial_snappy(xerial, fake_snappy) == b"ABC"
    assert kafka._decode_xerial_snappy(b"one", fake_snappy) == b"ONE"
    with pytest.raises(kafka.KafkaCompressionError, match="chunk"):
        kafka._decode_xerial_snappy(xerial[:-1], fake_snappy)
    with pytest.raises(kafka.KafkaCompressionError, match="header"):
        kafka._decode_xerial_snappy(xerial[:15], fake_snappy)
    assert kafka._decompress_kafka_records(1, gzip.compress(b"records")) == b"records"

    fake_lz4 = SimpleNamespace(decompress=lambda raw: raw[::-1])

    class Decoder:
        def decompress(self, raw: bytes, *, max_output_size: int) -> bytes:
            assert max_output_size == kafka.KAFKA_MAX_DECOMPRESSED_BYTES
            return raw[::-1]

    def import_module(name: str):
        return {
            "snappy": fake_snappy,
            "lz4.frame": fake_lz4,
            "zstandard": SimpleNamespace(ZstdDecompressor=Decoder),
        }[name]

    monkeypatch.setattr(kafka.importlib, "import_module", import_module)
    assert kafka._decompress_kafka_records(2, b"abc") == b"ABC"
    assert kafka._decompress_kafka_records(3, b"abc") == b"cba"
    assert kafka._decompress_kafka_records(4, b"abc") == b"cba"


@pytest.mark.parametrize("code", [0, 29, 35])
def test_kafka_sasl_handshake_parses_success_rejection_and_unsupported(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    payload = struct.pack(">ihi", 9, code, 0)
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda *_args, **_kwargs: payload)
    ok, next_id, error = kafka._sasl_handshake_plain(object(), 9)
    assert next_id == 10
    if code == 0:
        assert ok and error is None
    else:
        assert not ok and error is not None


@pytest.mark.parametrize("code", [0, 29])
def test_kafka_modern_sasl_auth_identity_result(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    payload = struct.pack(">ihh", 9, code, -1) + struct.pack(">i", -1)
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda *_args, **_kwargs: payload)
    result, next_id, _error = kafka._sasl_authenticate_plain(object(), 9, "alice", "secret")
    assert result is (code == 0)
    assert next_id == 10


def test_kafka_leader_pool_reuses_identity_and_closes_evicted_sessions(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[object] = []

    class Session:
        def __init__(self) -> None:
            self.closed = False

        def bootstrap(self, **_kwargs: object):
            return True, None

        def close(self) -> None:
            self.closed = True

    def open_session(*_args: object, **_kwargs: object):
        session = Session()
        opened.append(session)
        return session

    monkeypatch.setattr(kafka.KafkaSession, "open", open_session)
    pool = kafka.KafkaLeaderPool(max_sessions=1)
    options = {
        "username": "alice",
        "password": "secret",
        "use_tls": False,
        "tls_config": None,
        "sasl_first": False,
        "known_kafka": True,
    }
    first, error = pool.get_or_open("127.0.0.1", 9092, 1, **options)
    assert error is None
    reused, error = pool.get_or_open("127.0.0.1", 9092, 1, **options)
    assert error is None and reused is first
    second, error = pool.get_or_open("127.0.0.1", 9092, 1, **(options | {"username": "bob"}))
    assert error is None and second is not first
    assert first.closed is True
    assert pool.stats()["reused"] == 1
    pool.close()
    assert second.closed is True
    assert len(opened) == 2


@pytest.mark.parametrize("offset_error,fetch_error", [("denied", None), (None, "timeout"), (None, None)])
def test_kafka_partition_read_reports_stage_error_without_losing_correlation(
    monkeypatch: pytest.MonkeyPatch, offset_error: str | None, fetch_error: str | None
) -> None:
    api_keys: list[int] = []

    def send(*_args: object, **kwargs: object) -> bytes:
        api_keys.append(int(kwargs["api_key"]))
        return b"frame"

    monkeypatch.setattr(kafka, "_send_kafka_request", send)
    monkeypatch.setattr(kafka, "_parse_list_offsets_response", lambda *_args: (1, offset_error))
    monkeypatch.setattr(kafka, "_parse_fetch_response", lambda *_args, **_kwargs: ([(1, "event")], fetch_error))
    items, next_id, error = kafka._read_partition_messages_on_leader(object(), 5, "orders", 0, 1)
    assert error == offset_error or error == fetch_error
    if error is None:
        assert items == ["p0@1 event"]
        assert api_keys == [kafka.KAFKA_LIST_OFFSETS, kafka.KAFKA_FETCH]
        assert next_id == 7
    else:
        assert items == []


def test_kafka_acl_probe_preserves_borrowed_session_correlation_and_read_only_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Socket:
        def close(self) -> None:
            raise AssertionError("borrowed socket must not be closed")

    session = kafka.KafkaSession(
        sock=Socket(),
        transport_mode="plaintext",
        identity=(None, None),
        correlation_id=11,
        api_versions={kafka.KAFKA_FETCH: (0, 10)},
    )
    monkeypatch.setattr(kafka, "_probe_create_topic_permission", lambda _sock, corr: (True, corr + 1))
    monkeypatch.setattr(kafka, "_probe_delete_topic_permission", lambda _sock, corr: (False, corr + 1))
    monkeypatch.setattr(kafka, "_probe_topic_read_permission", lambda _sock, corr, _topic, **_kw: (True, corr + 1))
    monkeypatch.setattr(
        kafka, "_probe_topic_write_permission", lambda *_args: pytest.fail("write probe must be opt-in")
    )
    result = kafka._probe_kafka_acls("127.0.0.1", 9092, 1, ["orders"], existing_session=session)
    assert result == {"cluster": {"create": True, "delete": False}, "topics": {"orders": {"read": True, "write": None}}}
    assert session.correlation_id == 14


def test_kafka_session_lifecycle_preserves_versions_metadata_and_idempotent_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Socket:
        def __init__(self) -> None:
            self.closes = 0

        def close(self) -> None:
            self.closes += 1

    sock = Socket()
    session = kafka.KafkaSession(sock=sock, transport_mode="plaintext", identity=("alice", "secret"), api_versions={})
    monkeypatch.setattr(
        kafka,
        "_probe_apiversions",
        lambda _sock, _corr: kafka.KafkaApiVersionsResult(True, 0, None, {kafka.KAFKA_FETCH: (0, 10)}),
    )
    monkeypatch.setattr(kafka, "_authenticate_or_probe", lambda *_args, **_kw: (True, 3, None))
    monkeypatch.setattr(kafka, "_fetch_metadata", lambda *_args, **_kw: ({"topics": ["orders"]}, None))
    assert session.detect().ok is True
    assert session.bootstrap(known_kafka=True) == (True, None)
    metadata, error = session.fetch_metadata()
    assert error is None and metadata is not None
    assert metadata["api_versions"][kafka.KAFKA_FETCH] == (0, 10)
    assert session.correlation_id == 4
    session.close()
    session.close()
    assert sock.closes == 1


def test_kafka_known_session_bootstrap_does_not_skip_apiversions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda *_args, **_kwargs: b"frame")
    monkeypatch.setattr(
        kafka,
        "_parse_apiversions_response",
        lambda *_args: kafka.KafkaApiVersionsResult(True, 0, None, {kafka.KAFKA_FETCH: (0, 7)}),
    )
    versions: dict[int, tuple[int, int]] = {}
    assert kafka._bootstrap_known_kafka_session(object(), 4, api_versions_out=versions) == (True, 5, None)
    assert versions == {kafka.KAFKA_FETCH: (0, 7)}


def test_kafka_legacy_sasl_partial_frame_reports_auth_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class Socket:
        def __init__(self) -> None:
            self.pending = [b"\x00", b"\x00\x00", b"\x14", b"authentication failed"]
            self.timeout = 1.0
            self.sent: list[bytes] = []

        def sendall(self, raw: bytes) -> None:
            self.sent.append(raw)

        def recv(self, _size: int) -> bytes:
            return self.pending.pop(0) if self.pending else b""

        def gettimeout(self) -> float:
            return self.timeout

        def settimeout(self, value: float) -> None:
            self.timeout = value

    sock = Socket()
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda *_args, **_kwargs: b"")
    result, next_id, reason = kafka._sasl_authenticate_plain(sock, 6, "alice", "secret")
    assert result is False and next_id == 6
    assert "authentication failed" in str(reason)
    assert sock.sent and sock.timeout == 1.0


def test_kafka_tls_context_validation_closes_unwrapped_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    class Socket:
        def __init__(self) -> None:
            self.closed = False

        def settimeout(self, _timeout: float) -> None:
            pass

        def close(self) -> None:
            self.closed = True

    sock = Socket()
    monkeypatch.setattr(kafka.socket, "create_connection", lambda *_args, **_kwargs: sock)
    monkeypatch.setattr(
        kafka, "shared_client_ssl_context", lambda **_kwargs: (_ for _ in ()).throw(ValueError("invalid CA"))
    )
    with pytest.raises(ValueError, match="invalid CA"):
        kafka.open_kafka_socket("127.0.0.1", 9093, 1, use_tls=True)
    assert sock.closed


def test_kafka_optional_codec_failures_are_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(name: str):
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(kafka.importlib, "import_module", unavailable)
    for codec, package in ((2, "python-snappy"), (3, "lz4"), (4, "zstandard")):
        with pytest.raises(kafka.KafkaCompressionError, match=package):
            kafka._decompress_kafka_records(codec, b"payload")
    with pytest.raises(kafka.KafkaCompressionError, match="unsupported"):
        kafka._decompress_kafka_records(17, b"payload")


def test_kafka_leader_pool_closes_session_after_failed_bootstrap(monkeypatch: pytest.MonkeyPatch) -> None:
    class Session:
        def __init__(self) -> None:
            self.closed = False

        def bootstrap(self, **_kwargs: object):
            return False, "SASL rejected"

        def close(self) -> None:
            self.closed = True

    session = Session()
    monkeypatch.setattr(kafka.KafkaSession, "open", lambda *_args, **_kwargs: session)
    pool = kafka.KafkaLeaderPool()
    opened, error = pool.get_or_open(
        "127.0.0.1",
        9092,
        1,
        username="alice",
        password="wrong",
        use_tls=False,
        tls_config=None,
        sasl_first=False,
        known_kafka=True,
    )
    assert opened is None and error == "SASL rejected" and session.closed
    assert pool.stats()["connections"] == 0
