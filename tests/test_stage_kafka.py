from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

import pytest

from redposture_core import stage_kafka as kafka
from redposture_core.modules.kafka import actions as kafka_actions
from redposture_core.modules.kafka import stage as kafka_stage_pkg
from redposture_core.stage_kafka import _parse_apiversions_response, _parse_metadata_response
from redposture_core.stage_runtime import AuditCommandResult
from tests.stage_runtime_helpers import patch_runner_for_legacy_target_fake, run_module_targets_for_test


def test_kafka_lab_seed_has_health_markers_and_nonempty_topic_guards(lab_full_compose_path: Path) -> None:
    compose = lab_full_compose_path.read_text(encoding="utf-8")
    open_seed = compose.split("  kafka-open-seed:", 1)[1].split("  kafka-auth:", 1)[0]
    auth_seed = compose.split("  kafka-auth-seed:", 1)[1].split("  registry-open:", 1)[0]

    assert "redposture-kafka-open-seed-ready" in open_seed
    assert "redposture-kafka-auth-seed-ready" in auth_seed
    assert "topic $${topic} is empty" in open_seed
    assert "topic $${topic} is empty" in auth_seed
    assert "tail -f /dev/null" in open_seed
    assert "tail -f /dev/null" in auth_seed
    assert "condition: service_healthy" in auth_seed


class _DummySocket:
    def __enter__(self) -> _DummySocket:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        _ = timeout


class _RecvSocket(_DummySocket):
    def __init__(self, payload: bytes = b"") -> None:
        self.payload = payload
        self.sent: list[bytes] = []
        self._timeout = 1.0

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        if not self.payload:
            return b""
        chunk = self.payload[:size]
        self.payload = self.payload[size:]
        return chunk

    def gettimeout(self) -> float:
        return self._timeout

    def settimeout(self, timeout: float) -> None:
        self._timeout = timeout


class _ConsoleCapture:
    instances: list[_ConsoleCapture] = []

    def __init__(self, debug: bool = False) -> None:
        self.debug = debug
        self.messages: list[tuple[str, str]] = []
        type(self).instances.append(self)

    def error(self, message: str) -> None:
        self.messages.append(("error", message))

    def warn(self, message: str) -> None:
        self.messages.append(("warn", message))

    def info(self, message: str) -> None:
        self.messages.append(("info", message))

    def plain(self, message: str, color: str | None = None) -> None:
        _ = color
        self.messages.append(("plain", message))

    def render_tagged_payload_line(self, line: str, tag: str, payload_color: str | None = None) -> bool:
        _ = (line, tag, payload_color)
        return False


def _kafka_args(**overrides: object) -> argparse.Namespace:
    data: dict[str, object] = {
        "debug": False,
        "timeout": 1.0,
        "retries": 0,
        "max_messages": 10,
        "username": None,
        "password": None,
        "ports": None,
        "port": 9092,
        "targets": "127.0.0.1",
        "hosts": None,
        "hosts_file": None,
        "output": None,
        "output_format": "txt",
        "workers": 1,
        "show_topics": False,
        "topic": None,
        "dump": False,
    }
    data.update(overrides)
    return argparse.Namespace(**data)


def _kstr(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack(">h", len(raw)) + raw


def _partition_meta(error_code: int, partition_id: int = 0) -> bytes:
    return (
        struct.pack(">h", error_code)
        + struct.pack(">i", partition_id)
        + struct.pack(">i", 1)  # leader
        + struct.pack(">i", 1)
        + struct.pack(">i", 1)  # replicas [1]
        + struct.pack(">i", 1)
        + struct.pack(">i", 1)  # isr [1]
    )


def _fetch_message_set(offset: int, value: str) -> bytes:
    raw = value.encode("utf-8")
    message = (
        struct.pack(">i", 0)
        + struct.pack(">b", 0)
        + struct.pack(">b", 0)
        + struct.pack(">i", -1)
        + struct.pack(">i", len(raw))
        + raw
    )
    return struct.pack(">q", offset) + struct.pack(">i", len(message)) + message


def _varint(value: int) -> bytes:
    unsigned = (int(value) << 1) ^ (int(value) >> 63)
    out = bytearray()
    while True:
        byte = unsigned & 0x7F
        unsigned >>= 7
        if unsigned:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def _fetch_record_batch(base_offset: int, values: list[str]) -> bytes:
    records = bytearray()
    for idx, value in enumerate(values):
        raw = value.encode("utf-8")
        record_body = (
            struct.pack(">b", 0) + _varint(0) + _varint(idx) + _varint(-1) + _varint(len(raw)) + raw + _varint(0)
        )
        records += _varint(len(record_body)) + record_body

    batch = (
        struct.pack(">i", 0)  # partition leader epoch
        + struct.pack(">b", 2)  # magic
        + struct.pack(">i", 0)  # crc, ignored by parser
        + struct.pack(">h", 0)  # attributes
        + struct.pack(">i", max(0, len(values) - 1))
        + struct.pack(">q", 0)
        + struct.pack(">q", 0)
        + struct.pack(">q", -1)
        + struct.pack(">h", -1)
        + struct.pack(">i", -1)
        + struct.pack(">i", len(values))
        + bytes(records)
    )
    return struct.pack(">q", base_offset) + struct.pack(">i", len(batch)) + batch


def test_parse_apiversions_response_basic() -> None:
    correlation_id = 12
    payload = (
        struct.pack(">i", correlation_id)
        + struct.pack(">h", 0)  # error_code
        + struct.pack(">i", 1)  # api_versions array size
        + struct.pack(">h", 3)  # api key metadata
        + struct.pack(">h", 0)  # min
        + struct.pack(">h", 12)  # max
    )
    ok, error_code, error = _parse_apiversions_response(payload, correlation_id)
    assert ok is True
    assert error_code == 0
    assert error is None


def test_parse_metadata_response_mixed_access_does_not_force_auth_required() -> None:
    correlation_id = 7
    brokers = struct.pack(">i", 1) + struct.pack(">i", 1) + _kstr("kafka-1") + struct.pack(">i", 9092)

    topic_orders = (
        struct.pack(">h", 0)  # topic error
        + _kstr("orders")
        + struct.pack(">i", 2)  # partitions
        + _partition_meta(0, 0)
        + _partition_meta(0, 1)
    )
    topic_secret = (
        struct.pack(">h", 29)  # TOPIC_AUTHORIZATION_FAILED
        + _kstr("secret")
        + struct.pack(">i", 0)  # partitions
    )
    topics = struct.pack(">i", 2) + topic_orders + topic_secret

    payload = struct.pack(">i", correlation_id) + brokers + topics
    metadata, error = _parse_metadata_response(payload, correlation_id)
    assert error is None
    assert isinstance(metadata, dict)
    assert metadata["topic_map"]["orders"] == 2
    assert metadata["topic_map"]["secret"] == 0
    assert metadata["auth_required"] is False


def test_parse_metadata_response_all_auth_errors_sets_auth_required() -> None:
    correlation_id = 11
    brokers = struct.pack(">i", 1) + struct.pack(">i", 1) + _kstr("kafka-1") + struct.pack(">i", 9092)
    topic_only = (
        struct.pack(">h", 29)  # TOPIC_AUTHORIZATION_FAILED
        + _kstr("private")
        + struct.pack(">i", 0)
    )
    topics = struct.pack(">i", 1) + topic_only
    payload = struct.pack(">i", correlation_id) + brokers + topics

    metadata, error = _parse_metadata_response(payload, correlation_id)
    assert error is None
    assert isinstance(metadata, dict)
    assert metadata["auth_required"] is True


def test_kafka_error_helpers_and_format_record_statuses() -> None:
    assert kafka._kafka_error_name(29) == "TOPIC_AUTHORIZATION_FAILED"
    assert kafka._kafka_error_name(999) == "ERR_999"
    assert kafka._is_probable_auth_error("SASL authentication failed", None) is True
    assert kafka._is_sasl_probe_candidate("unexpected EOF from broker") is True
    assert kafka._is_connection_refused_fail_record({"status": "fail", "error": "connection refused"}) is True
    assert kafka._is_suppressed_fail_record({"status": "fail", "error": "connection timeout"}) is True

    base = {"host": "127.0.0.1", "port": 9092, "topic_count": 2}
    assert "[+] anonymous access (topics:2)" in kafka._format_record({**base, "status": "open_no_auth"}, "txt")
    assert "[-] alice:bad" in kafka._format_record(
        {**base, "status": "invalid_credentials_anonymous", "provided_username": "alice", "provided_password": "bad"},
        "txt",
    )
    assert "[+] alice:<empty>" in kafka._format_record(
        {**base, "status": "valid_credentials", "provided_username": "alice", "provided_password": ""},
        "txt",
    )
    assert "[-] authentication required" in kafka._format_record({**base, "status": "auth_required"}, "txt")
    assert "[!] auth status unknown err=weird" in kafka._format_record(
        {**base, "status": "unknown_auth", "error": "weird"},
        "txt",
    )
    assert "[!] connection failed err=boom" in kafka._format_record({**base, "status": "fail", "error": "boom"}, "txt")


def test_kafka_default_credential_runs_are_exact_and_deduplicated() -> None:
    assert kafka._build_credential_runs(None, None, True) == [
        ("admin", "admin"),
        ("kafka", "kafka"),
        ("kafka", "password"),
    ]
    assert kafka._build_credential_runs("kafka", "kafka", True) == [
        ("kafka", "kafka"),
        ("admin", "admin"),
        ("kafka", "password"),
    ]
    assert kafka._build_credential_runs(None, None, False) == [(None, None)]


def test_kafka_frame_reader_and_request_helpers_cover_edge_cases() -> None:
    assert kafka._friendly_error_text("[Errno 61] Connection refused") == (
        "connection refused (service is not listening on target port)"
    )
    assert kafka._friendly_error_from_exception(TimeoutError("timed out")) == "connection timeout"

    with pytest.raises(ConnectionError, match="unexpected EOF"):
        kafka._recv_exact(_RecvSocket(b""), 1)

    frame = struct.pack(">i", 4) + b"ping"
    assert kafka._recv_kafka_frame(_RecvSocket(frame)) == b"ping"

    with pytest.raises(ValueError, match="invalid Kafka frame size"):
        kafka._recv_kafka_frame(_RecvSocket(struct.pack(">i", 0)))

    assert kafka._encode_kafka_nullable_string(None) == struct.pack(">h", -1)
    assert kafka._encode_kafka_bytes(b"ab") == struct.pack(">i", 2) + b"ab"
    assert kafka._build_metadata_request_body(None) == struct.pack(">i", 0)
    assert kafka._build_metadata_request_body(["orders"]) == struct.pack(">i", 1) + _kstr("orders")
    assert kafka._build_request_header(3, 0, 7, "rp").endswith(_kstr("rp"))

    with pytest.raises(ValueError, match="Kafka string exceeds int16 length"):
        kafka._encode_kafka_string("A" * 40000)

    reader = kafka._KafkaReader(struct.pack(">h", 2) + b"ok" + struct.pack(">i", -1))
    assert reader.read_string(nullable=False) == "ok"
    assert reader.read_bytes(nullable=True) is None

    with pytest.raises(ValueError, match="Kafka non-nullable string is null"):
        kafka._KafkaReader(struct.pack(">h", -1)).read_string(nullable=False)


def test_format_topics_detail_records_text_and_json() -> None:
    record = {
        "timestamp": "2026-03-26T00:00:00Z",
        "host": "127.0.0.1",
        "port": 9092,
        "show_topics": True,
        "topics": ["orders", "audit"],
        "topic_count": 2,
        "query_topic": "orders",
        "query_topic_value": "partitions=2",
        "dump": True,
        "max_messages": 2,
        "dump_topics": ["orders", "audit"],
        "dump_results": {"orders": ["msg-1", "msg-2"]},
        "dump_errors": {"audit": "topic authorization failed"},
    }
    lines = kafka._format_topics_detail_records(record, "txt")
    joined = "\n".join(lines)
    assert "[*] Show Topics" in joined
    assert "[*] Topic orders" in joined
    assert "[*] Dump Topic orders (max:2)" in joined
    assert "msg-1" in joined

    json_payloads = [json.loads(item) for item in kafka._format_topics_detail_records(record, "json")]
    assert {item["type"] for item in json_payloads} == {"topics_list", "topic_query", "topic_dump"}
    dump_payloads = [item for item in json_payloads if item["type"] == "topic_dump"]
    assert len(dump_payloads) == 2
    assert any(item["topic"] == "orders" and item["message_count"] == 2 for item in dump_payloads)
    assert any(item["topic"] == "audit" and item["error"] == "topic authorization failed" for item in dump_payloads)


def test_format_topics_detail_records_dump_fallbacks() -> None:
    no_topics = kafka._format_topics_detail_records(
        {"host": "127.0.0.1", "port": 9092, "dump": True, "max_messages": 1},
        "txt",
    )
    assert "<no topics>" in "\n".join(no_topics)

    no_messages = kafka._format_topics_detail_records(
        {
            "host": "127.0.0.1",
            "port": 9092,
            "query_topic": "orders",
            "dump": True,
            "max_messages": 1,
            "topic_messages": [],
        },
        "txt",
    )
    assert "<no messages>" in "\n".join(no_messages)


def test_audit_kafka_host_open_access_with_dump(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.clients.kafka.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(kafka, "_probe_apiversions", lambda *_args, **_kwargs: (True, None, None))
    monkeypatch.setattr(
        kafka,
        "_fetch_metadata",
        lambda *_args, **_kwargs: ({"auth_required": False, "topic_map": {"orders": 2, "audit": 1}}, None),
    )
    monkeypatch.setattr(
        kafka,
        "_read_dump_topics",
        lambda **_kwargs: ({"orders": ["msg-1", "msg-2"]}, {}),
    )

    record = kafka._audit_kafka_host(
        "127.0.0.1",
        9092,
        1.0,
        0,
        username=None,
        password=None,
        show_topics=True,
        query_topic="orders",
        dump=True,
        max_messages=2,
    )

    assert record["status"] == "open_no_auth"
    assert record["topic_count"] == 2
    assert record["query_topic_value"] == "orders (partitions:2)"
    assert record["dump_topics"] == ["orders"]
    assert record["topic_messages"] == ["msg-1", "msg-2"]


def test_audit_kafka_host_uses_valid_credentials_when_auth_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.clients.kafka.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(kafka, "_probe_apiversions", lambda *_args, **_kwargs: (True, None, None))
    monkeypatch.setattr(
        kafka,
        "_fetch_metadata",
        lambda *_args, **_kwargs: (
            {"auth_required": True, "topic_map": {}, "error_codes": [29]},
            None,
        ),
    )
    monkeypatch.setattr(
        kafka,
        "_authenticate_and_fetch_metadata",
        lambda *_args, **_kwargs: (True, {"topic_map": {"private": 3}}, None),
    )

    record = kafka._audit_kafka_host(
        "127.0.0.1",
        9092,
        1.0,
        0,
        username="alice",
        password="secret",
        show_topics=True,
        query_topic="private",
        dump=False,
        max_messages=10,
    )

    assert record["status"] == "valid_credentials"
    assert record["auth_required"] is True
    assert record["provided_credentials_ok"] is True
    assert record["query_topic_value"] == "private (partitions:3)"
    assert record["topics"] == ["private"]


def test_audit_kafka_host_falls_back_to_sasl_probe_and_retries_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.clients.kafka.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        kafka, "_probe_apiversions", lambda *_args, **_kwargs: (False, None, "unexpected EOF from broker")
    )
    monkeypatch.setattr(
        kafka,
        "_audit_kafka_via_sasl_fallback",
        lambda **_kwargs: {
            "timestamp": "2026-03-26T00:00:00Z",
            "host": "127.0.0.1",
            "port": 9092,
            "is_kafka": True,
            "status": "valid_credentials",
            "auth_required": True,
            "provided_credentials": True,
            "provided_credentials_ok": True,
            "topics": ["orders"],
            "topic_count": 1,
            "show_topics": True,
            "query_topic": None,
            "dump": False,
            "max_messages": None,
            "error": None,
        },
    )

    record = kafka._audit_kafka_host(
        "127.0.0.1",
        9092,
        1.0,
        0,
        username="alice",
        password="secret",
        show_topics=True,
        query_topic=None,
        dump=False,
        max_messages=10,
    )
    assert record["status"] == "valid_credentials"
    assert record["is_kafka"] is True

    monkeypatch.setattr(
        "redposture_core.clients.kafka.socket.create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("connection refused")),
    )
    monkeypatch.setattr(kafka, "_audit_kafka_via_sasl_fallback", lambda **_kwargs: None)
    monkeypatch.setattr(kafka, "_retry_delay", lambda _attempt: 0.0)
    failed = kafka._audit_kafka_host(
        "127.0.0.1",
        9092,
        1.0,
        1,
        username=None,
        password=None,
        show_topics=False,
        query_topic=None,
        dump=False,
        max_messages=10,
    )
    assert failed["status"] == "fail"
    assert "connection refused" in str(failed["error"])


def test_offsets_fetch_and_message_parsers_cover_success_and_errors() -> None:
    correlation_id = 21
    list_offsets_payload = (
        struct.pack(">i", correlation_id)
        + struct.pack(">i", 1)
        + _kstr("orders")
        + struct.pack(">i", 1)
        + struct.pack(">i", 0)
        + struct.pack(">h", 0)
        + struct.pack(">i", 1)
        + struct.pack(">q", 42)
    )
    offset, error = kafka._parse_list_offsets_response(list_offsets_payload, correlation_id)
    assert offset == 42
    assert error is None

    fetch_payload = (
        struct.pack(">i", correlation_id)
        + struct.pack(">i", 1)
        + _kstr("orders")
        + struct.pack(">i", 1)
        + struct.pack(">i", 0)
        + struct.pack(">h", 0)
        + struct.pack(">q", 99)
        + struct.pack(">i", len(_fetch_message_set(7, "hello")))
        + _fetch_message_set(7, "hello")
    )
    items, fetch_error = kafka._parse_fetch_response(
        fetch_payload,
        correlation_id,
        expected_partition=0,
        max_messages=5,
    )
    assert fetch_error is None
    assert items == [(7, "hello")]

    record_batch_payload = (
        struct.pack(">i", correlation_id)
        + struct.pack(">i", 1)
        + _kstr("audit.logs")
        + struct.pack(">i", 1)
        + struct.pack(">i", 0)
        + struct.pack(">h", 0)
        + struct.pack(">q", 99)
        + struct.pack(">i", len(_fetch_record_batch(11, ["alpha", "beta"])))
        + _fetch_record_batch(11, ["alpha", "beta"])
    )
    record_batch_items, record_batch_error = kafka._parse_fetch_response(
        record_batch_payload,
        correlation_id,
        expected_partition=0,
        max_messages=5,
    )
    assert record_batch_error is None
    assert record_batch_items == [(11, "alpha"), (12, "beta")]

    bad_fetch_payload = (
        struct.pack(">i", correlation_id)
        + struct.pack(">i", 1)
        + _kstr("orders")
        + struct.pack(">i", 1)
        + struct.pack(">i", 0)
        + struct.pack(">h", 29)
        + struct.pack(">q", 99)
        + struct.pack(">i", 0)
    )
    items, fetch_error = kafka._parse_fetch_response(
        bad_fetch_payload,
        correlation_id,
        expected_partition=0,
        max_messages=5,
    )
    assert items is None
    assert fetch_error == "Fetch failed: TOPIC_AUTHORIZATION_FAILED"


def test_sasl_helpers_and_dump_targets(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    def fake_send_kafka_request(
        _sock: object,
        *,
        api_key: int,
        api_version: int,
        correlation_id: int,
        client_id: str,
        body: bytes,
    ) -> bytes:
        _ = (client_id, body)
        if api_key == kafka.KAFKA_SASL_HANDSHAKE and api_version == 1:
            return struct.pack(">i", correlation_id) + struct.pack(">h", 35)
        if api_key == kafka.KAFKA_SASL_HANDSHAKE and api_version == 0:
            return struct.pack(">i", correlation_id) + struct.pack(">h", 0) + struct.pack(">i", 1) + _kstr("PLAIN")
        if api_key == kafka.KAFKA_SASL_AUTHENTICATE:
            return (
                struct.pack(">i", correlation_id)
                + struct.pack(">h", 0)
                + struct.pack(">h", -1)
                + struct.pack(">i", -1)
                + struct.pack(">q", 0)
            )
        pytest.fail(f"unexpected api_key={api_key} api_version={api_version}")

    monkeypatch.setattr(kafka, "_send_kafka_request", fake_send_kafka_request)

    hs_ok, next_corr, hs_error = kafka._sasl_handshake_plain(_RecvSocket(), 9)
    assert (hs_ok, next_corr, hs_error) == (True, 10, None)

    auth_ok, next_corr, auth_error = kafka._sasl_authenticate_plain(_RecvSocket(), 10, "alice", "secret")
    assert (auth_ok, next_corr, auth_error) == (True, 11, None)

    monkeypatch.setattr(
        "redposture_core.clients.kafka.socket.create_connection", lambda *_args, **_kwargs: _RecvSocket()
    )
    monkeypatch.setattr(kafka, "_probe_apiversions", lambda *_args, **_kwargs: (True, None, None))
    monkeypatch.setattr(kafka, "_sasl_handshake_plain", lambda *_args, **_kwargs: (True, 2, None))
    monkeypatch.setattr(kafka, "_sasl_authenticate_plain", lambda *_args, **_kwargs: (True, 3, None))
    monkeypatch.setattr(
        kafka,
        "_fetch_metadata",
        lambda *_args, **_kwargs: ({"topic_map": {"orders": 1}, "auth_required": False}, None),
    )

    ok, metadata, error = kafka._authenticate_and_fetch_metadata("127.0.0.1", 9092, 1.0, "alice", "secret")
    assert ok is True
    assert error is None
    assert metadata == {"topic_map": {"orders": 1}, "auth_required": False}

    monkeypatch.setattr(
        kafka,
        "_read_topic_messages",
        lambda **kwargs: (["p0@7 hello"], None) if kwargs["topic"] == "orders" else (None, "denied"),
    )
    dump_results, dump_errors = kafka._read_dump_topics(
        host="127.0.0.1",
        port=9092,
        timeout=1.0,
        topics=["orders", "secret"],
        max_messages=2,
        username=None,
        password=None,
    )
    assert dump_results["orders"] == ["p0@7 hello"]
    assert dump_errors["secret"] == "denied"

    def fake_audit_kafka_host(*args, **kwargs):
        _ = (args, kwargs)
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": "127.0.0.1",
            "port": 9092,
            "is_kafka": True,
            "status": "open_no_auth",
            "auth_required": False,
            "provided_credentials": False,
            "provided_credentials_ok": None,
            "show_topics": True,
            "query_topic": "orders",
            "query_topic_value": "orders (partitions:1)",
            "dump": True,
            "max_messages": 1,
            "topic_count": 1,
            "topics": ["orders"],
            "dump_topics": ["orders"],
            "dump_results": {"orders": ["p0@7 hello"]},
            "dump_errors": {},
            "topic_messages": ["p0@7 hello"],
            "topic_read_error": None,
            "error": None,
        }

    monkeypatch.setattr(kafka, "_audit_kafka_host", fake_audit_kafka_host)
    output_path = tmp_path / "kafka.json"
    emitted: list[str] = []
    totals = run_module_targets_for_test(
        "kafka",
        hosts=["127.0.0.1"],
        port=9092,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        show_topics=True,
        query_topic="orders",
        dump=True,
        max_messages=1,
        output_path=str(output_path),
        output_format="json",
        emit_line=emitted.append,
    )
    assert totals == (1, 1, 0, 0, 0)
    lines = output_path.read_text(encoding="utf-8").splitlines()
    assert any(json.loads(line).get("service") == "kafka" for line in lines)
    assert any("orders" in line for line in lines + emitted)


@pytest.mark.parametrize(
    ("overrides", "expected_message"),
    [
        ({"timeout": 0}, "--timeout must be > 0"),
        ({"retries": -1}, "--retries must be >= 0"),
        ({"max_messages": 0}, "--max-messages must be > 0"),
        ({"dump": 5, "max_messages": 10}, "--dump count cannot conflict with --max-messages"),
        ({"username": "alice"}, "--username and --password must be set together"),
        ({"ports": "bad"}, "failed to parse --port"),
        ({"targets": None, "hosts": None}, "kafka requires -t/--targets"),
    ],
)
def test_run_kafka_stage_validation_errors(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object], expected_message: str
) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kafka, "Console", _ConsoleCapture)
    rc = kafka.run_kafka_stage(_kafka_args(**overrides), logger=object())
    assert rc == 2
    assert any(expected_message in msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "error")


def test_run_kafka_stage_accepts_explicit_empty_password(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_passwords: list[str | None] = []

    def fake_run_plan(self, plan):
        _ = self
        captured_passwords.extend(credential.password for credential in plan.credential_runs)
        return AuditCommandResult(records=[], detected_count=1, emitted_lines=0, typed_records=[])

    monkeypatch.setattr(kafka_stage_pkg.AuditCommandRunner, "run_plan", fake_run_plan)

    rc = kafka.run_kafka_stage(_kafka_args(username="empire", password=""), logger=object())

    assert rc == 0
    assert captured_passwords == [""]


def test_run_kafka_stage_uses_dump_count_as_message_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[bool, bool, int]] = []

    def fake_stage_call(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        username: str | None,
        password: str | None,
        show_topics: bool,
        query_topic: str | None,
        dump: bool,
        max_messages: int,
        *,
        run_deep_checks: bool,
        debug: bool,
        debug_emit,
        show_topics_limit: int | None = None,
    ) -> dict[str, object]:
        _ = (
            timeout,
            retries,
            username,
            password,
            show_topics,
            query_topic,
            debug,
            debug_emit,
            show_topics_limit,
        )
        captured.append((bool(run_deep_checks), bool(dump), int(max_messages)))
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": port,
            "is_kafka": True,
            "status": "open_no_auth",
            "auth_required": False,
            "provided_credentials": False,
            "show_topics": bool(show_topics),
            "query_topic": query_topic,
            "topic_count": 1,
            "topics": ["orders"] if run_deep_checks else None,
            "query_topic_value": "orders (partitions:1)" if query_topic else None,
            "dump": bool(dump),
            "max_messages": int(max_messages) if dump else None,
            "dump_topics": ["orders"] if dump else None,
            "dump_results": {"orders": ["p0@1 ord-1001"]} if dump else None,
            "dump_errors": {},
            "dump_error": None,
            "error": None,
        }

    monkeypatch.setattr(kafka_actions, "_call_audit_kafka_host_with_stage_debug", fake_stage_call)

    rc = kafka.run_kafka_stage(
        _kafka_args(show_topics=True, topic="orders", dump=3, max_messages=None),
        logger=object(),
    )

    assert rc == 0
    assert (True, True, 3) in captured


def test_run_kafka_stage_suppresses_unreachable_summary_without_debug(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kafka, "Console", _ConsoleCapture)
    monkeypatch.setattr(kafka, "collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(kafka, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])
    patch_runner_for_legacy_target_fake(monkeypatch, "kafka", lambda **_kwargs: (1, 0, 0, 0, 1))
    rc = kafka.run_kafka_stage(_kafka_args(), logger=object())
    assert rc == 0
    warnings = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "warn"]
    assert not any("all kafka targets are unreachable" in msg for msg in warnings)


def test_run_kafka_stage_debug_flow_passes_logger_and_append_output(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kafka, "Console", _ConsoleCapture)
    monkeypatch.setattr(kafka, "collect_scan_ports", lambda *_args, **_kwargs: [9092, 29092])
    monkeypatch.setattr(kafka, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        kwargs["emit_line"]("KAFKA\t127.0.0.1\t9092\t[*] Kafka Broker")
        return 1, 0, 1, 0, 0

    patch_runner_for_legacy_target_fake(monkeypatch, "kafka", fake_audit_targets)
    rc = kafka.run_kafka_stage(
        _kafka_args(debug=True, output="kafka.json", output_format="json", show_topics=True, dump=True, topic="orders"),
        logger=object(),
    )
    assert rc == 0
    assert len(captured) == 2
    assert captured[0]["append_output"] is False
    assert captured[1]["append_output"] is True
    assert captured[0]["logger"] is not None


def test_run_kafka_stage_multi_port_verbose_uses_single_global_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kafka, "Console", _ConsoleCapture)
    monkeypatch.setattr(kafka, "collect_scan_ports", lambda *_args, **_kwargs: [9092, 29092, 39092])
    monkeypatch.setattr(kafka, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        kwargs["emit_line"]("KAFKA\t127.0.0.1\t9092\t[*] Kafka Broker")
        return 1, 0, 1, 0, 0

    patch_runner_for_legacy_target_fake(monkeypatch, "kafka", fake_audit_targets)

    progress_totals: list[int] = []
    progress_advances: list[int] = []

    class _FakeProgressBar:
        def __init__(self, _label: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            _ = (enabled, leave)
            progress_totals.append(int(total))

        def advance(self, amount: int = 1) -> None:
            progress_advances.append(int(amount))

        def close(self) -> None:
            return

    monkeypatch.setattr(
        kafka,
        "start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgressBar(label, total, **kwargs),
    )

    rc = kafka.run_kafka_stage(
        _kafka_args(show_topics=True, dump=True, topic="orders"),
        logger=object(),
    )
    assert rc == 0
    assert len(captured) == 3
    assert [bool(call["show_progress"]) for call in captured] == [False, False, False]
    assert progress_totals == [3]
    assert progress_advances == [1, 1, 1]


def test_run_kafka_stage_credential_file_output_uses_single_global_progress(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kafka, "Console", _ConsoleCapture)
    monkeypatch.setattr(
        kafka, "filter_open_tcp_hosts_for_credential_file", lambda hosts, *_args, **_kwargs: list(hosts)
    )

    creds_file = tmp_path / "creds.txt"
    creds_file.write_text("alice:one\nbob:two\n", encoding="utf-8")
    output_file = tmp_path / "kafka.txt"

    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return 1, 0, 0, 1, 0

    progress_totals: list[int] = []
    progress_advances: list[int] = []

    class _FakeProgressBar:
        def __init__(self, _label: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            _ = (enabled, leave)
            progress_totals.append(int(total))

        def advance(self, amount: int = 1) -> None:
            progress_advances.append(int(amount))

        def close(self) -> None:
            return

    patch_runner_for_legacy_target_fake(monkeypatch, "kafka", fake_audit_targets)
    monkeypatch.setattr(
        kafka,
        "start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgressBar(label, total, **kwargs),
    )

    rc = kafka.run_kafka_stage(
        _kafka_args(username=str(creds_file), output=str(output_file), show_topics=True, targets="10.0.0.1,10.0.0.2"),
        logger=object(),
    )

    assert rc == 0
    assert len(captured) == 4
    assert all(call["show_progress"] is False for call in captured)
    assert [(call["hosts"], call["username"], call["password"]) for call in captured] == [
        (["10.0.0.1"], "alice", "one"),
        (["10.0.0.1"], "bob", "two"),
        (["10.0.0.2"], "alice", "one"),
        (["10.0.0.2"], "bob", "two"),
    ]
    assert progress_totals == [4]
    assert progress_advances == [1, 1, 1, 1]


def test_run_kafka_stage_defcreds_expands_default_pairs(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kafka, "Console", _ConsoleCapture)
    monkeypatch.setattr(kafka, "collect_scan_ports", lambda *_args, **_kwargs: [9092])
    monkeypatch.setattr(kafka, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    captured: list[tuple[str | None, str | None]] = []

    def fake_audit_targets(**kwargs):
        captured.append((kwargs["username"], kwargs["password"]))
        return 1, 0, 0, 1, 0

    class _FakeProgressBar:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def advance(self, _amount: int = 1) -> None:
            return

        def close(self) -> None:
            return

    patch_runner_for_legacy_target_fake(monkeypatch, "kafka", fake_audit_targets)
    monkeypatch.setattr(
        kafka,
        "start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgressBar(label, total, **kwargs),
    )

    rc = kafka.run_kafka_stage(_kafka_args(defcreds=True), logger=object())

    assert rc == 0
    assert captured == [
        ("admin", "admin"),
        ("kafka", "kafka"),
        ("kafka", "password"),
    ]


def test_run_kafka_stage_txt_emit_line_and_error_path(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kafka, "Console", _ConsoleCapture)
    monkeypatch.setattr(kafka, "collect_scan_ports", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        kafka,
        "collect_scan_targets",
        lambda targets: ["127.0.0.1"] if "hosts.txt" not in str(targets) else ["127.0.0.1", "127.0.0.2"],
    )

    def fake_audit_targets(**kwargs):
        kwargs["emit_line"]("KAFKA\t127.0.0.1\t9092\tpayload only")
        return 1, 0, 1, 0, 0

    patch_runner_for_legacy_target_fake(monkeypatch, "kafka", fake_audit_targets)
    rc = kafka.run_kafka_stage(
        _kafka_args(debug=True, output_format="txt", show_topics=True, dump=True, topic="orders"),
        logger=object(),
    )
    assert rc == 0
    plains = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "plain"]
    infos = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "info"]
    assert any("payload only" in msg for msg in plains)
    assert any("mode=show-topics,topic=orders,dump,max=10" in msg for msg in infos)
    assert capsys.readouterr().out == ""

    patch_runner_for_legacy_target_fake(
        monkeypatch, "kafka", lambda **_kwargs: (_ for _ in ()).throw(OSError("disk full"))
    )
    rc = kafka.run_kafka_stage(_kafka_args(output="kafka.json"), logger=object())
    assert rc == 2
    assert any(
        "failed to process kafka output: disk full" in msg
        for level, msg in _ConsoleCapture.instances[-1].messages
        if level == "error"
    )


def test_call_audit_kafka_host_with_stage_debug_adds_stage_telemetry(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": "127.0.0.1",
            "port": 9092,
            "is_kafka": True,
            "status": "open_no_auth",
            "auth_required": False,
            "show_topics": False,
            "query_topic": None,
            "dump": False,
            "error": None,
        }

    monkeypatch.setattr(kafka, "_audit_kafka_host", fake_audit)
    debug_lines: list[str] = []
    result = kafka._call_audit_kafka_host_with_stage_debug(
        "127.0.0.1",
        9092,
        1.0,
        1,
        None,
        None,
        False,
        None,
        False,
        10,
        run_deep_checks=True,
        debug=True,
        debug_emit=debug_lines.append,
    )
    assert isinstance(result.get("stages"), list)
    assert result.get("stage_durations_ms") is not None
    assert any("stage_trace stage_name=detect_protocol" in line for line in debug_lines)


def test_audit_kafka_targets_emits_two_pass_debug_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_stage_call(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        username: str | None,
        password: str | None,
        show_topics: bool,
        query_topic: str | None,
        dump: bool,
        max_messages: int,
        *,
        run_deep_checks: bool,
        debug: bool,
        debug_emit,
    ) -> dict[str, object]:
        _ = (
            port,
            timeout,
            retries,
            username,
            password,
            show_topics,
            query_topic,
            dump,
            max_messages,
            debug,
            debug_emit,
        )
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": 9092,
            "is_kafka": True,
            "status": "open_no_auth",
            "auth_required": False,
            "provided_credentials": False,
            "show_topics": bool(run_deep_checks),
            "query_topic": None,
            "topic_count": 1,
            "topics": ["orders"] if run_deep_checks else None,
            "query_topic_value": None,
            "dump": False,
            "dump_topics": None,
            "dump_results": None,
            "dump_errors": None,
            "topic_messages": None,
            "topic_read_error": None,
            "error": None,
            "debug_events": [],
            "debug_events_streamed": True,
            "stages": [],
            "stage_durations_ms": {},
            "stage_attempts": {},
            "stage_failed_at": None,
        }

    monkeypatch.setattr(kafka, "_call_audit_kafka_host_with_stage_debug", fake_stage_call)
    debug_lines: list[str] = []
    emitted: list[str] = []
    totals = run_module_targets_for_test(
        "kafka",
        hosts=["127.0.0.1"],
        port=9092,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        show_topics=True,
        query_topic=None,
        dump=False,
        max_messages=10,
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
        debug_emit=debug_lines.append,
        show_progress=False,
    )
    assert totals == (1, 1, 0, 0, 0)
    assert any("pass=1 detect start total=1" in line for line in debug_lines)
    assert any("stage2_gate=run reason=status=open_no_auth" in line for line in debug_lines)
    assert any("pass=2 deep complete processed=1" in line for line in debug_lines)


def test_read_topic_messages_covers_non_auth_and_loop_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.clients.kafka.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    assert kafka._read_topic_messages("127.0.0.1", 9092, 1.0, "orders", 0) == ([], None)

    monkeypatch.setattr(kafka, "_probe_apiversions", lambda *_args, **_kwargs: (False, None, "service is not kafka"))
    assert kafka._read_topic_messages("127.0.0.1", 9092, 1.0, "orders", 2) == (None, "service is not kafka")

    monkeypatch.setattr(kafka, "_probe_apiversions", lambda *_args, **_kwargs: (True, None, None))
    monkeypatch.setattr(kafka, "_fetch_metadata", lambda *_args, **_kwargs: (None, "metadata failed"))
    assert kafka._read_topic_messages("127.0.0.1", 9092, 1.0, "orders", 2) == (None, "metadata failed")

    monkeypatch.setattr(kafka, "_fetch_metadata", lambda *_args, **_kwargs: ({"topic_map": {}}, None))
    assert kafka._read_topic_messages("127.0.0.1", 9092, 1.0, "orders", 2) == ([], None)

    monkeypatch.setattr(kafka, "_fetch_metadata", lambda *_args, **_kwargs: ({"topic_map": {"orders": 2}}, None))
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda *_args, **_kwargs: b"x")
    offsets = iter([(10, None), (None, "offset denied")])
    fetches = iter([([(10, "msg")], None)])
    monkeypatch.setattr(kafka, "_parse_list_offsets_response", lambda *_args, **_kwargs: next(offsets))
    monkeypatch.setattr(kafka, "_parse_fetch_response", lambda *_args, **_kwargs: next(fetches))
    assert kafka._read_topic_messages("127.0.0.1", 9092, 1.0, "orders", 2) == (["p0@10 msg"], None)

    offsets = iter([(10, None)])
    fetches = iter([(None, "fetch failed")])
    monkeypatch.setattr(kafka, "_parse_list_offsets_response", lambda *_args, **_kwargs: next(offsets))
    monkeypatch.setattr(kafka, "_parse_fetch_response", lambda *_args, **_kwargs: next(fetches))
    assert kafka._read_topic_messages("127.0.0.1", 9092, 1.0, "orders", 2) == (None, "fetch failed")


def test_read_topic_messages_with_credentials_covers_auth_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.clients.kafka.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(kafka, "_sasl_handshake_plain", lambda *_args, **_kwargs: (False, 2, "hs fail"))
    assert kafka._read_topic_messages(
        "127.0.0.1",
        9092,
        1.0,
        "orders",
        1,
        username="alice",
        password="secret",
    ) == (None, "hs fail")

    monkeypatch.setattr(kafka, "_sasl_handshake_plain", lambda *_args, **_kwargs: (True, 2, None))
    monkeypatch.setattr(kafka, "_sasl_authenticate_plain", lambda *_args, **_kwargs: (False, 3, "auth fail"))
    assert kafka._read_topic_messages(
        "127.0.0.1",
        9092,
        1.0,
        "orders",
        1,
        username="alice",
        password="secret",
    ) == (None, "auth fail")


def test_audit_kafka_via_sasl_fallback_branch_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.clients.kafka.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(kafka, "_sasl_handshake_plain", lambda *_args, **_kwargs: (False, 2, "hs fail"))
    assert (
        kafka._audit_kafka_via_sasl_fallback(
            host="127.0.0.1",
            port=9092,
            timeout=1.0,
            username=None,
            password=None,
            show_topics=False,
            query_topic=None,
            dump=False,
            max_messages=1,
        )
        is None
    )

    monkeypatch.setattr(kafka, "_sasl_handshake_plain", lambda *_args, **_kwargs: (True, 2, None))
    monkeypatch.setattr(kafka, "_sasl_authenticate_plain", lambda *_args, **_kwargs: (False, 3, "bad creds"))
    denied = kafka._audit_kafka_via_sasl_fallback(
        host="127.0.0.1",
        port=9092,
        timeout=1.0,
        username="alice",
        password="bad",
        show_topics=False,
        query_topic="orders",
        dump=True,
        max_messages=1,
    )
    assert isinstance(denied, dict)
    assert denied["status"] == "auth_required"
    assert denied["query_topic_value"] == "orders:<authentication required>"
    assert denied["dump_error"] == "authentication required"
    assert "bad creds" in str(denied["error"])

    monkeypatch.setattr(kafka, "_sasl_authenticate_plain", lambda *_args, **_kwargs: (True, 3, None))
    monkeypatch.setattr(kafka, "_fetch_metadata", lambda *_args, **_kwargs: ({"topic_map": {"orders": 1}}, None))
    monkeypatch.setattr(kafka, "_read_dump_topics", lambda **_kwargs: ({"orders": ["p0@1 hello"]}, {}))
    allowed = kafka._audit_kafka_via_sasl_fallback(
        host="127.0.0.1",
        port=9092,
        timeout=1.0,
        username="alice",
        password="secret",
        show_topics=True,
        query_topic="orders",
        dump=True,
        max_messages=1,
    )
    assert isinstance(allowed, dict)
    assert allowed["status"] == "valid_credentials"
    assert allowed["topics"] == ["orders"]
    assert allowed["topic_messages"] == ["p0@1 hello"]
