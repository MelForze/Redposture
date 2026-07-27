from __future__ import annotations

import argparse
import json
import struct

import pytest

from redposture_core import stage_kafka as kafka
from redposture_core.audit_models import AuditRecord
from redposture_core.clients import kafka as kafka_client
from redposture_core.modules.kafka import actions as kafka_actions
from redposture_core.modules.kafka import stage as kafka_stage_pkg
from redposture_core.stage_kafka import _parse_apiversions_response, _parse_metadata_response
from redposture_core.stage_runtime import AuditCommandResult
from tests.stage_runtime_helpers import patch_module_host_stage_for_test, run_module_targets_for_test


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

    def _paint(self, text: str, _color: str, _stream) -> str:
        return text

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


def _kafka_host_record(
    kwargs: dict[str, object],
    *,
    status: str,
    detected: bool,
    error: str | None = None,
) -> AuditRecord:
    deep = bool(kwargs.get("run_deep_checks"))
    topic = kwargs.get("query_topic")
    dump = bool(kwargs.get("dump"))
    return AuditRecord(
        host=str(kwargs["host"]),
        port=int(kwargs["port"]),
        service="kafka",
        module="kafka",
        status=status,
        auth_required=status == "auth_required",
        extra={
            "is_kafka": detected,
            "error": error,
            "provided_username": kwargs.get("username"),
            "provided_password": kwargs.get("password"),
            "show_topics": bool(kwargs.get("show_topics")),
            "topic_count": 1 if detected else None,
            "topics": ["orders"] if deep else None,
            "query_topic": topic,
            "query_topic_value": "orders (partitions:1)" if deep and topic else None,
            "dump": dump,
            "max_messages": kwargs.get("max_messages") if dump else None,
            "dump_topics": ["orders"] if deep and dump else None,
            "dump_results": {"orders": ["p0@1 ord-1001"]} if deep and dump else None,
        },
    )


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
    open_record = {**base, "status": "open_no_auth"}
    assert kafka._format_record(open_record, "txt") == ""
    assert json.loads(kafka._format_record(open_record, "json"))["status"] == "open_no_auth"
    assert "[-] alice:bad" in kafka._format_record(
        {**base, "status": "invalid_credentials_anonymous", "provided_username": "alice", "provided_password": "bad"},
        "txt",
    )
    assert "[-] alice:<empty>" in kafka._format_record(
        {**base, "status": "invalid_credentials_anonymous", "provided_username": "alice", "provided_password": ""},
        "txt",
    )
    assert "[+] alice:<empty>" in kafka._format_record(
        {**base, "status": "valid_credentials", "provided_username": "alice", "provided_password": ""},
        "txt",
    )
    assert "[-] authentication required attempts=2 users=admin,kafka" in kafka._format_record(
        {
            **base,
            "status": "auth_required",
            "provided_credentials": True,
            "provided_username": "kafka",
            "provided_password": "password",
            "attempted_credentials": [
                {"username": "admin", "password": "admin", "source": "default", "status": "auth_required"},
                {"username": "kafka", "password": "password", "source": "default", "status": "auth_required"},
            ],
        },
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


def test_run_kafka_stage_defcreds_keeps_no_auth_result_as_anonymous(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kafka, "Console", _ConsoleCapture)
    calls: list[tuple[str | None, str | None, bool]] = []

    def fake_detect(ctx, _options) -> dict[str, object]:
        calls.append((ctx.credential.username, ctx.credential.password, False))
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": ctx.host,
            "port": ctx.port,
            "is_kafka": True,
            "status": "open_no_auth",
            "auth_required": False,
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "provided_credentials_ok": None,
            "show_topics": True,
            "query_topic": None,
            "dump": False,
            "topic_count": 1,
            "topics": None,
            "error": None,
        }

    def fake_data(ctx, record, _options) -> dict[str, object]:
        calls.append((ctx.credential.username, ctx.credential.password, True))
        payload = record.to_dict()
        payload.update({"show_topics": True, "topics": ["orders"], "topic_count": 1})
        return payload

    monkeypatch.setattr(kafka_actions, "detect_kafka", fake_detect)
    monkeypatch.setattr(
        kafka_actions,
        "authenticate_kafka",
        lambda *_args, **_kwargs: pytest.fail("anonymous-open detect must skip default credentials"),
    )
    monkeypatch.setattr(kafka_actions, "collect_kafka_data", fake_data)

    rc = kafka.run_kafka_stage(_kafka_args(defcreds=True, show_topics=True), logger=object())

    assert rc == 0
    plains = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "plain"]
    assert any("Kafka Broker (auth required:False)" in msg for msg in plains)
    assert not any("[+] anonymous access" in msg for msg in plains)
    assert not any("[-] kafka:password" in msg for msg in plains)
    assert not any("[-] admin:admin" in msg for msg in plains)
    assert calls == [(None, None, False), (None, None, True)]


def test_run_kafka_stage_defcreds_auth_required_renders_failed_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kafka, "Console", _ConsoleCapture)
    calls: list[tuple[str | None, str | None, bool]] = []

    def fake_detect(ctx, _options) -> dict[str, object]:
        calls.append((ctx.credential.username, ctx.credential.password, False))
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": ctx.host,
            "port": ctx.port,
            "is_kafka": True,
            "status": "auth_required",
            "auth_required": True,
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "provided_credentials_ok": None,
            "show_topics": False,
            "query_topic": None,
            "dump": False,
            "topic_count": None,
            "topics": None,
            "error": None,
        }

    def fake_auth(ctx, record, _options) -> dict[str, object]:
        calls.append((ctx.credential.username, ctx.credential.password, False))
        payload = record.to_dict()
        payload.update(
            {
                "provided_credentials": True,
                "provided_username": ctx.credential.username,
                "provided_password": ctx.credential.password,
                "provided_credentials_ok": False,
                "error": "SASL authentication failed",
            }
        )
        return payload

    monkeypatch.setattr(kafka_actions, "detect_kafka", fake_detect)
    monkeypatch.setattr(kafka_actions, "authenticate_kafka", fake_auth)
    monkeypatch.setattr(
        kafka_actions,
        "collect_kafka_data",
        lambda *_args, **_kwargs: pytest.fail("failed credentials must not reach data"),
    )

    rc = kafka.run_kafka_stage(_kafka_args(defcreds=True), logger=object())

    assert rc == 0
    assert calls == [
        (None, None, False),
        ("admin", "admin", False),
        ("kafka", "kafka", False),
        ("kafka", "password", False),
    ]
    plains = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "plain"]
    assert any("[-] authentication required attempts=3 users=admin,kafka" in msg for msg in plains)
    assert not any("[-] kafka:password" in msg for msg in plains)


def test_kafka_malformed_frame_failure_does_not_abort_next_target(monkeypatch: pytest.MonkeyPatch) -> None:
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
            dump,
            max_messages,
            run_deep_checks,
            debug,
            debug_emit,
            show_topics_limit,
        )
        if host == "bad":
            raise ValueError("invalid Kafka frame size 1213486160")
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": port,
            "is_kafka": True,
            "status": "open_no_auth",
            "auth_required": False,
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "provided_credentials_ok": None,
            "show_topics": False,
            "query_topic": None,
            "dump": False,
            "topic_count": 1,
            "topics": None,
            "error": None,
        }

    emitted: list[str] = []
    monkeypatch.setattr(kafka, "_call_audit_kafka_host_with_stage_debug", fake_stage_call)

    totals = run_module_targets_for_test(
        "kafka",
        hosts=["bad", "ok"],
        port=9092,
        emit_line=emitted.append,
        workers=2,
        topic=None,
    )

    assert totals == (2, 1, 0, 0, 1)
    assert any("invalid Kafka frame size 1213486160" in line for line in emitted)
    assert any("Kafka Broker (auth required:False)" in line and "\tok\t" in line for line in emitted)
    assert not any("[+] anonymous access" in line for line in emitted)


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
        "query_topic_value": "orders (partitions:2)",
        "dump": True,
        "max_messages": 2,
        "max_messages_explicit": True,
        "dump_topics": ["orders", "audit"],
        "dump_results": {"orders": ["msg-1", "msg-2"]},
        "dump_errors": {"audit": "topic authorization failed"},
    }
    lines = kafka._format_topics_detail_records(record, "txt")
    joined = "\n".join(lines)
    assert "[*] Show Topics" in joined
    # `--topic X --dump` now folds partition-info into the Dump header
    # instead of emitting `[*] Topic X` + `X(partitions:N)` + `[*] Dump
    # Topic X (max:M)` — three lines collapsed to one.
    assert "[*] Topic orders" not in joined
    assert "[*] Dump Topic orders (partitions:2) (max:2)" in joined
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
        lambda *_args, **_kwargs: (True, {"topic_map": {"private": 3}}, None, "plaintext"),
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


def test_audit_kafka_host_default_pair_yields_weak_default_creds_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kafka E2E-batch fix: when the winning credential pair matches one of
    `_KAFKA_DEFAULT_CREDENTIALS`, status must be `weak_default_creds` and
    `defcreds_enabled=True` — parity with postgres/mongodb. Previously kafka
    unconditionally reported `valid_credentials` even when `admin:admin`
    succeeded, hiding a real weak-credential finding from downstream reports.
    Regressioned against a live SASL/PLAIN lab that seeded `user_admin=admin`.
    """
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
        lambda *_args, **_kwargs: (True, {"topic_map": {}}, None, "plaintext"),
    )

    record = kafka._audit_kafka_host(
        "127.0.0.1",
        9092,
        1.0,
        0,
        username="admin",  # a member of _KAFKA_DEFAULT_CREDENTIALS
        password="admin",
        show_topics=True,
        query_topic=None,
        dump=False,
        max_messages=10,
    )

    assert record["status"] == "weak_default_creds"
    assert record["defcreds_enabled"] is True
    assert record["provided_credentials_ok"] is True
    assert record["effective_username"] == "admin"
    # credential_attempts populated with the winning attempt so downstream
    # renderers can surface `admin:admin` as a weak-cred finding.
    attempts = record["credential_attempts"]
    assert len(attempts) == 1
    assert attempts[0]["username"] == "admin"
    assert attempts[0]["default"] is True
    assert attempts[0]["ok"] is True


def test_audit_kafka_host_non_default_pair_stays_valid_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Twin of the weak_default_creds test: a non-default winning pair MUST
    stay `valid_credentials` (and `defcreds_enabled=False`), so we don't
    over-report every successful auth as a weak-credential finding."""
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
        lambda *_args, **_kwargs: (True, {"topic_map": {}}, None, "plaintext"),
    )

    record = kafka._audit_kafka_host(
        "127.0.0.1",
        9092,
        1.0,
        0,
        username="metrics",
        password="metricspass",
        show_topics=True,
        query_topic=None,
        dump=False,
        max_messages=10,
    )

    assert record["status"] == "valid_credentials"
    assert record["defcreds_enabled"] is False
    assert record["credential_attempts"][0]["default"] is False


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

    # Fetch v10 wire format:
    #   correlation_id | throttle_time_ms | top_error_code (v7+) |
    #   session_id (v7+) | topic_count | topic_name | partition_count |
    #   partition_id | error_code | high_watermark | last_stable_offset (v4+) |
    #   log_start_offset (v5+) | aborted_txns_count (0) | records_size | records
    def _v10_fetch(topic: str, partition: int, error_code: int, records: bytes) -> bytes:
        return (
            struct.pack(">i", correlation_id)
            + struct.pack(">i", 0)  # throttle_time_ms
            + struct.pack(">h", 0)  # top_error_code (v7+)
            + struct.pack(">i", 0)  # session_id (v7+)
            + struct.pack(">i", 1)  # topic count
            + _kstr(topic)
            + struct.pack(">i", 1)  # partition count
            + struct.pack(">i", partition)
            + struct.pack(">h", error_code)
            + struct.pack(">q", 99)  # high_watermark
            + struct.pack(">q", 99)  # last_stable_offset
            + struct.pack(">q", 0)  # log_start_offset (v5+)
            + struct.pack(">i", 0)  # aborted_transactions count
            + struct.pack(">i", len(records))
            + records
        )

    fetch_payload = _v10_fetch("orders", 0, 0, _fetch_message_set(7, "hello"))
    items, fetch_error = kafka._parse_fetch_response(
        fetch_payload,
        correlation_id,
        expected_partition=0,
        max_messages=5,
    )
    assert fetch_error is None
    assert items == [(7, "hello")]

    record_batch_payload = _v10_fetch("audit.logs", 0, 0, _fetch_record_batch(11, ["alpha", "beta"]))
    record_batch_items, record_batch_error = kafka._parse_fetch_response(
        record_batch_payload,
        correlation_id,
        expected_partition=0,
        max_messages=5,
    )
    assert record_batch_error is None
    assert record_batch_items == [(11, "alpha"), (12, "beta")]

    bad_fetch_payload = _v10_fetch("orders", 0, 29, b"")
    items, fetch_error = kafka._parse_fetch_response(
        bad_fetch_payload,
        correlation_id,
        expected_partition=0,
        max_messages=5,
    )
    assert items is None
    assert fetch_error is not None
    assert "Fetch failed: TOPIC_AUTHORIZATION_FAILED" in fetch_error
    # Diagnostics: partition + high_watermark carried through so operators
    # can see broker-side state without wire tracing.
    assert "partition=0" in fetch_error
    assert "high_watermark=99" in fetch_error


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

    ok, metadata, error, transport_mode = kafka._authenticate_and_fetch_metadata(
        "127.0.0.1", 9092, 1.0, "alice", "secret"
    )
    assert ok is True
    assert error is None
    assert metadata == {"topic_map": {"orders": 1}, "auth_required": False}
    assert transport_mode == "plaintext"

    monkeypatch.setattr(
        kafka,
        "_read_topic_messages",
        lambda **kwargs: (
            (["p0@7 hello"], None, "plaintext") if kwargs["topic"] == "orders" else (None, "denied", "plaintext")
        ),
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
    patch_module_host_stage_for_test(
        monkeypatch,
        "kafka",
        lambda **kwargs: _kafka_host_record(
            kwargs,
            status="fail",
            detected=False,
            error="connection refused",
        ),
    )
    rc = kafka.run_kafka_stage(_kafka_args(), logger=object())
    assert rc == 0
    warnings = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "warn"]
    assert not any("all kafka targets are unreachable" in msg for msg in warnings)


def test_run_kafka_stage_debug_flow_binds_actions_and_writes_all_ports(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kafka, "Console", _ConsoleCapture)
    monkeypatch.setattr(kafka, "collect_scan_ports", lambda *_args, **_kwargs: [9092, 29092])
    monkeypatch.setattr(kafka, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):
        captured.append(dict(kwargs))
        return _kafka_host_record(kwargs, status="open_no_auth", detected=True)

    patch_module_host_stage_for_test(monkeypatch, "kafka", fake_audit_targets)
    output = tmp_path / "kafka.jsonl"
    rc = kafka.run_kafka_stage(
        _kafka_args(
            debug=True,
            output=str(output),
            output_format="json",
            show_topics=True,
            dump=True,
            topic="orders",
        ),
        logger=object(),
    )
    assert rc == 0
    assert [(call["port"], call["run_deep_checks"]) for call in captured] == [
        (9092, False),
        (29092, False),
        (9092, True),
        (29092, True),
    ]
    assert all(call["debug"] is True and callable(call["debug_emit"]) for call in captured)
    assert len(output.read_text(encoding="utf-8").splitlines()) == 2


def test_run_kafka_stage_multi_port_verbose_uses_single_global_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kafka, "Console", _ConsoleCapture)
    monkeypatch.setattr(kafka, "collect_scan_ports", lambda *_args, **_kwargs: [9092, 29092, 39092])
    monkeypatch.setattr(kafka, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):
        captured.append(dict(kwargs))
        return _kafka_host_record(kwargs, status="open_no_auth", detected=True)

    patch_module_host_stage_for_test(monkeypatch, "kafka", fake_audit_targets)

    progress_totals: list[int] = []
    progress_advances: list[int] = []

    class _FakeProgressBar:
        def __init__(self, _label: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            _ = (enabled, leave)
            progress_totals.append(int(total))

        def advance(self, amount: int = 1) -> None:
            progress_advances.append(int(amount))

        def add_total(self, amount: int) -> None:
            progress_totals.append(progress_totals.pop() + int(amount))

        def close(self) -> None:
            return

    monkeypatch.setattr(
        "redposture_core.stage_runtime.start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgressBar(label, total, **kwargs),
    )

    rc = kafka.run_kafka_stage(
        _kafka_args(show_topics=True, dump=True, topic="orders"),
        logger=object(),
    )
    assert rc == 0
    assert [(call["port"], call["run_deep_checks"]) for call in captured] == [
        (9092, False),
        (29092, False),
        (39092, False),
        (9092, True),
        (29092, True),
        (39092, True),
    ]
    assert progress_totals == [6]
    assert progress_advances == [1, 1, 1, 1, 1, 1]


def test_run_kafka_stage_credential_file_output_uses_single_global_progress(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kafka, "Console", _ConsoleCapture)
    monkeypatch.setattr(
        "redposture_core.stage_runtime.filter_open_tcp_hosts_for_credential_file",
        lambda *_args, **_kwargs: pytest.fail("credential-file TCP prefilter must not run"),
    )

    creds_file = tmp_path / "creds.txt"
    creds_file.write_text("alice:one\nbob:two\n", encoding="utf-8")
    output_file = tmp_path / "kafka.txt"

    captured: list[dict[str, object]] = []

    def fake_audit_targets(**kwargs):
        captured.append(dict(kwargs))
        username = kwargs.get("username")
        status = "valid_credentials" if username == "bob" else "auth_required"
        return _kafka_host_record(kwargs, status=status, detected=True)

    progress_totals: list[int] = []
    progress_advances: list[int] = []

    class _FakeProgressBar:
        def __init__(self, _label: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            _ = (enabled, leave)
            progress_totals.append(int(total))

        def advance(self, amount: int = 1) -> None:
            progress_advances.append(int(amount))

        def add_total(self, amount: int) -> None:
            progress_totals.append(progress_totals.pop() + int(amount))

        def close(self) -> None:
            return

    patch_module_host_stage_for_test(monkeypatch, "kafka", fake_audit_targets)
    monkeypatch.setattr(
        "redposture_core.stage_runtime.start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgressBar(label, total, **kwargs),
    )

    rc = kafka.run_kafka_stage(
        _kafka_args(username=str(creds_file), output=str(output_file), show_topics=True, targets="10.0.0.1,10.0.0.2"),
        logger=object(),
    )

    assert rc == 0
    assert [(call["host"], call["username"], call["password"], call["run_deep_checks"]) for call in captured] == [
        ("10.0.0.1", None, None, False),
        ("10.0.0.2", None, None, False),
        ("10.0.0.1", "alice", "one", True),
        ("10.0.0.1", "bob", "two", True),
        ("10.0.0.2", "alice", "one", True),
        ("10.0.0.2", "bob", "two", True),
    ]
    assert progress_totals == [4]
    assert progress_advances == [1, 1, 1, 1]


def test_run_kafka_stage_defcreds_expands_default_pairs(monkeypatch: pytest.MonkeyPatch) -> None:
    _ConsoleCapture.instances.clear()
    monkeypatch.setattr(kafka, "Console", _ConsoleCapture)
    monkeypatch.setattr(kafka, "collect_scan_ports", lambda *_args, **_kwargs: [9092])
    monkeypatch.setattr(kafka, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    captured: list[tuple[str | None, str | None, bool]] = []

    def fake_audit_targets(**kwargs):
        captured.append((kwargs["username"], kwargs["password"], kwargs["run_deep_checks"]))
        status = (
            "valid_credentials"
            if (kwargs["username"], kwargs["password"]) == ("kafka", "password")
            else "auth_required"
        )
        return _kafka_host_record(kwargs, status=status, detected=True)

    class _FakeProgressBar:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def advance(self, _amount: int = 1) -> None:
            return

        def add_total(self, _amount: int) -> None:
            return

        def close(self) -> None:
            return

    patch_module_host_stage_for_test(monkeypatch, "kafka", fake_audit_targets)
    monkeypatch.setattr(
        "redposture_core.stage_runtime.start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgressBar(label, total, **kwargs),
    )

    rc = kafka.run_kafka_stage(_kafka_args(defcreds=True), logger=object())

    assert rc == 0
    assert captured == [
        (None, None, False),
        ("admin", "admin", True),
        ("kafka", "kafka", True),
        ("kafka", "password", True),
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
        return _kafka_host_record(kwargs, status="open_no_auth", detected=True)

    patch_module_host_stage_for_test(monkeypatch, "kafka", fake_audit_targets)
    rc = kafka.run_kafka_stage(
        _kafka_args(debug=True, output_format="txt", show_topics=True, dump=True, topic="orders"),
        logger=object(),
    )
    assert rc == 0
    plains = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "plain"]
    infos = [msg for level, msg in _ConsoleCapture.instances[-1].messages if level == "info"]
    assert any("Kafka Broker" in msg or "anonymous access" in msg for msg in plains)
    assert any("mode=show-topics,topic=orders,dump,max=10" in msg for msg in infos)
    assert capsys.readouterr().out == ""

    monkeypatch.setattr(
        kafka_stage_pkg.AuditCommandRunner,
        "run_plan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
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
    assert kafka._read_topic_messages("127.0.0.1", 9092, 1.0, "orders", 0) == ([], None, "plaintext")

    monkeypatch.setattr(kafka, "_probe_apiversions", lambda *_args, **_kwargs: (False, None, "service is not kafka"))
    assert kafka._read_topic_messages("127.0.0.1", 9092, 1.0, "orders", 2) == (
        None,
        "service is not kafka",
        "plaintext",
    )

    monkeypatch.setattr(kafka, "_probe_apiversions", lambda *_args, **_kwargs: (True, None, None))
    monkeypatch.setattr(kafka, "_fetch_metadata", lambda *_args, **_kwargs: (None, "metadata failed"))
    assert kafka._read_topic_messages("127.0.0.1", 9092, 1.0, "orders", 2) == (None, "metadata failed", "plaintext")

    monkeypatch.setattr(kafka, "_fetch_metadata", lambda *_args, **_kwargs: ({"topic_map": {}}, None))
    assert kafka._read_topic_messages("127.0.0.1", 9092, 1.0, "orders", 2) == ([], None, "plaintext")

    monkeypatch.setattr(kafka, "_fetch_metadata", lambda *_args, **_kwargs: ({"topic_map": {"orders": 2}}, None))
    monkeypatch.setattr(kafka, "_send_kafka_request", lambda *_args, **_kwargs: b"x")
    offsets = iter([(10, None), (None, "offset denied")])
    fetches = iter([([(10, "msg")], None)])
    monkeypatch.setattr(kafka, "_parse_list_offsets_response", lambda *_args, **_kwargs: next(offsets))
    monkeypatch.setattr(kafka, "_parse_fetch_response", lambda *_args, **_kwargs: next(fetches))
    assert kafka._read_topic_messages("127.0.0.1", 9092, 1.0, "orders", 2) == (["p0@10 msg"], None, "plaintext")

    # Partition-aware routing walks EVERY partition even when the first
    # one fails, so per-partition errors accumulate and the first-seen
    # error surfaces if no partition delivered any data. Iterators must
    # supply enough entries for both partitions.
    offsets = iter([(10, None), (20, None)])
    fetches = iter([(None, "fetch failed"), (None, "fetch failed")])
    monkeypatch.setattr(kafka, "_parse_list_offsets_response", lambda *_args, **_kwargs: next(offsets))
    monkeypatch.setattr(kafka, "_parse_fetch_response", lambda *_args, **_kwargs: next(fetches))
    assert kafka._read_topic_messages("127.0.0.1", 9092, 1.0, "orders", 2) == (None, "fetch failed", "plaintext")


def test_read_topic_messages_with_credentials_covers_auth_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.clients.kafka.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    # `_authenticate_or_probe` now always starts with ApiVersions before
    # optional SASL (matches real Kafka session lifecycle); mock the probe
    # to succeed so the SASL branch is exercised.
    monkeypatch.setattr(kafka, "_probe_apiversions", lambda *_args, **_kwargs: (True, None, None))
    monkeypatch.setattr(kafka, "_sasl_handshake_plain", lambda *_args, **_kwargs: (False, 2, "hs fail"))
    assert kafka._read_topic_messages(
        "127.0.0.1",
        9092,
        1.0,
        "orders",
        1,
        username="alice",
        password="secret",
    ) == (None, "hs fail", "plaintext")

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
    ) == (None, "auth fail", "plaintext")


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


def test_sasl_fallback_collects_and_renders_acl_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kafka, "open_kafka_socket", lambda *_args, **_kwargs: (_KafkaContextSocket(), "tls"))
    monkeypatch.setattr(kafka, "_sasl_handshake_plain", lambda *_args, **_kwargs: (True, 2, None))
    monkeypatch.setattr(kafka, "_sasl_authenticate_plain", lambda *_args, **_kwargs: (True, 3, None))
    monkeypatch.setattr(kafka, "_fetch_metadata", lambda *_args, **_kwargs: ({"topic_map": {"raw-keycloak": 1}}, None))
    acl_calls: list[dict[str, object]] = []

    def fake_probe(*_args, **kwargs):
        acl_calls.append(kwargs)
        return {
            "cluster": {"create": True, "delete": False},
            "topics": {"raw-keycloak": {"read": True, "write": None}},
        }

    monkeypatch.setattr(kafka_actions._kafka_client, "_probe_kafka_acls", fake_probe)
    record = kafka._audit_kafka_via_sasl_fallback(
        host="10.14.0.26",
        port=9093,
        timeout=1.0,
        username="user",
        password="pass",
        show_topics=True,
        query_topic=None,
        dump=False,
        max_messages=1,
        probe_write=True,
    )

    assert isinstance(record, dict)
    assert record["auth_flow"] == "sasl_fallback"
    assert record["cluster_permissions"] == {"create": True, "delete": False}
    assert record["topic_permissions"] == {"raw-keycloak": {"read": True, "write": None}}
    assert acl_calls == [
        {
            "username": "user",
            "password": "pass",
            "use_tls": True,
            "probe_write": True,
            "probe_cluster": True,
            "debug_emit": None,
        }
    ]
    assert "[+] user:pass (create:true) (delete:false) (topics:1)" in kafka._format_record(record, "txt")
    assert kafka._format_topics_detail_records(record, "txt")[-1].endswith("raw-keycloak (read:true)")


def test_cluster_acl_probe_retries_with_sasl_first_session(monkeypatch: pytest.MonkeyPatch) -> None:
    sockets = iter((_DummySocket(), _DummySocket()))
    session_modes: list[bool] = []
    debug_messages: list[str] = []

    monkeypatch.setattr(
        kafka_client,
        "open_kafka_socket",
        lambda *_args, **_kwargs: (next(sockets), "tls"),
    )

    def fake_auth(_sock, correlation, _username, _password, *, sasl_first=False):
        session_modes.append(sasl_first)
        if not sasl_first:
            return False, correlation + 1, "ApiVersions requires SASL"
        return True, correlation + 2, None

    monkeypatch.setattr(kafka_client, "_authenticate_or_probe", fake_auth)
    monkeypatch.setattr(kafka_client, "_probe_create_topic_permission", lambda _sock, corr: (True, corr + 1))
    monkeypatch.setattr(kafka_client, "_probe_delete_topic_permission", lambda _sock, corr: (False, corr + 1))
    monkeypatch.setattr(kafka_client, "_probe_topic_read_permission", lambda _sock, corr, _topic: (True, corr + 1))

    result = kafka_client._probe_kafka_acls(
        "10.14.0.26",
        9093,
        1.0,
        ["raw-keycloak"],
        username="user",
        password="pass",
        use_tls=True,
        debug_emit=debug_messages.append,
    )

    assert session_modes == [False, True]
    assert result == {
        "cluster": {"create": True, "delete": False},
        "topics": {"raw-keycloak": {"read": True, "write": None}},
    }
    assert any("SASL-first" in message for message in debug_messages)


def test_cluster_create_acl_probe_uses_broker_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[dict[str, object]] = []

    def fake_send(_sock, **kwargs):
        requests.append(kwargs)
        return struct.pack(">iii", 7, 0, 1) + _kstr("probe") + struct.pack(">h", 0) + struct.pack(">h", -1)

    monkeypatch.setattr(kafka_client, "_send_kafka_request", fake_send)

    allowed, next_correlation = kafka_client._probe_create_topic_permission(_DummySocket(), 7)

    assert allowed is True
    assert next_correlation == 8
    body = requests[0]["body"]
    assert isinstance(body, bytes)
    name_size = struct.unpack(">h", body[4:6])[0]
    defaults_offset = 6 + name_size
    assert struct.unpack(">i", body[defaults_offset : defaults_offset + 4])[0] == -1
    assert struct.unpack(">h", body[defaults_offset + 4 : defaults_offset + 6])[0] == -1


class _KafkaContextSocket(_DummySocket):
    def __init__(self) -> None:
        self.timeout: float | None = 1.0
        self.sent: list[bytes] = []
        self.recv_chunks: list[bytes] = []
        self.settimeout_calls: list[float | None] = []

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout
        self.settimeout_calls.append(timeout)

    def gettimeout(self) -> float | None:
        return self.timeout

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        if not self.recv_chunks:
            return b""
        chunk = self.recv_chunks.pop(0)
        if len(chunk) > size:
            self.recv_chunks.insert(0, chunk[size:])
            return chunk[:size]
        return chunk


def test_kafka_format_detail_records_additional_empty_and_json_branches() -> None:
    assert kafka._format_topics_detail_records({"host": "h", "port": 9092}, "txt") == []

    detect_json = json.loads(
        kafka._format_detect_record(
            {"timestamp": "ts", "host": "h", "port": 9092, "is_kafka": True, "auth_required": None},
            "json",
        )
    )
    assert detect_json["detected"] is True
    assert detect_json["auth_required"] is None

    assert "(topics:unknown)" in kafka._with_optional_topics({"topic_count": "many"}, "KAFKA h 9092 [+] ok")

    limited_record = {
        "timestamp": "ts",
        "host": "h",
        "port": 9092,
        "show_topics": True,
        "topics": ["zeta", "alpha", "beta"],
        "topic_count": 3,
        "show_topics_limit": 2,
        "query_topic": "missing",
        "query_topic_value": None,
        "dump": True,
        "max_messages": 3,
        "dump_topics": [],
        "dump_results": {},
        "dump_errors": {},
        "dump_error": "metadata unavailable",
    }
    limited_text = "\n".join(kafka._format_topics_detail_records(limited_record, "txt"))
    assert "Show Topics (showing:2 of 3)" in limited_text
    assert "Topic missing" in limited_text
    assert "[-] metadata unavailable" in limited_text

    limited_json = [json.loads(line) for line in kafka._format_topics_detail_records(limited_record, "json")]
    assert any(item["type"] == "topics_list" and item["topics"] == ["alpha", "beta"] for item in limited_json)
    assert any(item["type"] == "topic_dump" and item["error"] == "metadata unavailable" for item in limited_json)

    no_query_messages = "\n".join(
        kafka._format_topics_detail_records(
            {
                "host": "h",
                "port": 9092,
                "query_topic": "orders",
                "query_topic_value": "orders (partitions:1)",
                "dump": True,
                "max_messages": 1,
                "dump_topics": ["orders"],
                "dump_results": {"orders": []},
                "dump_errors": {},
            },
            "txt",
        )
    )
    assert "<no messages>" in no_query_messages

    no_topic_messages = "\n".join(
        kafka._format_topics_detail_records(
            {
                "host": "h",
                "port": 9092,
                "dump": True,
                "max_messages": 1,
                "dump_topics": ["orders"],
                "dump_results": {"orders": []},
                "dump_errors": {},
            },
            "txt",
        )
    )
    assert "<no messages>" in no_topic_messages


def test_kafka_sasl_fallback_metadata_and_exception_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kafka, "open_kafka_socket", lambda *_args, **_kwargs: (_KafkaContextSocket(), "plaintext"))

    monkeypatch.setattr(kafka, "_sasl_handshake_plain", lambda *_args, **_kwargs: (True, 2, "listener requires sasl"))
    no_creds = kafka._audit_kafka_via_sasl_fallback(
        host="127.0.0.1",
        port=9092,
        timeout=1.0,
        username=None,
        password=None,
        show_topics=False,
        query_topic="orders",
        dump=True,
        max_messages=2,
    )
    assert isinstance(no_creds, dict)
    assert no_creds["status"] == "auth_required"
    assert no_creds["query_topic_value"] == "orders:<authentication required>"
    assert no_creds["dump_error"] == "authentication required"
    assert no_creds["error"] == "listener requires sasl"

    monkeypatch.setattr(kafka, "_sasl_handshake_plain", lambda *_args, **_kwargs: (True, 2, None))
    monkeypatch.setattr(kafka, "_sasl_authenticate_plain", lambda *_args, **_kwargs: (True, 3, None))
    monkeypatch.setattr(kafka, "_fetch_metadata", lambda *_args, **_kwargs: (None, "metadata denied"))
    metadata_unavailable = kafka._audit_kafka_via_sasl_fallback(
        host="127.0.0.1",
        port=9092,
        timeout=1.0,
        username="alice",
        password="",
        show_topics=True,
        query_topic="orders",
        dump=True,
        max_messages=2,
    )
    assert isinstance(metadata_unavailable, dict)
    assert metadata_unavailable["status"] == "valid_credentials"
    assert metadata_unavailable["query_topic_value"] == "orders:<not available>"
    assert metadata_unavailable["dump_error"] == "topic metadata unavailable"
    assert metadata_unavailable["error"] == "metadata denied"

    monkeypatch.setattr(kafka, "_fetch_metadata", lambda *_args, **_kwargs: ({"topic_map": {"orders": 1}}, None))
    not_found = kafka._audit_kafka_via_sasl_fallback(
        host="127.0.0.1",
        port=9092,
        timeout=1.0,
        username="alice",
        password="secret",
        show_topics=True,
        query_topic="missing",
        dump=True,
        max_messages=2,
    )
    assert isinstance(not_found, dict)
    assert not_found["query_topic_value"] == "missing:<not found>"
    assert not_found["dump_error"] == "topic not found"

    monkeypatch.setattr(
        kafka,
        "open_kafka_socket",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("connection reset")),
    )
    assert (
        kafka._audit_kafka_via_sasl_fallback(
            host="127.0.0.1",
            port=9092,
            timeout=1.0,
            username="alice",
            password="secret",
            show_topics=False,
            query_topic=None,
            dump=False,
            max_messages=1,
        )
        is None
    )


def test_kafka_audit_host_metadata_auth_and_fallback_error_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kafka, "open_kafka_socket", lambda *_args, **_kwargs: (_KafkaContextSocket(), "plaintext"))
    monkeypatch.setattr(kafka, "_probe_apiversions", lambda *_args, **_kwargs: (False, 35, "plain EOF"))
    monkeypatch.setattr(kafka, "_is_sasl_probe_candidate", lambda _error: True)
    fallback_record = {
        "timestamp": "ts",
        "host": "127.0.0.1",
        "port": 9092,
        "is_kafka": True,
        "status": "auth_required",
        "auth_required": True,
        "provided_credentials": False,
        "show_topics": False,
        "dump": False,
        "error": "sasl required",
    }
    monkeypatch.setattr(kafka, "_audit_kafka_via_sasl_fallback", lambda **_kwargs: fallback_record)
    fallback = kafka._audit_kafka_host(
        "127.0.0.1",
        9092,
        1.0,
        0,
        username=None,
        password=None,
        show_topics=False,
        query_topic=None,
        dump=False,
        max_messages=1,
    )
    assert fallback["status"] == "auth_required"

    monkeypatch.setattr(kafka, "_audit_kafka_via_sasl_fallback", lambda **_kwargs: None)
    not_kafka = kafka._audit_kafka_host(
        "127.0.0.1",
        9092,
        1.0,
        0,
        username=None,
        password=None,
        show_topics=False,
        query_topic=None,
        dump=False,
        max_messages=1,
    )
    assert not_kafka["status"] == "fail"
    assert "plain EOF" in str(not_kafka["error"])

    monkeypatch.setattr(kafka, "_probe_apiversions", lambda *_args, **_kwargs: (True, 0, None))
    monkeypatch.setattr(
        kafka,
        "_fetch_metadata",
        lambda *_args, **_kwargs: ({"auth_required": True, "error_codes": [29, 58], "topic_map": {}}, None),
    )
    auth_required = kafka._audit_kafka_host(
        "127.0.0.1",
        9092,
        1.0,
        0,
        username=None,
        password=None,
        show_topics=True,
        query_topic="private",
        dump=True,
        max_messages=1,
    )
    assert auth_required["status"] == "auth_required"
    assert auth_required["query_topic_value"] == "private:<authentication required>"
    assert auth_required["dump_error"] == "authentication required"
    assert "auth errors:" in str(auth_required["error"])

    monkeypatch.setattr(kafka, "_fetch_metadata", lambda *_args, **_kwargs: (None, "metadata timeout"))
    unknown = kafka._audit_kafka_host(
        "127.0.0.1",
        9092,
        1.0,
        0,
        username=None,
        password=None,
        show_topics=False,
        query_topic="orders",
        dump=True,
        max_messages=1,
    )
    assert unknown["status"] == "unknown_auth"
    assert unknown["query_topic_value"] == "orders:<not available>"
    assert unknown["dump_error"] == "topic metadata unavailable"

    monkeypatch.setattr(
        kafka,
        "_fetch_metadata",
        lambda *_args, **_kwargs: ({"auth_required": False, "topic_map": {"orders": 1}}, None),
    )
    monkeypatch.setattr(
        kafka,
        "_authenticate_and_fetch_metadata",
        lambda *_args, **_kwargs: (False, None, "bad sasl", "plaintext"),
    )
    invalid_but_anonymous = kafka._audit_kafka_host(
        "127.0.0.1",
        9092,
        1.0,
        0,
        username="alice",
        password="bad",
        show_topics=True,
        query_topic="missing",
        dump=True,
        max_messages=1,
    )
    assert invalid_but_anonymous["status"] == "invalid_credentials_anonymous"
    assert invalid_but_anonymous["query_topic_value"] == "missing:<not found>"
    assert invalid_but_anonymous["dump_error"] == "topic not found"

    monkeypatch.setattr(
        kafka,
        "open_kafka_socket",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unexpected EOF")),
    )
    monkeypatch.setattr(
        kafka,
        "_audit_kafka_via_sasl_fallback",
        lambda **_kwargs: {**fallback_record, "status": "valid_credentials", "provided_credentials": True},
    )
    exception_fallback = kafka._audit_kafka_host(
        "127.0.0.1",
        9092,
        1.0,
        0,
        username="alice",
        password="secret",
        show_topics=False,
        query_topic=None,
        dump=False,
        max_messages=1,
    )
    assert exception_fallback["status"] == "valid_credentials"


# ---------------------------------------------------------------------------
# TLS auto-detect regression tests (SASL_SSL on port 9093)
# ---------------------------------------------------------------------------


def test_audit_kafka_host_switches_to_tls_on_prelude(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the plaintext ApiVersions probe returns a TLS record (0x15/0x03/...),
    `_audit_kafka_host` must re-open with TLS on the second transport
    attempt — not surface `ValueError('invalid Kafka frame size ...')` and
    not abort the host. Also asserts the resulting record carries
    `transport_mode="tls"` so downstream renderers can annotate the line.
    """
    from redposture_core.clients import kafka as kafka_client

    open_calls: list[dict] = []
    probe_calls: list[bool] = []

    def _fake_open(host, port, timeout, *, use_tls=None):
        open_calls.append({"host": host, "port": port, "use_tls": use_tls})
        if len(open_calls) == 1:
            # First attempt — pretend we were opened plaintext but the first
            # probe reveals a TLS listener. The socket is a stub because we
            # short-circuit before any real send/recv (see _fake_probe).
            return _KafkaContextSocket(), "plaintext"
        # Second attempt — TLS wrap succeeded.
        return _KafkaContextSocket(), "tls"

    def _fake_probe(_sock, _correlation):
        # First call raises _TlsProbeError to drive the fallback; second call
        # returns "yes, this is Kafka" so the module can classify normally.
        probe_calls.append(True)
        if len(probe_calls) == 1:
            raise kafka_client._TlsProbeError("plaintext read returned TLS record prelude")
        return True, None, None

    monkeypatch.setattr(kafka, "open_kafka_socket", _fake_open)
    monkeypatch.setattr(kafka, "_probe_apiversions", _fake_probe)
    monkeypatch.setattr(
        kafka, "_fetch_metadata", lambda *_a, **_k: ({"topic_map": {"tls.orders": 2}, "auth_required": False}, None)
    )

    record = kafka._audit_kafka_host(
        "127.0.0.1",
        29093,
        1.0,
        0,
        username=None,
        password=None,
        show_topics=False,
        query_topic=None,
        dump=False,
        max_messages=0,
    )

    assert record["status"] == "open_no_auth"
    assert record["transport_mode"] == "tls"
    assert len(open_calls) == 2
    assert open_calls[0]["use_tls"] is None  # first attempt: auto (plaintext for non-9093 host)
    assert open_calls[1]["use_tls"] is True  # fallback: forced TLS


def test_kafka_tls_marker_only_on_detect_line() -> None:
    """`_format_detect_record` must annotate the detect line with
    `(tls:true)` / `(tls:false)` per `transport_mode`. `_format_record`
    (the status/credential line) must NOT duplicate the marker — the
    transport is already established by the detect line above and adding
    it to every credential line is noise the user asked to remove.
    """
    base = {"host": "127.0.0.1", "port": 9093, "topic_count": 2, "auth_required": True}

    tls_detect = {**base, "is_kafka": True, "transport_mode": "tls"}
    assert " (tls:true)" in kafka._format_detect_record(tls_detect, "txt")

    plain_detect = {**base, "is_kafka": True, "transport_mode": "plaintext"}
    assert " (tls:false)" in kafka._format_detect_record(plain_detect, "txt")

    # No transport_mode → no marker (backward compat with legacy records).
    legacy_detect = {**base, "is_kafka": True}
    assert "(tls:" not in kafka._format_detect_record(legacy_detect, "txt")

    # Credential/status lines: transport marker must be ABSENT (design fix).
    tls_open = {**base, "status": "open_no_auth", "transport_mode": "tls"}
    assert "tls:" not in kafka._format_record(tls_open, "txt")
    assert "transport:" not in kafka._format_record(tls_open, "txt")

    tls_weak = {
        **base,
        "status": "weak_default_creds",
        "provided_username": "admin",
        "provided_password": "admin",
        "transport_mode": "tls",
    }
    weak_line = kafka._format_record(tls_weak, "txt")
    assert "[+] admin:admin" in weak_line
    assert "tls:" not in weak_line
    assert "transport:" not in weak_line


def test_kafka_malformed_frame_still_fails_when_not_tls_prelude(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sibling of the existing `test_kafka_malformed_frame_failure_does_not_
    abort_next_target` regression: when the 4-byte header is NOT a TLS
    record prelude (0x14/0x15/0x16/0x17 + 0x03), `_recv_kafka_frame` must
    still raise `ValueError('invalid Kafka frame size ...')` — we haven't
    accidentally silenced genuine framing errors along with the TLS false
    positive.
    """
    from redposture_core.clients import kafka as kafka_client

    class _BogusHeaderSocket:
        def __init__(self) -> None:
            # 0x40000000 = 1_073_741_824 — well above KAFKA_MAX_FRAME.
            self._payload = b"\x40\x00\x00\x00"

        def recv(self, size: int) -> bytes:
            chunk = self._payload[:size]
            self._payload = self._payload[size:]
            return chunk

    with pytest.raises(ValueError, match="invalid Kafka frame size"):
        kafka_client._recv_kafka_frame(_BogusHeaderSocket())

    # And when a TLS record prelude comes in, it does NOT surface as a ValueError.
    class _TlsAlertSocket:
        def __init__(self) -> None:
            self._payload = b"\x15\x03\x03\x00"

        def recv(self, size: int) -> bytes:
            chunk = self._payload[:size]
            self._payload = self._payload[size:]
            return chunk

    with pytest.raises(kafka_client._TlsProbeError):
        kafka_client._recv_kafka_frame(_TlsAlertSocket())


def test_open_kafka_socket_9093_is_tls_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end check via the module namespace (not the client module):
    calling `kafka.open_kafka_socket(host, 9093, timeout)` from `actions.py`
    with no explicit `use_tls` must open a TLS-wrapped socket, because 9093
    is the well-known SASL_SSL listener.
    """
    from redposture_core.clients import kafka as kafka_client

    monkeypatch.setattr(
        kafka_client.socket,
        "create_connection",
        lambda addr, timeout: _DummySocket(),
    )
    wrap_calls: list[str] = []

    class _FakeCtx:
        check_hostname = True
        verify_mode = 0

        def wrap_socket(self, sock, server_hostname):
            wrap_calls.append(server_hostname)
            return _DummySocket()

    monkeypatch.setattr(kafka_client.ssl, "create_default_context", lambda: _FakeCtx())

    sock, transport_mode = kafka.open_kafka_socket("kafka.internal", 9093, 1.0)
    assert transport_mode == "tls"
    assert wrap_calls == ["kafka.internal"]

    wrap_calls.clear()
    sock, transport_mode = kafka.open_kafka_socket("kafka.internal", 9092, 1.0)
    assert transport_mode == "plaintext"
    assert wrap_calls == []
