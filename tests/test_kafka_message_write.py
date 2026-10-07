"""Explicit one-record Kafka writes: protocol, CLI, and lifecycle contracts."""

from __future__ import annotations

import json
import struct
from types import SimpleNamespace
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redposture_core.cli_args import parse_args
from redposture_core.clients import kafka as client
from redposture_core.console import Console
from redposture_core.modules.kafka import actions, policy, stage
from redposture_core.stage_runtime import AuditCredentialRun


class _Errors:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def error(self, message: str) -> None:
        self.messages.append(message)


def _args(*extra: str) -> Any:
    return parse_args(["kafka", "-t", "127.0.0.1:9092", *extra])


def test_text_and_binary_payloads_require_an_explicit_topic(tmp_path: Any) -> None:
    console = _Errors()
    args = _args("--write-message", "hello")
    assert policy.validate_args(args, console) == 2
    assert "--topic" in console.messages[-1]

    args = _args("--topic", "orders", "--write-message", "hello", "--write-key", "audit")
    assert policy.validate_args(args, console) is None
    assert args._kafka_write_payload == b"hello"
    assert args._kafka_write_key == b"audit"
    assert stage._build_kafka_lifecycle_options(args)["write_payload"] == b"hello"

    source = tmp_path / "record.bin"
    source.write_bytes(b"\x00\xff\x01")
    args = _args("--topic", "orders", "--write-file", str(source))
    assert policy.validate_args(args, console) is None
    assert args._kafka_write_payload == b"\x00\xff\x01"


@pytest.mark.parametrize(
    "flags",
    [
        ("--topic", "orders", "--write-key", "key"),
        ("--topic", "orders", "--write-message", "x", "--probe-write"),
        ("--topic", "bad\ttopic", "--write-message", "x"),
    ],
)
def test_write_policy_rejects_unsafe_flag_combinations(flags: tuple[str, ...]) -> None:
    assert policy.validate_args(_args(*flags), _Errors()) == 2


def test_write_policy_caps_message_and_key_sizes(tmp_path: Any) -> None:
    console = _Errors()
    source = tmp_path / "oversized.bin"
    source.write_bytes(b"x" * (client.KAFKA_MAX_WRITE_VALUE_BYTES + 1))
    assert policy.validate_args(_args("--topic", "orders", "--write-file", str(source)), console) == 2
    assert (
        policy.validate_args(_args("--topic", "orders", "--write-message", "x", "--write-key", "k" * 65537), console)
        == 2
    )


def _response(correlation: int, topic: str, partition: int, code: int, offset: int = 9) -> bytes:
    topic_raw = topic.encode()
    return (
        struct.pack(">ii", correlation, 1)
        + struct.pack(">h", len(topic_raw))
        + topic_raw
        + struct.pack(">ii", 1, partition)
        + struct.pack(">hqq", code, offset, -1)
    )


@pytest.mark.parametrize(("code", "status"), [(0, "written"), (29, "denied"), (6, "rejected")])
def test_produce_response_is_classified_without_retries(
    monkeypatch: pytest.MonkeyPatch, code: int, status: str
) -> None:
    calls: list[dict[str, Any]] = []

    def send(_sock: object, **kwargs: Any) -> bytes:
        calls.append(kwargs)
        return _response(7, "orders", 2, code)

    monkeypatch.setattr(client, "_send_kafka_request", send)
    result, next_correlation = client._produce_message_once(object(), 7, "orders", 2, b"\x00data", b"key")
    assert result["status"] == status
    assert result["error_code"] == code
    assert result["offset"] == (9 if code == 0 else None)
    assert next_correlation == 8
    assert len(calls) == 1
    assert calls[0]["api_key"] == client.KAFKA_PRODUCE
    assert b"\x00data" in calls[0]["body"]
    assert b"key" in calls[0]["body"]


def test_lost_produce_response_is_unknown_and_not_resent(monkeypatch: pytest.MonkeyPatch) -> None:
    count = 0

    def send(_sock: object, **_kwargs: Any) -> bytes:
        nonlocal count
        count += 1
        raise TimeoutError("response lost")

    monkeypatch.setattr(client, "_send_kafka_request", send)
    result, _next = client._produce_message_once(object(), 7, "orders", 0, b"data", None)
    assert result["status"] == "unknown"
    assert "may have been written" in result["reason"]
    assert count == 1


@given(st.binary(max_size=512), st.one_of(st.none(), st.binary(max_size=64)))
def test_fuzz_binary_record_batch_has_valid_length_and_crc(value: bytes, key: bytes | None) -> None:
    batch = client._build_produce_probe_batch(value, key)
    assert struct.unpack(">i", batch[8:12])[0] == len(batch) - 12
    assert struct.unpack(">i", batch[57:61])[0] == 1
    assert struct.unpack(">I", batch[17:21])[0] == client._crc32c(batch[21:])


@given(st.binary(max_size=128))
def test_fuzz_wrong_correlation_never_confirms_write(suffix: bytes) -> None:
    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(client, "_send_kafka_request", lambda *_args, **_kwargs: struct.pack(">i", 99) + suffix)
        result, _next = client._produce_message_once(object(), 7, "orders", 0, b"x", None)
        assert result["status"] == "unknown"


def test_missing_topic_never_sends_produce(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client, "_produce_message_once", lambda *_args: pytest.fail("Produce sent"))
    result = client.produce_kafka_message(
        "localhost",
        9092,
        1,
        "missing",
        b"data",
        metadata={"topic_map": {"orders": 1}},
        username=None,
        password=None,
        use_tls=None,
        tls_config=None,
        sasl_first=False,
        existing_session=None,
        leader_pool=None,
    )
    assert result["status"] == "unavailable"


def _write_with_metadata(metadata: Any, *, session: Any = None, pool: Any = None) -> dict[str, Any]:
    return client.produce_kafka_message(
        "localhost",
        9092,
        1,
        "orders",
        b"data",
        metadata=metadata,
        username="alice",
        password="secret",
        use_tls=None,
        tls_config=None,
        sasl_first=False,
        existing_session=session,
        leader_pool=pool,
    )


@pytest.mark.parametrize(
    ("metadata", "reason"),
    [
        (None, "authenticated topic metadata unavailable"),
        ({"topic_map": {"orders": 1}, "partition_leaders": {"orders": []}}, "partition leader unavailable"),
        (
            {
                "topic_map": {"orders": 1},
                "partition_leaders": {"orders": {"broken": 1}},
                "broker_map": {1: ["localhost", 9092]},
            },
            "partition leader unavailable",
        ),
        (
            {"topic_map": {"orders": 1}, "partition_leaders": {"orders": {0: 1}}, "broker_map": {1: ["localhost", 0]}},
            "partition leader unavailable",
        ),
    ],
)
def test_write_requires_usable_authenticated_leader_metadata(metadata: Any, reason: str) -> None:
    assert _write_with_metadata(metadata)["reason"] == reason


def test_write_selects_lowest_partition_and_reuses_authenticated_session(monkeypatch: pytest.MonkeyPatch) -> None:
    session = SimpleNamespace(sock=object(), correlation_id=7, closed=False)
    calls: list[tuple[Any, ...]] = []

    def produce(*args: Any) -> tuple[dict[str, Any], int]:
        calls.append(args)
        return {"status": "written", "partition": args[3], "offset": 42}, args[1] + 1

    monkeypatch.setattr(client, "_produce_message_once", produce)
    metadata = {
        "topic_map": {"orders": 1},
        "partition_leaders": {"orders": {2: 1, 0: 1}},
        "broker_map": {1: ["localhost", 9092]},
    }
    result = _write_with_metadata(metadata, session=session)
    assert result == {"status": "written", "partition": 0, "offset": 42, "bytes": 4}
    assert session.correlation_id == 8
    assert len(calls) == 1


def test_unreachable_advertised_leader_falls_back_before_produce(monkeypatch: pytest.MonkeyPatch) -> None:
    session = SimpleNamespace(sock=object(), correlation_id=4, closed=False)
    pool = SimpleNamespace(get_or_open=lambda *_args, **_kwargs: (None, "unreachable"))
    calls = 0

    def produce(*args: Any) -> tuple[dict[str, Any], int]:
        nonlocal calls
        calls += 1
        return {"status": "denied", "partition": args[3]}, args[1] + 1

    monkeypatch.setattr(client, "_produce_message_once", produce)
    metadata = {
        "topic_map": {"orders": 1},
        "partition_leaders": {"orders": {0: 1}},
        "broker_map": {1: ["advertised.internal", 9092]},
    }
    assert _write_with_metadata(metadata, session=session, pool=pool)["status"] == "denied"
    assert calls == 1
    assert _write_with_metadata(metadata, pool=pool)["reason"] == "leader connection unavailable"
    assert calls == 1


def test_owned_leader_session_is_closed_after_single_produce(monkeypatch: pytest.MonkeyPatch) -> None:
    class LeaderSession:
        def __init__(self) -> None:
            self.sock = object()
            self.correlation_id = 1
            self.closed = False

        def bootstrap(self, **_kwargs: Any) -> tuple[bool, None]:
            return True, None

        def close(self) -> None:
            self.closed = True

    owned = LeaderSession()
    monkeypatch.setattr(client.KafkaSession, "open", lambda *_args, **_kwargs: owned)
    monkeypatch.setattr(client, "_produce_message_once", lambda *_args: ({"status": "written"}, 2))
    metadata = {
        "topic_map": {"orders": 1},
        "partition_leaders": {"orders": {0: 1}},
        "broker_map": {1: ["leader.internal", 9092]},
    }
    assert _write_with_metadata(metadata)["status"] == "written"
    assert owned.closed


def test_authenticated_lifecycle_writes_once_and_renders_result(monkeypatch: pytest.MonkeyPatch) -> None:
    args = _args("-u", "alice", "-p", "secret", "--topic", "orders", "--write-message", "hello")
    assert policy.validate_args(args, _Errors()) is None
    options = stage._build_kafka_lifecycle_options(args)
    state = actions.KafkaLifecycleState(auth_required=True, transport_mode="plaintext")
    credential = AuditCredentialRun("alice", "secret", source="provided")
    state.credential_metadata[("alice", "secret", "provided")] = {"topic_map": {"orders": 1}}
    ctx = SimpleNamespace(
        lifecycle_state=state, credential=credential, args=args, host="localhost", port=9092, debug_emit=None
    )
    calls: list[dict[str, Any]] = []

    def fake_produce(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"status": "written", "partition": 0, "offset": 42, "bytes": 5, "reason": "broker acknowledged record"}

    monkeypatch.setattr(actions._kafka_client, "produce_kafka_message", fake_produce)
    monkeypatch.setattr(actions, "_probe_kafka_acl_state", lambda **_kwargs: ({}, {"create": None, "delete": None}))
    record = actions.collect_kafka_data(ctx, {"status": "valid_credentials", "auth_required": True}, options)
    assert len(calls) == 1
    assert calls[0]["username"] == "alice"
    assert record["write_result"]["status"] == "written"
    lines = actions._format_topics_detail_records(record, "txt")
    assert any("[*] Topic Write" in line for line in lines)
    assert any('[+] Message written to "orders" (partition:0) (offset:42) (bytes:5)' in line for line in lines)
    assert "\x1b" not in "\n".join(lines)
    json_lines = [json.loads(line) for line in actions._format_topics_detail_records(record, "json")]
    assert any(line.get("type") == "topic_write" and line["offset"] == 42 for line in json_lines)


def test_unverified_credentials_cannot_write(monkeypatch: pytest.MonkeyPatch) -> None:
    args = _args("--topic", "orders", "--write-message", "hello")
    assert policy.validate_args(args, _Errors()) is None
    options = stage._build_kafka_lifecycle_options(args)
    state = actions.KafkaLifecycleState(auth_required=True)
    ctx = SimpleNamespace(
        lifecycle_state=state,
        credential=AuditCredentialRun("alice", "bad", source="provided"),
        args=args,
        host="localhost",
        port=9092,
        debug_emit=None,
    )
    monkeypatch.setattr(actions._kafka_client, "produce_kafka_message", lambda *_args, **_kwargs: pytest.fail("wrote"))
    monkeypatch.setattr(actions, "_probe_kafka_acl_state", lambda **_kwargs: ({}, {"create": None, "delete": None}))
    record = actions.collect_kafka_data(ctx, {"status": "auth_required", "auth_required": True}, options)
    assert record["write_result"]["status"] == "unavailable"


def test_write_result_colors_and_no_color(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    line = 'KAFKA\tlocalhost\t9092\t [+] Message written to "orders" (partition:0) (offset:42) (bytes:5)'
    assert actions._render_colored_kafka_line(Console(no_color=False), line)
    colored = capsys.readouterr().out
    assert "\x1b[" in colored
    assert "\x1b[1;38;5;208m" in colored
    assert actions._render_colored_kafka_line(Console(no_color=True), line)
    assert "\x1b[" not in capsys.readouterr().out
