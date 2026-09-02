from __future__ import annotations

import re
import struct
from types import SimpleNamespace
from typing import Any, cast

import pytest

import redposture_core.stage_zookeeper as zookeeper_stage
from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.clients.zookeeper import ZkImplementationFingerprint, ZkTransportConfig
from redposture_core.modules.zookeeper import actions as lifecycle_actions
from redposture_core.modules.zookeeper import engine as implementation_engine
from redposture_core.modules.zookeeper import stage as lifecycle_stage
from redposture_core.modules.zookeeper.types import ZooKeeperFingerprintCache
from redposture_core.stage_runtime import (
    AuditCommandRunner,
    AuditCredentialRun,
    AuditHookContext,
    LineOutputSink,
    _build_colored_emit,
)
from redposture_core.stage_zookeeper import (
    _ZK_ERR_NOAUTH,
    _ZK_ERR_NONODE,
    _ZK_ERR_OK,
    _ZK_ERR_SESSION_CLOSED_REQUIRES_AUTH,
    _audit_zookeeper_host,
    _call_audit_host_with_thread_debug,
    _decode_zk_buffer,
    _decode_zk_string,
    _encode_zk_string,
    _enumerate_znodes,
    _format_record,
    _format_znode_data,
    _format_znodes_detail_records,
    _is_system_znode,
    _join_znode_path,
    _normalize_znode_path,
    _parse_children_vector,
    _parse_stat,
    _recv_exact,
    _recv_frame,
    _send_frame,
    run_zookeeper_stage,
)
from tests.stage_runtime_helpers import patch_module_host_stage_for_test, run_module_targets_for_test


def test_canonical_zookeeper_stage_has_no_keeper_package_dependency() -> None:
    assert lifecycle_stage.engine is implementation_engine
    assert not hasattr(lifecycle_stage, "keeper_actions")


def _zk_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack(">i", len(raw)) + raw


def _zookeeper_host_record(
    kwargs: dict[str, object],
    *,
    status: str,
    detected: bool,
    error: str | None = None,
) -> AuditRecord:
    deep = bool(kwargs.get("run_deep_checks"))
    query_znode = kwargs.get("query_znode")
    return AuditRecord(
        host=str(kwargs["host"]),
        port=int(kwargs["port"]),
        service="zookeeper",
        module="zookeeper",
        status=status,
        auth_required=status == "auth_required",
        extra={
            "is_zookeeper": detected,
            "is_keeper": False if detected else None,
            "error": error,
            "provided_username": kwargs.get("username"),
            "provided_password": kwargs.get("password"),
            "show_znodes": bool(kwargs.get("show_znodes")),
            "dump": bool(kwargs.get("dump")),
            "query_znode": query_znode,
            "znode_count": 1 if detected else None,
            "znodes": ["/demo"] if deep else None,
            "znode_values": ["/demo:value"] if deep and bool(kwargs.get("dump")) else None,
            "query_znode_value": f"{query_znode}:value" if deep and query_znode else None,
            "create_allowed": False if detected else None,
            "delete_allowed": False if detected else None,
        },
    )


class _QueuedSocket:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.sent = b""
        self.timeout: float | None = None
        self.closed = False

    def recv(self, size: int) -> bytes:
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if len(chunk) > size:
            self._chunks.insert(0, chunk[size:])
            return chunk[:size]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def close(self) -> None:
        self.closed = True


def _frame(payload: bytes) -> bytes:
    return struct.pack(">i", len(payload)) + payload


def test_clip_and_error_helpers() -> None:
    assert zookeeper_stage._clip("abcd", 3) == "abc"
    assert zookeeper_stage._clip("abcdef", 4) == "a..."
    assert zookeeper_stage._friendly_error_text("") == "connection failed"
    assert (
        zookeeper_stage._friendly_error_text("[Errno 111] Connection refused")
        == "connection refused (service is not listening on target port)"
    )
    assert zookeeper_stage._friendly_error_text("[Errno 60] timed out") == "connection timeout"
    assert zookeeper_stage._friendly_error_text("[Errno 8] nodename nor servname provided") == "dns lookup failed"
    assert zookeeper_stage._friendly_error_text("[Errno 65] No route to host") == "network unreachable"
    assert zookeeper_stage._friendly_error_text("[Errno 999] custom detail") == "custom detail"
    assert zookeeper_stage._friendly_error_from_exception(TimeoutError()) == "connection timeout"
    assert zookeeper_stage._is_connection_refused_error("connection refused (service is not listening on target port)")
    assert not zookeeper_stage._is_connection_refused_error("connection timeout")
    assert zookeeper_stage._is_connection_refused_fail_record({"status": "fail", "error": "connection refused"})
    assert zookeeper_stage._is_connection_timeout_error("connection timeout")
    assert zookeeper_stage._is_unexpected_eof_error("unexpected EOF")
    assert not zookeeper_stage._is_retryable_stage_error("SESSIONCLOSEDREQUIRESASLAUTH")
    assert zookeeper_stage._is_retryable_stage_error("THROTTLEDOP")
    assert zookeeper_stage._is_remote_closed_connection_error("Remote end closed connection without response")
    assert zookeeper_stage._is_suppressed_fail_record({"status": "fail", "error": "unexpected eof"})
    assert not zookeeper_stage._is_suppressed_fail_record(
        {"status": "fail", "error": "authentication failed: AUTHFAILED", "provided_credentials": True}
    )
    assert zookeeper_stage._zk_error_name(123456) == "ERR_123456"


def test_parse_children_and_stat_invalid_payloads() -> None:
    with pytest.raises(ValueError):
        _parse_children_vector(b"\x00\x00\x00")
    assert _parse_children_vector(struct.pack(">i", -1)) == (None, 4)
    with pytest.raises(ValueError):
        _parse_stat(b"\x00" * 67)


def test_format_znode_data_nil_and_control_chars() -> None:
    assert _format_znode_data(None) == "<nil>"
    assert _format_znode_data(b"\x01hello") == "<base64:AWhlbGxv>"


def test_zkclient_require_sock_and_next_xid() -> None:
    client = zookeeper_stage._ZkClient("127.0.0.1", 2181, 0.5)
    with pytest.raises(RuntimeError):
        client._require_sock()
    assert client._next_xid() == 1
    assert client._next_xid() == 2


def test_zkclient_request_with_xid_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    client = zookeeper_stage._ZkClient("127.0.0.1", 2181, 0.5)
    client.sock = object()
    monkeypatch.setattr("redposture_core.clients.zookeeper._send_frame", lambda *_a, **_k: None)
    monkeypatch.setattr("redposture_core.clients.zookeeper._recv_frame", lambda *_a, **_k: b"\x00" * 15)
    with pytest.raises(ValueError):
        client._request_with_xid(3, 1, b"")

    bad_xid_resp = struct.pack(">i", 4) + struct.pack(">q", 1) + struct.pack(">i", 0)
    monkeypatch.setattr("redposture_core.clients.zookeeper._recv_frame", lambda *_a, **_k: bad_xid_resp)
    with pytest.raises(ValueError):
        client._request_with_xid(3, 1, b"")

    good_resp = struct.pack(">i", 3) + struct.pack(">q", 2) + struct.pack(">i", -101) + b"payload"
    monkeypatch.setattr("redposture_core.clients.zookeeper._recv_frame", lambda *_a, **_k: good_resp)
    err, payload = client._request_with_xid(3, 1, b"")
    assert err == -101
    assert payload == b"payload"


def test_zkclient_connect_and_close_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = (
        struct.pack(">i", 0)
        + struct.pack(">i", 1000)
        + struct.pack(">q", 1)
        + struct.pack(">i", 16)
        + (b"\x00" * 16)
        + b"\x00"
    )
    fake_sock = _QueuedSocket([_frame(payload)])
    monkeypatch.setattr("socket.create_connection", lambda *_a, **_k: fake_sock)

    client = zookeeper_stage._ZkClient("127.0.0.1", 2181, 1.2)
    client.connect()
    assert fake_sock.timeout == 1.2
    assert len(fake_sock.sent) > 4

    client.close()
    assert fake_sock.closed is True
    assert client.sock is None

    bad_payload = (
        struct.pack(">i", 0) + struct.pack(">i", 1000) + struct.pack(">q", 1) + struct.pack(">i", 9999) + b"\x00"
    )
    bad_sock = _QueuedSocket([_frame(bad_payload)])
    monkeypatch.setattr("socket.create_connection", lambda *_a, **_k: bad_sock)
    bad_client = zookeeper_stage._ZkClient("127.0.0.1", 2181, 1.2)
    with pytest.raises(ValueError):
        bad_client.connect()


def test_zkclient_close_ignores_send_and_close_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class _BadSocket:
        def sendall(self, _data: bytes) -> None:
            raise OSError("send failed")

        def close(self) -> None:
            raise OSError("close failed")

    client = zookeeper_stage._ZkClient("127.0.0.1", 2181, 1.0)
    client.sock = _BadSocket()
    client.close()
    assert client.sock is None


def test_zkclient_auth_children_data_create_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    client = zookeeper_stage._ZkClient("127.0.0.1", 2181, 1.0)
    stat_payload = struct.pack(">qqqqiiiqiiq", 1, 2, 3, 4, 5, 6, 7, 8, 9, 2, 10)
    children_payload = struct.pack(">i", 2) + _zk_string("a") + _zk_string("b") + stat_payload
    data_payload = struct.pack(">i", 3) + b"abc" + stat_payload

    monkeypatch.setattr(client, "_request_with_xid", lambda *_a, **_k: (_ZK_ERR_OK, b""))
    ok, err = client.auth_digest("admin", "admin")
    assert (ok, err) == (True, None)

    monkeypatch.setattr(client, "_request_with_xid", lambda *_a, **_k: (-115, b""))
    ok, err = client.auth_digest("admin", "bad")
    assert ok is False
    assert err == "authentication failed: AUTHFAILED"

    monkeypatch.setattr(client, "_request_with_xid", lambda *_a, **_k: (_ for _ in ()).throw(TimeoutError("boom")))
    with pytest.raises(TimeoutError, match="boom"):
        client.auth_digest("admin", "bad")

    monkeypatch.setattr(client, "_request", lambda *_a, **_k: (-102, b""))
    children, code, stat = client.get_children2("/")
    assert (children, code, stat) == (None, -102, None)

    monkeypatch.setattr(client, "_request", lambda *_a, **_k: (_ZK_ERR_OK, children_payload))
    children, code, stat = client.get_children2("/")
    assert children == ["a", "b"]
    assert code == _ZK_ERR_OK
    assert stat == {"data_length": 9, "num_children": 2}

    monkeypatch.setattr(client, "_request", lambda *_a, **_k: (-102, b""))
    data, code, stat = client.get_data("/")
    assert (data, code, stat) == (None, -102, None)

    monkeypatch.setattr(client, "_request", lambda *_a, **_k: (_ZK_ERR_OK, data_payload))
    data, code, stat = client.get_data("/")
    assert data == b"abc"
    assert code == _ZK_ERR_OK
    assert stat == {"data_length": 9, "num_children": 2}

    monkeypatch.setattr(client, "_request", lambda *_a, **_k: (-110, b""))
    assert client.create("/tmp") == -110
    assert client.delete("/tmp") == -110


def test_normalize_znode_path() -> None:
    assert _normalize_znode_path(None) is None
    assert _normalize_znode_path("") is None
    assert _normalize_znode_path("brokers/ids") == "/brokers/ids"
    assert _normalize_znode_path("/brokers/ids") == "/brokers/ids"


def test_parse_children_vector() -> None:
    payload = struct.pack(">i", 2) + _zk_string("brokers") + _zk_string("config")
    children, offset = _parse_children_vector(payload)
    assert children == ["brokers", "config"]
    assert offset == len(payload)


def test_parse_stat_extracts_data_length_and_children() -> None:
    stat_payload = struct.pack(">qqqqiiiqiiq", 1, 2, 3, 4, 5, 6, 7, 8, 128, 4, 9)
    stat, offset = _parse_stat(stat_payload)
    assert stat["data_length"] == 128
    assert stat["num_children"] == 4
    assert offset == 68


def test_decode_zk_string_nullable() -> None:
    value, offset = _decode_zk_string(struct.pack(">i", -1))
    assert value is None
    assert offset == 4


def test_format_znode_data_text_and_binary() -> None:
    assert _format_znode_data(b"hello") == "hello"
    assert _format_znode_data(b"") == "<empty>"
    assert _format_znode_data(b"line1\nline2") == "line1\\nline2"
    assert _format_znode_data(b"\x01\x02\xff") == "<base64:AQL/>"


def test_socket_helpers_encode_decode_and_path_helpers() -> None:
    class _FakeSocket:
        def __init__(self, chunks: list[bytes]) -> None:
            self._chunks = list(chunks)
            self.sent = b""

        def recv(self, _size: int) -> bytes:
            if not self._chunks:
                return b""
            chunk = self._chunks.pop(0)
            if len(chunk) > _size:
                self._chunks.insert(0, chunk[_size:])
                return chunk[:_size]
            return chunk

        def sendall(self, data: bytes) -> None:
            self.sent += data

    sock = _FakeSocket([b"ab", b"cd"])
    assert _recv_exact(sock, 4) == b"abcd"

    framed = struct.pack(">i", 3) + b"xyz"
    assert _recv_frame(_FakeSocket([framed[:2], framed[2:]])) == b"xyz"
    with pytest.raises(ValueError):
        _recv_frame(_FakeSocket([struct.pack(">i", 0)]))

    out_sock = _FakeSocket([])
    _send_frame(out_sock, b"ping")
    assert out_sock.sent == struct.pack(">i", 4) + b"ping"

    assert _encode_zk_string("brokers") == _zk_string("brokers")
    assert _decode_zk_buffer(struct.pack(">i", 3) + b"abc") == (b"abc", 7)
    with pytest.raises(ValueError):
        _decode_zk_buffer(b"\x00\x00\x00")
    with pytest.raises(ValueError):
        _decode_zk_string(struct.pack(">i", 5) + b"ab")

    assert _join_znode_path("/", "brokers") == "/brokers"
    assert _join_znode_path("/brokers", "ids") == "/brokers/ids"
    assert _is_system_znode("/zookeeper") is True
    assert _is_system_znode("/zookeeper/config") is True
    assert _is_system_znode("/keeper") is True
    assert _is_system_znode("/keeper/api_version") is True
    assert _is_system_znode("/brokers") is False


def test_enumerate_znodes_handles_noauth_and_truncation() -> None:
    class _FakeClient:
        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            if path == "/":
                return ["brokers", "zookeeper"], _ZK_ERR_OK, None
            if path == "/brokers":
                return ["ids", "topics"], _ZK_ERR_OK, None
            if path == "/brokers/ids":
                return [], _ZK_ERR_NOAUTH, None
            if path == "/brokers/topics":
                return [], _ZK_ERR_OK, None
            return [], _ZK_ERR_NONODE, None

    nodes, total_count, truncated, meta, error = _enumerate_znodes(_FakeClient(), 2)
    assert nodes == ["/brokers"]
    assert total_count == 1
    assert truncated is True
    assert meta["/brokers"]["error"] is None
    assert error is None


def test_enumerate_znodes_count_only_mode_skips_path_collection() -> None:
    class _FakeClient:
        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            if path == "/":
                return ["brokers", "zookeeper"], _ZK_ERR_OK, None
            if path == "/brokers":
                return ["ids", "topics"], _ZK_ERR_OK, None
            if path == "/brokers/ids":
                return [], _ZK_ERR_NOAUTH, None
            if path == "/brokers/topics":
                return [], _ZK_ERR_OK, None
            return [], _ZK_ERR_NONODE, None

    nodes, total_count, truncated, meta, error = _enumerate_znodes(
        _FakeClient(),
        2,
        collect_paths=False,
    )
    assert nodes == []
    assert total_count == 1
    assert truncated is True
    assert meta == {}
    assert error is None


def test_enumerate_znodes_progress_is_time_throttled_and_uses_window_metrics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeClient:
        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            if path == "/":
                return [f"node-{idx}" for idx in range(30)], _ZK_ERR_OK, None
            return [], _ZK_ERR_OK, None

    now = {"value": 0.0}

    def _fake_monotonic() -> float:
        current = float(now["value"])
        now["value"] = current + 0.5
        return current

    monkeypatch.setattr("redposture_core.stage_zookeeper.time.monotonic", _fake_monotonic)
    events: list[dict[str, object]] = []
    _nodes, _total_count, _truncated, _meta, _error = _enumerate_znodes(
        _FakeClient(), 100, progress_hook=events.append, progress_interval_s=2.0
    )

    progress_events = [event for event in events if str(event.get("event")) == "enumerate_progress"]
    assert progress_events
    assert all(float(event.get("elapsed_s") or 0.0) >= 2.0 for event in progress_events)
    assert all(float(event.get("interval_s") or 0.0) >= 2.0 for event in progress_events)
    assert any(str(event.get("event")) == "enumerate_done" for event in events)
    if len(progress_events) > 1:
        second = progress_events[1]
        assert int(second.get("interval_count") or 0) < int(second.get("total_count") or 0)


def test_audit_host_does_not_count_tree_when_details_not_requested(monkeypatch: pytest.MonkeyPatch) -> None:
    collect_flags: list[bool] = []

    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            if path == "/":
                return ["brokers"], _ZK_ERR_OK, {"data_length": 0, "num_children": 1}
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

    def _fake_enumerate(
        _client,
        _max_znodes: int,
        _progress_hook=None,
        _progress_interval_s: float = 2.0,
        collect_paths: bool = True,
        enum_workers: int = 1,
        auth_username: str | None = None,
        auth_password: str | None = None,
    ):
        _ = (_progress_interval_s, enum_workers, auth_username, auth_password)
        collect_flags.append(bool(collect_paths))
        return [], 3210, False, {}, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)
    monkeypatch.setattr("redposture_core.stage_zookeeper._enumerate_znodes", _fake_enumerate)
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._probe_znode_create_delete", lambda *_a, **_k: (False, False, None)
    )

    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )

    assert collect_flags == []
    assert record["status"] == "open_no_auth"
    assert record["znode_count"] is None
    assert record["znodes"] is None
    assert record["znode_details"] is None


def test_audit_zookeeper_suppresses_unexpected_eof_when_suppression_enabled(monkeypatch) -> None:
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-03-02T00:00:00Z",
            "host": "127.0.0.1",
            "port": 2181,
            "is_zookeeper": False,
            "status": "fail",
            "auth_required": None,
            "error": "unexpected EOF",
        }

    monkeypatch.setattr("redposture_core.stage_zookeeper._audit_zookeeper_host", fake_audit)

    lines: list[str] = []
    total, open_no_auth, valid, auth_required, failed = run_module_targets_for_test(
        "zookeeper",
        hosts=["127.0.0.1"],
        port=2181,
        timeout=0.2,
        retries=0,
        workers=1,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        suppress_connection_refused_status_lines=True,
    )

    assert (total, open_no_auth, valid, auth_required, failed) == (1, 0, 0, 0, 1)
    assert len(lines) == 1
    assert "ZOOKEEPER audit inconclusive" in lines[0]
    assert all("Connection refused" not in line for line in lines)


def test_audit_zookeeper_emits_records_in_input_order(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_audit(host: str, *_args, **_kwargs):
        return {
            "timestamp": "2026-03-02T00:00:00Z",
            "host": host,
            "port": 2181,
            "is_zookeeper": True,
            "status": "open_no_auth",
            "auth_required": False,
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "provided_credentials_ok": None,
            "show_znodes": False,
            "dump": False,
            "query_znode": None,
            "max_znodes": 100,
            "znode_count": 1,
            "znodes": ["/root"],
            "znode_details": None,
            "znode_values": None,
            "znodes_truncated": False,
            "query_znode_value": None,
            "query_znode_dump": None,
            "query_znode_dump_error": None,
            "can_create_znode": None,
            "can_delete_znode": None,
            "znode_capability_error": None,
            "auth_inference_source": "root_ok",
            "auth_probe_trace": ["/:ok"],
            "elapsed_ms": 1,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.stage_zookeeper._audit_zookeeper_host", fake_audit)

    lines: list[str] = []
    totals = run_module_targets_for_test(
        "zookeeper",
        hosts=["host-a", "host-b"],
        port=2181,
        timeout=0.2,
        retries=0,
        workers=2,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        suppress_connection_refused_status_lines=False,
    )

    assert totals == (2, 2, 0, 0, 0)
    detect_lines = [line for line in lines if "ZooKeeper-compatible" in line]
    status_lines = [line for line in lines if "anonymous access" in line]
    assert len(detect_lines) == 2
    assert status_lines == []
    assert "\thost-a\t" in detect_lines[0]
    assert "\thost-b\t" in detect_lines[1]
    assert all("(auth required:False)" in line for line in detect_lines)


def test_audit_zookeeper_two_pass_scope_and_policy_parity(monkeypatch: pytest.MonkeyPatch) -> None:
    call_trace: list[tuple[str, bool, float, int]] = []

    def _record_for(
        host: str,
        *,
        status: str,
        is_zookeeper: bool,
        znode_count: int | None,
    ) -> dict[str, object]:
        return {
            "timestamp": "2026-03-02T00:00:00Z",
            "host": host,
            "port": 2181,
            "is_zookeeper": is_zookeeper,
            "is_keeper": False if is_zookeeper else None,
            "status": status,
            "auth_required": False if status != "auth_required" else True,
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "provided_credentials_ok": None,
            "show_znodes": False,
            "dump": False,
            "query_znode": None,
            "max_znodes": 100,
            "znode_count": znode_count,
            "znodes": [] if znode_count is not None else None,
            "znode_details": None,
            "znode_values": None,
            "znodes_truncated": False,
            "query_znode_value": None,
            "query_znode_dump": None,
            "query_znode_dump_error": None,
            "can_create_znode": None,
            "can_delete_znode": None,
            "znode_capability_error": None,
            "auth_inference_source": "root_ok",
            "auth_probe_trace": ["/:ok"],
            "elapsed_ms": 1,
            "error": "connection timeout" if status == "fail" else None,
            "debug_events": [],
        }

    def fake_audit(
        host: str,
        _port: int,
        timeout: float,
        retries: int,
        _username: str | None,
        _password: str | None,
        _show_znodes: bool,
        _dump: bool,
        _query_znode: str | None,
        _max_znodes: int,
        _debug: bool,
        run_deep_checks: bool = True,
    ) -> dict[str, object]:
        call_trace.append((host, bool(run_deep_checks), float(timeout), int(retries)))
        if not run_deep_checks:
            if host == "host-open":
                return _record_for(host, status="open_no_auth", is_zookeeper=True, znode_count=None)
            if host == "host-valid":
                return _record_for(host, status="valid_credentials", is_zookeeper=True, znode_count=None)
            if host == "host-auth":
                return _record_for(host, status="auth_required", is_zookeeper=True, znode_count=None)
            return _record_for(host, status="fail", is_zookeeper=False, znode_count=None)

        if host == "host-open":
            return _record_for(host, status="open_no_auth", is_zookeeper=True, znode_count=123)
        if host == "host-valid":
            return _record_for(host, status="valid_credentials", is_zookeeper=True, znode_count=321)
        return _record_for(host, status="fail", is_zookeeper=False, znode_count=None)

    monkeypatch.setattr("redposture_core.stage_zookeeper._audit_zookeeper_host", fake_audit)

    lines: list[str] = []
    totals = run_module_targets_for_test(
        "zookeeper",
        hosts=["host-open", "host-valid", "host-auth", "host-fail"],
        port=2181,
        timeout=2.5,
        retries=3,
        workers=1,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        suppress_connection_refused_status_lines=False,
    )

    assert totals == (4, 1, 1, 1, 1)
    detect_calls = [entry for entry in call_trace if entry[1] is False]
    deep_calls = [entry for entry in call_trace if entry[1] is True]
    assert [host for host, *_rest in detect_calls] == ["host-open", "host-valid", "host-auth", "host-fail"]
    assert {host for host, *_rest in deep_calls} == {"host-open", "host-valid"}
    assert all(timeout == 2.5 for _, _, timeout, _ in detect_calls + deep_calls)
    assert all(retries == 3 for _, _, _, retries in detect_calls + deep_calls)
    assert any("host-open" in line and "(auth required:False)" in line for line in lines)
    assert not any("host-open" in line and "[+] anonymous access" in line for line in lines)
    assert any("host-valid" in line and "(znodes:321)" in line for line in lines)
    assert any("host-auth" in line and "(auth required:True)" in line for line in lines)


def test_audit_zookeeper_debug_pass_markers_and_stage2_gate_reasons(monkeypatch: pytest.MonkeyPatch) -> None:
    def _record_for(host: str, *, is_zookeeper: bool, status: str, znode_count: int | None = None) -> dict[str, object]:
        return {
            "timestamp": "2026-03-02T00:00:00Z",
            "host": host,
            "port": 2181,
            "is_zookeeper": is_zookeeper,
            "is_keeper": False if is_zookeeper else None,
            "status": status,
            "auth_required": status == "auth_required",
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "provided_credentials_ok": None,
            "show_znodes": False,
            "dump": False,
            "query_znode": None,
            "max_znodes": 100,
            "znode_count": znode_count,
            "znodes": [] if znode_count is not None else None,
            "znode_details": None,
            "znode_values": None,
            "znodes_truncated": False,
            "query_znode_value": None,
            "query_znode_dump": None,
            "query_znode_dump_error": None,
            "can_create_znode": None,
            "can_delete_znode": None,
            "znode_capability_error": None,
            "auth_inference_source": "root_ok",
            "auth_probe_trace": ["/:ok"],
            "elapsed_ms": 1,
            "error": None,
            "debug_events": [],
        }

    def _fake_audit(host: str, *args, **kwargs) -> dict[str, object]:
        run_deep_checks = bool(args[10]) if len(args) >= 11 else bool(kwargs.get("run_deep_checks", True))
        if not run_deep_checks:
            if host == "host-open":
                return _record_for(host, is_zookeeper=True, status="open_no_auth")
            if host == "host-valid":
                return _record_for(host, is_zookeeper=True, status="valid_credentials")
            if host == "host-auth":
                return _record_for(host, is_zookeeper=True, status="auth_required")
            return _record_for(host, is_zookeeper=False, status="fail")
        if host == "host-open":
            return _record_for(host, is_zookeeper=True, status="open_no_auth", znode_count=12)
        if host == "host-valid":
            return _record_for(host, is_zookeeper=True, status="valid_credentials", znode_count=7)
        return _record_for(host, is_zookeeper=False, status="fail")

    monkeypatch.setattr("redposture_core.stage_zookeeper._audit_zookeeper_host", _fake_audit)
    debug_lines: list[str] = []
    _totals = run_module_targets_for_test(
        "zookeeper",
        hosts=["host-open", "host-valid", "host-auth", "host-fail"],
        port=2181,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
        output_path=None,
        output_format="txt",
        emit_line=None,
        suppress_connection_refused_status_lines=False,
        debug_emit=debug_lines.append,
    )

    assert any("pass=1 detect start total=4" in line for line in debug_lines)
    assert any("host-open:2181 stage2_gate=run reason=status=open_no_auth" in line for line in debug_lines)
    assert any("host-valid:2181 stage2_gate=run reason=status=valid_credentials" in line for line in debug_lines)
    assert any("host-auth:2181 stage2_gate=skip reason=status=auth_required" in line for line in debug_lines)
    assert any("host-fail:2181 stage2_gate=skip reason=not_zookeeper" in line for line in debug_lines)
    assert any("pass=1 detect complete detected=3 deep_candidates=2" in line for line in debug_lines)
    assert any("pass=2 deep start total=2" in line for line in debug_lines)
    assert any("pass=2 deep complete processed=2" in line for line in debug_lines)


def test_audit_zookeeper_without_actions_skips_enumeration_debug(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        implementation_engine,
        "fingerprint_zookeeper_implementation",
        lambda *_args, **_kwargs: ZkImplementationFingerprint("apache-zookeeper", False, "confirmed"),
    )
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._infer_auth_required_from_anonymous_probes",
        lambda *_a, **_k: (False, "root_ok", ["/:ok"]),
    )

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, _path: str):
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, _path: str):
            return b"", _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

    def _enum(_client, _max_znodes, progress_hook=None, collect_paths=True):
        _ = collect_paths
        if callable(progress_hook):
            progress_hook(
                {
                    "event": "enumerate_progress",
                    "processed_parents": 1,
                    "queued": 0,
                    "total_count": 1,
                    "listed_count": 1,
                    "elapsed_s": 2.1,
                    "interval_s": 2.1,
                    "interval_count": 1,
                }
            )
            progress_hook(
                {
                    "event": "enumerate_done",
                    "processed_parents": 1,
                    "queued": 0,
                    "total_count": 1,
                    "listed_count": 1,
                    "elapsed_s": 2.2,
                }
            )
        return ["/a"], 1, False, {"/a": {"path": "/a", "children": 0, "bytes": 0, "error": None}}, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _Client)
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._probe_znode_create_delete", lambda *_a, **_k: (True, True, None)
    )
    monkeypatch.setattr("redposture_core.stage_zookeeper._enumerate_znodes", _enum)

    debug_lines: list[str] = []
    totals = run_module_targets_for_test(
        "zookeeper",
        hosts=["127.0.0.1"],
        port=2181,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
        output_path=None,
        output_format="txt",
        emit_line=None,
        suppress_connection_refused_status_lines=False,
        debug_emit=debug_lines.append,
    )

    assert totals == (1, 1, 0, 0, 0)
    progress_matches = [line for line in debug_lines if "enumerate progress discovered=1" in line]
    done_matches = [line for line in debug_lines if "enumerate done discovered=1" in line]
    assert progress_matches == []
    assert done_matches == []


def test_direct_host_stage_without_actions_skips_write_probe_and_tree_walk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Client:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            calls.append("connect")

        def get_children2(self, path: str):
            calls.append(f"children:{path}")
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def close(self) -> None:
            calls.append("close")

    monkeypatch.setattr(lifecycle_actions, "_ZkClient", Client)
    monkeypatch.setattr(
        lifecycle_actions,
        "_infer_auth_required_from_anonymous_probes",
        lambda *_args, **_kwargs: (False, "root_ok", ["/:ok"]),
    )
    monkeypatch.setattr(
        lifecycle_actions,
        "_probe_znode_create_delete",
        lambda *_args, **_kwargs: pytest.fail("write capability probe must not run without an action"),
    )
    monkeypatch.setattr(
        lifecycle_actions,
        "_enumerate_znodes",
        lambda *_args, **_kwargs: pytest.fail("tree traversal must not run without an action"),
    )

    record = lifecycle_actions.host_stage(
        host="127.0.0.1",
        port=2181,
        timeout=0.1,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
        debug=False,
        run_deep_checks=True,
        enum_workers=3,
        debug_emit=None,
    )

    assert calls == ["connect", "children:/", "close"]
    assert record["status"] == "open_no_auth"
    assert record["znode_count"] is None
    assert record["znodes"] is None
    assert record["can_create_znode"] is None
    assert record["can_delete_znode"] is None


def test_merge_stage2_record_marks_unknown_partial_and_timeout_note() -> None:
    detect_record = {
        "host": "127.0.0.1",
        "port": 2181,
        "is_zookeeper": True,
        "status": "open_no_auth",
        "show_znodes": True,
        "dump": False,
        "query_znode": None,
        "max_znodes": 100,
        "debug_events": ["stage1"],
    }
    deep_record = {
        "host": "127.0.0.1",
        "port": 2181,
        "is_zookeeper": True,
        "status": "open_no_auth",
        "znode_count": 12,
        "znodes": ["/a"],
        "znode_details": [{"path": "/a", "state": "empty", "children": 0, "bytes": 0, "error": None}],
        "znode_values": None,
        "znodes_truncated": False,
        "query_znode_value": None,
        "query_znode_dump": None,
        "query_znode_dump_error": None,
        "can_create_znode": True,
        "can_delete_znode": True,
        "znode_capability_error": None,
        "connect_ms": 10,
        "auth_ms": 0,
        "enumerate_ms": 100,
        "dump_ms": None,
        "elapsed_ms": 110,
        "connect_error": None,
        "auth_error": None,
        "enum_error": "connection timeout",
        "query_error": None,
        "dump_error": None,
        "attempts": 2,
        "max_attempts": 2,
        "stage2_error": None,
        "error": "connection timeout",
        "debug_events": ["stage2"],
    }

    merged = zookeeper_stage._merge_stage2_record(detect_record, deep_record, timeout=3.0, retries=2)
    assert merged["znode_count_unknown"] is True
    assert merged["znode_count_partial"] is True
    assert merged["znode_count_attempt_timeouts"] == [3.0, 3.0, 3.0]
    assert merged["stage2_error"] == "connection timeout"
    assert merged["debug_events"] == ["stage1", "stage2"]

    detail_lines = _format_znodes_detail_records(merged, "txt")
    assert not any("znode count unknown (partial)" in line for line in detail_lines)
    debug_lines = _format_znodes_detail_records(merged, "txt", debug=True)
    assert any("znode count unknown (partial)" in line for line in debug_lines)
    assert any("timeouts=3s,3s,3s" in line for line in debug_lines)


def test_audit_host_show_action_enumerates_without_write_capability_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    call_order: list[str] = []

    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._infer_auth_required_from_anonymous_probes",
        lambda *_a, **_k: (False, "root_ok", ["/:ok"]),
    )

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, path: str):
            if path == "/":
                return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, _path: str):
            return b"", _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

    def _enumerate(*_args, **_kwargs):
        call_order.append("enumerate")
        return [], 0, False, {}, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _Client)
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._probe_znode_create_delete",
        lambda *_args, **_kwargs: pytest.fail("read-only action must not issue a write probe"),
    )
    monkeypatch.setattr("redposture_core.stage_zookeeper._enumerate_znodes", _enumerate)

    rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=True,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )
    assert rec["status"] == "open_no_auth"
    assert call_order == ["enumerate"]
    assert rec["can_create_znode"] is None
    assert rec["can_delete_znode"] is None


def test_stage_trace_contains_all_stages_for_success_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._infer_auth_required_from_anonymous_probes",
        lambda *_a, **_k: (False, "root_ok", ["/:ok"]),
    )

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, _path: str):
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, _path: str):
            return b"", _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _Client)
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._probe_znode_create_delete",
        lambda *_a, **_k: (True, True, None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._enumerate_znodes",
        lambda *_a, **_k: (["/a"], 1, False, {"/a": {"path": "/a", "children": 0, "bytes": 0, "error": None}}, None),
    )

    rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=True,
        dump=False,
        query_znode=None,
        max_znodes=100,
        debug=True,
    )
    assert rec["status"] == "open_no_auth"
    stages = rec.get("stages") or []
    stage_names = [item.get("stage_name") for item in stages if isinstance(item, dict)]
    assert "detect_protocol" in stage_names
    assert "auth_inference_credentials" in stage_names
    assert "access_capabilities" in stage_names
    assert "data" in stage_names
    assert isinstance(rec.get("stage_durations_ms"), dict)
    assert isinstance(rec.get("stage_attempts"), dict)
    assert any("stage_trace stage_name=detect_protocol" in line for line in rec.get("debug_events") or [])
    assert any("stage_timing_summary status=open_no_auth" in line for line in rec.get("debug_events") or [])


def test_stage_trace_skips_deep_stages_when_auth_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._infer_auth_required_from_anonymous_probes",
        lambda *_a, **_k: (True, "root_noauth", ["/:noauth"]),
    )

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, _path: str):
            return None, _ZK_ERR_NOAUTH, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _Client)

    rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
        debug=True,
    )
    assert rec["status"] == "auth_required"
    stage_names = [item.get("stage_name") for item in rec.get("stages") or [] if isinstance(item, dict)]
    assert "detect_protocol" in stage_names
    assert "auth_inference_credentials" in stage_names
    assert "access_capabilities" not in stage_names
    assert "data" not in stage_names


def test_stage4_throttled_operation_retries_with_shared_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._infer_auth_required_from_anonymous_probes",
        lambda *_a, **_k: (False, "root_ok", ["/:ok"]),
    )

    class _Client:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, _path: str):
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, _path: str):
            return b"", _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

    enum_calls = {"count": 0}
    sleep_calls: list[float] = []

    def _enum(*_args, **_kwargs):
        enum_calls["count"] += 1
        if enum_calls["count"] < 3:
            return [], 0, False, {}, "getChildren failed for /: THROTTLEDOP"
        return ["/a"], 1, False, {"/a": {"path": "/a", "children": 0, "bytes": 0, "error": None}}, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _Client)
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._probe_znode_create_delete",
        lambda *_a, **_k: (True, True, None),
    )
    monkeypatch.setattr("redposture_core.stage_zookeeper._enumerate_znodes", _enum)
    monkeypatch.setattr("redposture_core.stage_zookeeper._retry_delay", lambda *_a, **_k: 0.0)
    monkeypatch.setattr("redposture_core.stage_zookeeper.time.sleep", lambda value: sleep_calls.append(float(value)))

    rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=2,
        username=None,
        password=None,
        show_znodes=True,
        dump=False,
        query_znode=None,
        max_znodes=100,
        debug=True,
    )
    assert rec["status"] == "open_no_auth"
    assert enum_calls["count"] == 3
    assert rec["attempts"] == 3
    assert rec["max_attempts"] == 3
    assert rec.get("stage_attempts", {}).get("data") == 3
    assert len(sleep_calls) >= 2
    assert any("retry_decision stage=data" in line for line in rec.get("debug_events") or [])


def test_audit_zookeeper_digest_on_open_target_is_unverified(monkeypatch) -> None:
    calls = {"auth": 0}

    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def auth_digest(self, username: str, password: str) -> tuple[bool, str | None]:
            calls["auth"] += 1
            assert username == "admin"
            assert password == "admin"
            return True, None

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            if path == "/":
                return ["clickhouse"], _ZK_ERR_OK, {"data_length": 0, "num_children": 1}
            if path == "/clickhouse":
                return None, _ZK_ERR_NOAUTH, None
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
            _ = path
            return None, _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)

    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username="admin",
        password="admin",
        show_znodes=True,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )

    assert calls["auth"] == 1
    assert record["status"] == "invalid_credentials_anonymous"
    assert record["provided_credentials_ok"] is False
    assert record["credential_verdict"] == "rejected"
    assert record["auth_required"] is False
    rendered = _format_record(record, "txt")
    assert "[-] admin:admin" in rendered
    assert "(auth required:False)" in zookeeper_stage._format_detect_record(record, "txt")
    assert any("/clickhouse:<Access Denied>" in line for line in _format_znodes_detail_records(record, "txt"))


def test_audit_zookeeper_dump_uses_access_denied_after_successful_auth(monkeypatch) -> None:
    calls = {"auth": 0}

    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)
            self._authed = False

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def auth_digest(self, username: str, password: str) -> tuple[bool, str | None]:
            calls["auth"] += 1
            assert username == "admin"
            assert password == "admin"
            self._authed = True
            return True, None

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            if path == "/" and not self._authed:
                return None, _ZK_ERR_NOAUTH, None
            if path == "/":
                return ["clickhouse"], _ZK_ERR_OK, {"data_length": 0, "num_children": 1}
            if path == "/clickhouse":
                return [], _ZK_ERR_OK, {"data_length": 16, "num_children": 0}
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
            _ = path
            return None, _ZK_ERR_NOAUTH, {"data_length": 0, "num_children": 0}

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)

    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username="admin",
        password="admin",
        show_znodes=True,
        dump=True,
        query_znode=None,
        max_znodes=100,
    )

    assert calls["auth"] == 1
    assert record["status"] == "valid_credentials"
    assert record["provided_credentials_ok"] is True
    znode_values = record.get("znode_values")
    assert isinstance(znode_values, list)
    assert "/clickhouse:<Access Denied>" in znode_values


def test_audit_zookeeper_valid_credentials_when_auth_was_required(monkeypatch) -> None:
    calls = {"auth": 0}

    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)
            self._authed = False

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def auth_digest(self, username: str, password: str) -> tuple[bool, str | None]:
            calls["auth"] += 1
            assert username == "admin"
            assert password == "admin"
            self._authed = True
            return True, None

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            if path == "/" and not self._authed:
                return None, _ZK_ERR_NOAUTH, None
            if path == "/":
                return ["secure"], _ZK_ERR_OK, {"data_length": 0, "num_children": 1}
            if path == "/secure":
                return [], _ZK_ERR_OK, {"data_length": 2, "num_children": 0}
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
            _ = path
            return b"ok", _ZK_ERR_OK, {"data_length": 2, "num_children": 0}

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)

    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username="admin",
        password="admin",
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )

    assert calls["auth"] == 1
    assert record["status"] == "valid_credentials"
    assert record["provided_credentials_ok"] is True
    assert record["auth_required"] is True
    assert record["auth_inference_source"] == "root_noauth"
    assert record["auth_probe_trace"] == ["/:noauth"]


def test_audit_zookeeper_valid_credentials_after_session_requires_auth(monkeypatch) -> None:
    calls = {"auth": 0, "instances": 0}

    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)
            calls["instances"] += 1
            self._authed = False

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def auth_digest(self, username: str, password: str) -> tuple[bool, str | None]:
            calls["auth"] += 1
            assert username == "admin"
            assert password == "admin"
            self._authed = True
            return True, None

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            if not self._authed:
                return None, _ZK_ERR_SESSION_CLOSED_REQUIRES_AUTH, None
            if path == "/":
                return ["secure"], _ZK_ERR_OK, {"data_length": 0, "num_children": 1}
            if path == "/secure":
                return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}
            return None, _ZK_ERR_NONODE, None

        def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
            _ = path
            return b"ok", _ZK_ERR_OK, {"data_length": 2, "num_children": 0}

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)

    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username="admin",
        password="admin",
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )

    assert calls["auth"] == 1
    assert calls["instances"] == 2
    assert record["status"] == "valid_credentials"
    assert record["provided_credentials_ok"] is True
    assert record["auth_required"] is True
    assert record["auth_inference_source"] == "session_closed_requires_auth"
    assert record["auth_probe_trace"] == ["/:sessionclosedrequiresaslauth"]


def test_audit_zookeeper_infers_auth_required_true_from_anonymous_probes(monkeypatch) -> None:
    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            if path == "/":
                return None, -1, None
            if path == "/zookeeper":
                return None, _ZK_ERR_NOAUTH, None
            if path == "/zookeeper/config":
                return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}
            return [], _ZK_ERR_NONODE, None

        def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
            _ = path
            return None, _ZK_ERR_NONODE, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)
    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )

    assert record["status"] == "fail"
    assert record["auth_required"] is True
    assert record["auth_inference_source"] == "probe_noauth"
    assert "/:systemerror" in record["auth_probe_trace"]
    assert "/zookeeper:noauth" in record["auth_probe_trace"]


def test_audit_zookeeper_infers_auth_required_false_from_anonymous_probes(monkeypatch) -> None:
    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            if path == "/":
                return None, -1, None
            if path == "/zookeeper":
                return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}
            if path == "/zookeeper/config":
                return [], _ZK_ERR_NONODE, None
            return [], _ZK_ERR_NONODE, None

        def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
            _ = path
            return None, _ZK_ERR_NONODE, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)
    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )

    assert record["status"] == "fail"
    assert record["auth_required"] is False
    assert record["auth_inference_source"] == "probe_ok"
    assert "/:systemerror" in record["auth_probe_trace"]
    assert "/zookeeper:ok" in record["auth_probe_trace"]


def test_audit_zookeeper_inference_keeps_unknown_for_neutral_and_error_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            if path == "/":
                return None, -1, None
            if path == "/zookeeper":
                return None, _ZK_ERR_NONODE, None
            if path == "/zookeeper/config":
                raise ConnectionError("simulated probe transport error")
            return [], _ZK_ERR_NONODE, None

        def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
            _ = path
            return None, _ZK_ERR_NONODE, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)
    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )

    assert record["status"] == "fail"
    assert record["auth_required"] is None
    assert record["auth_inference_source"] == "inconclusive"
    assert "/:systemerror" in record["auth_probe_trace"]
    assert "/zookeeper:nonode" in record["auth_probe_trace"]


def test_audit_zookeeper_session_closed_requires_auth_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"root": 0}

    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            _ = path
            calls["root"] += 1
            return None, _ZK_ERR_SESSION_CLOSED_REQUIRES_AUTH, None

        def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
            _ = path
            return None, _ZK_ERR_NONODE, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)
    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )

    assert calls["root"] == 1
    assert record["status"] == "auth_required"
    assert record["auth_required"] is True
    assert record["auth_inference_source"] == "session_closed_requires_auth"
    assert record["auth_probe_trace"] == ["/:sessionclosedrequiresaslauth"]
    rendered = _format_record(record, "txt")
    assert rendered == ""


def test_audit_zookeeper_invalid_credentials_on_anonymous_target_are_reported(monkeypatch) -> None:
    calls = {"auth": 0}

    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def auth_digest(self, username: str, password: str) -> tuple[bool, str | None]:
            calls["auth"] += 1
            assert username == "admin"
            assert password == "wrong"
            return False, "authentication failed: AUTHFAILED"

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            if path == "/":
                return ["clickhouse"], _ZK_ERR_OK, {"data_length": 0, "num_children": 1}
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
            _ = path
            return b"ok", _ZK_ERR_OK, {"data_length": 2, "num_children": 0}

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)

    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username="admin",
        password="wrong",
        show_znodes=True,
        dump=True,
        query_znode=None,
        max_znodes=100,
    )

    assert calls["auth"] == 1
    assert record["status"] == "invalid_credentials_anonymous"
    assert record["auth_required"] is False
    assert record["provided_credentials_ok"] is False
    assert "authentication failed" in str(record["error"]).lower()
    line = _format_record(record, "txt")
    assert "[-] admin:wrong" in line


def test_audit_zookeeper_auth_eof_with_required_auth_is_reported_as_auth_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"auth": 0}

    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def auth_digest(self, username: str, password: str) -> tuple[bool, str | None]:
            calls["auth"] += 1
            assert username == "admin"
            assert password == "wrong"
            return False, "unexpected EOF"

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            if path == "/":
                return None, _ZK_ERR_NOAUTH, None
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
            _ = path
            return None, _ZK_ERR_NONODE, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)

    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username="admin",
        password="wrong",
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )

    assert calls["auth"] == 1
    assert record["status"] == "auth_required"
    assert record["auth_required"] is True
    assert record["provided_credentials_ok"] is False
    assert str(record["error"]).lower().startswith("authentication failed:")
    line = _format_record(record, "txt")
    assert "[-] admin:wrong" in line


def test_format_record_shows_zookeeper_password_for_valid_credentials() -> None:
    line = _format_record(
        {
            "status": "valid_credentials",
            "host": "127.0.0.1",
            "port": 2181,
            "provided_username": "admin",
            "provided_password": "admin",
            "znode_count": 1,
            "znodes_truncated": False,
        },
        "txt",
    )
    assert "[+] admin:admin" in line


def test_format_record_places_authenticated_write_capabilities_after_credentials() -> None:
    record = {
        "status": "valid_credentials",
        "host": "127.0.0.1",
        "port": 22185,
        "provided_username": "zk",
        "provided_password": "zookeeper",
        "probe_write_requested": True,
        "znode_capability_scope": "/",
        "znode_capability_identity": "zk",
        "can_create_znode": True,
        "can_delete_znode": True,
        "znode_count": 1,
    }

    line = _format_record(record, "txt")

    assert "[+] zk:zookeeper (create:True) (delete:True)" in line
    assert "scope:" not in line
    assert lifecycle_actions._format_znode_capability_records(record, "txt") == []


def test_format_record_renders_confirmed_default_credentials_as_success() -> None:
    line = _format_record(
        {
            "status": "weak_default_creds",
            "host": "127.0.0.1",
            "port": 2181,
            "provided_username": "zk",
            "provided_password": None,
            "znode_count": 1,
            "znodes_truncated": False,
        },
        "txt",
    )

    assert "[+] zk:<none>" in line
    assert "connection failed" not in line


def test_audit_zookeeper_does_not_retry_session_closed_requires_auth(monkeypatch) -> None:
    calls = {"root": 0}

    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def auth_digest(self, username: str, password: str) -> tuple[bool, str | None]:
            _ = (username, password)
            return False, None

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            if path == "/":
                calls["root"] += 1
                if calls["root"] == 1:
                    return None, _ZK_ERR_SESSION_CLOSED_REQUIRES_AUTH, None
                return ["brokers"], _ZK_ERR_OK, {"data_length": 0, "num_children": 1}
            if path == "/secure":
                return None, _ZK_ERR_NOAUTH, None
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
            _ = path
            return None, _ZK_ERR_NONODE, {"data_length": 0, "num_children": 0}

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._enumerate_znodes",
        lambda _client, _max_znodes: (
            ["/brokers"],
            1,
            False,
            {"/brokers": {"path": "/brokers", "children": 0, "bytes": 0, "error": None}},
            None,
        ),
    )
    monkeypatch.setattr("redposture_core.stage_zookeeper._retry_delay", lambda _attempt: 0.0)

    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=True,
        dump=False,
        query_znode="/secure",
        max_znodes=100,
        debug=True,
    )

    assert calls["root"] == 1
    assert record["status"] == "auth_required"
    assert record["query_znode_value"] is None
    assert not any("retry_decision" in line for line in record.get("debug_events") or [])


def test_audit_zookeeper_session_policy_auth_required_txt_is_not_connection_failure(monkeypatch) -> None:
    calls = {"root": 0}

    class _RetryableRootClient:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, path: str):
            assert path == "/"
            calls["root"] += 1
            return None, _ZK_ERR_SESSION_CLOSED_REQUIRES_AUTH, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _RetryableRootClient)

    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )

    assert calls["root"] == 1
    assert record["status"] == "auth_required"
    assert record["auth_required"] is True
    assert record["auth_inference_source"] == "session_closed_requires_auth"
    rendered = _format_record(record, "txt")
    assert rendered == ""


def test_audit_zookeeper_sasl_required_after_digest_is_unsupported(monkeypatch) -> None:
    class _RetryableAfterDigestClient:
        def __init__(self, *_args, **_kwargs) -> None:
            self.authed = False

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def auth_digest(self, _username: str, _password: str):
            self.authed = True
            return True, None

        def get_children2(self, path: str):
            assert path == "/"
            return None, _ZK_ERR_SESSION_CLOSED_REQUIRES_AUTH, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _RetryableAfterDigestClient)
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._probe_znode_create_delete",
        lambda *_a, **_k: (None, None, None),
    )
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._enumerate_znodes",
        lambda *_a, **_k: ([], 0, False, {}, "getChildren failed for /: ERR_-124"),
    )

    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username="admin",
        password="admin",
        show_znodes=True,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )

    assert record["status"] == "auth_required"
    assert record["provided_credentials_ok"] is None
    assert record["credential_verdict"] == "unsupported_sasl"
    assert record["auth_mechanism"] == "sasl"
    assert record["verification_capability"] == "unsupported"
    rendered = _format_record(record, "txt")
    assert "[!] admin:admin (unsupported:SASL)" in rendered
    assert "connection failed" not in rendered


def test_format_znodes_detail_records_cover_text_and_json_paths() -> None:
    record = {
        "timestamp": "2026-03-27T00:00:00Z",
        "host": "127.0.0.1",
        "port": 2181,
        "show_znodes": True,
        "dump": True,
        "query_znode": "/brokers",
        "znode_count": 2,
        "znodes": ["/brokers", "/brokers/ids"],
        "znode_details": [
            {"path": "/brokers", "state": "empty", "children": 0, "bytes": 0, "error": None},
            {"path": "/brokers/ids", "state": "denied", "children": None, "bytes": None, "error": "Access Denied"},
        ],
        "znode_values": ["/brokers:<empty>"],
        "query_znode_value": "/brokers (children:1,bytes:0)",
        "query_znode_dump": None,
        "query_znode_dump_error": "Access Denied",
    }

    txt_lines = _format_znodes_detail_records(record, "txt")
    assert any("[*] Show Znodes" in line for line in txt_lines)
    assert any("[*] Znode /brokers" in line for line in txt_lines)
    assert any("[*] Dump Znode /brokers" in line for line in txt_lines)
    assert any("[-] Access Denied" in line for line in txt_lines)
    assert any("/brokers:<empty>" in line for line in txt_lines)
    assert any("/brokers/ids:<Access Denied>" in line for line in txt_lines)

    json_lines = _format_znodes_detail_records(record, "json")
    assert any('"type": "znodes_list"' in line for line in json_lines)
    assert any('"type": "znode_detail"' in line for line in json_lines)
    assert any('"type": "znode_dump"' in line for line in json_lines)


def test_format_record_suppresses_open_no_auth_txt_but_preserves_json() -> None:
    record = {
        "status": "open_no_auth",
        "host": "127.0.0.1",
        "port": 2181,
        "znode_count": 2050,
        "znodes_truncated": True,
        "can_create_znode": True,
        "can_delete_znode": False,
    }
    assert _format_record(record, "txt") == ""
    rendered_json = _format_record(record, "json")
    assert '"status": "open_no_auth"' in rendered_json
    assert '"znode_count": 2050' in rendered_json


def test_format_record_shows_single_unverified_explicit_credential() -> None:
    record = {
        "status": "open_no_auth",
        "host": "127.0.0.1",
        "port": 2181,
        "provided_credentials": True,
        "provided_username": "admin",
        "provided_password": "secret",
        "provided_credentials_ok": None,
        "credential_verdict": "unverified_anonymous",
    }

    assert _format_record(record, "txt") == ""


def test_format_record_does_not_repeat_auth_required_without_credentials() -> None:
    record = {
        "status": "auth_required",
        "host": "127.0.0.1",
        "port": 2181,
        "provided_credentials": False,
        "auth_required": True,
        "auth_inference_source": "root_noauth",
    }

    assert _format_record(record, "txt") == ""


def test_format_znodes_detail_records_shows_truncation_note() -> None:
    record = {
        "timestamp": "2026-03-27T00:00:00Z",
        "host": "127.0.0.1",
        "port": 2181,
        "show_znodes": True,
        "dump": False,
        "query_znode": None,
        "znode_count": 3000,
        "max_znodes": 2000,
        "znodes_truncated": True,
        "znode_details": [
            {"path": "/a", "state": "empty", "children": 0, "bytes": 0, "error": None},
            {"path": "/b", "state": "denied", "children": None, "bytes": None, "error": "Access Denied"},
        ],
    }
    txt_lines = _format_znodes_detail_records(record, "txt")
    assert any("Show Znodes (Count:2)" in line for line in txt_lines)
    assert not any("showing first" in line for line in txt_lines)
    debug_lines = _format_znodes_detail_records(record, "txt", debug=True)
    assert any("showing first 2 of 3000 znodes (max_znodes=2000)" in line for line in debug_lines)
    assert any("/a:<empty>" in line for line in txt_lines)
    assert any("/b:<Access Denied>" in line for line in txt_lines)


def test_audit_zookeeper_legacy_action_path_keeps_success_capabilities_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            _ = path
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
            _ = path
            return b"", _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def create(self, path: str, data: bytes = b"", flags: int = 1) -> int:
            _ = (path, data, flags)
            pytest.fail("read-only znode action must not call create")

        def delete(self, path: str, version: int = -1) -> int:
            _ = (path, version)
            pytest.fail("read-only znode action must not call delete")

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)
    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode="/",
        max_znodes=100,
    )
    assert record["status"] == "open_no_auth"
    assert record["can_create_znode"] is None
    assert record["can_delete_znode"] is None
    assert record["znode_capability_error"] is None


def test_audit_zookeeper_legacy_action_path_keeps_denied_capabilities_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            _ = path
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
            _ = path
            return b"", _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def create(self, path: str, data: bytes = b"", flags: int = 1) -> int:
            _ = (path, data, flags)
            pytest.fail("read-only znode action must not call create")

        def delete(self, path: str, version: int = -1) -> int:
            _ = (path, version)
            pytest.fail("read-only znode action must not call delete")

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)
    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode="/",
        max_znodes=100,
    )
    assert record["status"] == "open_no_auth"
    assert record["can_create_znode"] is None
    assert record["can_delete_znode"] is None
    assert record["znode_capability_error"] is None


def test_audit_zookeeper_legacy_action_path_never_tests_delete_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeZkClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, path: str) -> tuple[list[str] | None, int, dict[str, int] | None]:
            _ = path
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, path: str) -> tuple[bytes | None, int, dict[str, int] | None]:
            _ = path
            return b"", _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def create(self, path: str, data: bytes = b"", flags: int = 1) -> int:
            _ = (path, data, flags)
            pytest.fail("read-only znode action must not call create")

        def delete(self, path: str, version: int = -1) -> int:
            _ = (path, version)
            pytest.fail("read-only znode action must not call delete")

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _FakeZkClient)
    record = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode="/",
        max_znodes=100,
    )
    assert record["status"] == "open_no_auth"
    assert record["can_create_znode"] is None
    assert record["can_delete_znode"] is None
    assert record["znode_capability_error"] is None


def test_audit_zookeeper_targets_suppresses_auth_required_and_connection_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    records = {
        "127.0.0.1": {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": "127.0.0.1",
            "port": 2181,
            "is_zookeeper": True,
            "status": "auth_required",
            "auth_required": True,
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "provided_credentials_ok": None,
            "show_znodes": False,
            "dump": False,
            "query_znode": None,
            "max_znodes": 10,
            "znode_count": None,
            "znodes": None,
            "znode_values": None,
            "znodes_truncated": False,
            "query_znode_value": None,
            "query_znode_dump": None,
            "query_znode_dump_error": None,
            "elapsed_ms": 1,
            "error": None,
        },
        "127.0.0.2": {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": "127.0.0.2",
            "port": 2181,
            "is_zookeeper": False,
            "status": "fail",
            "auth_required": None,
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "provided_credentials_ok": None,
            "show_znodes": False,
            "dump": False,
            "query_znode": None,
            "max_znodes": 10,
            "znode_count": None,
            "znodes": None,
            "znode_values": None,
            "znodes_truncated": False,
            "query_znode_value": None,
            "query_znode_dump": None,
            "query_znode_dump_error": None,
            "elapsed_ms": None,
            "error": "connection refused",
        },
    }
    logged: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._audit_zookeeper_host",
        lambda host, *_args, **_kwargs: records[host],
    )

    emitted: list[str] = []
    totals = run_module_targets_for_test(
        "zookeeper",
        hosts=["127.0.0.1", "127.0.0.2"],
        port=2181,
        timeout=0.2,
        retries=0,
        workers=2,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=10,
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
        logger=SimpleNamespace(log=lambda *a, **k: logged.append((a, k))),
        suppress_connection_refused_status_lines=True,
    )
    assert totals == (2, 0, 0, 1, 1)
    assert any("ZooKeeper-compatible" in line for line in emitted)
    assert not any("authentication required" in line for line in emitted if "[-]" in line)
    assert not any("connection failed" in line for line in emitted)
    assert len(logged) == 1


def test_run_zookeeper_stage_validation_and_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []
            self.warns: list[str] = []
            self.infos: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def warn(self, message: str) -> None:
            self.warns.append(message)

        def info(self, message: str) -> None:
            self.infos.append(message)

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def _paint(self, text: str, _color: str, _stream: object) -> str:
            return text

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    fake_console = _FakeConsole()
    monkeypatch.setattr("redposture_core.stage_zookeeper.Console", lambda debug=False: fake_console)

    base_args = dict(
        debug=False,
        timeout=1.0,
        retries=0,
        max_znodes=100,
        username=None,
        password=None,
        port=2181,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        show_znodes=False,
        dump=False,
        znode=None,
        output=None,
        output_format="txt",
        workers=1,
    )

    assert (
        run_zookeeper_stage(
            SimpleNamespace(**{**base_args, "timeout": 0}), logger=SimpleNamespace(log=lambda *_a, **_k: None)
        )
        == 2
    )
    assert any("--timeout must be > 0" in msg for msg in fake_console.errors)

    fake_console.errors.clear()
    assert (
        run_zookeeper_stage(
            SimpleNamespace(**{**base_args, "username": "admin"}), logger=SimpleNamespace(log=lambda *_a, **_k: None)
        )
        == 2
    )
    assert any("--username and --password must be set together" in msg for msg in fake_console.errors)

    monkeypatch.setattr("redposture_core.stage_zookeeper.collect_scan_ports", lambda *_args, **_kwargs: [2181])
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper.collect_scan_targets",
        lambda *_args, **_kwargs: ["127.0.0.1"],
    )
    monkeypatch.setattr(
        "redposture_core.modules.zookeeper.stage.AuditCommandRunner.run_plan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("write failed")),
    )

    fake_console.errors.clear()
    assert run_zookeeper_stage(SimpleNamespace(**base_args), logger=SimpleNamespace(log=lambda *_a, **_k: None)) == 2
    assert any("failed to process zookeeper output" in msg for msg in fake_console.errors)


def test_run_zookeeper_stage_trims_and_forwards_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def warn(self, _message: str) -> None:
            return

        def info(self, _message: str) -> None:
            return

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def _paint(self, text: str, _color: str, _stream: object) -> str:
            return text

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    captured: dict[str, str | None] = {}
    fake_console = _FakeConsole()
    monkeypatch.setattr("redposture_core.stage_zookeeper.Console", lambda debug=False: fake_console)
    monkeypatch.setattr("redposture_core.stage_zookeeper.collect_scan_ports", lambda *_args, **_kwargs: [2181])
    monkeypatch.setattr("redposture_core.stage_zookeeper.collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    def _fake_audit(**kwargs):
        captured["username"] = kwargs.get("username")
        captured["password"] = kwargs.get("password")
        return _zookeeper_host_record(kwargs, status="valid_credentials", detected=True)

    patch_module_host_stage_for_test(monkeypatch, "zookeeper", _fake_audit)

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        max_znodes=100,
        username=" admin ",
        password=" secret ",
        port=2181,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        show_znodes=False,
        dump=False,
        znode=None,
        output=None,
        output_format="txt",
        workers=1,
    )

    rc = run_zookeeper_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 0
    assert captured == {"username": "admin", "password": " secret "}
    assert fake_console.errors == []

    captured.clear()
    args_empty_password = SimpleNamespace(**{**args.__dict__, "username": "admin", "password": ""})
    rc_empty_password = run_zookeeper_stage(args_empty_password, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc_empty_password == 0
    assert captured == {"username": "admin", "password": ""}


def test_run_zookeeper_stage_multi_port_uses_single_global_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug

        def error(self, _message: str) -> None:
            return

        def warn(self, _message: str) -> None:
            return

        def info(self, _message: str) -> None:
            return

        def plain(self, _message: str, color: str | None = None) -> None:
            _ = color
            return

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    class _FakeProgress:
        instances: list[_FakeProgress] = []

        def __init__(self, _label: str, total: int, *, enabled: bool = True, leave: bool = True) -> None:
            _ = (enabled, leave)
            self.total = total
            self.advances: list[int] = []
            self.closed = False
            type(self).instances.append(self)

        def advance(self, step: int = 1) -> None:
            self.advances.append(int(step))

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr("redposture_core.stage_zookeeper.Console", _FakeConsole)
    monkeypatch.setattr(
        "redposture_core.stage_runtime.start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgress(label, total, **kwargs),
    )
    monkeypatch.setattr("redposture_core.stage_zookeeper.collect_scan_ports", lambda *_args, **_kwargs: [2181, 2182])
    monkeypatch.setattr("redposture_core.stage_zookeeper.collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    captured: list[dict[str, object]] = []

    def _fake_audit(**kwargs):
        captured.append(dict(kwargs))
        return _zookeeper_host_record(kwargs, status="fail", detected=False, error="connection refused")

    patch_module_host_stage_for_test(monkeypatch, "zookeeper", _fake_audit)

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        max_znodes=100,
        username=None,
        password=None,
        port=2181,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        show_znodes=False,
        dump=False,
        znode=None,
        output=None,
        output_format="txt",
        workers=1,
        enum_workers=3,
    )
    rc = run_zookeeper_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 1
    assert len(captured) == 2
    assert [call["port"] for call in captured] == [2181, 2182]
    assert all(call["run_deep_checks"] is False for call in captured)
    assert len(_FakeProgress.instances) == 1
    progress = _FakeProgress.instances[0]
    assert progress.total == 2
    assert progress.advances == [1, 1]
    assert progress.closed is True


def test_probe_znode_create_delete_nodeexists_and_exceptions() -> None:
    class _NodeExistsClient:
        def __init__(self) -> None:
            self.calls = 0

        def create(self, _path: str) -> int:
            self.calls += 1
            return -110

        def delete(self, _path: str, _version: int = -1) -> int:
            return 0

    nodeexists_client = _NodeExistsClient()
    create_ok, delete_ok, err = zookeeper_stage._probe_znode_create_delete(nodeexists_client, "127.0.0.1", 2181)
    assert (create_ok, delete_ok, err) == (None, None, "NODEEXISTS")
    assert nodeexists_client.calls == 3

    class _NoCreateClient:
        pass

    create_ok, delete_ok, err = zookeeper_stage._probe_znode_create_delete(_NoCreateClient(), "127.0.0.1", 2181)
    assert (create_ok, delete_ok, err) == (None, None, "capability probe unsupported")

    class _TimeoutClient:
        def create(self, _path: str) -> int:
            raise TimeoutError("slow")

        def delete(self, _path: str, _version: int = -1) -> int:
            return 0

    create_ok, delete_ok, err = zookeeper_stage._probe_znode_create_delete(_TimeoutClient(), "127.0.0.1", 2181)
    assert (create_ok, delete_ok, err) == (None, None, "connection timeout")

    class _CreateDeniedClient:
        def create(self, _path: str) -> int:
            return _ZK_ERR_NOAUTH

    assert zookeeper_stage._probe_znode_create_delete(_CreateDeniedClient(), "127.0.0.1", 2181) == (
        False,
        None,
        "NOAUTH",
    )

    class _DeleteDeniedClient:
        def create(self, _path: str) -> int:
            return _ZK_ERR_OK

        def delete(self, _path: str, _version: int = -1) -> int:
            return _ZK_ERR_NOAUTH

    assert zookeeper_stage._probe_znode_create_delete(_DeleteDeniedClient(), "127.0.0.1", 2181) == (
        True,
        False,
        "NOAUTH",
    )


def test_zookeeper_explicit_write_probe_and_capability_render(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []

    class FakeClient:
        def connect(self) -> None:
            calls.append("connect")

        def create(self, path: str) -> int:
            calls.append(("create", path))
            return _ZK_ERR_OK

        def delete(self, path: str, version: int = -1) -> int:
            calls.append(("delete", path, version))
            return _ZK_ERR_OK

        def close(self) -> None:
            calls.append("close")

    state = lifecycle_actions.ZooKeeperLifecycleState()
    monkeypatch.setattr(lifecycle_actions, "_zookeeper_lifecycle_client", lambda *_args, **_kwargs: FakeClient())
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
    )
    options = {**_lifecycle_options(), "probe_write": True}

    record = lifecycle_actions.probe_zookeeper_capabilities(ctx, {"status": "open_no_auth"}, options)

    assert record["can_create_znode"] is True
    assert record["can_delete_znode"] is True
    assert record["znode_capability_scope"] == "/"
    assert record["znode_capability_identity"] == "anonymous"
    create_path = next(value[1] for value in calls if isinstance(value, tuple) and value[0] == "create")
    assert create_path.startswith("/redposture_probe_127_0_0_1_2181_")
    assert ("delete", create_path, -1) in calls
    assert calls[-1] == "close"
    capability_lines = lifecycle_actions._format_znode_capability_records(record, "txt")
    assert len(capability_lines) == 1
    assert capability_lines[0].endswith("[*] Anonymous znode permissions (create:True) (delete:True)")
    assert "scope:" not in capability_lines[0]


def test_zookeeper_write_probe_absent_is_read_only_and_verifier_search_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = lifecycle_actions.ZooKeeperLifecycleState()
    monkeypatch.setattr(
        lifecycle_actions,
        "_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: pytest.fail("write client must not open without --probe-write"),
    )
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
    )
    record = lifecycle_actions.probe_zookeeper_capabilities(
        ctx,
        {"status": "open_no_auth"},
        {**_lifecycle_options(), "probe_write": False},
    )
    assert record["probe_write_requested"] is False
    assert lifecycle_actions._format_znode_capability_records(record, "txt") == []

    candidates = lifecycle_actions._credential_verifier_candidates(
        [f"child-{index:02d}" for index in range(40)],
        "/explicit",
    )
    assert candidates[:2] == ("/", "/explicit")
    assert len(candidates) == 34
    assert candidates[-1] == "/child-31"
    assert (
        lifecycle_actions._protected_credential_verification_path(
            {"/": _ZK_ERR_OK, "/public": _ZK_ERR_OK, "/protected": _ZK_ERR_NOAUTH}
        )
        == "/protected"
    )


def test_zookeeper_verification_unavailable_is_one_aggregate_line() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 2181,
        "credential_verification_requested": True,
        "credential_verification_status": "unavailable",
        "credential_verification_reason": "no protected znode found",
    }
    lines = lifecycle_actions._format_credential_verification_records(record, "txt")
    assert len(lines) == 1
    assert lines[0].endswith(
        "[!] credential verification unavailable: no protected znode found; use --znode <protected-path>"
    )
    assert lifecycle_actions._format_credential_verification_records(record, "json") == []


def test_zookeeper_detect_finds_protected_direct_child_as_exact_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClient:
        selected_transport = "plaintext"

        def connect(self) -> None:
            return

        def get_children2(self, path: str):
            if path == "/":
                return ["public", "protected"], _ZK_ERR_OK, {"data_length": 0, "num_children": 2}
            if path == "/protected":
                return None, _ZK_ERR_NOAUTH, None
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def close(self) -> None:
            return

    state = lifecycle_actions.ZooKeeperLifecycleState()
    monkeypatch.setattr(lifecycle_actions, "_zookeeper_lifecycle_client", lambda *_args, **_kwargs: FakeClient())
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(timeout=0.1, retries=0, defcreds=True, username=None, password=None),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
    )

    record = lifecycle_actions.detect_zookeeper(ctx, _lifecycle_options())

    assert record["status"] == "open_no_auth"
    assert record["auth_required"] is False
    assert record["credential_verification_status"] == "available"
    assert record["credential_verification_path"] == "/protected"
    assert record["anonymous_auth_probe_results"]["/protected"] == "noauth"


def test_detail_entry_and_auth_probe_helpers() -> None:
    assert zookeeper_stage._znode_detail_entry("/x", {"error": "Access Denied"})["state"] == "denied"
    assert zookeeper_stage._znode_detail_entry("/x", {"error": "BROKEN"})["state"] == "error"
    assert zookeeper_stage._znode_detail_entry("/x", {"children": 0, "bytes": 0})["state"] == "empty"
    assert zookeeper_stage._znode_detail_entry("/x", {"children": 1, "bytes": 1})["state"] == "readable"
    assert zookeeper_stage._znode_detail_entry("/x", None)["state"] == "unknown"

    assert zookeeper_stage._normalize_auth_probe_result(_ZK_ERR_SESSION_CLOSED_REQUIRES_AUTH) == (
        "auth_required",
        "sessionclosedrequiresaslauth",
    )
    assert zookeeper_stage._normalize_auth_probe_result(_ZK_ERR_NONODE) == ("neutral", "nonode")
    assert zookeeper_stage._normalize_auth_probe_result(-115) == ("error", "authfailed")


@pytest.mark.parametrize(
    ("code", "name"),
    [
        (0, "OK"),
        (-4, "CONNECTIONLOSS"),
        (-7, "OPERATIONTIMEOUT"),
        (-101, "NONODE"),
        (-102, "NOAUTH"),
        (-115, "AUTHFAILED"),
        (-122, "REQUESTTIMEOUT"),
        (-124, "SESSIONCLOSEDREQUIRESASLAUTH"),
        (-125, "QUOTAEXCEEDED"),
        (-126, "BADAVERSION"),
        (-127, "THROTTLEDOP"),
    ],
)
def test_keeper_exception_code_mapping(code: int, name: str) -> None:
    assert zookeeper_stage._zk_error_name(code) == name


def test_run_anonymous_probe_and_infer_unknown_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    class _ProbeClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            _ = (host, port, timeout)

        def connect(self) -> None:
            return

        def get_children2(self, _path: str):
            return ([], _ZK_ERR_OK, None)

        def close(self) -> None:
            return

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _ProbeClient)
    err_code, probe_exc = zookeeper_stage._run_anonymous_auth_probe("127.0.0.1", 2181, 0.2, "/")
    assert (err_code, probe_exc) == (_ZK_ERR_OK, None)

    class _ProbeFailClient(_ProbeClient):
        def connect(self) -> None:
            raise ConnectionError("probe fail")

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _ProbeFailClient)
    err_code, probe_exc = zookeeper_stage._run_anonymous_auth_probe("127.0.0.1", 2181, 0.2, "/")
    assert err_code is None
    assert probe_exc == "probe fail"

    seq = [(None, None), (_ZK_ERR_NONODE, None), (_ZK_ERR_NONODE, None), (_ZK_ERR_NONODE, None)]

    def fake_probe(*_args, **_kwargs):
        return seq.pop(0)

    monkeypatch.setattr("redposture_core.stage_zookeeper._run_anonymous_auth_probe", fake_probe)
    auth_required, source, trace = zookeeper_stage._infer_auth_required_from_anonymous_probes(
        "127.0.0.1", 2181, 0.2, -1, "/x"
    )
    assert auth_required is None
    assert source == "inconclusive"
    assert "/x:nonode" in trace
    assert any(item.endswith("error:unknown") for item in trace)


def test_auth_inference_checks_explicit_znode_even_when_root_is_public(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probed_paths: list[str] = []

    def fake_probe(_host, _port, _timeout, path, **_kwargs):
        probed_paths.append(path)
        return _ZK_ERR_NOAUTH, None

    monkeypatch.setattr(lifecycle_actions, "_run_anonymous_auth_probe", fake_probe)

    auth_required, source, trace = lifecycle_actions._infer_auth_required_from_anonymous_probes(
        "127.0.0.1",
        2181,
        0.2,
        _ZK_ERR_OK,
        "secure",
    )

    assert auth_required is True
    assert source == "probe_noauth"
    assert trace == ["/:ok", "/secure:noauth"]
    assert probed_paths == ["/secure"]


def test_credential_verification_paths_replay_protected_trace_with_colon() -> None:
    assert lifecycle_actions._credential_verification_paths(
        None,
        ["/:ok", "/tenants/acme:prod:noauth"],
    ) == ("/", "/tenants/acme:prod")


def test_format_detect_record_and_record_json_branches() -> None:
    record = {
        "timestamp": "2026-04-09T00:00:00Z",
        "host": "127.0.0.1",
        "port": 2181,
        "is_zookeeper": True,
        "auth_required": True,
        "auth_inference_source": "root_noauth",
        "auth_probe_trace": ["/:noauth"],
    }
    detect_json = zookeeper_stage._format_detect_record(record, "json")
    assert '"type": "detect"' in detect_json
    assert '"auth_required": true' in detect_json
    assert '"implementation": "zookeeper-compatible"' in detect_json
    assert '"implementation_confidence": "unconfirmed"' in detect_json
    assert '"vendor": null' in detect_json
    assert '"protocol": "zookeeper"' in detect_json
    assert '"transport": "plaintext"' in detect_json

    compatible_line = zookeeper_stage._format_detect_record(record, "txt")
    assert "[*] ZooKeeper-compatible Service (implementation:unconfirmed)" in compatible_line
    assert "(auth required:True) (transport:plaintext) (version:-)" in compatible_line
    apache_line = zookeeper_stage._format_detect_record(
        {
            **record,
            "implementation": "apache-zookeeper",
            "is_keeper": False,
            "transport": "tls",
            "version": "3.9.3",
        },
        "txt",
    )
    assert "[*] Apache ZooKeeper" in apache_line
    assert "(transport:tls) (version:3.9.3)" in apache_line
    keeper_line = zookeeper_stage._format_detect_record(
        {
            **record,
            "implementation": "clickhouse-keeper",
            "is_keeper": True,
            "version": "v25.1",
        },
        "txt",
    )
    assert "[*] ClickHouse Keeper" in keeper_line
    assert keeper_line.startswith("KEEPER")
    assert apache_line.startswith("ZOOKEEPER")
    unconfirmed_keeper_line = zookeeper_stage._format_detect_record(
        {
            **record,
            "implementation": "clickhouse-keeper",
            "is_keeper": None,
            "version": "v25.1",
        },
        "txt",
    )
    assert unconfirmed_keeper_line.startswith("ZOOKEEPER")

    record_json = zookeeper_stage._format_record(
        {
            **record,
            "status": "fail",
            "provided_credentials": False,
            "error": None,
        },
        "json",
    )
    assert '"status": "fail"' in record_json
    line = zookeeper_stage._format_record({"status": "auth_required", "host": "h", "port": 1}, "txt")
    assert line == ""
    line = zookeeper_stage._format_record({"status": "fail", "host": "h", "port": 1, "error": None}, "txt")
    assert "[!] connection failed" in line


def test_format_znodes_detail_records_extra_paths() -> None:
    record_json_dump = {
        "timestamp": "2026-04-09T00:00:00Z",
        "host": "127.0.0.1",
        "port": 2181,
        "show_znodes": False,
        "dump": True,
        "query_znode": None,
        "znode_count": 2,
        "znode_values": ["/a:1", "/b:2"],
    }
    lines = _format_znodes_detail_records(record_json_dump, "json")
    assert any('"type": "znodes_dump"' in line for line in lines)

    record_txt_dump = {
        "host": "127.0.0.1",
        "port": 2181,
        "show_znodes": False,
        "dump": True,
        "query_znode": "/x",
        "query_znode_dump": None,
        "query_znode_dump_error": "",
    }
    lines = _format_znodes_detail_records(record_txt_dump, "txt")
    assert any("<no data>" in line for line in lines)


def test_render_colored_zookeeper_line_and_emit_line(tmp_path) -> None:
    class _FakeConsole:
        def __init__(self) -> None:
            self.lines: list[str] = []
            self.paint_calls: list[tuple[str, str]] = []

        def _paint(self, text: str, color: str, _stream) -> str:
            self.paint_calls.append((text, color))
            return f"<{color}>{text}</{color}>"

        def plain(self, text: str, color: str | None = None) -> None:
            _ = color
            self.lines.append(text)

    console = _FakeConsole()
    assert not zookeeper_stage._render_colored_zookeeper_line(console, "OTHER line")
    assert zookeeper_stage._render_colored_zookeeper_line(
        console, "ZOOKEEPER   127.0.0.1 2181 [*] ZooKeeper Service (auth required:True)"
    )
    assert any("<blue>ZOOKEEPER</blue>" in line for line in console.lines)

    assert zookeeper_stage._render_colored_zookeeper_line(
        console,
        "KEEPER      127.0.0.1 9181 [*] ClickHouse Keeper (transport:plaintext)",
    )
    assert any("<blue>KEEPER</blue>" in line for line in console.lines)
    assert ("transport:plaintext", "yellow") in console.paint_calls

    assert zookeeper_stage._render_colored_zookeeper_line(
        console,
        "ZOOKEEPER   127.0.0.1 2181 [+] anonymous access (create:True) (delete:False) (znodes:12)",
    )
    assert len(console.lines) >= 2

    assert zookeeper_stage._render_colored_zookeeper_line(
        console,
        "ZOOKEEPER\t127.0.0.1\t2181\t/x (children:0,bytes:25)",
    )
    assert ("(children:0,bytes:25)", "white") in console.paint_calls

    output_path = tmp_path / "out.txt"
    emitted: list[str] = []
    with output_path.open("w", encoding="utf-8") as out_fh:
        zookeeper_stage._emit_line(out_fh, emitted.append, "line-a")
    assert output_path.read_text(encoding="utf-8").strip() == "line-a"
    assert emitted == ["line-a"]

    plaintext_line = "KEEPER      127.0.0.1 9181 [*] ClickHouse Keeper (transport:plaintext)"
    colored_output_path = tmp_path / "colored-out.txt"
    sink = LineOutputSink(
        str(colored_output_path),
        _build_colored_emit(console, zookeeper_stage._render_colored_zookeeper_line),
    )
    sink.prepare()
    sink.emit_many((plaintext_line,))
    sink.close()
    assert colored_output_path.read_text(encoding="utf-8") == f"{plaintext_line}\n"
    assert "\x1b[" not in colored_output_path.read_text(encoding="utf-8")


def test_audit_targets_writes_output_file_and_append(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    def fake_audit(host: str, *_args, **_kwargs):
        return {
            "timestamp": "2026-04-09T00:00:00Z",
            "host": host,
            "port": 2181,
            "is_zookeeper": True,
            "status": "valid_credentials",
            "auth_required": True,
            "provided_credentials": True,
            "provided_username": "admin",
            "provided_password": "admin",
            "provided_credentials_ok": True,
            "show_znodes": False,
            "dump": False,
            "query_znode": None,
            "max_znodes": 2000,
            "znode_count": 1,
            "znodes": ["/a"],
            "znode_details": None,
            "znode_values": None,
            "znodes_truncated": False,
            "query_znode_value": None,
            "query_znode_dump": None,
            "query_znode_dump_error": None,
            "can_create_znode": True,
            "can_delete_znode": True,
            "znode_capability_error": None,
            "auth_inference_source": "root_noauth",
            "auth_probe_trace": ["/:noauth"],
            "elapsed_ms": 1,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.stage_zookeeper._audit_zookeeper_host", fake_audit)
    out_path = tmp_path / "zk.txt"

    totals = run_module_targets_for_test(
        "zookeeper",
        hosts=["h1"],
        port=2181,
        timeout=0.2,
        retries=0,
        workers=1,
        username="admin",
        password="admin",
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=2000,
        output_path=str(out_path),
        output_format="txt",
        debug=True,
        append_output=False,
    )
    assert totals == (1, 0, 1, 0, 0)
    first_size = out_path.stat().st_size
    assert first_size > 0

    run_module_targets_for_test(
        "zookeeper",
        hosts=["h2"],
        port=2181,
        timeout=0.2,
        retries=0,
        workers=1,
        username="admin",
        password="admin",
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=2000,
        output_path=str(out_path),
        output_format="txt",
        append_output=True,
    )
    assert out_path.stat().st_size > first_size


def test_run_stage_additional_error_paths_and_output_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []
            self.warns: list[str] = []
            self.infos: list[str] = []
            self.plain_lines: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def warn(self, message: str) -> None:
            self.warns.append(message)

        def info(self, message: str) -> None:
            self.infos.append(message)

        def plain(self, message: str, color: str | None = None) -> None:
            _ = color
            self.plain_lines.append(message)

        def _paint(self, text: str, _color: str, _stream: object) -> str:
            return text

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    fake_console = _FakeConsole()
    monkeypatch.setattr("redposture_core.stage_zookeeper.Console", lambda debug=False: fake_console)

    base_args = dict(
        debug=True,
        timeout=1.0,
        retries=0,
        max_znodes=100,
        username=None,
        password=None,
        port=2181,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        show_znodes=False,
        dump=False,
        znode=None,
        output=None,
        output_format="txt",
        workers=1,
    )

    assert (
        run_zookeeper_stage(
            SimpleNamespace(**{**base_args, "ports": "bad"}),
            logger=SimpleNamespace(log=lambda *_a, **_k: None),
        )
        == 2
    )
    assert any("failed to parse --port" in msg for msg in fake_console.errors)

    fake_console.errors.clear()
    assert (
        run_zookeeper_stage(
            SimpleNamespace(**{**base_args, "targets": "999.999.999.999/24"}),
            logger=SimpleNamespace(log=lambda *_a, **_k: None),
        )
        == 2
    )
    assert any("failed to parse targets" in msg for msg in fake_console.errors)

    fake_console.errors.clear()
    assert (
        run_zookeeper_stage(
            SimpleNamespace(**{**base_args, "targets": None}),
            logger=SimpleNamespace(log=lambda *_a, **_k: None),
        )
        == 2
    )
    assert any("zookeeper requires -t/--targets" in msg for msg in fake_console.errors)

    patch_module_host_stage_for_test(
        monkeypatch,
        "zookeeper",
        lambda **kwargs: _zookeeper_host_record(
            kwargs,
            status="fail",
            detected=False,
            error="connection refused",
        ),
    )
    fake_console.warns.clear()
    fake_console.infos.clear()
    rc = run_zookeeper_stage(SimpleNamespace(**base_args), logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 1
    assert any("no target confirmed as Apache ZooKeeper" in msg for msg in fake_console.warns)
    assert any("zookeeper audit started" in msg for msg in fake_console.infos)

    args_json = {**base_args, "output_format": "json", "debug": False}
    printed: list[str] = []
    monkeypatch.setattr("builtins.print", lambda *a, **_k: printed.append(" ".join(str(x) for x in a)))

    def fake_audit_json(**kwargs):
        return _zookeeper_host_record(kwargs, status="open_no_auth", detected=True)

    patch_module_host_stage_for_test(monkeypatch, "zookeeper", fake_audit_json)
    rc = run_zookeeper_stage(SimpleNamespace(**args_json), logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 0
    json_lines = [line for line in fake_console.plain_lines + printed if line.startswith("{")]
    assert any('"status": "open_no_auth"' in line for line in json_lines)


def test_friendly_error_extra_branches_and_decode_edge_cases() -> None:
    assert (
        zookeeper_stage._friendly_error_text("temporary failure in name resolution") == "dns lookup temporary failure"
    )
    assert (
        zookeeper_stage._friendly_error_text("operation not permitted")
        == "operation not permitted by local environment"
    )
    assert zookeeper_stage._friendly_error_text("[Errno 111] denied") == (
        "connection refused (service is not listening on target port)"
    )
    assert zookeeper_stage._friendly_error_text("[Errno 110] denied") == "connection timeout"
    assert zookeeper_stage._friendly_error_text("[Errno -2] denied") == "dns lookup failed"
    assert zookeeper_stage._friendly_error_text("[Errno 113] denied") == "network unreachable"

    class _EmptySocket:
        def recv(self, _size: int) -> bytes:
            return b""

    with pytest.raises(ConnectionError):
        _recv_exact(_EmptySocket(), 1)
    with pytest.raises(ValueError):
        _decode_zk_string(b"\x00\x00\x00")
    assert _decode_zk_buffer(struct.pack(">i", -1)) == (None, 4)
    with pytest.raises(ValueError):
        _decode_zk_buffer(struct.pack(">i", 8) + b"abc")


def test_zkclient_more_branches_and_enumerate_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    client = zookeeper_stage._ZkClient("127.0.0.1", 2181, 1.0)
    client.sock = object()
    monkeypatch.setattr("redposture_core.clients.zookeeper._send_frame", lambda *_a, **_k: None)
    monkeypatch.setattr(
        "redposture_core.clients.zookeeper._recv_frame",
        lambda *_a, **_k: struct.pack(">i", 1) + struct.pack(">q", 2) + struct.pack(">i", _ZK_ERR_OK),
    )
    err, payload = client._request(123)
    assert err == _ZK_ERR_OK
    assert payload == b""

    short_payload = struct.pack(">i", 0) + struct.pack(">i", 1000) + struct.pack(">q", 1) + struct.pack(">i", 0)
    short_sock = _QueuedSocket([_frame(short_payload)])
    monkeypatch.setattr("socket.create_connection", lambda *_a, **_k: short_sock)
    bad_client = zookeeper_stage._ZkClient("127.0.0.1", 2181, 1.0)
    with pytest.raises(ValueError):
        bad_client.connect()

    close_client = zookeeper_stage._ZkClient("127.0.0.1", 2181, 1.0)
    close_client.close()
    assert close_client.sock is None

    class _EnumClient:
        def get_children2(self, path: str):
            if path == "/":
                return ["dup", "dup", "gone", "err", "none"], _ZK_ERR_OK, {"data_length": 0, "num_children": 5}
            if path == "/dup":
                return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}
            if path == "/gone":
                return None, _ZK_ERR_NONODE, None
            if path == "/err":
                return None, -1, None
            if path == "/none":
                return None, _ZK_ERR_OK, None
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

    nodes, total_count, truncated, meta, enum_error = _enumerate_znodes(_EnumClient(), 100)
    assert "/dup" in nodes
    assert total_count >= 3
    assert truncated is False
    assert meta["/gone"]["error"] == "not found"
    assert enum_error == "getChildren failed for /err: SYSTEMERROR"


def test_audit_host_additional_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    class _WhitespaceCredsClient:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, _path: str):
            return None, _ZK_ERR_NOAUTH, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _WhitespaceCredsClient)
    rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=" ",
        password=" ",
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )
    assert rec["status"] == "auth_required"
    assert rec["provided_credentials"] is False

    class _AuthWeirdClient:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def auth_digest(self, _u: str, _p: str):
            return False, "digest transport failed"

        def get_children2(self, _path: str):
            return None, _ZK_ERR_NOAUTH, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _AuthWeirdClient)
    rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username="admin",
        password="admin",
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )
    assert rec["status"] == "fail"
    assert rec["error"] == "digest transport failed"

    class _QueryDumpClient:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, path: str):
            if path == "/":
                return ["q"], _ZK_ERR_OK, {"data_length": 0, "num_children": 1}
            if path == "/q":
                return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}
            if path == "/missing":
                return None, _ZK_ERR_NONODE, None
            if path == "/denied":
                return None, _ZK_ERR_NOAUTH, None
            if path == "/boom":
                return None, -115, None
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, path: str):
            if path == "/q":
                return b"ok", _ZK_ERR_OK, {"data_length": 2, "num_children": 0}
            if path == "/missing":
                return None, _ZK_ERR_NONODE, None
            if path == "/denied":
                return None, _ZK_ERR_NOAUTH, None
            return None, -115, None

        def create(self, _path: str, data: bytes = b"", flags: int = 1) -> int:
            _ = (data, flags)
            return _ZK_ERR_OK

        def delete(self, _path: str, version: int = -1) -> int:
            _ = version
            return _ZK_ERR_OK

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _QueryDumpClient)
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._enumerate_znodes",
        lambda *_a, **_k: pytest.fail("--znode must not traverse the tree"),
    )
    rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=True,
        query_znode="/missing",
        max_znodes=100,
    )
    assert rec["query_znode_value"] == "/missing:<not found>"
    assert rec["query_znode_dump_error"] == "znode not found"
    assert rec["znode_count"] is None
    assert rec["error"] is None

    rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=True,
        query_znode="/denied",
        max_znodes=100,
    )
    assert rec["query_znode_value"] == "/denied:<Access Denied>"
    assert rec["query_znode_dump_error"] == "Access Denied"

    rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=True,
        query_znode="/boom",
        max_znodes=100,
    )
    assert rec["query_znode_value"] == "/boom:<error:AUTHFAILED>"
    assert rec["query_znode_dump_error"] == "AUTHFAILED"


def test_render_color_extra_markers_and_run_stage_debug_output(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.lines: list[str] = []
            self.infos: list[str] = []

        def _paint(self, text: str, color: str, _stream) -> str:
            return f"<{color}>{text}</{color}>"

        def plain(self, text: str, color: str | None = None) -> None:
            _ = color
            self.lines.append(text)

        def info(self, text: str) -> None:
            self.infos.append(text)

        def warn(self, _text: str) -> None:
            return

        def error(self, _text: str) -> None:
            return

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    c = _FakeConsole()
    assert zookeeper_stage._render_colored_zookeeper_line(c, "ZOOKEEPER\th\t1\t [*] plain marker")
    assert zookeeper_stage._render_colored_zookeeper_line(c, "ZOOKEEPER\th\t1\t [*] x (auth required:False)")
    assert zookeeper_stage._render_colored_zookeeper_line(c, "ZOOKEEPER\th\t1\t [*] x (auth required:unknown)")
    assert zookeeper_stage._render_colored_zookeeper_line(
        c, "ZOOKEEPER\th\t1\t [+] x (create:unknown) (delete:unknown)"
    )

    fake_console = _FakeConsole(debug=True)
    monkeypatch.setattr("redposture_core.stage_zookeeper.Console", lambda debug=False: fake_console)
    monkeypatch.setattr("redposture_core.stage_zookeeper.collect_scan_ports", lambda *_a, **_k: [2181])
    monkeypatch.setattr("redposture_core.stage_zookeeper.collect_scan_targets", lambda *_a, **_k: ["127.0.0.1"])

    def fake_audit(**kwargs):
        return _zookeeper_host_record(kwargs, status="open_no_auth", detected=True)

    patch_module_host_stage_for_test(monkeypatch, "zookeeper", fake_audit)
    args = SimpleNamespace(
        debug=True,
        timeout=1.0,
        retries=0,
        max_znodes=100,
        username=None,
        password=None,
        port=2181,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        show_znodes=False,
        dump=False,
        znode=None,
        output="/tmp/zookeeper-debug-out.json",
        output_format="json",
        workers=1,
    )
    rc = run_zookeeper_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 0
    assert any("format=json output=/tmp/zookeeper-debug-out.json" in msg for msg in fake_console.infos)


def test_enumerate_znodes_children_none_with_ok_error_is_ignored() -> None:
    class _Client:
        def get_children2(self, path: str):
            if path == "/":
                return ["none"], _ZK_ERR_OK, {"data_length": 0, "num_children": 1}
            if path == "/none":
                return None, _ZK_ERR_OK, None
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

    nodes, total_count, truncated, meta, enum_error = _enumerate_znodes(_Client(), 100)
    assert nodes == ["/none"]
    assert total_count == 1
    assert truncated is False
    assert enum_error is None
    assert meta["/none"]["children"] is None
    assert meta["/none"]["bytes"] is None


def test_audit_host_auth_digest_edge_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._infer_auth_required_from_anonymous_probes",
        lambda *_a, **_k: (True, "probe_noauth", []),
    )

    class _StillNoAuthAfterDigestClient:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, _path: str):
            return None, _ZK_ERR_NOAUTH, None

        def auth_digest(self, _u: str, _p: str):
            return True, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _StillNoAuthAfterDigestClient)
    rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username="admin",
        password="admin",
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )
    # D3 fix: anon=NOAUTH + post-auth=NOAUTH is ambiguous — could be "auth
    # applied to a valid low-privilege principal" or "creds silently rejected".
    # We now probe /zookeeper (world-readable on default ZK) to disambiguate.
    # In this fake every read returns NOAUTH, so /zookeeper NOAUTH means creds
    # were silently rejected → provided_credentials_ok=False (was True prior).
    assert rec["provided_credentials_ok"] is False

    class _AuthDigestFailsWithoutErrorClient:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, _path: str):
            return None, _ZK_ERR_NOAUTH, None

        def auth_digest(self, _u: str, _p: str):
            return False, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _AuthDigestFailsWithoutErrorClient)
    rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username="admin",
        password="admin",
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )
    assert rec["status"] == "auth_required"
    assert rec["error"] == "authentication failed"


def test_audit_host_session_auth_policy_is_not_retried_after_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._infer_auth_required_from_anonymous_probes",
        lambda *_a, **_k: (True, "probe_noauth", []),
    )
    monkeypatch.setattr("redposture_core.stage_zookeeper._enumerate_znodes", lambda *_a, **_k: ([], 0, False, {}, None))
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._probe_znode_create_delete",
        lambda *_a, **_k: (True, True, None),
    )

    class _RetryAfterDigestClient:
        instance_idx = 0

        def __init__(self, *_args, **_kwargs) -> None:
            self.idx = _RetryAfterDigestClient.instance_idx
            _RetryAfterDigestClient.instance_idx += 1
            self.root_calls = 0

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def auth_digest(self, _u: str, _p: str):
            return True, None

        def get_children2(self, path: str):
            if path != "/":
                return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}
            self.root_calls += 1
            if self.idx == 0:
                if self.root_calls == 1:
                    return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}
                if self.root_calls == 2:
                    return None, _ZK_ERR_SESSION_CLOSED_REQUIRES_AUTH, None
            else:
                if self.root_calls == 1:
                    return None, _ZK_ERR_NOAUTH, None
                if self.root_calls == 2:
                    return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _RetryAfterDigestClient)
    rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=1,
        username="admin",
        password="admin",
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )
    assert rec["status"] == "auth_required"
    assert rec["provided_credentials_ok"] is False
    assert rec["attempts"] == 1


def test_audit_host_dump_query_dump_and_retry_fail_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper._infer_auth_required_from_anonymous_probes",
        lambda *_a, **_k: (False, "root_ok", []),
    )

    class _DumpClient:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, path: str):
            if path == "/":
                return ["a", "b"], _ZK_ERR_OK, {"data_length": 0, "num_children": 2}
            if path in {"/a", "/b", "/q_nonode", "/q_noauth", "/q_other", "/q_ok"}:
                return [], _ZK_ERR_OK, {"data_length": 5, "num_children": 0}
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, path: str):
            if path == "/a":
                return None, _ZK_ERR_NONODE, None
            if path == "/b":
                return None, -115, None
            if path == "/q_nonode":
                return None, _ZK_ERR_NONODE, None
            if path == "/q_noauth":
                return None, _ZK_ERR_NOAUTH, None
            if path == "/q_other":
                return None, -115, None
            if path == "/q_ok":
                return b"payload", _ZK_ERR_OK, {"data_length": 7, "num_children": 0}
            return None, _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def create(self, _path: str, data: bytes = b"", flags: int = 1) -> int:
            _ = (data, flags)
            return _ZK_ERR_OK

        def delete(self, _path: str, version: int = -1) -> int:
            _ = version
            return _ZK_ERR_OK

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _DumpClient)
    rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=True,
        query_znode=None,
        max_znodes=100,
    )
    assert isinstance(rec["znode_values"], list)
    assert any("<not found>" in item for item in rec["znode_values"])
    assert any("<error:AUTHFAILED>" in item for item in rec["znode_values"])

    rec_nonode = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=True,
        query_znode="/q_nonode",
        max_znodes=100,
    )
    assert rec_nonode["query_znode_dump_error"] == "znode not found"

    rec_noauth = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=True,
        query_znode="/q_noauth",
        max_znodes=100,
    )
    assert rec_noauth["query_znode_dump_error"] == "Access Denied"

    rec_other = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=True,
        query_znode="/q_other",
        max_znodes=100,
    )
    assert rec_other["query_znode_dump_error"] == "AUTHFAILED"

    rec_ok = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=False,
        dump=True,
        query_znode="/q_ok",
        max_znodes=100,
    )
    assert rec_ok["query_znode_value"] == "/q_ok (children:0,bytes:5)"
    assert rec_ok["query_znode_dump"] == "payload"

    class _TimeoutClient:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            raise TimeoutError("slow")

        def close(self) -> None:
            return

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _TimeoutClient)
    monkeypatch.setattr("redposture_core.stage_zookeeper._retry_delay", lambda *_a, **_k: 0.0)
    monkeypatch.setattr("redposture_core.stage_zookeeper.time.sleep", lambda *_a, **_k: None)
    fail_rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=1,
        username=None,
        password=None,
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )
    assert fail_rec["status"] == "fail"
    assert fail_rec["is_zookeeper"] is False
    assert fail_rec["error"] == "connection timeout"


def test_formatting_remaining_text_branches() -> None:
    assert zookeeper_stage._with_optional_znodes({"znode_count": None}, "line") == "line (znodes:unknown)"

    auth_failed_line = _format_record(
        {
            "host": "127.0.0.1",
            "port": 2181,
            "status": "fail",
            "provided_credentials": True,
            "provided_username": "admin",
            "provided_password": "bad",
            "error": "authentication failed: AUTHFAILED",
        },
        output_format="txt",
    )
    assert "[-] admin:bad" in auth_failed_line

    fail_line = _format_record(
        {"host": "127.0.0.1", "port": 2181, "status": "fail", "error": "boom"},
        output_format="txt",
    )
    assert "err=boom" in fail_line

    detail_lines = _format_znodes_detail_records(
        {
            "host": "127.0.0.1",
            "port": 2181,
            "show_znodes": True,
            "dump": False,
            "query_znode": None,
            "znode_count": 2,
            "max_znodes": 100,
            "znodes_truncated": False,
            "znode_details": [
                {"path": "/a", "state": "non_empty", "children": 2, "bytes": 9, "error": None},
                "skip-me",
                {"path": "/b", "state": "unknown", "children": None, "bytes": None, "error": None},
            ],
            "znode_values": None,
        },
        output_format="txt",
    )
    assert any("/a (children:2,bytes:9)" in line for line in detail_lines)
    assert any(line.endswith(" /b") for line in detail_lines)

    query_dump_lines = _format_znodes_detail_records(
        {
            "host": "127.0.0.1",
            "port": 2181,
            "show_znodes": False,
            "dump": True,
            "query_znode": "/q",
            "query_znode_value": "/q (children:0,bytes:0)",
            "query_znode_dump": "payload-value",
            "query_znode_dump_error": None,
            "znodes": [],
            "znode_details": [],
            "znode_values": [],
        },
        output_format="txt",
    )
    assert any(line.endswith(" payload-value") for line in query_dump_lines)

    dump_lines = _format_znodes_detail_records(
        {
            "host": "127.0.0.1",
            "port": 2181,
            "show_znodes": False,
            "dump": True,
            "query_znode": None,
            "query_znode_value": None,
            "query_znode_dump": None,
            "query_znode_dump_error": None,
            "znodes": ["/a"],
            "znode_details": [],
            "znode_values": ["/a:payload"],
            "znode_count": 10,
            "max_znodes": 1,
            "znodes_truncated": True,
        },
        output_format="txt",
        debug=True,
    )
    assert any("[*] Dump Znodes" in line for line in dump_lines)
    assert any("showing first" in line for line in dump_lines)
    assert any(line.endswith(" /a:payload") for line in dump_lines)


def test_audit_targets_detail_emit_and_run_stage_remaining_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    class _RenderConsole:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, text: str, color: str, _stream) -> str:
            return f"<{color}>{text}</{color}>"

        def plain(self, text: str, color: str | None = None) -> None:
            _ = color
            self.lines.append(text)

    # After the cross-module colorization pass, tag-prefixed detail lines
    # (no `[*]/[+]/[-]/[!]` marker) go through `render_tagged_detail_line`
    # instead of being emitted raw. The colorizer now returns True for these
    # lines — mirrors the kafka/grpc/redis/etcd/etc. behavior.
    assert (
        zookeeper_stage._render_colored_zookeeper_line(_RenderConsole(), "ZOOKEEPER\t127.0.0.1\t2181\t plain line")
        is True
    )

    class _FakeMatch:
        def __init__(self, start: int, end: int, group1: str = "") -> None:
            self._start = start
            self._end = end
            self._group1 = group1

        def start(self) -> int:
            return self._start

        def end(self) -> int:
            return self._end

        def group(self, index: int = 0) -> str:
            return self._group1 if index == 1 else ""

    real_search = re.search

    def _overlap_search(pattern: str, text: str):
        if pattern == r"\(znodes:(\d+)(?:\+)?(?: [^)]*)?\)":
            return _FakeMatch(0, 2, "9")
        if pattern.startswith(r"\(create:"):
            return _FakeMatch(1, 3, "True")
        if pattern.startswith(r"\(delete:"):
            return None
        return real_search(pattern, text)

    monkeypatch.setattr("re.search", _overlap_search)
    overlap_console = _RenderConsole()
    assert zookeeper_stage._render_colored_zookeeper_line(
        overlap_console, "ZOOKEEPER\t127.0.0.1\t2181\t [*] znodes-tail"
    )
    assert overlap_console.lines

    def _fake_audit_host(*_args, **_kwargs):
        return {
            "timestamp": "2026-01-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 2181,
            "is_zookeeper": True,
            "status": "open_no_auth",
            "auth_required": False,
            "provided_credentials": False,
            "provided_username": None,
            "provided_password": None,
            "provided_credentials_ok": None,
            "show_znodes": True,
            "dump": False,
            "query_znode": None,
            "max_znodes": 100,
            "znode_count": 1,
            "znodes": ["/a"],
            "znode_details": [{"path": "/a", "state": "empty", "children": 0, "bytes": 0, "error": None}],
            "znode_values": None,
            "znodes_truncated": False,
            "query_znode_value": None,
            "query_znode_dump": None,
            "query_znode_dump_error": None,
            "can_create_znode": None,
            "can_delete_znode": None,
            "znode_capability_error": None,
            "auth_inference_source": "root_ok",
            "auth_probe_trace": [],
            "elapsed_ms": 1,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.stage_zookeeper._audit_zookeeper_host", _fake_audit_host)
    emitted: list[str] = []
    totals = run_module_targets_for_test(
        "zookeeper",
        hosts=["127.0.0.1"],
        port=2181,
        timeout=0.2,
        retries=0,
        workers=1,
        username=None,
        password=None,
        show_znodes=True,
        dump=False,
        query_znode=None,
        max_znodes=100,
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
    )
    assert totals == (1, 1, 0, 0, 0)
    assert any("/a:<empty>" in line for line in emitted)

    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug = debug
            self.errors: list[str] = []
            self.infos: list[str] = []
            self.warns: list[str] = []
            self.plain_lines: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def warn(self, message: str) -> None:
            self.warns.append(message)

        def info(self, message: str) -> None:
            self.infos.append(message)

        def plain(self, message: str, color: str | None = None) -> None:
            _ = color
            self.plain_lines.append(message)

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            if _args and isinstance(_args[0], str):
                return "payload-tagged-line" in _args[0]
            return False

    fake_console = _FakeConsole(debug=True)
    monkeypatch.setattr("redposture_core.stage_zookeeper.Console", lambda debug=False: fake_console)

    def _fake_render_colored(_console: object, line: str) -> bool:
        return "marker-line" in line

    monkeypatch.setattr("redposture_core.stage_zookeeper._render_colored_zookeeper_line", _fake_render_colored)

    def _fake_stage_audit(**kwargs):
        return _zookeeper_host_record(kwargs, status="open_no_auth", detected=True)

    patch_module_host_stage_for_test(monkeypatch, "zookeeper", _fake_stage_audit)
    assert (
        zookeeper_stage._render_colored_zookeeper_line(fake_console, "ZOOKEEPER\t127.0.0.1\t2181\t plain line") is False
    )

    args_neg_retries = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=-1,
        max_znodes=100,
        username=None,
        password=None,
        port=2181,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        show_znodes=False,
        dump=False,
        znode=None,
        output=None,
        output_format="txt",
        workers=1,
    )
    assert run_zookeeper_stage(args_neg_retries, logger=SimpleNamespace(log=lambda *_a, **_k: None)) == 2
    assert any("--retries must be >= 0" in msg for msg in fake_console.errors)

    args_bad_max = SimpleNamespace(**{**args_neg_retries.__dict__, "retries": 0, "max_znodes": 0})
    fake_console.errors.clear()
    assert run_zookeeper_stage(args_bad_max, logger=SimpleNamespace(log=lambda *_a, **_k: None)) == 2
    assert any("--max-znodes must be > 0" in msg for msg in fake_console.errors)

    args_trim = SimpleNamespace(
        **{**args_neg_retries.__dict__, "retries": 0, "max_znodes": 100, "username": "", "password": ""}
    )
    fake_console.errors.clear()
    rc_trim = run_zookeeper_stage(args_trim, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc_trim == 0

    args_debug_stdout = SimpleNamespace(
        **{
            **args_neg_retries.__dict__,
            "debug": True,
            "retries": 0,
            "max_znodes": 100,
            "username": "admin",
            "password": "admin",
            "show_znodes": True,
            "dump": True,
            "znode": "/demo",
            "targets": "127.0.0.1",
            "hosts_file": None,
            "output": None,
            "output_format": "txt",
        }
    )
    rc_debug_stdout = run_zookeeper_stage(args_debug_stdout, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc_debug_stdout == 0
    assert any("zookeeper audit started: format=txt" in msg for msg in fake_console.infos)
    assert any("anonymous access" in line or "/demo" in line for line in fake_console.plain_lines)

    args_debug_file = SimpleNamespace(
        **{
            **args_debug_stdout.__dict__,
            "output": "/tmp/zookeeper-stage-out.txt",
        }
    )
    rc_debug_file = run_zookeeper_stage(args_debug_file, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc_debug_file == 0
    assert any("output=/tmp/zookeeper-stage-out.txt" in msg for msg in fake_console.infos)


def test_audit_host_debug_events_and_phase_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    class _DebugClient:
        def __init__(self, *_args, **_kwargs) -> None:
            return

        def connect(self) -> None:
            return

        def close(self) -> None:
            return

        def get_children2(self, path: str):
            if path == "/":
                return ["app"], _ZK_ERR_OK, {"data_length": 0, "num_children": 1}
            if path == "/app":
                return [], _ZK_ERR_OK, {"data_length": 4, "num_children": 0}
            return [], _ZK_ERR_OK, {"data_length": 0, "num_children": 0}

        def get_data(self, path: str):
            if path == "/app":
                return b"demo", _ZK_ERR_OK, {"data_length": 4, "num_children": 0}
            return None, _ZK_ERR_NONODE, None

        def create(self, _path: str, data: bytes = b"", flags: int = 1) -> int:
            _ = (data, flags)
            return _ZK_ERR_OK

        def delete(self, _path: str, version: int = -1) -> int:
            _ = version
            return _ZK_ERR_OK

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _DebugClient)
    rec = _audit_zookeeper_host(
        host="127.0.0.1",
        port=2181,
        timeout=0.2,
        retries=0,
        username=None,
        password=None,
        show_znodes=True,
        dump=False,
        query_znode=None,
        max_znodes=50,
        debug=True,
    )
    assert rec["status"] == "open_no_auth"
    assert isinstance(rec.get("connect_ms"), int)
    assert isinstance(rec.get("enumerate_ms"), int)
    assert rec.get("attempts") == 1
    assert rec.get("max_attempts") == 1
    assert rec.get("connect_error") is None
    assert isinstance(rec.get("debug_events"), list)
    assert any("auth decision" in line for line in rec["debug_events"])
    assert any("result=open_no_auth" in line for line in rec["debug_events"])


def test_run_stage_debug_summaries(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConsole:
        def __init__(self, debug: bool = False) -> None:
            self.debug_enabled = debug
            self.errors: list[str] = []
            self.infos: list[str] = []
            self.warns: list[str] = []
            self.debug_lines: list[str] = []
            self.plain_lines: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

        def warn(self, message: str) -> None:
            self.warns.append(message)

        def info(self, message: str) -> None:
            self.infos.append(message)

        def debug(self, message: str) -> None:
            self.debug_lines.append(message)

        def _paint(self, text: str, color: str, _stream) -> str:
            _ = color
            return text

        def plain(self, message: str, color: str | None = None) -> None:
            _ = color
            self.plain_lines.append(message)

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    fake_console = _FakeConsole(debug=True)
    monkeypatch.setattr("redposture_core.stage_zookeeper.Console", lambda debug=False: fake_console)
    monkeypatch.setattr("redposture_core.stage_zookeeper.collect_scan_ports", lambda *_a, **_k: [2181])
    monkeypatch.setattr("redposture_core.stage_zookeeper.collect_scan_targets", lambda *_a, **_k: ["127.0.0.1"])

    def _fake_audit(**kwargs):
        debug_emit = kwargs.get("debug_emit")
        if callable(debug_emit):
            debug_emit("127.0.0.1:2181 attempt=1/1 start timeout=1.0s")
        return _zookeeper_host_record(kwargs, status="open_no_auth", detected=True)

    patch_module_host_stage_for_test(monkeypatch, "zookeeper", _fake_audit)
    args = SimpleNamespace(
        debug=True,
        timeout=1.0,
        retries=0,
        max_znodes=100,
        username=None,
        password=None,
        port=2181,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        show_znodes=False,
        dump=False,
        znode=None,
        output=None,
        output_format="txt",
        workers=1,
    )
    rc = run_zookeeper_stage(args, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 0
    assert any("attempt=1/1 start timeout=1.0s" in line for line in fake_console.infos)
    assert any("zookeeper audit started: format=txt" in line for line in fake_console.infos)


def test_call_audit_zookeeper_wrapper_fallbacks_for_legacy_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def fake_audit(*args, **kwargs):
        calls.append((args, dict(kwargs)))
        if "enum_workers" in kwargs:
            raise TypeError("got an unexpected keyword argument 'enum_workers'")
        return {"status": "ok"}

    monkeypatch.setattr("redposture_core.stage_zookeeper._audit_zookeeper_host", fake_audit)
    result = _call_audit_host_with_thread_debug(
        "127.0.0.1",
        2181,
        1.0,
        0,
        None,
        None,
        False,
        False,
        None,
        100,
        False,
        True,
        3,
        None,
    )

    assert result == {"status": "ok"}
    assert len(calls) == 2
    assert calls[0][1]["enum_workers"] == 3
    assert "enum_workers" not in calls[1][1]


def test_call_audit_zookeeper_wrapper_propagates_unexpected_typeerror(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_audit(*_args, **_kwargs):
        raise TypeError("boom")

    monkeypatch.setattr("redposture_core.stage_zookeeper._audit_zookeeper_host", fake_audit)
    with pytest.raises(TypeError, match="boom"):
        _call_audit_host_with_thread_debug(
            "127.0.0.1",
            2181,
            1.0,
            0,
            None,
            None,
            False,
            False,
            None,
            100,
            False,
            True,
            1,
            None,
        )


def _lifecycle_options() -> dict[str, object]:
    return {
        "show_znodes": False,
        "dump": False,
        "dump_limit": None,
        "query_znode": None,
        "max_znodes": 100,
        "enum_workers": 3,
        "transport_config": None,
    }


def test_lifecycle_detect_exhausted_retries_emit_coherent_protocol_traces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connects = 0

    class FakeClient:
        def connect(self) -> None:
            nonlocal connects
            connects += 1
            raise ConnectionRefusedError(61, "Connection refused")

        def close(self) -> None:
            return

    monkeypatch.setattr(
        lifecycle_actions,
        "_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: FakeClient(),
    )
    monkeypatch.setattr(lifecycle_actions.time, "sleep", lambda _delay: None)
    ctx = SimpleNamespace(
        lifecycle_state=lifecycle_actions.ZooKeeperLifecycleState(),
        args=SimpleNamespace(retries=2, timeout=0.1),
        host="127.0.0.1",
        port=12181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
    )

    record = lifecycle_actions.detect_zookeeper(ctx, _lifecycle_options())

    assert connects == 3
    assert record["status"] == "fail"
    assert record["is_zookeeper"] is False
    stages = record["stages"]
    assert [stage["attempt"] for stage in stages] == [1, 2, 3]
    assert [stage["result"] for stage in stages] == ["retry", "retry", "fail"]
    assert {stage["stage_name"] for stage in stages} == {"detect_protocol"}
    assert {stage["error"] for stage in stages} == {record["error"]}
    assert record["connect_error"] == record["error"]
    assert record["stage_failed_at"] == "detect_protocol"
    assert record["stage_attempts"] == {"detect_protocol": 3}
    assert record["stage_durations_ms"] == {"detect_protocol": sum(int(stage["duration_ms"]) for stage in stages)}


def test_lifecycle_detect_success_defers_complete_stage_contract_to_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class FakeClient:
        selected_transport = "plaintext"

        def connect(self) -> None:
            events.append("connect")

        def get_children2(self, path: str):
            events.append(f"children:{path}")
            return [], _ZK_ERR_OK, {}

        def close(self) -> None:
            events.append("close")

    monkeypatch.setattr(
        lifecycle_actions,
        "_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: FakeClient(),
    )
    monkeypatch.setattr(
        lifecycle_actions,
        "_infer_auth_required_from_anonymous_probes",
        lambda *_args, **_kwargs: (False, "root_ok", ["/:ok"]),
    )
    ctx = SimpleNamespace(
        lifecycle_state=lifecycle_actions.ZooKeeperLifecycleState(),
        args=SimpleNamespace(retries=3, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
    )

    record = lifecycle_actions.detect_zookeeper(ctx, _lifecycle_options())

    assert events == ["connect", "children:/"]
    assert record["status"] == "open_no_auth"
    assert record["stages"] == []
    assert record["stage_durations_ms"] == {}
    assert record["stage_attempts"] == {}


def test_lifecycle_detect_retries_transient_root_protocol_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_statuses = iter([-7, _ZK_ERR_OK])  # OPERATIONTIMEOUT, then success
    events: list[str] = []

    class FakeClient:
        selected_transport = "plaintext"

        def connect(self) -> None:
            events.append("connect")

        def get_children2(self, path: str):
            events.append(f"children:{path}")
            return [], next(root_statuses), {}

        def close(self) -> None:
            events.append("close")

    monkeypatch.setattr(lifecycle_actions, "_zookeeper_lifecycle_client", lambda *_args, **_kwargs: FakeClient())
    monkeypatch.setattr(lifecycle_actions.time, "sleep", lambda _delay: events.append("sleep"))
    monkeypatch.setattr(
        lifecycle_actions,
        "_infer_auth_required_from_anonymous_probes",
        lambda *_args, **_kwargs: (False, "root_ok", ["/:ok"]),
    )
    ctx = SimpleNamespace(
        lifecycle_state=lifecycle_actions.ZooKeeperLifecycleState(),
        args=SimpleNamespace(retries=1, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
    )

    record = lifecycle_actions.detect_zookeeper(ctx, _lifecycle_options())

    assert events == ["connect", "children:/", "close", "sleep", "connect", "children:/"]
    assert record["status"] == "open_no_auth"
    assert record["attempts"] == 2


def test_lifecycle_auth_refresh_preserves_runner_stage_telemetry(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeClient:
        def connect(self) -> None:
            return

        def auth_digest(self, _username: str, _password: str):
            return True, None

        def get_children2(self, _path: str):
            return [], _ZK_ERR_OK, {}

        def close(self) -> None:
            return

    state = lifecycle_actions.ZooKeeperLifecycleState(root_err=_ZK_ERR_NOAUTH, auth_required=True)
    monkeypatch.setattr(
        lifecycle_actions,
        "_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: FakeClient(),
    )
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=0, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username="user", password="pass", source="provided"),
    )
    detect_record = {
        "host": "127.0.0.1",
        "port": 2181,
        "status": "auth_required",
        "stages": [
            {
                "stage_name": "detect_protocol",
                "attempt": 1,
                "duration_ms": 7,
                "result": "ok",
                "error": None,
            }
        ],
        "stage_failed_at": None,
        "stage_durations_ms": {"detect_protocol": 7},
        "stage_attempts": {"detect_protocol": 1},
        "debug_events": ["detect event"],
        "debug_events_streamed": True,
    }

    record = lifecycle_actions.authenticate_zookeeper(ctx, detect_record, _lifecycle_options())

    assert record["status"] == "valid_credentials"
    assert record["stages"] == detect_record["stages"]
    assert record["stage_durations_ms"] == {"detect_protocol": 7}
    assert record["stage_attempts"] == {"detect_protocol": 1}
    assert record["debug_events"] == ["detect event"]
    assert record["debug_events_streamed"] is True


def test_lifecycle_without_action_flags_is_read_only_and_skips_tree_walk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClient:
        def close(self) -> None:
            return

    state = lifecycle_actions.ZooKeeperLifecycleState(anonymous_client=FakeClient())
    monkeypatch.setattr(
        lifecycle_actions,
        "_refresh_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: (state.anonymous_client, None),
    )
    monkeypatch.setattr(
        lifecycle_actions,
        "_probe_znode_create_delete",
        lambda *_args, **_kwargs: pytest.fail("create/delete probe must not run"),
    )
    monkeypatch.setattr(
        lifecycle_actions,
        "_enumerate_zookeeper_lifecycle",
        lambda *_args, **_kwargs: pytest.fail("tree traversal must not run"),
    )
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=0, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
        debug_emit=None,
    )

    record = lifecycle_actions.collect_zookeeper_data(
        ctx,
        {"status": "open_no_auth", "can_create_znode": None, "can_delete_znode": None},
        _lifecycle_options(),
    )

    assert record["znode_count"] is None
    assert record["znodes"] is None
    assert record["can_create_znode"] is None
    assert record["can_delete_znode"] is None
    assert record["znode_count_partial"] is False


def test_lifecycle_znode_query_is_direct_only_and_dump_is_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    class FakeClient:
        def get_children2(self, path: str):
            calls.append(("children", path))
            return ["child"], _ZK_ERR_OK, {"data_length": 6}

        def get_data(self, path: str):
            calls.append(("data", path))
            return b"secret", _ZK_ERR_OK, {"data_length": 6}

        def close(self) -> None:
            return

    state = lifecycle_actions.ZooKeeperLifecycleState(anonymous_client=FakeClient())
    monkeypatch.setattr(
        lifecycle_actions,
        "_refresh_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: (state.anonymous_client, None),
    )
    monkeypatch.setattr(
        lifecycle_actions,
        "_probe_znode_create_delete",
        lambda *_args, **_kwargs: pytest.fail("create/delete probe must not run"),
    )
    monkeypatch.setattr(
        lifecycle_actions,
        "_enumerate_zookeeper_lifecycle",
        lambda *_args, **_kwargs: pytest.fail("tree traversal must not run for --znode"),
    )
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=0, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
        debug_emit=None,
    )
    options = {
        **_lifecycle_options(),
        "query_znode": "/secret",
        "show_znodes": True,
        "dump": True,
    }

    record = lifecycle_actions.collect_zookeeper_data(ctx, {"status": "open_no_auth"}, options)

    assert calls == [("children", "/secret"), ("data", "/secret")]
    assert record["query_znode_value"] == "/secret (children:1,bytes:6)"
    assert record["query_znode_dump"] == "secret"
    assert record["znode_count"] is None
    assert record["znodes"] == []
    assert record["can_create_znode"] is None
    assert record["can_delete_znode"] is None


def test_lifecycle_direct_znode_reconnects_after_transient_children_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []

    class InitialClient:
        def get_children2(self, path: str):
            calls.append(("initial-children", path))
            return [], -4, {}  # CONNECTIONLOSS

        def close(self) -> None:
            return

    class RetryClient:
        def get_children2(self, path: str):
            calls.append(("retry-children", path))
            return ["child"], _ZK_ERR_OK, {"data_length": 7}

        def close(self) -> None:
            return

    initial = InitialClient()
    state = lifecycle_actions.ZooKeeperLifecycleState(anonymous_client=initial)
    monkeypatch.setattr(
        lifecycle_actions,
        "_refresh_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: (initial, None),
    )

    def fake_reopen(_ctx, _state, *, authenticated: bool):
        calls.append(("reopen", authenticated))
        return RetryClient()

    monkeypatch.setattr(lifecycle_actions, "_reopen_zookeeper_lifecycle_client", fake_reopen)
    monkeypatch.setattr(lifecycle_actions.time, "sleep", lambda _delay: calls.append(("sleep", _delay)))
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=1, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
        debug_emit=None,
    )
    options = {**_lifecycle_options(), "query_znode": "/secret"}

    record = lifecycle_actions.collect_zookeeper_data(ctx, {"status": "open_no_auth"}, options)

    assert [call[0] for call in calls] == ["initial-children", "sleep", "reopen", "retry-children"]
    assert calls[2] == ("reopen", False)
    assert record["query_znode_value"] == "/secret (children:1,bytes:7)"
    assert record["query_error"] is None
    assert record["attempts"] == 2
    assert record["stage_attempts"]["data"] == 2


def test_lifecycle_direct_znode_dump_reconnects_with_selected_digest_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []

    class InitialClient:
        def get_children2(self, path: str):
            calls.append(("children", path))
            return [], _ZK_ERR_OK, {"data_length": 5}

        def get_data(self, path: str):
            calls.append(("initial-data", path))
            raise ConnectionResetError("connection reset by peer")

        def close(self) -> None:
            return

    class RetryClient:
        def get_data(self, path: str):
            calls.append(("retry-data", path))
            return b"fresh", _ZK_ERR_OK, {"data_length": 5}

        def close(self) -> None:
            return

    credential = SimpleNamespace(username="zk", password="zookeeper", source="default")
    initial = InitialClient()
    state = lifecycle_actions.ZooKeeperLifecycleState()
    state.credential_clients[(credential.username, credential.password, credential.source)] = cast(Any, initial)
    monkeypatch.setattr(
        lifecycle_actions,
        "_refresh_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: (initial, None),
    )

    def fake_reopen(_ctx, _state, *, authenticated: bool):
        calls.append(("reopen", authenticated))
        return RetryClient()

    monkeypatch.setattr(lifecycle_actions, "_reopen_zookeeper_lifecycle_client", fake_reopen)
    monkeypatch.setattr(lifecycle_actions.time, "sleep", lambda _delay: None)
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=1, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=credential,
        debug_emit=None,
    )
    options = {**_lifecycle_options(), "query_znode": "/secret", "dump": True}

    record = lifecycle_actions.collect_zookeeper_data(ctx, {"status": "weak_default_creds"}, options)

    assert calls == [
        ("children", "/secret"),
        ("initial-data", "/secret"),
        ("reopen", True),
        ("retry-data", "/secret"),
    ]
    assert record["query_znode_value"] == "/secret (children:0,bytes:5)"
    assert record["query_znode_dump"] == "fresh"
    assert record["query_znode_dump_error"] is None
    assert record["dump_error"] is None


def test_lifecycle_tree_dump_retries_only_failed_get_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []

    class Client:
        def __init__(self, name: str, *, transient: bool = False) -> None:
            self.name = name
            self.transient = transient

        def get_data(self, path: str):
            calls.append((f"data:{self.name}", path))
            if self.transient:
                return b"", -122, {}  # REQUESTTIMEOUT
            return b"value", _ZK_ERR_OK, {}

        def close(self) -> None:
            return

    enumerate_client = Client("enumerate")
    dump_client = Client("dump", transient=True)
    retry_client = Client("retry")
    refresh_clients = iter([enumerate_client, dump_client])

    def fake_refresh(*_args, **_kwargs):
        client = next(refresh_clients)
        calls.append(("refresh", client.name))
        return client, None

    def fake_enumerate(_ctx, _options, _state, client, **_kwargs):
        calls.append(("enumerate", client.name))
        return ["/secret"], 1, False, {"/secret": {}}, None

    def fake_reopen(_ctx, _state, *, authenticated: bool):
        calls.append(("reopen", authenticated))
        return retry_client

    monkeypatch.setattr(lifecycle_actions, "_refresh_zookeeper_lifecycle_client", fake_refresh)
    monkeypatch.setattr(lifecycle_actions, "_enumerate_zookeeper_lifecycle", fake_enumerate)
    monkeypatch.setattr(lifecycle_actions, "_reopen_zookeeper_lifecycle_client", fake_reopen)
    monkeypatch.setattr(lifecycle_actions.time, "sleep", lambda _delay: None)
    state = lifecycle_actions.ZooKeeperLifecycleState(anonymous_client=Client("stale"))
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=1, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
        debug_emit=None,
    )

    record = lifecycle_actions.collect_zookeeper_data(
        ctx,
        {"status": "open_no_auth"},
        {**_lifecycle_options(), "dump": True},
    )

    assert calls == [
        ("refresh", "enumerate"),
        ("enumerate", "enumerate"),
        ("refresh", "dump"),
        ("data:dump", "/secret"),
        ("reopen", False),
        ("data:retry", "/secret"),
    ]
    assert record["znode_values"] == ["/secret:value"]
    assert record["dump_error"] is None
    assert record["attempts"] == 2


def test_lifecycle_direct_znode_retry_is_bounded_and_skips_definitive_statuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transient_calls = 0
    reopen_calls = 0

    class TransientClient:
        def get_children2(self, _path: str):
            nonlocal transient_calls
            transient_calls += 1
            return [], -4, {}  # CONNECTIONLOSS

        def close(self) -> None:
            return

    initial = TransientClient()
    state = lifecycle_actions.ZooKeeperLifecycleState(anonymous_client=initial)
    monkeypatch.setattr(
        lifecycle_actions,
        "_refresh_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: (initial, None),
    )

    def fake_reopen(_ctx, _state, *, authenticated: bool):
        nonlocal reopen_calls
        assert authenticated is False
        reopen_calls += 1
        return TransientClient()

    monkeypatch.setattr(lifecycle_actions, "_reopen_zookeeper_lifecycle_client", fake_reopen)
    monkeypatch.setattr(lifecycle_actions.time, "sleep", lambda _delay: None)
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=2, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
        debug_emit=None,
    )
    options = {**_lifecycle_options(), "query_znode": "/secret"}

    record = lifecycle_actions.collect_zookeeper_data(ctx, {"status": "open_no_auth"}, options)

    assert transient_calls == 3
    assert reopen_calls == 2
    assert record["query_znode_value"] == "/secret:<error:CONNECTIONLOSS>"
    assert record["query_error"] == "CONNECTIONLOSS"
    assert record["attempts"] == 3
    assert record["max_attempts"] == 3

    reopen_calls = 0

    class DeniedClient:
        def get_children2(self, _path: str):
            return [], _ZK_ERR_NOAUTH, {}

        def close(self) -> None:
            return

    denied = DeniedClient()
    state.anonymous_client = cast(Any, denied)
    monkeypatch.setattr(
        lifecycle_actions,
        "_refresh_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: (denied, None),
    )

    denied_record = lifecycle_actions.collect_zookeeper_data(ctx, {"status": "open_no_auth"}, options)

    assert reopen_calls == 0
    assert denied_record["query_znode_value"] == "/secret:<Access Denied>"
    assert denied_record["query_error"] == "NOAUTH"
    assert denied_record["attempts"] == 1


@pytest.mark.parametrize(
    ("status", "credential", "authenticated"),
    [
        (
            "weak_default_creds",
            SimpleNamespace(username="zk", password="zookeeper", source="default"),
            True,
        ),
        (
            "open_no_auth",
            SimpleNamespace(username=None, password=None, source="anonymous"),
            False,
        ),
    ],
)
def test_exhaustive_defcreds_refreshes_selected_session_before_direct_read(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    credential: SimpleNamespace,
    authenticated: bool,
) -> None:
    calls: list[tuple[str, object]] = []

    class StaleClient:
        def get_children2(self, _path: str):
            pytest.fail("an idle detect/auth session must not reach the data phase")

        def close(self) -> None:
            return

    class FreshClient:
        def get_children2(self, path: str):
            calls.append(("children", path))
            return [], _ZK_ERR_OK, {"data_length": 5}

        def get_data(self, path: str):
            calls.append(("data", path))
            return b"fresh", _ZK_ERR_OK, {"data_length": 5}

        def close(self) -> None:
            return

    stale = StaleClient()
    state = lifecycle_actions.ZooKeeperLifecycleState()
    if authenticated:
        key = (credential.username, credential.password, credential.source)
        state.credential_clients[key] = cast(Any, stale)
    else:
        state.anonymous_client = cast(Any, stale)

    fresh = FreshClient()

    def fake_reopen(_ctx, _state, *, authenticated: bool):
        calls.append(("reopen", authenticated))
        return fresh

    monkeypatch.setattr(lifecycle_actions, "_reopen_zookeeper_lifecycle_client", fake_reopen)
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=0, timeout=0.1, defcreds=True),
        host="127.0.0.1",
        port=2181,
        credential=credential,
        debug_emit=None,
    )
    options = {
        **_lifecycle_options(),
        "query_znode": "/protected",
        "dump": True,
    }

    record = lifecycle_actions.collect_zookeeper_data(ctx, {"status": status}, options)

    assert calls == [
        ("reopen", authenticated),
        ("children", "/protected"),
        ("data", "/protected"),
    ]
    assert record["query_znode_dump"] == "fresh"


def test_tree_dump_refreshes_session_again_after_enumeration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []

    class Client:
        def __init__(self, name: str) -> None:
            self.name = name

        def get_data(self, path: str):
            calls.append((f"data:{self.name}", path))
            return b"value", _ZK_ERR_OK, {}

        def close(self) -> None:
            return

    stale = Client("stale")
    enumerate_client = Client("enumerate")
    dump_client = Client("dump")
    refreshed = iter([enumerate_client, dump_client])

    def fake_refresh(*_args, **_kwargs):
        client = next(refreshed)
        calls.append(("refresh", client.name))
        return client, None

    def fake_enumerate(_ctx, _options, _state, client, **_kwargs):
        calls.append(("enumerate", client.name))
        return ["/secret"], 1, False, {"/secret": {}}, None

    monkeypatch.setattr(lifecycle_actions, "_refresh_zookeeper_lifecycle_client", fake_refresh)
    monkeypatch.setattr(lifecycle_actions, "_enumerate_zookeeper_lifecycle", fake_enumerate)
    state = lifecycle_actions.ZooKeeperLifecycleState(anonymous_client=stale)
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=0, timeout=0.1, defcreds=False),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
        debug_emit=None,
    )
    options = {**_lifecycle_options(), "dump": True}

    record = lifecycle_actions.collect_zookeeper_data(ctx, {"status": "open_no_auth"}, options)

    assert calls == [
        ("refresh", "enumerate"),
        ("enumerate", "enumerate"),
        ("refresh", "dump"),
        ("data:dump", "/secret"),
    ]
    assert record["znode_values"] == ["/secret:value"]


def test_lifecycle_refresh_failure_marks_tree_scan_unknown_and_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StaleClient:
        def close(self) -> None:
            return

    state = lifecycle_actions.ZooKeeperLifecycleState(anonymous_client=StaleClient())
    monkeypatch.setattr(
        lifecycle_actions,
        "_refresh_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: (None, "connection reset by peer"),
    )
    monkeypatch.setattr(
        lifecycle_actions,
        "_enumerate_zookeeper_lifecycle",
        lambda *_args, **_kwargs: pytest.fail("enumeration must not use a stale session"),
    )
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=0, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
        debug_emit=None,
    )
    options = {**_lifecycle_options(), "show_znodes": True}

    record = lifecycle_actions.collect_zookeeper_data(
        ctx,
        {"status": "open_no_auth", "is_zookeeper": True},
        options,
    )

    assert record["znode_count"] is None
    assert record["znodes_truncated"] is True
    assert record["znode_count_partial"] is True
    assert record["znode_count_unknown"] is True
    assert record["znode_truncated_reason"] == "session_refresh"
    assert record["enum_error"] == "session refresh failed: connection reset by peer"
    assert record["stage2_error"] == record["enum_error"]
    assert "enum_error" in lifecycle_actions._format_record(record, "json")
    assert any(
        "znode count unknown (partial) reason=session refresh failed: connection reset by peer" in line
        for line in lifecycle_actions._format_znodes_detail_records(record, "txt", debug=True)
    )

    merged = lifecycle_actions._merge_stage2_record(
        {"status": "open_no_auth", "is_zookeeper": True},
        record,
        timeout=0.1,
        retries=0,
    )
    assert merged["znode_count"] is None
    assert merged["znode_count_partial"] is True
    assert merged["znode_count_unknown"] is True
    assert merged["znode_truncated_reason"] == "session_refresh"


def test_tree_dump_refresh_failure_is_reported_without_losing_enumeration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Client:
        def close(self) -> None:
            return

    enumerate_client = Client()
    refreshed = iter(((enumerate_client, None), (None, "connection reset by peer")))
    monkeypatch.setattr(
        lifecycle_actions,
        "_refresh_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: next(refreshed),
    )
    monkeypatch.setattr(
        lifecycle_actions,
        "_enumerate_zookeeper_lifecycle",
        lambda *_args, **_kwargs: (
            ["/secret"],
            1,
            False,
            {"/secret": {"path": "/secret", "children": 0, "bytes": 6, "error": None}},
            None,
        ),
    )
    state = lifecycle_actions.ZooKeeperLifecycleState(anonymous_client=Client())
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=0, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
        debug_emit=None,
    )

    record = lifecycle_actions.collect_zookeeper_data(
        ctx,
        {"status": "open_no_auth", "is_zookeeper": True},
        {**_lifecycle_options(), "dump": True},
    )

    assert record["znode_count"] == 1
    assert record["znode_count_unknown"] is False
    assert record["znode_values"] is None
    assert record["dump_error"] == "session refresh failed: connection reset by peer"
    txt_lines = lifecycle_actions._format_znodes_detail_records(record, "txt")
    assert any("[*] Dump Znodes" in line for line in txt_lines)
    assert any("[-] session refresh failed: connection reset by peer" in line for line in txt_lines)
    json_lines = lifecycle_actions._format_znodes_detail_records(record, "json")
    assert any('"error": "session refresh failed: connection reset by peer"' in line for line in json_lines)


def test_lifecycle_tree_walk_delegates_hard_bound_workers_auth_and_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, int, object, dict[str, object]]] = []
    expected = (["/a", "/b"], 2, True, {"/a": {}, "/b": {}}, None)

    def fake_enumerate(client, max_znodes, progress_hook, **kwargs):
        calls.append((client, max_znodes, progress_hook, dict(kwargs)))
        return expected

    monkeypatch.setattr(lifecycle_actions, "_enumerate_znodes", fake_enumerate)
    client = object()
    progress_hook = object()
    transport_config = ZkTransportConfig(mode="tls", insecure=True)
    state = lifecycle_actions.ZooKeeperLifecycleState(selected_transport_config=transport_config)
    ctx = SimpleNamespace(credential=SimpleNamespace(username="zk", password="secret"))
    options = {**_lifecycle_options(), "max_znodes": 2, "enum_workers": 7}

    result = lifecycle_actions._enumerate_zookeeper_lifecycle(
        ctx,
        options,
        state,
        client,
        authenticated=True,
        collect_paths=True,
        progress_hook=progress_hook,
    )

    assert result == expected
    assert calls == [
        (
            client,
            2,
            progress_hook,
            {
                "collect_paths": True,
                "enum_workers": 7,
                "auth_username": "zk",
                "auth_password": "secret",
                "transport_config": transport_config,
            },
        )
    ]


def test_lifecycle_show_znodes_reports_hard_limit_as_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, dict[str, object]]] = []

    class FakeClient:
        def close(self) -> None:
            return

    def fake_enumerate(_client, max_znodes, _progress_hook, **kwargs):
        calls.append((max_znodes, dict(kwargs)))
        return (
            ["/a", "/b"],
            2,
            True,
            {
                "/a": {"path": "/a", "children": None, "bytes": None, "error": None},
                "/b": {"path": "/b", "children": None, "bytes": None, "error": None},
            },
            None,
        )

    monkeypatch.setattr(lifecycle_actions, "_enumerate_znodes", fake_enumerate)

    state = lifecycle_actions.ZooKeeperLifecycleState(anonymous_client=FakeClient())
    monkeypatch.setattr(
        lifecycle_actions,
        "_refresh_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: (state.anonymous_client, None),
    )
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=0, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
        debug_emit=None,
    )
    options = {**_lifecycle_options(), "show_znodes": True, "max_znodes": 2}

    record = lifecycle_actions.collect_zookeeper_data(ctx, {"status": "open_no_auth"}, options)

    assert calls == [
        (
            2,
            {
                "collect_paths": True,
                "enum_workers": 3,
                "auth_username": None,
                "auth_password": None,
            },
        )
    ]
    assert record["znode_count"] == 2
    assert record["znodes"] == ["/a", "/b"]
    assert record["znodes_truncated"] is True
    assert record["znode_count_partial"] is True
    assert record["znode_count_unknown"] is True
    assert record["znode_truncated_reason"] == "max_znodes"
    detail_lines = lifecycle_actions._format_znodes_detail_records(record, "txt", debug=True)
    assert any("scanned first 2 znodes; more may exist" in line for line in detail_lines)


def test_lifecycle_noauth_subtree_reports_partial_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClient:
        def close(self) -> None:
            return

    monkeypatch.setattr(
        lifecycle_actions,
        "_enumerate_znodes",
        lambda *_args, **_kwargs: (
            ["/public", "/protected"],
            2,
            False,
            {
                "/public": {"path": "/public", "children": 0, "bytes": 1, "error": None},
                "/protected": {
                    "path": "/protected",
                    "children": None,
                    "bytes": None,
                    "error": "Access Denied",
                },
            },
            None,
        ),
    )
    state = lifecycle_actions.ZooKeeperLifecycleState(anonymous_client=FakeClient())
    monkeypatch.setattr(
        lifecycle_actions,
        "_refresh_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: (state.anonymous_client, None),
    )
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=0, timeout=0.1, defcreds=False),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username=None, password=None, source="anonymous"),
        debug_emit=None,
    )
    options = {**_lifecycle_options(), "show_znodes": True}

    record = lifecycle_actions.collect_zookeeper_data(ctx, {"status": "open_no_auth"}, options)

    assert record["znodes_truncated"] is True
    assert record["znode_count_partial"] is True
    assert record["znode_count_unknown"] is True
    assert record["znode_truncated_reason"] == "noauth"
    detail_lines = lifecycle_actions._format_znodes_detail_records(record, "txt", debug=True)
    assert any("scan partial: one or more znode subtrees are access denied" in line for line in detail_lines)
    assert not any("max_znodes=" in line for line in detail_lines)


def test_lifecycle_digest_is_verified_by_non_root_access_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClient:
        def connect(self) -> None:
            return

        def auth_digest(self, _username: str, _password: str):
            return True, None

        def get_children2(self, path: str):
            assert path in {"/", "/secure"}
            return [], _ZK_ERR_OK, {}

        def close(self) -> None:
            return

    state = lifecycle_actions.ZooKeeperLifecycleState(
        root_err=_ZK_ERR_OK,
        auth_required=False,
        anonymous_auth_probe_results={"/": _ZK_ERR_OK, "/secure": _ZK_ERR_NOAUTH},
    )
    monkeypatch.setattr(lifecycle_actions, "_zookeeper_lifecycle_client", lambda *_args, **_kwargs: FakeClient())
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=0, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username="user", password="pass", source="provided"),
    )

    record = lifecycle_actions.authenticate_zookeeper(
        ctx,
        {"status": "open_no_auth"},
        _lifecycle_options(),
    )

    assert record["status"] == "valid_credentials"
    assert record["provided_credentials_ok"] is True
    assert record["credential_verdict"] == "valid"
    assert record["credential_auth_probe_results"] == {"/": "ok", "/secure": "ok"}


def test_lifecycle_digest_transport_failure_is_unverified_not_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ResetClient:
        def connect(self) -> None:
            return

        def auth_digest(self, _username: str, _password: str):
            raise ConnectionResetError("connection reset by peer")

        def close(self) -> None:
            return

    state = lifecycle_actions.ZooKeeperLifecycleState(
        root_err=_ZK_ERR_NOAUTH,
        auth_required=True,
        anonymous_auth_probe_results={"/": _ZK_ERR_NOAUTH},
    )
    monkeypatch.setattr(lifecycle_actions, "_zookeeper_lifecycle_client", lambda *_args, **_kwargs: ResetClient())
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=0, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username="user", password="pass", source="provided"),
    )

    record = lifecycle_actions.authenticate_zookeeper(
        ctx,
        {"status": "auth_required"},
        _lifecycle_options(),
    )

    assert record["status"] == "fail"
    assert record["provided_credentials_ok"] is None
    assert record["credential_verdict"] == "unverified"
    assert "connection reset" in str(record["error"])


def test_lifecycle_sasl_required_marks_digest_unsupported_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = lifecycle_actions.ZooKeeperLifecycleState(
        root_err=_ZK_ERR_SESSION_CLOSED_REQUIRES_AUTH,
        auth_required=True,
        anonymous_auth_probe_results={"/": _ZK_ERR_SESSION_CLOSED_REQUIRES_AUTH},
    )
    monkeypatch.setattr(
        lifecycle_actions,
        "_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: pytest.fail("digest network attempt must be skipped for SASL-only policy"),
    )
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=0, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username="user", password="pass", source="default"),
    )

    record = lifecycle_actions.authenticate_zookeeper(
        ctx,
        {"status": "auth_required"},
        _lifecycle_options(),
    )

    assert record["status"] == "auth_required"
    assert record["provided_credentials_ok"] is None
    assert record["credential_verdict"] == "unsupported_sasl"
    assert record["auth_mechanism"] == "sasl"
    assert record["verification_capability"] == "unsupported"


def test_lifecycle_digest_auth_response_sasl_required_is_not_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_clients = 0

    class FakeClient:
        def connect(self) -> None:
            return

        def auth_digest(self, _username: str, _password: str):
            return False, "authentication failed: SESSIONCLOSEDREQUIRESASLAUTH"

        def get_children2(self, _path: str):
            pytest.fail("closed SASL-required session must not be probed")

        def close(self) -> None:
            return

    def fake_client(*_args, **_kwargs):
        nonlocal created_clients
        created_clients += 1
        return FakeClient()

    state = lifecycle_actions.ZooKeeperLifecycleState(
        root_err=_ZK_ERR_NOAUTH,
        auth_required=True,
        anonymous_auth_probe_results={"/": _ZK_ERR_NOAUTH},
    )
    monkeypatch.setattr(lifecycle_actions, "_zookeeper_lifecycle_client", fake_client)
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=0, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username="user", password="pass", source="default"),
    )

    first = lifecycle_actions.authenticate_zookeeper(ctx, {"status": "auth_required"}, _lifecycle_options())
    ctx.credential = SimpleNamespace(username="zk", password="zookeeper", source="default")
    second = lifecycle_actions.authenticate_zookeeper(ctx, {"status": "auth_required"}, _lifecycle_options())

    assert created_clients == 1
    for record in (first, second):
        assert record["status"] == "auth_required"
        assert record["provided_credentials_ok"] is None
        assert record["credential_verdict"] == "unsupported_sasl"
        assert record["auth_mechanism"] == "sasl"
        assert record["verification_capability"] == "unsupported"


def test_lifecycle_exhaustive_success_keeps_only_first_verified_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients: list[FakeClient] = []

    class FakeClient:
        def __init__(self) -> None:
            self.closed = False

        def connect(self) -> None:
            return

        def auth_digest(self, _username: str, _password: str):
            return True, None

        def get_children2(self, _path: str):
            return [], _ZK_ERR_OK, {}

        def close(self) -> None:
            self.closed = True

    def fake_client(*_args, **_kwargs):
        client = FakeClient()
        clients.append(client)
        return client

    state = lifecycle_actions.ZooKeeperLifecycleState(
        root_err=_ZK_ERR_NOAUTH,
        auth_required=True,
        anonymous_auth_probe_results={"/": _ZK_ERR_NOAUTH},
    )
    monkeypatch.setattr(lifecycle_actions, "_zookeeper_lifecycle_client", fake_client)
    ctx = SimpleNamespace(
        lifecycle_state=state,
        args=SimpleNamespace(retries=0, timeout=0.1),
        host="127.0.0.1",
        port=2181,
        credential=SimpleNamespace(username="first", password="secret", source="default"),
    )

    first = lifecycle_actions.authenticate_zookeeper(ctx, {"status": "auth_required"}, _lifecycle_options())
    ctx.credential = SimpleNamespace(username="second", password="secret", source="default")
    second = lifecycle_actions.authenticate_zookeeper(ctx, {"status": "auth_required"}, _lifecycle_options())

    assert first["provided_credentials_ok"] is True
    assert second["provided_credentials_ok"] is True
    assert len(state.credential_clients) == 1
    assert clients[0].closed is False
    assert clients[1].closed is True


def test_zookeeper_defcreds_plan_has_exact_stable_catalog_order() -> None:
    expected = (
        ("admin", "admin"),
        ("admin", "changeme"),
        ("admin", "kafka"),
        ("admin", "password"),
        ("admin", "zookeeper"),
        ("broker", "broker"),
        ("broker", "brokerpass"),
        ("client", "client"),
        ("dev", "dev"),
        ("guest", "guest"),
        ("hadoop", "hadoop"),
        ("kafka", "changeme"),
        ("kafka", "kafka"),
        ("kafka", "password"),
        ("kafka", "zookeeper"),
        ("root", "admin"),
        ("root", "password"),
        ("root", "root"),
        ("root", "rootpass"),
        ("root", "zookeeper"),
        ("service", "password"),
        ("service", "service"),
        ("solr", "solr"),
        ("super", "super"),
        ("test", "test"),
        ("user", "password"),
        ("user", "user"),
        ("user1", "12345"),
        ("zk", "password"),
        ("zk", "zk"),
        ("zk", "zookeeper"),
        ("zookeeper", "admin"),
        ("zookeeper", "password"),
        ("zookeeper", "zookeeper"),
    )
    args = parse_args(
        [
            "zookeeper",
            "-t",
            "127.0.0.1",
            "--port",
            "2181",
            "--defcreds",
        ]
    )

    plan = lifecycle_stage.build_zookeeper_plan(args)

    assert lifecycle_stage._DEFAULT_CREDENTIALS == expected
    assert tuple((run.username, run.password) for run in plan.credential_runs) == expected
    assert len(plan.credential_runs) == 34
    assert {run.source for run in plan.credential_runs} == {"default"}


def test_zookeeper_canonical_plan_scans_only_apache_default_ports() -> None:
    args = parse_args(["zookeeper", "-t", "127.0.0.1"])

    assert lifecycle_stage.build_zookeeper_plan(args).ports == (2181, 12181, 22181)


def test_zookeeper_canonical_tls_policy_rejects_conflicting_or_incomplete_trust_options() -> None:
    class Console:
        def __init__(self) -> None:
            self.errors: list[str] = []

        def error(self, message: str) -> None:
            self.errors.append(message)

    conflicting = parse_args(["zookeeper", "-t", "127.0.0.1", "--ca-file", "ca.pem", "--insecure"])
    console = Console()
    assert lifecycle_stage.policy.validate_args(conflicting, console) == 2
    assert console.errors == ["--ca-file cannot be combined with --insecure"]

    incomplete = parse_args(["zookeeper", "-t", "127.0.0.1", "--tls-cert", "client.pem"])
    console = Console()
    assert lifecycle_stage.policy.validate_args(incomplete, console) == 2
    assert console.errors == ["--tls-cert and --tls-key must be used together"]


def test_zookeeper_canonical_spec_auto_classifies_apache_without_rejecting_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = parse_args(["zookeeper", "-t", "127.0.0.1", "--insecure"])
    args.zookeeper_fingerprint_cache = ZooKeeperFingerprintCache()
    spec = lifecycle_stage.build_zookeeper_spec(args)
    assert spec.lifecycle_state_factory is not None
    assert spec.detect is not None
    state = spec.lifecycle_state_factory(None)
    assert isinstance(state, implementation_engine.ZooKeeperImplementationLifecycleState)
    assert state.requested_config.mode == "auto"
    assert state.requested_config.insecure is True

    def fake_detect(ctx, _options):
        ctx.lifecycle_state.selected_transport_config = ZkTransportConfig(mode="plaintext")
        return {
            "host": ctx.host,
            "port": ctx.port,
            "service": "zookeeper",
            "status": "open_no_auth",
            "auth_required": False,
            "is_zookeeper": True,
            "error": None,
            "stages": [],
        }

    monkeypatch.setattr(implementation_engine.zookeeper_actions, "detect_zookeeper", fake_detect)
    monkeypatch.setattr(
        implementation_engine,
        "fingerprint_zookeeper_implementation",
        lambda *_args, **_kwargs: ZkImplementationFingerprint(
            "apache-zookeeper",
            False,
            "rejected",
            version="3.9.5",
        ),
    )
    ctx = AuditHookContext(
        args=args,
        logger=None,
        host="127.0.0.1",
        port=2181,
        credential=AuditCredentialRun(source="anonymous"),
        lifecycle_state=state,
    )

    record = spec.detect(ctx)
    payload = record.to_dict()

    assert payload["module"] == "zookeeper"
    assert payload["service"] == "zookeeper"
    assert payload["implementation"] == "apache-zookeeper"
    assert payload["implementation_confidence"] == "confirmed"
    assert payload["vendor"] == "apache"
    assert payload["is_keeper"] is False
    assert payload["status"] == "open_no_auth"
    assert payload["error"] is None
    assert payload["transport"] == "plaintext"


def test_zookeeper_credential_file_precedes_defaults_and_is_stably_deduplicated(tmp_path) -> None:
    credentials = tmp_path / "zookeeper.creds"
    credentials.write_text("custom:secret\nadmin:admin\ncustom:secret\n", encoding="utf-8")
    args = parse_args(
        [
            "zookeeper",
            "-t",
            "127.0.0.1",
            "--port",
            "2181",
            "-u",
            str(credentials),
            "--defcreds",
        ]
    )

    plan = lifecycle_stage.build_zookeeper_plan(args)
    pairs = tuple((run.username, run.password) for run in plan.credential_runs)

    assert pairs[:2] == (("custom", "secret"), ("admin", "admin"))
    assert tuple(run.source for run in plan.credential_runs[:2]) == ("file", "file")
    assert pairs[2:] == tuple(pair for pair in lifecycle_stage._DEFAULT_CREDENTIALS if pair != ("admin", "admin"))
    assert pairs.count(("custom", "secret")) == 1
    assert pairs.count(("admin", "admin")) == 1


def test_zookeeper_credential_file_preserves_password_bytes_into_digest_auth(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    exact_password = "  secret:with:colons  "
    credentials = tmp_path / "zookeeper-exact.creds"
    credentials.write_text(f" zk-user :{exact_password}\n", encoding="utf-8")
    args = parse_args(
        [
            "zookeeper",
            "-t",
            "127.0.0.1",
            "--port",
            "2181",
            "-u",
            str(credentials),
            "--format",
            "json",
        ]
    )
    observed: list[tuple[str, str]] = []
    monkeypatch.setattr(
        implementation_engine,
        "fingerprint_zookeeper_implementation",
        lambda *_args, **_kwargs: ZkImplementationFingerprint("apache-zookeeper", False, "confirmed"),
    )

    class _ExactCredentialClient:
        selected_transport = "plaintext"

        def __init__(self) -> None:
            self.authenticated = False

        def connect(self) -> None:
            return None

        def auth_digest(self, username: str, password: str):
            observed.append((username, password))
            self.authenticated = True
            return True, None

        def get_children2(self, _path: str):
            return [], _ZK_ERR_OK if self.authenticated else _ZK_ERR_NOAUTH, {}

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        lifecycle_actions,
        "_zookeeper_lifecycle_client",
        lambda *_args, **_kwargs: _ExactCredentialClient(),
    )
    monkeypatch.setattr(
        lifecycle_actions,
        "_infer_auth_required_from_anonymous_probes",
        lambda *_args, **_kwargs: (True, "root_noauth", ["/:noauth"]),
    )
    monkeypatch.setattr(lifecycle_actions, "collect_zookeeper_data", lambda _ctx, record, _options: record.to_dict())

    runner = AuditCommandRunner(
        args=args,
        spec=lifecycle_stage.build_zookeeper_spec(args),
        emit_line=lambda _line: None,
    )
    result = runner.run_plan(lifecycle_stage.build_zookeeper_plan(args))

    assert result.detected_count == 1
    assert observed == [("zk-user", exact_password)]


def test_zookeeper_explicit_default_pair_stays_provided_and_precedes_defaults() -> None:
    args = parse_args(
        [
            "zookeeper",
            "-t",
            "127.0.0.1",
            "--port",
            "2181",
            "-u",
            "zk",
            "-p",
            "zookeeper",
            "--defcreds",
        ]
    )

    plan = lifecycle_stage.build_zookeeper_plan(args)
    pairs = tuple((run.username, run.password) for run in plan.credential_runs)

    assert plan.credential_runs[0].source == "provided"
    assert pairs[0] == ("zk", "zookeeper")
    assert pairs.count(("zk", "zookeeper")) == 1
    assert len(pairs) == len(lifecycle_stage._DEFAULT_CREDENTIALS)


def _run_zookeeper_defcreds_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    *,
    accepted_pair: tuple[str, str] | None,
    explicit_pair: tuple[str, str] | None = None,
    anonymous_open: bool = False,
) -> tuple[list[tuple[str, str]], int, dict[str, object]]:
    auth_attempts: list[tuple[str, str]] = []
    data_calls = 0
    monkeypatch.setattr(
        implementation_engine,
        "fingerprint_zookeeper_implementation",
        lambda *_args, **_kwargs: ZkImplementationFingerprint("apache-zookeeper", False, "confirmed"),
    )

    class FakeClient:
        def __init__(self, credential) -> None:
            self.credential = credential
            self.selected_transport = "plaintext"
            self.digest_pair: tuple[str, str] | None = None

        def connect(self) -> None:
            return

        def auth_digest(self, username: str, password: str):
            pair = (username, password)
            auth_attempts.append(pair)
            self.digest_pair = pair
            # ZooKeeper digest authentication accepts a well-formed identity;
            # the protected znode ACL is what verifies whether it grants access.
            return True, None

        def get_children2(self, _path: str):
            if self.credential.username is None:
                code = _ZK_ERR_OK if anonymous_open else _ZK_ERR_NOAUTH
                return ([] if anonymous_open else None), code, {}
            code = _ZK_ERR_OK if self.digest_pair == accepted_pair else _ZK_ERR_NOAUTH
            return ([] if code == _ZK_ERR_OK else None), code, {}

        def close(self) -> None:
            return

    monkeypatch.setattr(
        lifecycle_actions,
        "_zookeeper_lifecycle_client",
        lambda ctx, *_args, **_kwargs: FakeClient(ctx.credential),
    )
    monkeypatch.setattr(
        lifecycle_actions,
        "_infer_auth_required_from_anonymous_probes",
        lambda *_args, **_kwargs: (
            not anonymous_open,
            "root_ok" if anonymous_open else "root_noauth",
            ["/:ok" if anonymous_open else "/:noauth"],
        ),
    )

    def fake_collect(_ctx, record, _options):
        nonlocal data_calls
        data_calls += 1
        return record.to_dict()

    monkeypatch.setattr(lifecycle_actions, "collect_zookeeper_data", fake_collect)
    argv = [
        "zookeeper",
        "-t",
        "127.0.0.1",
        "--port",
        "2181",
        "--defcreds",
        "--format",
        "json",
    ]
    if explicit_pair is not None:
        argv.extend(("-u", explicit_pair[0], "-p", explicit_pair[1]))
    args = parse_args(argv)
    runner = AuditCommandRunner(
        args=args,
        spec=lifecycle_stage.build_zookeeper_spec(args),
        emit_line=lambda _line: None,
    )

    result = runner.run_plan(lifecycle_stage.build_zookeeper_plan(args))

    assert len(result.records) == 1
    return auth_attempts, data_calls, result.records[0]


def test_zookeeper_defcreds_full_refusal_tries_every_pair_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth_attempts, data_calls, record = _run_zookeeper_defcreds_lifecycle(
        monkeypatch,
        accepted_pair=None,
    )

    assert tuple(auth_attempts) == lifecycle_stage._DEFAULT_CREDENTIALS
    assert data_calls == 0
    assert record["status"] == "auth_required"
    attempted_credentials = record["attempted_credentials"]
    assert isinstance(attempted_credentials, list)
    assert len(attempted_credentials) == 34


def test_zookeeper_defcreds_checks_full_catalog_after_late_digest_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth_attempts, data_calls, record = _run_zookeeper_defcreds_lifecycle(
        monkeypatch,
        accepted_pair=("zk", "zookeeper"),
    )

    assert tuple(auth_attempts) == lifecycle_stage._DEFAULT_CREDENTIALS
    assert data_calls == 1
    assert record["status"] == "weak_default_creds"
    assert record["provided_credentials"] is False
    assert record["defcreds_enabled"] is True
    attempted_credentials = record["attempted_credentials"]
    assert isinstance(attempted_credentials, list)
    assert len(attempted_credentials) == len(lifecycle_stage._DEFAULT_CREDENTIALS)
    assert record["credential_verification_status"] == "available"
    rendered = lifecycle_actions._format_credential_attempts_records(record, "txt")
    assert len(rendered) == len(lifecycle_stage._DEFAULT_CREDENTIALS)
    assert any("[+] zk:zookeeper" in line for line in rendered)
    assert any("[-] root:rootpass" in line for line in rendered)


def test_zookeeper_credential_attempt_renderer_distinguishes_rejected_and_unverified() -> None:
    record = {
        "module": "zookeeper",
        "host": "127.0.0.1",
        "port": 2181,
        "attempted_credentials": [
            {
                "username": "bad",
                "password": "secret",
                "status": "auth_required",
                "provided_credentials_ok": False,
                "credential_verdict": "rejected",
            },
            {
                "username": "sasl",
                "password": "secret",
                "status": "auth_required",
                "provided_credentials_ok": None,
                "credential_verdict": "unsupported_sasl",
            },
            {
                "username": "network",
                "password": "secret",
                "status": "fail",
                "provided_credentials_ok": None,
                "credential_verdict": "unverified",
            },
        ],
    }

    rendered = lifecycle_actions._format_credential_attempts_records(record, "txt")

    assert any("[-] bad:secret" in line for line in rendered)
    assert any("[!] sasl:secret (unsupported:SASL)" in line for line in rendered)
    assert not any("network:secret" in line for line in rendered)


def test_zookeeper_credential_attempt_renderer_attaches_capabilities_only_to_selected_success() -> None:
    record = {
        "module": "zookeeper",
        "host": "127.0.0.1",
        "port": 22185,
        "provided_username": "zk",
        "probe_write_requested": True,
        "znode_capability_scope": "/",
        "znode_capability_identity": "zk",
        "can_create_znode": True,
        "can_delete_znode": True,
        "attempted_credentials": [
            {
                "username": "admin",
                "password": "admin",
                "status": "auth_required",
                "provided_credentials_ok": False,
                "credential_verdict": "rejected",
            },
            {
                "username": "zk",
                "password": "zookeeper",
                "status": "weak_default_creds",
                "provided_credentials_ok": True,
                "credential_verdict": "valid",
            },
        ],
    }

    rendered = lifecycle_actions._format_credential_attempts_records(record, "txt")

    assert rendered[1].endswith("[+] zk:zookeeper (create:True) (delete:True)")
    assert all("scope:" not in line for line in rendered)
    assert lifecycle_actions._format_znode_capability_records(record, "txt") == []


def test_zookeeper_explicit_pair_matching_default_is_not_classified_as_weak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth_attempts, data_calls, record = _run_zookeeper_defcreds_lifecycle(
        monkeypatch,
        accepted_pair=("zk", "zookeeper"),
        explicit_pair=("zk", "zookeeper"),
    )

    expected = [
        ("zk", "zookeeper"),
        *(pair for pair in lifecycle_stage._DEFAULT_CREDENTIALS if pair != ("zk", "zookeeper")),
    ]
    assert auth_attempts == expected
    assert data_calls == 1
    assert record["status"] == "valid_credentials"
    assert record["provided_credentials"] is True
    assert record["defcreds_enabled"] is False


def test_zookeeper_anonymous_access_checks_defcreds_then_uses_anonymous_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth_attempts, data_calls, record = _run_zookeeper_defcreds_lifecycle(
        monkeypatch,
        accepted_pair=None,
        anonymous_open=True,
    )

    assert auth_attempts == []
    assert data_calls == 1
    assert record["status"] == "open_no_auth"
    assert record["attempted_credentials"] == []
    assert record["credential_verification_status"] == "unavailable"
