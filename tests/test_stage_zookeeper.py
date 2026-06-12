from __future__ import annotations

import re
import struct
from collections import Counter
from types import SimpleNamespace

import pytest

import redposture_core.stage_zookeeper as zookeeper_stage
from redposture_core.stage_zookeeper import (
    _ZK_ERR_NOAUTH,
    _ZK_ERR_NONODE,
    _ZK_ERR_OK,
    _ZK_ERR_RETRYABLE_ROOT_QUERY,
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
from tests.stage_runtime_helpers import patch_runner_for_legacy_target_fake, run_module_targets_for_test


def _zk_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack(">i", len(raw)) + raw


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
    assert zookeeper_stage._is_root_query_err_124_error("root query failed: err_-124")
    assert zookeeper_stage._is_remote_closed_connection_error("Remote end closed connection without response")
    assert zookeeper_stage._is_suppressed_fail_record({"status": "fail", "error": "unexpected eof"})
    assert not zookeeper_stage._is_suppressed_fail_record(
        {"status": "fail", "error": "authentication failed: AUTHFAILED", "provided_credentials": True}
    )
    assert zookeeper_stage._zk_error_name(123456) == "ERR_123456"


def test_parse_children_and_stat_invalid_payloads() -> None:
    with pytest.raises(ValueError):
        _parse_children_vector(b"\x00\x00\x00")
    assert _parse_children_vector(struct.pack(">i", -1)) == ([], 4)
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
    ok, err = client.auth_digest("admin", "bad")
    assert ok is False
    assert err == "connection timeout"

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
    assert nodes == ["/brokers", "/brokers/ids"]
    assert total_count == 3
    assert truncated is True
    assert meta["/brokers/ids"]["error"] == "Access Denied"
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
    assert total_count == 3
    assert truncated is False
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


def test_audit_host_uses_count_only_enumeration_when_details_not_requested(monkeypatch: pytest.MonkeyPatch) -> None:
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

    assert collect_flags == [False]
    assert record["status"] == "open_no_auth"
    assert record["znode_count"] == 3210
    assert record["znodes"] == []
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
    assert lines == []


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
    detect_lines = [line for line in lines if "ZooKeeper Service" in line]
    status_lines = [line for line in lines if "anonymous access" in line]
    assert len(detect_lines) == 2
    assert len(status_lines) == 2
    assert "\thost-a\t" in detect_lines[0]
    assert "\thost-b\t" in detect_lines[1]
    assert "\thost-a\t" in status_lines[0]
    assert "\thost-b\t" in status_lines[1]
    assert lines.index(detect_lines[0]) < lines.index(status_lines[0])
    assert lines.index(detect_lines[1]) < lines.index(status_lines[1])


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
    assert any("host-open" in line and "(znodes:123)" in line for line in lines)
    assert any("host-valid" in line and "(znodes:321)" in line for line in lines)
    assert any("host-auth" in line and "(auth required:True)" in line for line in lines)


def test_audit_zookeeper_debug_pass_markers_and_stage2_gate_reasons(monkeypatch: pytest.MonkeyPatch) -> None:
    def _record_for(host: str, *, is_zookeeper: bool, status: str, znode_count: int | None = None) -> dict[str, object]:
        return {
            "timestamp": "2026-03-02T00:00:00Z",
            "host": host,
            "port": 2181,
            "is_zookeeper": is_zookeeper,
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


def test_audit_zookeeper_live_debug_streaming_avoids_duplicates(monkeypatch: pytest.MonkeyPatch) -> None:
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
    assert len(progress_matches) == 1
    assert len(done_matches) == 1


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
    assert any("znode count unknown (partial)" in line for line in detail_lines)
    assert any("timeouts=3s,3s,3s" in line for line in detail_lines)


def test_audit_host_runs_capability_probe_before_enumeration(monkeypatch: pytest.MonkeyPatch) -> None:
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

    def _probe(*_args, **_kwargs):
        call_order.append("probe")
        return True, True, None

    def _enumerate(*_args, **_kwargs):
        call_order.append("enumerate")
        return [], 0, False, {}, None

    monkeypatch.setattr("redposture_core.stage_zookeeper._ZkClient", _Client)
    monkeypatch.setattr("redposture_core.stage_zookeeper._probe_znode_create_delete", _probe)
    monkeypatch.setattr("redposture_core.stage_zookeeper._enumerate_znodes", _enumerate)

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
    )
    assert rec["status"] == "open_no_auth"
    assert call_order[:2] == ["probe", "enumerate"]


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


def test_stage4_timeout_retries_with_shared_policy_and_keeps_status(monkeypatch: pytest.MonkeyPatch) -> None:
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
            return [], 0, False, {}, "connection timeout"
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
        show_znodes=False,
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


def test_audit_zookeeper_marks_provided_credentials_invalid_on_anonymous_open_target(monkeypatch) -> None:
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
            _ = path
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
        show_znodes=False,
        dump=False,
        query_znode=None,
        max_znodes=100,
    )

    assert calls["auth"] == 1
    assert record["status"] == "invalid_credentials_anonymous"
    assert record["provided_credentials_ok"] is False
    assert record["auth_required"] is False
    assert "authentication failed" in str(record["error"]).lower()
    line = _format_record(record, "txt")
    assert "[-] admin:admin" in line


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


def test_audit_zookeeper_valid_credentials_after_retryable_root_query(monkeypatch) -> None:
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
            if not self._authed:
                return None, _ZK_ERR_RETRYABLE_ROOT_QUERY, None
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
    assert record["status"] == "valid_credentials"
    assert record["provided_credentials_ok"] is True
    assert record["auth_required"] is True
    assert record["auth_inference_source"] == "probe_retryable_124"


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


def test_audit_zookeeper_inference_maps_consistent_err_124_to_auth_required(
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
            return None, _ZK_ERR_RETRYABLE_ROOT_QUERY, None

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
    assert record["auth_inference_source"] == "probe_retryable_124"
    assert record["auth_probe_trace"] == ["/:err_-124", "/zookeeper:err_-124", "/zookeeper/config:err_-124"]


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


def test_audit_zookeeper_retries_retryable_root_query_and_reports_query_auth(monkeypatch) -> None:
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
                    return None, _ZK_ERR_RETRYABLE_ROOT_QUERY, None
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

    assert calls["root"] == 2
    assert record["status"] == "open_no_auth"
    assert record["query_znode_value"] == "/secure:<Access Denied>"
    assert record["query_znode_dump_error"] is None
    assert any("retry_decision stage=detect_protocol" in line for line in record.get("debug_events") or [])


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


def test_format_record_shows_exact_znode_count_without_plus_and_capabilities() -> None:
    line = _format_record(
        {
            "status": "open_no_auth",
            "host": "127.0.0.1",
            "port": 2181,
            "znode_count": 2050,
            "znodes_truncated": True,
            "can_create_znode": True,
            "can_delete_znode": False,
        },
        "txt",
    )
    assert "(znodes:2050)" in line
    assert "(znodes:2050+)" not in line
    assert "(create:True)" in line
    assert "(delete:False)" in line


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
    assert any("showing first 2 of 3000 znodes (max_znodes=2000)" in line for line in txt_lines)
    assert any("/a:<empty>" in line for line in txt_lines)
    assert any("/b:<Access Denied>" in line for line in txt_lines)


def test_audit_zookeeper_sets_create_delete_capabilities_success(monkeypatch: pytest.MonkeyPatch) -> None:
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
            return _ZK_ERR_OK

        def delete(self, path: str, version: int = -1) -> int:
            _ = (path, version)
            return _ZK_ERR_OK

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
    assert record["status"] == "open_no_auth"
    assert record["can_create_znode"] is True
    assert record["can_delete_znode"] is True
    assert record["znode_capability_error"] is None


def test_audit_zookeeper_sets_create_delete_capabilities_denied(monkeypatch: pytest.MonkeyPatch) -> None:
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
            return _ZK_ERR_NOAUTH

        def delete(self, path: str, version: int = -1) -> int:
            _ = (path, version)
            return _ZK_ERR_OK

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
    assert record["status"] == "open_no_auth"
    assert record["can_create_znode"] is False
    assert record["can_delete_znode"] is False
    assert record["znode_capability_error"] == "NOAUTH"


def test_audit_zookeeper_sets_create_true_delete_false(monkeypatch: pytest.MonkeyPatch) -> None:
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
            return _ZK_ERR_OK

        def delete(self, path: str, version: int = -1) -> int:
            _ = (path, version)
            return _ZK_ERR_NOAUTH

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
    assert record["status"] == "open_no_auth"
    assert record["can_create_znode"] is True
    assert record["can_delete_znode"] is False
    assert record["znode_capability_error"] == "NOAUTH"


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
    assert any("ZooKeeper Service" in line for line in emitted)
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
    patch_runner_for_legacy_target_fake(
        monkeypatch,
        "zookeeper",
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

        def render_tagged_payload_line(self, *_args: object, **_kwargs: object) -> bool:
            return False

    captured: dict[str, str | None] = {}
    fake_console = _FakeConsole()
    monkeypatch.setattr("redposture_core.stage_zookeeper.Console", lambda debug=False: fake_console)
    monkeypatch.setattr("redposture_core.stage_zookeeper.collect_scan_ports", lambda *_args, **_kwargs: [2181])
    monkeypatch.setattr("redposture_core.stage_zookeeper.collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    def _fake_audit(*_args, **kwargs):
        captured["username"] = kwargs.get("username")
        captured["password"] = kwargs.get("password")
        return (1, 0, 0, 1, 0)

    patch_runner_for_legacy_target_fake(monkeypatch, "zookeeper", _fake_audit)

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
    assert captured == {"username": "admin", "password": "secret"}
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
        "redposture_core.stage_zookeeper.start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgress(label, total, **kwargs),
    )
    monkeypatch.setattr("redposture_core.stage_zookeeper.collect_scan_ports", lambda *_args, **_kwargs: [2181, 2182])
    monkeypatch.setattr("redposture_core.stage_zookeeper.collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

    captured: list[dict[str, object]] = []

    def _fake_audit(*_args, **kwargs):
        captured.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return (len(kwargs["hosts"]), 1, 0, 0, 0)

    patch_runner_for_legacy_target_fake(monkeypatch, "zookeeper", _fake_audit)

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
    assert rc == 0
    assert len(captured) == 2
    assert all(call["show_progress"] is False for call in captured)
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
    assert (create_ok, delete_ok, err) == (False, False, "NODEEXISTS")
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


def test_detail_entry_and_auth_probe_helpers() -> None:
    assert zookeeper_stage._znode_detail_entry("/x", {"error": "Access Denied"})["state"] == "denied"
    assert zookeeper_stage._znode_detail_entry("/x", {"error": "BROKEN"})["state"] == "error"
    assert zookeeper_stage._znode_detail_entry("/x", {"children": 0, "bytes": 0})["state"] == "empty"
    assert zookeeper_stage._znode_detail_entry("/x", {"children": 1, "bytes": 1})["state"] == "readable"
    assert zookeeper_stage._znode_detail_entry("/x", None)["state"] == "unknown"

    assert zookeeper_stage._normalize_auth_probe_result(_ZK_ERR_RETRYABLE_ROOT_QUERY) == (
        "retryable_auth_hint",
        "err_-124",
    )
    assert zookeeper_stage._normalize_auth_probe_result(_ZK_ERR_NONODE) == ("neutral", "nonode")
    assert zookeeper_stage._normalize_auth_probe_result(-115) == ("error", "authfailed")


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
    assert "authentication required" in line
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

        def _paint(self, text: str, color: str, _stream) -> str:
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
        "ZOOKEEPER   127.0.0.1 2181 [+] anonymous access (create:True) (delete:False) (znodes:12)",
    )
    assert len(console.lines) >= 2

    output_path = tmp_path / "out.txt"
    emitted: list[str] = []
    with output_path.open("w", encoding="utf-8") as out_fh:
        zookeeper_stage._emit_line(out_fh, emitted.append, "line-a")
    assert output_path.read_text(encoding="utf-8").strip() == "line-a"
    assert emitted == ["line-a"]


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

    patch_runner_for_legacy_target_fake(monkeypatch, "zookeeper", lambda *_args, **_kwargs: (1, 0, 0, 0, 1))
    fake_console.warns.clear()
    fake_console.infos.clear()
    rc = run_zookeeper_stage(SimpleNamespace(**base_args), logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 0
    assert any("all zookeeper targets are unreachable" in msg for msg in fake_console.warns)
    assert any("zookeeper audit started" in msg for msg in fake_console.infos)

    args_json = {**base_args, "output_format": "json", "debug": False}
    printed: list[str] = []
    monkeypatch.setattr("builtins.print", lambda *a, **_k: printed.append(" ".join(str(x) for x in a)))

    def fake_audit_json(*_args, **kwargs):
        emit = kwargs.get("emit_line")
        if emit:
            emit('{"k":"v"}')
        return (1, 1, 0, 0, 0)

    patch_runner_for_legacy_target_fake(monkeypatch, "zookeeper", fake_audit_json)
    rc = run_zookeeper_stage(SimpleNamespace(**args_json), logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 0
    assert '{"k":"v"}' in fake_console.plain_lines or '{"k":"v"}' in printed


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
        lambda *_a, **_k: (
            ["/q"],
            0,
            False,
            {"/q": {"path": "/q", "children": 0, "bytes": 0, "error": None}},
            "enum warn",
        ),
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
    assert rec["error"] == "enum warn"
    assert rec["znode_count"] == 1

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

    def fake_audit(*_args, **kwargs):
        emit = kwargs.get("emit_line")
        if emit:
            emit("ZOOKEEPER\t127.0.0.1\t2181\t payload-only-line")
            emit("ZOOKEEPER\t127.0.0.1\t2181\t [*] marker-line")
        return (1, 1, 0, 0, 0)

    patch_runner_for_legacy_target_fake(monkeypatch, "zookeeper", fake_audit)
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
    assert rec["status"] == "auth_required"
    assert rec["provided_credentials_ok"] is True

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


def test_audit_host_retryable_root_query_after_auth(monkeypatch: pytest.MonkeyPatch) -> None:
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
                    return None, _ZK_ERR_RETRYABLE_ROOT_QUERY, None
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
    assert rec["status"] == "valid_credentials"
    assert rec["provided_credentials_ok"] is True


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
    assert zookeeper_stage._with_optional_znodes({"znode_count": None}, "line") == "line (znodes:-)"

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

    assert (
        zookeeper_stage._render_colored_zookeeper_line(_RenderConsole(), "ZOOKEEPER\t127.0.0.1\t2181\t plain line")
        is False
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

    def _fake_stage_audit(*_args, **kwargs):
        emit = kwargs.get("emit_line")
        if emit:
            emit("ZOOKEEPER\t127.0.0.1\t2181\t payload-tagged-line")
            emit("ZOOKEEPER\t127.0.0.1\t2181\t payload-plain-line")
            emit("ZOOKEEPER\t127.0.0.1\t2181\t [*] marker-line")
            emit("raw debug payload")
        return (1, 1, 0, 0, 0)

    patch_runner_for_legacy_target_fake(monkeypatch, "zookeeper", _fake_stage_audit)
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
            "hosts_file": "hosts.txt",
            "output": None,
            "output_format": "txt",
        }
    )
    rc_debug_stdout = run_zookeeper_stage(args_debug_stdout, logger=SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc_debug_stdout == 0
    assert any("zookeeper audit started: format=txt" in msg for msg in fake_console.infos)
    assert any("payload-plain-line" in line for line in fake_console.plain_lines)
    assert "raw debug payload" in fake_console.plain_lines

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
        show_znodes=False,
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

    def _fake_audit(*_args, **kwargs):
        debug_emit = kwargs.get("debug_emit")
        debug_stats = kwargs.get("debug_stats")
        if callable(debug_emit):
            debug_emit("127.0.0.1:2181 attempt=1/1 start timeout=1.0s")
        if isinstance(debug_stats, dict):
            debug_stats["timing_sums"] = Counter(
                {"connect_ms": 10, "auth_ms": 5, "enumerate_ms": 30, "dump_ms": 0, "elapsed_ms": 55}
            )
            debug_stats["timing_counts"] = Counter({"connect_ms": 1, "auth_ms": 1, "enumerate_ms": 1, "elapsed_ms": 1})
            debug_stats["timing_max"] = Counter(
                {"connect_ms": 10, "auth_ms": 5, "enumerate_ms": 30, "dump_ms": 0, "elapsed_ms": 55}
            )
            debug_stats["auth_sources"] = Counter({"root_ok": 1})
            debug_stats["error_counts"] = Counter({"connect:connection timeout": 2, "query:NOAUTH": 1})
        emit = kwargs.get("emit_line")
        if callable(emit):
            emit("ZOOKEEPER\t127.0.0.1\t2181\t [*] marker-line")
        return (1, 1, 0, 0, 0)

    patch_runner_for_legacy_target_fake(monkeypatch, "zookeeper", _fake_audit)
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
