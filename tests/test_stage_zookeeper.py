from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from redposture_core.stage_zookeeper import (
    _ZK_ERR_NOAUTH,
    _ZK_ERR_NONODE,
    _ZK_ERR_OK,
    _ZK_ERR_RETRYABLE_ROOT_QUERY,
    _audit_zookeeper_host,
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
    audit_zookeeper_targets,
    run_zookeeper_stage,
)


def _zk_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack(">i", len(raw)) + raw


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

    nodes, truncated, error = _enumerate_znodes(_FakeClient(), 2)  # type: ignore[arg-type]
    assert nodes == ["/brokers", "/brokers/ids"]
    assert truncated is True
    assert error is None


def test_audit_zookeeper_suppresses_unexpected_eof_when_suppression_enabled(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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
    total, open_no_auth, valid, auth_required, failed = audit_zookeeper_targets(
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


def test_audit_zookeeper_marks_provided_credentials_invalid_on_anonymous_open_target(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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


def test_audit_zookeeper_dump_uses_access_denied_after_successful_auth(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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
    assert "/clickhouse:<access denied>" in znode_values


def test_audit_zookeeper_valid_credentials_when_auth_was_required(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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


def test_audit_zookeeper_invalid_credentials_on_anonymous_target_are_reported(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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
            _ = path
            return ["clickhouse"], _ZK_ERR_OK, {"data_length": 0, "num_children": 1}

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


def test_audit_zookeeper_retries_retryable_root_query_and_reports_query_auth(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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
        lambda _client, _max_znodes: (["/brokers"], False, None),
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
    )

    assert calls["root"] == 2
    assert record["status"] == "open_no_auth"
    assert record["query_znode_value"] == "/secure:<authentication required>"
    assert record["query_znode_dump_error"] is None


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
        "znode_values": ["/brokers:<empty>"],
        "query_znode_value": "/brokers (children:1,bytes:0)",
        "query_znode_dump": None,
        "query_znode_dump_error": "access denied",
    }

    txt_lines = _format_znodes_detail_records(record, "txt")
    assert any("[*] Show Znodes" in line for line in txt_lines)
    assert any("[*] Znode /brokers" in line for line in txt_lines)
    assert any("[*] Dump Znode /brokers" in line for line in txt_lines)
    assert any("[-] access denied" in line for line in txt_lines)

    json_lines = _format_znodes_detail_records(record, "json")
    assert any('"type": "znodes_list"' in line for line in json_lines)
    assert any('"type": "znode_detail"' in line for line in json_lines)
    assert any('"type": "znode_dump"' in line for line in json_lines)


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
    totals = audit_zookeeper_targets(
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
    monkeypatch.setattr(
        "redposture_core.stage_zookeeper.audit_zookeeper_targets",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("write failed")),
    )

    fake_console.errors.clear()
    assert run_zookeeper_stage(SimpleNamespace(**base_args), logger=SimpleNamespace(log=lambda *_a, **_k: None)) == 2
    assert any("failed to process zookeeper output" in msg for msg in fake_console.errors)
