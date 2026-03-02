from __future__ import annotations

import struct

from redposture_core.stage_zookeeper import (
    _ZK_ERR_NOAUTH,
    _ZK_ERR_OK,
    _audit_zookeeper_host,
    _decode_zk_string,
    _format_record,
    _format_znode_data,
    _normalize_znode_path,
    _parse_children_vector,
    _parse_stat,
    audit_zookeeper_targets,
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


def test_audit_zookeeper_uses_provided_credentials_on_anonymous_open_target(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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
    assert record["status"] == "valid_credentials"
    assert record["provided_credentials_ok"] is True
    assert record["auth_required"] is False


def test_audit_zookeeper_dump_uses_access_denied_after_successful_auth(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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
    assert record["status"] == "auth_required"
    assert record["auth_required"] is False
    assert record["provided_credentials_ok"] is False
    assert "authentication failed" in str(record["error"]).lower()
    line = _format_record(record, "txt")
    assert "[-] admin:wrong invalid" in line


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
