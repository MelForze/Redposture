from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core import stage_redis as redis_stage
from redposture_core.audit_models import AuditRecord
from redposture_core.cli_args import parse_args
from redposture_core.modules.redis import actions as redis_actions
from redposture_core.modules.redis import stage as redis_module_stage
from redposture_core.stage_runtime import AuditCommandRunner
from tests.stage_runtime_helpers import patch_module_host_stage_for_test, run_module_targets_for_test


class _DummySocket:
    def __enter__(self) -> _DummySocket:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        _ = timeout


class _ReadSocket(_DummySocket):
    def __init__(self, payload: bytes = b"") -> None:
        self.payload = payload
        self.sent: list[bytes] = []

    def recv(self, size: int) -> bytes:
        if not self.payload:
            return b""
        chunk = self.payload[:size]
        self.payload = self.payload[size:]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)


def _redis_host_record(
    kwargs: dict[str, object],
    *,
    status: str,
    detected: bool,
    error: str | None = None,
) -> AuditRecord:
    return AuditRecord(
        host=str(kwargs["host"]),
        port=int(kwargs["port"]),
        service="redis",
        module="redis",
        status=status,
        auth_required=status == "auth_required",
        extra={
            "is_redis": detected,
            "error": error,
            "provided_username": kwargs.get("username"),
            "provided_password": kwargs.get("password"),
            "show_keys": bool(kwargs.get("show_keys")),
            "dump_keys": bool(kwargs.get("dump_keys")),
            "query_key": kwargs.get("query_key"),
        },
    )


def test_encode_resp_array_builds_valid_payload() -> None:
    payload = redis_stage._encode_resp_array(["PING", "hello"])
    assert payload == b"*2\r\n$4\r\nPING\r\n$5\r\nhello\r\n"


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("NOAUTH Authentication required.", True),
        ("authentication required", True),
        ("ERR wrongpass", False),
    ],
)
def test_is_noauth_error(message: str, expected: bool) -> None:
    assert redis_stage._is_noauth_error(message) is expected


def test_check_default_credentials_falls_back_to_password_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_user_auth(*_args: object, **_kwargs: object) -> tuple[bool, str | None]:
        calls.append("userpass")
        return False, "wrong number of arguments"

    def fake_password_auth(*_args: object, **_kwargs: object) -> tuple[bool, str | None]:
        calls.append("password")
        return True, None

    monkeypatch.setattr(redis_stage, "_auth_with_user_password", fake_user_auth)
    monkeypatch.setattr(redis_stage, "_auth_with_password", fake_password_auth)

    ok, err = redis_stage._check_default_credentials(sock=object())
    assert ok is True
    assert err is None
    assert calls == ["userpass", "password"]


def test_check_default_credentials_uses_actual_candidate_for_acl_and_legacy_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_user_auth(_sock: object, username: str, password: str) -> tuple[bool, str | None]:
        calls.append(("acl", username, password))
        return False, "ERR wrong number of arguments for 'auth' command"

    def fake_password_auth(_sock: object, password: str) -> tuple[bool, str | None]:
        calls.append(("legacy", password))
        return True, None

    monkeypatch.setattr(redis_stage, "_auth_with_user_password", fake_user_auth)
    monkeypatch.setattr(redis_stage, "_auth_with_password", fake_password_auth)

    assert redis_stage._check_default_credentials(object(), "default", "password") == (True, None)
    assert calls == [
        ("acl", "default", "password"),
        ("legacy", "password"),
    ]


def test_check_provided_credentials_without_password_returns_none() -> None:
    ok, err = redis_stage._check_provided_credentials(sock=object(), username="redis", password=None)
    assert ok is None
    assert err is None


def test_check_provided_credentials_with_username_falls_back_to_password_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_user_auth(*_args: object, **_kwargs: object) -> tuple[bool, str | None]:
        calls.append("userpass")
        return False, "ERR wrong number of arguments for 'auth' command"

    def fake_password_auth(*_args: object, **_kwargs: object) -> tuple[bool, str | None]:
        calls.append("password")
        return True, None

    monkeypatch.setattr(redis_stage, "_auth_with_user_password", fake_user_auth)
    monkeypatch.setattr(redis_stage, "_auth_with_password", fake_password_auth)

    ok, err = redis_stage._check_provided_credentials(sock=object(), username="default", password="redis")
    assert ok is True
    assert err is None
    assert calls == ["userpass", "password"]


def test_pairwise_ignores_last_odd_item() -> None:
    assert redis_stage._pairwise(["a", "1", "b"]) == [("a", "1")]


def test_format_record_for_credential_states() -> None:
    base = {"host": "127.0.0.1", "port": 6379, "key_count": 2}

    anonymous_record = {**base, "status": "open_no_auth"}
    assert redis_stage._format_record(anonymous_record, "txt") == ""
    assert json.loads(redis_stage._format_record(anonymous_record, "json"))["status"] == "open_no_auth"

    line_default = redis_stage._format_record({**base, "status": "weak_default_creds"}, "txt")
    assert "[+] redis:redis" in line_default

    line_valid = redis_stage._format_record(
        {
            **base,
            "status": "valid_credentials",
            "provided_username": "admin",
            "provided_password": "secret",
        },
        "txt",
    )
    assert "[+] admin:secret" in line_valid


def test_format_record_auth_required_variants() -> None:
    base = {"host": "127.0.0.1", "port": 6379}

    line_provided = redis_stage._format_record(
        {
            **base,
            "status": "auth_required",
            "provided_credentials": True,
            "provided_username": "admin",
            "provided_password": "bad",
        },
        "txt",
    )
    assert "[-] admin:bad" in line_provided

    line_default = redis_stage._format_record(
        {
            **base,
            "status": "auth_required",
            "provided_credentials": False,
            "default_credentials_attempted": True,
        },
        "txt",
    )
    assert "[-] redis:redis" in line_default

    line_plain = redis_stage._format_record(
        {
            **base,
            "status": "auth_required",
            "provided_credentials": False,
            "default_credentials_attempted": False,
        },
        "txt",
    )
    assert "[-] authentication required" in line_plain


def test_format_detect_record_txt() -> None:
    line = redis_stage._format_detect_record(
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 6379,
            "is_redis": True,
            "auth_required": True,
        },
        "txt",
    )
    assert "[*] Redis Database" in line
    assert "(auth required:True)" in line


def test_format_keys_detail_records_contains_sections() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 6379,
        "show_keys": True,
        "dump_keys": True,
        "query_key": "k1",
        "query_key_value": "k1:v1",
        "keys": ["k2", "k1"],
        "key_values": ["k1:v1", "k2:v2"],
        "key_count": 2,
    }
    lines = redis_stage._format_keys_detail_records(record, "txt")
    assert any("[*] Show Keys" in line for line in lines)
    assert any("[*] Dump Key k1" in line for line in lines)
    assert any("[*] Dump Keys" in line for line in lines)


def test_format_keys_detail_records_honors_show_limit() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 6379,
        "show_keys": True,
        "show_keys_limit": 1,
        "dump_keys": False,
        "query_key": None,
        "keys": ["k2", "k1"],
        "key_count": 2,
    }
    lines = redis_stage._format_keys_detail_records(record, "txt")
    assert any("Show Keys (showing:1 of 2)" in line for line in lines)
    assert any(line.strip().endswith("k1") for line in lines)
    assert not any(line.strip().endswith("k2") for line in lines)


def test_scan_redis_keys_stops_at_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def fake_send_cmd(_sock: object, *_parts: str) -> tuple[str, list[object]]:
        nonlocal calls
        calls += 1
        return "array", ["1", ["a", "b", "c"]]

    monkeypatch.setattr(redis_stage, "_send_cmd", fake_send_cmd)
    keys, err = redis_stage._scan_redis_keys(object(), limit=2)
    assert err is None
    assert keys == ["a", "b"]
    assert calls == 1


def test_is_connection_timeout_fail_record_detection() -> None:
    assert redis_stage._is_connection_timeout_fail_record({"status": "fail", "error": "connection timeout"})
    assert redis_stage._is_connection_timeout_fail_record({"status": "fail", "error": "socket timed out"})
    assert not redis_stage._is_connection_timeout_fail_record({"status": "open_no_auth", "error": "connection timeout"})


def test_is_connection_refused_fail_record_detection() -> None:
    assert redis_stage._is_connection_refused_error("[Errno 111] Connection refused")
    assert redis_stage._is_connection_refused_error("[Errno 61] Connection refused")
    assert redis_stage._is_connection_refused_error("winsock error 10061")
    assert redis_stage._is_connection_refused_fail_record({"status": "fail", "error": "connection refused"})
    assert not redis_stage._is_connection_refused_fail_record({"status": "fail", "error": "connection timeout"})
    assert not redis_stage._is_connection_refused_fail_record({"status": "open_no_auth", "error": "connection refused"})


def test_audit_redis_host_open_access_reads_keys_and_query(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_redis.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(redis_stage, "_send_cmd", lambda *_args, **_kwargs: ("simple", "PONG"))
    monkeypatch.setattr(redis_stage, "_count_redis_keys", lambda *_args, **_kwargs: (2, None))
    # Dumping now streams pages through _stream_dump_redis_keys (SCAN page -> dump -> delay)
    # instead of scanning the whole keyspace up front; record["keys"] reflects the dumped
    # (per-page sorted) entries rather than raw SCAN order.
    monkeypatch.setattr(
        redis_stage,
        "_stream_dump_redis_keys",
        lambda *_args, **_kwargs: (
            [redis_stage._redis_kv_entry("a", "1"), redis_stage._redis_kv_entry("b", "2")],
            None,
        ),
    )
    monkeypatch.setattr(
        redis_stage,
        "_dump_redis_key_value",
        lambda _sock, key_name: ({"a": "1", "b": "2"}[key_name], None),
    )

    record = redis_stage._audit_redis_host(
        "127.0.0.1",
        6379,
        1.0,
        0,
        username=None,
        password=None,
        defcreds=False,
        show_keys=True,
        dump_keys=True,
        query_key="a",
    )

    assert record["status"] == "open_no_auth"
    assert record["key_count"] == 2
    assert record["keys"] == ["a", "b"]
    assert record["key_values"] == ["a:1", "b:2"]
    assert record["query_key_value"] == "a:1"


def test_audit_redis_host_handles_default_and_provided_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_redis.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(
        redis_stage, "_send_cmd", lambda *_args, **_kwargs: ("error", "NOAUTH Authentication required.")
    )
    monkeypatch.setattr(redis_stage, "_count_redis_keys", lambda *_args, **_kwargs: (1, None))
    monkeypatch.setattr(redis_stage, "_scan_redis_keys", lambda *_args, **_kwargs: (["session"], None))

    monkeypatch.setattr(redis_stage, "_check_default_credentials", lambda *_args, **_kwargs: (True, None))
    weak = redis_stage._audit_redis_host(
        "127.0.0.1",
        6379,
        1.0,
        0,
        username=None,
        password=None,
        defcreds=True,
        show_keys=True,
        dump_keys=False,
        query_key=None,
    )
    assert weak["status"] == "weak_default_creds"
    assert weak["default_credentials_attempted"] is True

    monkeypatch.setattr(redis_stage, "_check_default_credentials", lambda *_args, **_kwargs: (False, "denied"))
    monkeypatch.setattr(redis_stage, "_check_provided_credentials", lambda *_args, **_kwargs: (True, None))
    valid = redis_stage._audit_redis_host(
        "127.0.0.1",
        6379,
        1.0,
        0,
        username="admin",
        password="secret",
        defcreds=True,
        show_keys=False,
        dump_keys=False,
        query_key=None,
    )
    assert valid["status"] == "valid_credentials"
    assert valid["provided_credentials_ok"] is True


def test_audit_redis_host_handles_unexpected_ping_and_retries_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "redposture_core.stage_redis.socket.create_connection", lambda *_args, **_kwargs: _DummySocket()
    )
    monkeypatch.setattr(redis_stage, "_send_cmd", lambda *_args, **_kwargs: ("bulk", "??"))
    record = redis_stage._audit_redis_host(
        "127.0.0.1",
        6379,
        1.0,
        0,
        username=None,
        password=None,
        defcreds=False,
        show_keys=False,
        dump_keys=False,
        query_key=None,
    )
    assert record["status"] == "fail"
    assert "unexpected PING response" in str(record["error"])

    monkeypatch.setattr(
        "redposture_core.stage_redis.socket.create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("connection refused")),
    )
    monkeypatch.setattr(redis_stage, "_retry_delay", lambda _attempt: 0.0)
    failed = redis_stage._audit_redis_host(
        "127.0.0.1",
        6379,
        1.0,
        1,
        username=None,
        password=None,
        defcreds=False,
        show_keys=False,
        dump_keys=False,
        query_key=None,
    )
    assert failed["status"] == "fail"
    assert "connection refused" in str(failed["error"])


def test_resp_readers_and_send_cmd_cover_types() -> None:
    simple = redis_stage._read_resp(_ReadSocket(b"+PONG\r\n"))
    error = redis_stage._read_resp(_ReadSocket(b"-NOAUTH Authentication required.\r\n"))
    integer = redis_stage._read_resp(_ReadSocket(b":2\r\n"))
    bulk = redis_stage._read_resp(_ReadSocket(b"$5\r\nhello\r\n"))
    null_bulk = redis_stage._read_resp(_ReadSocket(b"$-1\r\n"))
    array = redis_stage._read_resp(_ReadSocket(b"*2\r\n$3\r\none\r\n$3\r\ntwo\r\n"))

    assert simple == ("simple", "PONG")
    assert error == ("error", "NOAUTH Authentication required.")
    assert integer == ("integer", 2)
    assert bulk == ("bulk", b"hello")
    assert null_bulk == ("null", None)
    assert array == ("array", [b"one", b"two"])

    sock = _ReadSocket(b"+OK\r\n")
    resp_type, resp_value = redis_stage._send_cmd(sock, "PING")
    assert resp_type == "simple"
    assert resp_value == "OK"
    assert sock.sent == [b"*1\r\n$4\r\nPING\r\n"]


def test_count_scan_and_dump_key_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_send_cmd(_sock: object, *parts: str):
        if parts == ("DBSIZE",):
            return "integer", 3
        if parts == ("SCAN", "0", "COUNT", "500"):
            return "array", ["1", ["b", "a"]]
        if parts == ("SCAN", "1", "COUNT", "500"):
            return "array", ["0", ["a", "c"]]
        if parts == ("TYPE", "string-key"):
            return "bulk", "string"
        if parts == ("GET", "string-key"):
            return "bulk", "value"
        if parts == ("TYPE", "hash-key"):
            return "bulk", "hash"
        if parts == ("HGETALL", "hash-key"):
            return "array", ["field", "v1"]
        if parts == ("TYPE", "list-key"):
            return "bulk", "list"
        if parts == ("LRANGE", "list-key", "0", "-1"):
            return "array", ["a", "b"]
        if parts == ("TYPE", "set-key"):
            return "bulk", "set"
        if parts == ("SMEMBERS", "set-key"):
            return "array", ["b", "a"]
        if parts == ("TYPE", "zset-key"):
            return "bulk", "zset"
        if parts == ("ZRANGE", "zset-key", "0", "-1", "WITHSCORES"):
            return "array", ["m1", "1.0"]
        if parts == ("TYPE", "stream-key"):
            return "bulk", "stream"
        if parts == ("XLEN", "stream-key"):
            return "integer", 7
        pytest.fail(f"unexpected command: {parts}")

    monkeypatch.setattr(redis_stage, "_send_cmd", fake_send_cmd)

    key_count, count_error = redis_stage._count_redis_keys(object())
    assert (key_count, count_error) == (3, None)

    keys, scan_error = redis_stage._scan_redis_keys(object())
    assert scan_error is None
    assert keys == ["b", "a", "c"]

    assert redis_stage._dump_redis_key_value(object(), "string-key") == ("value", None)
    assert redis_stage._dump_redis_key_value(object(), "hash-key") == ("field=v1", None)
    assert redis_stage._dump_redis_key_value(object(), "list-key") == ("a,b", None)
    assert redis_stage._dump_redis_key_value(object(), "set-key") == ("a,b", None)
    assert redis_stage._dump_redis_key_value(object(), "zset-key") == ("m1=1.0", None)
    assert redis_stage._dump_redis_key_value(object(), "stream-key") == ("stream_len=7", None)


def test_redis_helper_error_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redis_stage, "_send_cmd", lambda *_args: ("integer", 1))
    ok, err = redis_stage._auth_with_password(object(), "pw")
    assert ok is False
    assert "unexpected AUTH response" in str(err)
    ok, err = redis_stage._auth_with_user_password(object(), "u", "pw")
    assert ok is False
    assert "unexpected AUTH response" in str(err)

    monkeypatch.setattr(redis_stage, "_send_cmd", lambda *_args: ("bulk", "bad"))
    assert redis_stage._count_redis_keys(object()) == (None, "unexpected DBSIZE response: bulk bad")

    monkeypatch.setattr(redis_stage, "_send_cmd", lambda *_args: ("array", ["1", []]))
    keys, err = redis_stage._scan_redis_keys(object(), max_rounds=1)
    assert keys == []
    assert "too many iterations" in str(err)

    monkeypatch.setattr(redis_stage, "_send_cmd", lambda *_args: ("bulk", "bad"))
    keys, err = redis_stage._scan_redis_keys(object())
    assert keys is None
    assert "unexpected SCAN response" in str(err)

    monkeypatch.setattr(redis_stage, "_send_cmd", lambda *_args: ("array", ["0", "not-list"]))
    keys, err = redis_stage._scan_redis_keys(object())
    assert keys is None
    assert "unexpected SCAN keys payload" in str(err)


def test_dump_redis_key_value_error_and_unknown_type_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = {
        ("TYPE", "type-error"): ("error", "denied"),
        ("TYPE", "unknown-key"): ("bulk", ""),
        ("TYPE", "none-key"): ("bulk", "none"),
        ("TYPE", "string-error"): ("bulk", "string"),
        ("GET", "string-error"): ("error", "denied"),
        ("TYPE", "string-null"): ("bulk", "string"),
        ("GET", "string-null"): ("null", None),
        ("TYPE", "hash-empty"): ("bulk", "hash"),
        ("HGETALL", "hash-empty"): ("array", []),
        ("TYPE", "hash-bad"): ("bulk", "hash"),
        ("HGETALL", "hash-bad"): ("bulk", "bad"),
        ("TYPE", "list-error"): ("bulk", "list"),
        ("LRANGE", "list-error", "0", "-1"): ("error", "denied"),
        ("TYPE", "list-bad"): ("bulk", "list"),
        ("LRANGE", "list-bad", "0", "-1"): ("bulk", "bad"),
        ("TYPE", "set-error"): ("bulk", "set"),
        ("SMEMBERS", "set-error"): ("error", "denied"),
        ("TYPE", "set-bad"): ("bulk", "set"),
        ("SMEMBERS", "set-bad"): ("bulk", "bad"),
        ("TYPE", "zset-error"): ("bulk", "zset"),
        ("ZRANGE", "zset-error", "0", "-1", "WITHSCORES"): ("error", "denied"),
        ("TYPE", "zset-empty"): ("bulk", "zset"),
        ("ZRANGE", "zset-empty", "0", "-1", "WITHSCORES"): ("array", []),
        ("TYPE", "zset-bad"): ("bulk", "zset"),
        ("ZRANGE", "zset-bad", "0", "-1", "WITHSCORES"): ("bulk", "bad"),
        ("TYPE", "stream-error"): ("bulk", "stream"),
        ("XLEN", "stream-error"): ("error", "denied"),
        ("TYPE", "stream-bad"): ("bulk", "stream"),
        ("XLEN", "stream-bad"): ("bulk", "bad"),
        ("TYPE", "geo-key"): ("bulk", "geo"),
    }

    def fake_send_cmd(_sock: object, *parts: str):
        return responses[parts]

    monkeypatch.setattr(redis_stage, "_send_cmd", fake_send_cmd)
    assert redis_stage._dump_redis_key_value(object(), "type-error") == ("<error>", "denied")
    assert redis_stage._dump_redis_key_value(object(), "unknown-key") == ("<unknown>", None)
    assert redis_stage._dump_redis_key_value(object(), "none-key") == ("<not found>", None)
    assert redis_stage._dump_redis_key_value(object(), "string-error") == ("<error>", "denied")
    assert redis_stage._dump_redis_key_value(object(), "string-null") == ("<nil>", None)
    assert redis_stage._dump_redis_key_value(object(), "hash-empty") == ("<empty-hash>", None)
    assert redis_stage._dump_redis_key_value(object(), "hash-bad") == ("<hash>", None)
    assert redis_stage._dump_redis_key_value(object(), "list-error") == ("<error>", "denied")
    assert redis_stage._dump_redis_key_value(object(), "list-bad") == ("<list>", None)
    assert redis_stage._dump_redis_key_value(object(), "set-error") == ("<error>", "denied")
    assert redis_stage._dump_redis_key_value(object(), "set-bad") == ("<set>", None)
    assert redis_stage._dump_redis_key_value(object(), "zset-error") == ("<error>", "denied")
    assert redis_stage._dump_redis_key_value(object(), "zset-empty") == ("<empty-zset>", None)
    assert redis_stage._dump_redis_key_value(object(), "zset-bad") == ("<zset>", None)
    assert redis_stage._dump_redis_key_value(object(), "stream-error") == ("<error>", "denied")
    assert redis_stage._dump_redis_key_value(object(), "stream-bad") == ("<stream>", None)
    assert redis_stage._dump_redis_key_value(object(), "geo-key") == ("<type:geo>", None)


def test_format_keys_detail_records_json_and_entry_text_branches() -> None:
    record = {
        "timestamp": "2026-03-27T00:00:00Z",
        "host": "127.0.0.1",
        "port": 6379,
        "show_keys": True,
        "show_keys_limit": 1,
        "dump_keys": True,
        "query_key": "offlineStocks:city_4949:552400",
        "query_key_value": "offlineStocks:city_4949:552400:v",
        "query_key_entry": {"key": "offlineStocks:city_4949:552400", "value": "v"},
        "keys": ["z", "a"],
        "key_count": 2,
        "key_value_entries": [
            {"key": "a", "value": "1"},
            {"key": "z", "value": None, "error": "denied\nnoacl"},
            "ignored",
        ],
    }

    assert redis_stage._redis_kv_entry_text({"key": "z", "error": "denied\nnoacl"}) == "z:<error:denied\\nnoacl>"
    assert redis_stage._redis_kv_entry_text("legacy") == "legacy"

    payloads = [json.loads(line) for line in redis_stage._format_keys_detail_records(record, "json")]
    assert [item["type"] for item in payloads] == ["keys_list", "key_dump", "keys_dump"]
    assert payloads[0]["keys"] == ["a"]
    assert payloads[0]["keys_truncated"] is True
    assert payloads[1]["query_key"] == "offlineStocks:city_4949:552400"
    assert payloads[2]["key_values"] == ["a:1", "z:<error:denied\\nnoacl>"]
    assert payloads[2]["key_value_entries"][1]["error"] == "denied\nnoacl"


def test_audit_redis_targets_json_output_and_suppression(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    records = iter(
        [
            {
                "timestamp": "2026-03-27T00:00:00Z",
                "host": "127.0.0.1",
                "port": 6379,
                "is_redis": True,
                "status": "auth_required",
                "auth_required": True,
                "default_credentials": False,
                "provided_credentials": False,
                "provided_username": None,
                "provided_password": None,
                "provided_credentials_ok": None,
                "defcreds_enabled": False,
                "default_credentials_attempted": False,
                "show_keys": False,
                "dump_keys": False,
                "query_key": None,
                "key_count": None,
                "keys": None,
                "key_values": None,
                "query_key_value": None,
                "elapsed_ms": 1,
                "error": None,
            },
            {
                "timestamp": "2026-03-27T00:00:01Z",
                "host": "127.0.0.2",
                "port": 6379,
                "is_redis": False,
                "status": "fail",
                "error": "connection timeout",
                "auth_required": None,
                "default_credentials": None,
                "provided_credentials": False,
                "provided_username": None,
                "provided_password": None,
                "provided_credentials_ok": None,
                "defcreds_enabled": False,
                "default_credentials_attempted": False,
                "show_keys": False,
                "dump_keys": False,
                "query_key": None,
                "key_count": None,
                "keys": None,
                "key_values": None,
                "query_key_value": None,
                "elapsed_ms": None,
            },
        ]
    )
    monkeypatch.setattr(
        redis_actions,
        "redis_detect_hook",
        lambda ctx: AuditRecord.from_mapping(next(records), module="redis", service="redis"),
    )
    monkeypatch.setattr(redis_actions, "redis_auth_hook", lambda _ctx, record: record)

    output_path = tmp_path / "redis.json"
    emitted: list[str] = []
    totals = run_module_targets_for_test(
        "redis",
        hosts=["127.0.0.1", "127.0.0.2"],
        port=6379,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        defcreds=False,
        show_keys=False,
        dump_keys=False,
        query_key=None,
        output_path=str(output_path),
        output_format="json",
        emit_line=emitted.append,
        suppress_timeout_status_lines=True,
    )
    assert totals == (2, 0, 0, 0, 1, 1)
    lines = output_path.read_text(encoding="utf-8").splitlines()
    payloads = [json.loads(line) for line in lines]
    assert all(item.get("service") == "redis" for item in payloads)
    assert any(item.get("status") == "auth_required" for item in payloads)


def test_audit_redis_targets_suppresses_pre_detect_connection_noise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = iter(
        [
            {
                "timestamp": "2026-03-27T00:00:00Z",
                "host": "127.0.0.1",
                "port": 6379,
                "is_redis": False,
                "status": "fail",
                "error": "[Errno 111] Connection refused",
                "auth_required": None,
                "default_credentials": None,
                "provided_credentials": False,
                "provided_username": None,
                "provided_password": None,
                "provided_credentials_ok": None,
                "defcreds_enabled": False,
                "default_credentials_attempted": False,
                "show_keys": False,
                "dump_keys": False,
                "query_key": None,
                "key_count": None,
                "keys": None,
                "key_values": None,
                "query_key_value": None,
                "elapsed_ms": None,
            },
            {
                "timestamp": "2026-03-27T00:00:01Z",
                "host": "127.0.0.2",
                "port": 6379,
                "is_redis": False,
                "status": "fail",
                "error": "connection timeout",
                "auth_required": None,
                "default_credentials": None,
                "provided_credentials": False,
                "provided_username": None,
                "provided_password": None,
                "provided_credentials_ok": None,
                "defcreds_enabled": False,
                "default_credentials_attempted": False,
                "show_keys": False,
                "dump_keys": False,
                "query_key": None,
                "key_count": None,
                "keys": None,
                "key_values": None,
                "query_key_value": None,
                "elapsed_ms": None,
            },
        ]
    )
    monkeypatch.setattr(
        redis_actions,
        "redis_detect_hook",
        lambda ctx: AuditRecord.from_mapping(next(records), module="redis", service="redis"),
    )

    emitted: list[str] = []
    totals = run_module_targets_for_test(
        "redis",
        hosts=["127.0.0.1", "127.0.0.2"],
        port=6379,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        defcreds=False,
        show_keys=False,
        dump_keys=False,
        query_key=None,
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
        suppress_connection_refused_status_lines=True,
    )

    assert totals == (2, 0, 0, 0, 0, 2)
    assert len(emitted) == 1
    assert "REDIS audit inconclusive" in emitted[0]
    assert all("Connection refused" not in line for line in emitted)


def test_audit_redis_targets_keeps_non_refused_fail_lines_when_suppression_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = iter(
        [
            {
                "timestamp": "2026-03-27T00:00:00Z",
                "host": "127.0.0.1",
                "port": 6379,
                "is_redis": False,
                "status": "fail",
                "error": "protocol mismatch",
                "auth_required": None,
                "default_credentials": None,
                "provided_credentials": False,
                "provided_username": None,
                "provided_password": None,
                "provided_credentials_ok": None,
                "defcreds_enabled": False,
                "default_credentials_attempted": False,
                "show_keys": False,
                "dump_keys": False,
                "query_key": None,
                "key_count": None,
                "keys": None,
                "key_values": None,
                "query_key_value": None,
                "elapsed_ms": None,
            }
        ]
    )
    monkeypatch.setattr(
        redis_actions,
        "redis_detect_hook",
        lambda ctx: AuditRecord.from_mapping(next(records), module="redis", service="redis"),
    )

    emitted: list[str] = []
    totals = run_module_targets_for_test(
        "redis",
        hosts=["127.0.0.1"],
        port=6379,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        defcreds=False,
        show_keys=False,
        dump_keys=False,
        query_key=None,
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
        suppress_timeout_status_lines=True,
        suppress_connection_refused_status_lines=True,
    )

    assert totals == (1, 0, 0, 0, 0, 1)
    assert any("protocol mismatch" in line for line in emitted)


@pytest.mark.parametrize("debug", [False, True])
def test_run_redis_stage_connection_refused_suppression_matches_debug(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], debug: bool
) -> None:
    captured: dict[str, object] = {}

    def fake_detect(ctx):
        captured.update(
            {
                "host": ctx.host,
                "port": ctx.port,
                "phase": ctx.phase,
                "username": ctx.credential.username,
                "run_deep_checks": ctx.run_deep_checks,
            }
        )
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="redis",
            service="redis",
            status="fail",
            extra={
                "is_redis": False,
                "error": "connection refused (service is not listening on target port)",
            },
        )

    monkeypatch.setattr(redis_actions, "redis_detect_hook", fake_detect)

    args = SimpleNamespace(
        debug=debug,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        defcreds=False,
        show_keys=False,
        dump=False,
        key=None,
        output=None,
        output_format="txt",
        port=6379,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
    )

    class _DummyLogger:
        def log(self, *_args: object, **_kwargs: object) -> None:
            return

    rc = redis_stage.run_redis_stage(args, _DummyLogger())
    assert rc == 1
    assert captured["phase"] == "detect"
    assert captured["username"] is None
    assert captured["run_deep_checks"] is False
    output = capsys.readouterr().out.lower()
    assert ("connection refused" in output) is debug


def test_run_redis_stage_non_debug_suppresses_unreachable_summary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    patch_module_host_stage_for_test(
        monkeypatch,
        "redis",
        lambda **kwargs: _redis_host_record(
            kwargs,
            status="fail",
            detected=False,
            error="connection refused",
        ),
    )

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        defcreds=False,
        show_keys=False,
        dump=False,
        key=None,
        output=None,
        output_format="txt",
        port=6379,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
    )

    class _DummyLogger:
        def log(self, *_args: object, **_kwargs: object) -> None:
            return

    rc = redis_stage.run_redis_stage(args, _DummyLogger())
    assert rc == 1
    captured = capsys.readouterr()
    assert "all redis targets are unreachable" not in captured.out


def test_run_redis_stage_debug_shows_unreachable_summary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    patch_module_host_stage_for_test(
        monkeypatch,
        "redis",
        lambda **kwargs: _redis_host_record(
            kwargs,
            status="fail",
            detected=False,
            error="connection refused",
        ),
    )

    args = SimpleNamespace(
        debug=True,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        defcreds=False,
        show_keys=False,
        dump=False,
        key=None,
        output=None,
        output_format="txt",
        port=6379,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
    )

    class _DummyLogger:
        def log(self, *_args: object, **_kwargs: object) -> None:
            return

    rc = redis_stage.run_redis_stage(args, _DummyLogger())
    assert rc == 1
    captured = capsys.readouterr()
    assert "all redis targets are unreachable" in captured.out


def test_run_redis_stage_multi_port_verbose_uses_single_global_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_calls: list[tuple[str, int, str]] = []

    def fake_detect(ctx):
        captured_calls.append((ctx.host, ctx.port, ctx.phase))
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="redis",
            service="redis",
            status="fail",
            extra={"is_redis": False, "error": "connection refused"},
        )

    monkeypatch.setattr(redis_actions, "redis_detect_hook", fake_detect)
    monkeypatch.setattr(redis_stage, "collect_scan_ports", lambda *_args, **_kwargs: [6379, 26380, 26381])
    monkeypatch.setattr(redis_stage, "collect_scan_targets", lambda *_args, **_kwargs: ["127.0.0.1"])

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
        redis_stage,
        "start_command_progress",
        lambda _args, label, total, **kwargs: _FakeProgressBar(label, total, **kwargs),
    )

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        username="redis",
        password="redis",
        defcreds=False,
        show_keys=True,
        dump=False,
        key=None,
        output=None,
        output_format="txt",
        port=6379,
        ports="6379,26380,26381",
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
    )

    rc = redis_stage.run_redis_stage(args, SimpleNamespace(log=lambda *_a, **_k: None))
    assert rc == 1
    assert [call[1] for call in captured_calls] == [6379, 26380, 26381]
    assert all(call[2] == "detect" for call in captured_calls)
    assert progress_totals == [3]
    assert progress_advances == [1, 1, 1]


def test_run_redis_stage_username_file_then_defaults_checks_every_pair(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    creds_file = tmp_path / "creds.txt"
    creds_file.write_text("bad:bad\ngood:good\n", encoding="utf-8")
    captured_calls: list[tuple[str, str | None, str | None, bool]] = []

    def fake_detect(ctx):
        captured_calls.append(("detect", ctx.credential.username, ctx.credential.password, ctx.run_deep_checks))
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="redis",
            service="redis",
            status="auth_required",
            auth_required=True,
            extra={"is_redis": True},
        )

    def fake_auth(ctx, record):
        captured_calls.append(("auth", ctx.credential.username, ctx.credential.password, ctx.run_deep_checks))
        status = "valid_credentials" if ctx.credential.username == "good" else "auth_required"
        return AuditRecord.from_mapping(
            {**record.to_dict(), "status": status, "is_redis": True},
            module="redis",
            service="redis",
        )

    def fake_data(ctx, record):
        captured_calls.append(("data", ctx.credential.username, ctx.credential.password, ctx.run_deep_checks))
        return record

    monkeypatch.setattr(redis_actions, "redis_detect_hook", fake_detect)
    monkeypatch.setattr(redis_actions, "redis_auth_hook", fake_auth)
    monkeypatch.setattr(redis_actions, "redis_data_hook", fake_data)
    monkeypatch.setattr(
        "redposture_core.stage_runtime.filter_open_tcp_hosts_for_credential_file",
        lambda hosts, _port, **_kwargs: list(hosts),
    )

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

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        username=str(creds_file),
        password=None,
        defcreds=True,
        show_keys=False,
        dump=False,
        key=None,
        output=None,
        output_format="txt",
        port=6379,
        ports=None,
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
    )

    rc = redis_stage.run_redis_stage(args, SimpleNamespace(log=lambda *_a, **_k: None))

    assert rc == 0
    expected_defaults = [
        ("auth", username, password, False) for username, password in redis_actions._REDIS_DEFAULT_CREDENTIALS
    ]
    assert captured_calls == [
        ("detect", None, None, False),
        ("auth", "bad", "bad", False),
        ("auth", "good", "good", False),
        *expected_defaults,
        ("data", "good", "good", True),
    ]
    assert progress_totals == [2]
    assert progress_advances == [1, 1]


def test_redis_production_path_credential_batch_detects_protocol_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    credentials = tmp_path / "credentials.txt"
    credentials.write_text("bad:bad\ngood:good\n", encoding="utf-8")
    command_counts: dict[str, int] = {"CONNECT": 0, "PING": 0, "AUTH": 0, "DBSIZE": 0}

    def create_connection(*_args, **_kwargs):
        command_counts["CONNECT"] += 1
        return _DummySocket()

    def send_cmd(_sock, *parts):
        command = str(parts[0]).upper()
        command_counts[command] = command_counts.get(command, 0) + 1
        if command == "PING":
            return "error", "NOAUTH Authentication required."
        if command == "AUTH":
            return ("simple", "OK") if parts[-1] == "good" else ("error", "WRONGPASS invalid credentials")
        if command == "DBSIZE":
            return "integer", 7
        pytest.fail(f"unexpected Redis command: {parts!r}")

    monkeypatch.setattr(redis_stage.socket, "create_connection", create_connection)
    monkeypatch.setattr(redis_stage, "_send_cmd", send_cmd)
    args = parse_args(
        [
            "redis",
            "-t",
            "127.0.0.1",
            "--port",
            "6379",
            "-u",
            str(credentials),
            "-f",
            "json",
        ]
    )

    rc = redis_stage.run_redis_stage(args, SimpleNamespace(log=lambda *_args, **_kwargs: None))

    assert rc == 0
    assert command_counts == {"CONNECT": 1, "PING": 1, "AUTH": 2, "DBSIZE": 1}


def test_redis_production_path_direct_credentials_detect_protocol_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_counts: dict[str, int] = {"CONNECT": 0, "PING": 0, "AUTH": 0, "DBSIZE": 0}

    def create_connection(*_args, **_kwargs):
        command_counts["CONNECT"] += 1
        return _DummySocket()

    def send_cmd(_sock, *parts):
        command = str(parts[0]).upper()
        command_counts[command] = command_counts.get(command, 0) + 1
        if command == "PING":
            return "error", "NOAUTH Authentication required."
        if command == "AUTH":
            return "simple", "OK"
        if command == "DBSIZE":
            return "integer", 7
        pytest.fail(f"unexpected Redis command: {parts!r}")

    monkeypatch.setattr(redis_stage.socket, "create_connection", create_connection)
    monkeypatch.setattr(redis_stage, "_send_cmd", send_cmd)
    args = parse_args(
        [
            "redis",
            "-t",
            "127.0.0.1",
            "--port",
            "6379",
            "-u",
            "good",
            "-p",
            "good",
            "-f",
            "json",
        ]
    )

    rc = redis_stage.run_redis_stage(args, SimpleNamespace(log=lambda *_args, **_kwargs: None))

    assert rc == 0
    assert command_counts == {"CONNECT": 1, "PING": 1, "AUTH": 1, "DBSIZE": 1}


def _run_redis_lifecycle_result(args):
    redis_module_stage._prepare_redis_credential_runs(args)
    plan = redis_module_stage.build_redis_plan(args)
    return AuditCommandRunner(
        args=args,
        spec=redis_module_stage.build_redis_spec(args),
        emit_line=lambda _line: None,
    ).run_plan(plan)


def test_redis_defcreds_expand_after_provided_and_file_candidates(tmp_path) -> None:
    defaults = [
        ("admin", "admin", "default"),
        ("admin", "changeme", "default"),
        ("admin", "password", "default"),
        ("default", "changeme", "default"),
        ("default", "default", "default"),
        ("default", "password", "default"),
        ("default", "redis", "default"),
        ("dev", "dev", "default"),
        ("redis", "changeme", "default"),
        ("redis", "password", "default"),
        ("redis", "redis", "default"),
        ("root", "password", "default"),
        ("root", "root", "default"),
        ("service", "service", "default"),
        ("test", "test", "default"),
        ("user", "password", "default"),
        ("user", "user", "default"),
    ]
    direct_args = parse_args(
        [
            "redis",
            "-t",
            "127.0.0.1",
            "--port",
            "6379",
            "-u",
            "app",
            "-p",
            "secret",
            "--defcreds",
        ]
    )
    redis_module_stage._prepare_redis_credential_runs(direct_args)
    assert [(run.username, run.password, run.source) for run in direct_args._audit_credential_runs] == [
        ("app", "secret", "provided"),
        *defaults,
    ]

    credentials = tmp_path / "credentials.txt"
    credentials.write_text("one:1\ntwo:2\n", encoding="utf-8")
    file_args = parse_args(
        [
            "redis",
            "-t",
            "127.0.0.1",
            "--port",
            "6379",
            "-u",
            str(credentials),
            "--defcreds",
        ]
    )
    redis_module_stage._prepare_redis_credential_runs(file_args)
    plan = redis_module_stage.build_redis_plan(file_args)
    assert [(run.username, run.password, run.source) for run in plan.credential_runs] == [
        ("one", "1", "file"),
        ("two", "2", "file"),
        *defaults,
    ]


def test_redis_explicit_default_overlap_stays_provided_and_is_stably_deduplicated() -> None:
    args = parse_args(
        [
            "redis",
            "-t",
            "127.0.0.1",
            "--port",
            "6379",
            "-u",
            "redis",
            "-p",
            "redis",
            "--defcreds",
        ]
    )

    redis_module_stage._prepare_redis_credential_runs(args)
    runs = args._audit_credential_runs

    assert (runs[0].username, runs[0].password, runs[0].source) == ("redis", "redis", "provided")
    assert [(run.username, run.password) for run in runs] == [
        ("redis", "redis"),
        *[pair for pair in redis_actions._REDIS_DEFAULT_CREDENTIALS if pair != ("redis", "redis")],
    ]
    assert sum((run.username, run.password) == ("redis", "redis") for run in runs) == 1


def test_redis_defcreds_try_provided_before_default_and_classify_default(monkeypatch) -> None:
    commands: list[tuple[str, ...]] = []
    monkeypatch.setattr(redis_actions.socket, "create_connection", lambda *_args, **_kwargs: _DummySocket())

    def send_cmd(_sock, *parts):
        command = tuple(str(item) for item in parts)
        commands.append(command)
        if command == ("PING",):
            return "error", "NOAUTH Authentication required."
        if command == ("AUTH", "app", "bad"):
            return "error", "WRONGPASS invalid credentials"
        if command == ("AUTH", "redis", "redis"):
            return "simple", "OK"
        if command[0] == "AUTH":
            return "error", "WRONGPASS invalid credentials"
        if command == ("DBSIZE",):
            return "integer", 3
        pytest.fail(f"unexpected Redis command: {command!r}")

    monkeypatch.setattr(redis_actions, "_send_cmd", send_cmd)
    args = parse_args(
        [
            "redis",
            "-t",
            "127.0.0.1",
            "--port",
            "6379",
            "-u",
            "app",
            "-p",
            "bad",
            "--defcreds",
            "-f",
            "json",
        ]
    )

    result = _run_redis_lifecycle_result(args)

    assert commands == [
        ("PING",),
        ("AUTH", "app", "bad"),
        *[("AUTH", username, password) for username, password in redis_actions._REDIS_DEFAULT_CREDENTIALS],
        ("DBSIZE",),
    ]
    assert result.records[0]["status"] == "weak_default_creds"
    assert result.records[0]["default_credentials"] is True


def test_redis_defcreds_checks_full_catalog_after_late_default_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[tuple[str, ...]] = []
    monkeypatch.setattr(redis_actions.socket, "create_connection", lambda *_args, **_kwargs: _DummySocket())

    def send_cmd(_sock: object, *parts: object):
        command = tuple(str(item) for item in parts)
        commands.append(command)
        if command == ("PING",):
            return "error", "NOAUTH Authentication required."
        if command == ("AUTH", "default", "password"):
            return "simple", "OK"
        if command[0] == "AUTH":
            return "error", "WRONGPASS invalid credentials"
        if command == ("DBSIZE",):
            return "integer", 2
        pytest.fail(f"unexpected Redis command: {command!r}")

    monkeypatch.setattr(redis_actions, "_send_cmd", send_cmd)
    args = parse_args(
        [
            "redis",
            "-t",
            "127.0.0.1",
            "--port",
            "6379",
            "--defcreds",
            "-f",
            "json",
        ]
    )

    result = _run_redis_lifecycle_result(args)

    assert commands == [
        ("PING",),
        *[("AUTH", username, password) for username, password in redis_actions._REDIS_DEFAULT_CREDENTIALS],
        ("DBSIZE",),
    ]
    assert result.records[0]["status"] == "weak_default_creds"
    assert result.records[0]["effective_username"] == "default"
    assert result.records[0]["effective_password"] == "password"
    attempts = result.records[0]["attempted_credentials"]
    assert isinstance(attempts, list)
    assert len(attempts) == len(redis_actions._REDIS_DEFAULT_CREDENTIALS)
    rendered = redis_actions._format_credential_attempts_records(result.records[0], "txt")
    assert len(rendered) == len(redis_actions._REDIS_DEFAULT_CREDENTIALS)
    assert any("[+] default:password" in line for line in rendered)
    assert any("[-] dev:dev" in line for line in rendered)


def test_redis_legacy_auth_fallback_is_deduplicated_by_password_without_skipping_acl_pairs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[tuple[str, ...]] = []
    monkeypatch.setattr(redis_actions.socket, "create_connection", lambda *_args, **_kwargs: _DummySocket())

    def send_cmd(_sock: object, *parts: object):
        command = tuple(str(item) for item in parts)
        commands.append(command)
        if command == ("PING",):
            return "error", "NOAUTH Authentication required."
        if command[0] == "AUTH" and len(command) == 3:
            return "error", "ERR wrong number of arguments for 'auth' command"
        if command[0] == "AUTH" and len(command) == 2:
            return "error", "WRONGPASS invalid credentials"
        pytest.fail(f"unexpected Redis command: {command!r}")

    monkeypatch.setattr(redis_actions, "_send_cmd", send_cmd)
    args = parse_args(
        [
            "redis",
            "-t",
            "127.0.0.1",
            "--port",
            "6379",
            "--defcreds",
            "-f",
            "json",
        ]
    )

    result = _run_redis_lifecycle_result(args)
    auth_commands = [command for command in commands if command[0] == "AUTH"]
    acl_pairs = [command[1:] for command in auth_commands if len(command) == 3]
    legacy_passwords = [command[1] for command in auth_commands if len(command) == 2]

    assert acl_pairs == list(redis_actions._REDIS_DEFAULT_CREDENTIALS)
    assert legacy_passwords == [
        "admin",
        "changeme",
        "password",
        "default",
        "redis",
        "dev",
        "root",
        "service",
        "test",
        "user",
    ]
    assert result.records[0]["status"] == "auth_required"


def test_redis_auth_transient_retries_without_repeating_detect(monkeypatch) -> None:
    commands: list[str] = []
    connects = 0

    def create_connection(*_args, **_kwargs):
        nonlocal connects
        connects += 1
        return _DummySocket()

    def send_cmd(_sock, *parts):
        command = str(parts[0]).upper()
        commands.append(command)
        if command == "PING":
            return "error", "NOAUTH Authentication required."
        if command == "AUTH" and commands.count("AUTH") == 1:
            raise ConnectionResetError("transient auth reset")
        if command == "AUTH":
            return "simple", "OK"
        if command == "DBSIZE":
            return "integer", 4
        pytest.fail(f"unexpected Redis command: {parts!r}")

    monkeypatch.setattr(redis_actions.socket, "create_connection", create_connection)
    monkeypatch.setattr(redis_actions, "_send_cmd", send_cmd)
    monkeypatch.setattr(redis_actions, "_retry_delay", lambda _attempt: 0.0)
    args = parse_args(
        [
            "redis",
            "-t",
            "127.0.0.1",
            "--port",
            "6379",
            "-u",
            "app",
            "-p",
            "good",
            "--retries",
            "1",
            "-f",
            "json",
        ]
    )

    result = _run_redis_lifecycle_result(args)

    assert connects == 2
    assert commands == ["PING", "AUTH", "AUTH", "DBSIZE"]
    assert result.records[0]["status"] == "valid_credentials"


def test_redis_conclusive_auth_rejection_is_not_retried(monkeypatch) -> None:
    commands: list[str] = []
    connects = 0

    def create_connection(*_args, **_kwargs):
        nonlocal connects
        connects += 1
        return _DummySocket()

    def send_cmd(_sock, *parts):
        command = str(parts[0]).upper()
        commands.append(command)
        if command == "PING":
            return "error", "NOAUTH Authentication required."
        if command == "AUTH":
            return "error", "WRONGPASS invalid credentials"
        pytest.fail(f"unexpected Redis command: {parts!r}")

    monkeypatch.setattr(redis_actions.socket, "create_connection", create_connection)
    monkeypatch.setattr(redis_actions, "_send_cmd", send_cmd)
    args = parse_args(
        [
            "redis",
            "-t",
            "127.0.0.1",
            "--port",
            "6379",
            "-u",
            "app",
            "-p",
            "bad",
            "--retries",
            "3",
            "-f",
            "json",
        ]
    )

    result = _run_redis_lifecycle_result(args)

    assert connects == 1
    assert commands == ["PING", "AUTH"]
    assert result.records[0]["status"] == "auth_required"


def test_redis_data_transient_reconnects_and_reauths_without_ping(monkeypatch) -> None:
    commands: list[str] = []
    connects = 0

    def create_connection(*_args, **_kwargs):
        nonlocal connects
        connects += 1
        return _DummySocket()

    def send_cmd(_sock, *parts):
        command = str(parts[0]).upper()
        commands.append(command)
        if command == "PING":
            return "error", "NOAUTH Authentication required."
        if command == "AUTH":
            return "simple", "OK"
        if command == "DBSIZE" and commands.count("DBSIZE") == 1:
            raise ConnectionResetError("transient data reset")
        if command == "DBSIZE":
            return "integer", 9
        pytest.fail(f"unexpected Redis command: {parts!r}")

    monkeypatch.setattr(redis_actions.socket, "create_connection", create_connection)
    monkeypatch.setattr(redis_actions, "_send_cmd", send_cmd)
    monkeypatch.setattr(redis_actions, "_retry_delay", lambda _attempt: 0.0)
    args = parse_args(
        [
            "redis",
            "-t",
            "127.0.0.1",
            "--port",
            "6379",
            "-u",
            "app",
            "-p",
            "good",
            "--retries",
            "1",
            "-f",
            "json",
        ]
    )

    result = _run_redis_lifecycle_result(args)

    assert connects == 2
    assert commands == ["PING", "AUTH", "DBSIZE", "AUTH", "DBSIZE"]
    assert result.records[0]["status"] == "valid_credentials"
    assert result.records[0]["key_count"] == 9


def test_redis_lifecycle_hooks_disable_when_host_stage_is_replaced(monkeypatch) -> None:
    def fake_host_stage(**kwargs):
        return _redis_host_record(kwargs, status="fail", detected=False, error="fake")

    patch_module_host_stage_for_test(monkeypatch, "redis", fake_host_stage)
    spec = redis_module_stage.build_redis_spec(SimpleNamespace())

    assert spec.detect is None
    assert spec.auth is None
    assert spec.data is None
    assert spec.lifecycle_state_factory is None


def test_redis_lifecycle_hooks_disable_when_audit_implementation_is_replaced(monkeypatch) -> None:
    monkeypatch.setattr(
        redis_actions,
        "_audit_redis_host",
        lambda *args, **kwargs: {
            "host": args[0] if args else kwargs["host"],
            "port": args[1] if len(args) > 1 else kwargs["port"],
            "status": "fail",
            "is_redis": False,
        },
    )
    spec = redis_module_stage.build_redis_spec(SimpleNamespace())

    assert spec.detect is None
    assert spec.auth is None
    assert spec.data is None
    assert spec.lifecycle_state_factory is None


def test_run_redis_stage_username_file_keeps_all_hosts_for_protocol_detect(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    creds_file = tmp_path / "creds.txt"
    creds_file.write_text("bad:bad\ngood:good\n", encoding="utf-8")
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("closed\nopen-a\nopen-b\n", encoding="utf-8")
    captured_calls: list[tuple[str, str, str | None, str | None]] = []

    def fake_detect(ctx):
        captured_calls.append(("detect", ctx.host, ctx.credential.username, ctx.credential.password))
        if ctx.host == "closed":
            return AuditRecord(
                host=ctx.host,
                port=ctx.port,
                module="redis",
                service="redis",
                status="fail",
                extra={"is_redis": False, "error": "connection refused"},
            )
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="redis",
            service="redis",
            status="auth_required",
            auth_required=True,
            extra={"is_redis": True},
        )

    def fake_auth(ctx, record):
        captured_calls.append(("auth", ctx.host, ctx.credential.username, ctx.credential.password))
        return AuditRecord.from_mapping(
            {
                **record.to_dict(),
                "status": "valid_credentials" if ctx.credential.username == "good" else "auth_required",
                "is_redis": True,
            },
            module="redis",
            service="redis",
        )

    def fake_data(ctx, record):
        captured_calls.append(("data", ctx.host, ctx.credential.username, ctx.credential.password))
        return record

    monkeypatch.setattr(redis_actions, "redis_detect_hook", fake_detect)
    monkeypatch.setattr(redis_actions, "redis_auth_hook", fake_auth)
    monkeypatch.setattr(redis_actions, "redis_data_hook", fake_data)
    monkeypatch.setattr(
        "redposture_core.stage_runtime.filter_open_tcp_hosts_for_credential_file",
        lambda *_args, **_kwargs: pytest.fail("credential-file TCP prefilter must not run"),
    )

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

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        username=str(creds_file),
        password=None,
        defcreds=False,
        show_keys=False,
        dump=False,
        key=None,
        output=None,
        output_format="txt",
        port=6379,
        ports=None,
        targets=str(targets_file),
        hosts=None,
        hosts_file=None,
    )

    rc = redis_stage.run_redis_stage(args, SimpleNamespace(log=lambda *_a, **_k: None))

    assert rc == 1
    assert [call for call in captured_calls if call[0] == "detect"] == [
        ("detect", "closed", None, None),
        ("detect", "open-a", None, None),
        ("detect", "open-b", None, None),
    ]
    assert [call for call in captured_calls if call[0] == "auth"] == [
        ("auth", "open-a", "bad", "bad"),
        ("auth", "open-a", "good", "good"),
        ("auth", "open-b", "bad", "bad"),
        ("auth", "open-b", "good", "good"),
    ]
    assert [call for call in captured_calls if call[0] == "data"] == [
        ("data", "open-a", "good", "good"),
        ("data", "open-b", "good", "good"),
    ]
    assert progress_totals == [5]
    assert progress_advances == [1, 1, 1, 1, 1]


def test_call_audit_redis_host_with_stage_debug_adds_stage_telemetry(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": "127.0.0.1",
            "port": 6379,
            "is_redis": True,
            "status": "open_no_auth",
            "auth_required": False,
            "show_keys": False,
            "dump_keys": False,
            "query_key": None,
            "error": None,
        }

    monkeypatch.setattr(redis_stage, "_audit_redis_host", fake_audit)
    debug_lines: list[str] = []
    result = redis_stage._call_audit_redis_host_with_stage_debug(
        "127.0.0.1",
        6379,
        1.0,
        1,
        None,
        None,
        False,
        False,
        False,
        None,
        run_deep_checks=True,
        debug=True,
        debug_emit=debug_lines.append,
    )
    assert isinstance(result.get("stages"), list)
    assert result.get("stage_durations_ms") is not None
    assert result.get("stage_attempts") is not None
    assert any("stage_trace stage_name=detect_protocol" in line for line in debug_lines)
    assert any("stage_timing_summary status=open_no_auth" in line for line in debug_lines)


def test_audit_redis_targets_emits_two_pass_debug_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_detect(ctx):
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="redis",
            service="redis",
            status="open_no_auth",
            auth_required=False,
            extra={"is_redis": True},
        )

    def fake_auth(_ctx, record):
        return record

    def fake_data(_ctx, record):
        return AuditRecord.from_mapping(
            {
                **record.to_dict(),
                "status": "open_no_auth",
                "is_redis": True,
                "show_keys": True,
                "keys": ["a"],
            },
            module="redis",
            service="redis",
        )

    monkeypatch.setattr(redis_actions, "redis_detect_hook", fake_detect)
    monkeypatch.setattr(redis_actions, "redis_auth_hook", fake_auth)
    monkeypatch.setattr(redis_actions, "redis_data_hook", fake_data)
    debug_lines: list[str] = []
    emitted: list[str] = []
    totals = run_module_targets_for_test(
        "redis",
        hosts=["127.0.0.1"],
        port=6379,
        timeout=1.0,
        retries=0,
        workers=1,
        username=None,
        password=None,
        defcreds=False,
        show_keys=True,
        dump_keys=False,
        query_key=None,
        output_path=None,
        output_format="txt",
        emit_line=emitted.append,
        debug_emit=debug_lines.append,
        show_progress=False,
    )
    assert totals == (1, 1, 0, 0, 0, 0)
    assert any("pass=1 detect start total=1" in line for line in debug_lines)
    assert any("stage2_gate=run reason=status=open_no_auth" in line for line in debug_lines)
    assert any("pass=2 deep complete processed=1" in line for line in debug_lines)


def test_stream_dump_redis_keys_pages_and_delays(monkeypatch: pytest.MonkeyPatch) -> None:
    # Two SCAN pages: cursor "0" -> "5" with three keys, then cursor "5" -> "0" with one key.
    scan_pages = iter(
        [
            ("array", ["5", ["k3", "k1", "k2"]]),
            ("array", ["0", ["k4"]]),
        ]
    )

    def fake_send_cmd(_sock: object, *parts: str) -> tuple[str, object]:
        assert parts[0] == "SCAN"
        return next(scan_pages)

    monkeypatch.setattr(redis_stage, "_send_cmd", fake_send_cmd)
    monkeypatch.setattr(redis_stage, "_dump_redis_key_value", lambda _s, k: (f"v-{k}", None))
    sleeps: list[float] = []
    monkeypatch.setattr(redis_stage.time, "sleep", lambda s: sleeps.append(s))

    entries, err = redis_stage._stream_dump_redis_keys(object(), batch=2, delay_ms=20)

    assert err is None
    # Page 1 dumps the first two buffered keys (sorted: k1,k3); the leftover k2 carries into
    # page 2 with k4 from the next SCAN call (sorted: k2,k4). Sorting is per page, not global.
    assert [entry["key"] for entry in entries] == ["k1", "k3", "k2", "k4"]
    assert [entry["value"] for entry in entries] == ["v-k1", "v-k3", "v-k2", "v-k4"]
    # One pause per flushed page (default 20ms -> 0.02s), not per key.
    assert sleeps == [0.02, 0.02]


def test_stream_dump_redis_keys_respects_total_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    scan_pages = iter([("array", ["0", ["a", "b", "c", "d", "e"]])])
    monkeypatch.setattr(redis_stage, "_send_cmd", lambda _s, *_p: next(scan_pages))
    monkeypatch.setattr(redis_stage, "_dump_redis_key_value", lambda _s, k: (f"v-{k}", None))
    monkeypatch.setattr(redis_stage.time, "sleep", lambda _s: None)

    entries, err = redis_stage._stream_dump_redis_keys(object(), batch=10, delay_ms=0, limit=3)

    assert err is None
    assert [entry["key"] for entry in entries] == ["a", "b", "c"]


def test_stream_dump_redis_keys_zero_delay_does_not_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    scan_pages = iter([("array", ["0", ["a", "b"]])])
    monkeypatch.setattr(redis_stage, "_send_cmd", lambda _s, *_p: next(scan_pages))
    monkeypatch.setattr(redis_stage, "_dump_redis_key_value", lambda _s, k: (f"v-{k}", None))
    sleeps: list[float] = []
    monkeypatch.setattr(redis_stage.time, "sleep", lambda s: sleeps.append(s))

    entries, err = redis_stage._stream_dump_redis_keys(object(), batch=1, delay_ms=0)

    assert err is None
    assert [entry["key"] for entry in entries] == ["a", "b"]
    assert sleeps == []  # delay_ms=0 disables inter-page pauses


def test_stream_dump_redis_keys_reports_bad_scan_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redis_stage, "_send_cmd", lambda *_a, **_k: ("simple", "PONG"))
    monkeypatch.setattr(redis_stage.time, "sleep", lambda _s: None)

    entries, err = redis_stage._stream_dump_redis_keys(object(), batch=10, delay_ms=0)

    assert entries == []
    assert err is not None and "unexpected SCAN response" in err


def test_redis_noperm_ping_still_attempts_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[tuple[str, ...]] = []
    monkeypatch.setattr(redis_actions.socket, "create_connection", lambda *_a, **_k: _DummySocket())

    def _send(_sock: object, *parts: str):
        command = tuple(parts)
        commands.append(command)
        if command == ("PING",):
            return "error", "NOPERM this user has no permissions to run PING"
        if command == ("AUTH", "app", "secret"):
            return "simple", "OK"
        if command == ("DBSIZE",):
            return "integer", 0
        pytest.fail(f"unexpected Redis command: {command!r}")

    monkeypatch.setattr(redis_actions, "_send_cmd", _send)
    args = parse_args(["redis", "-t", "127.0.0.1", "--port", "6379", "-u", "app", "-p", "secret", "-f", "json"])
    result = _run_redis_lifecycle_result(args)
    assert commands[:2] == [("PING",), ("AUTH", "app", "secret")]
    assert result.records[0]["status"] == "valid_credentials"


def test_redis_tls_loads_ca_and_client_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    class _Socket(_DummySocket):
        def close(self) -> None:
            calls["closed"] = True

    class _Context:
        check_hostname = True
        verify_mode = redis_actions.ssl.CERT_REQUIRED

        def load_cert_chain(self, *, certfile: str, keyfile: str) -> None:
            calls["identity"] = (certfile, keyfile)

        def wrap_socket(self, sock: _Socket, *, server_hostname: str) -> _Socket:
            calls["server_hostname"] = server_hostname
            return sock

    def _default_context(*, cafile: str | None = None):
        calls["cafile"] = cafile
        return _Context()

    monkeypatch.setattr(redis_actions.socket, "create_connection", lambda *_a, **_k: _Socket())
    monkeypatch.setattr(redis_actions.ssl, "create_default_context", _default_context)
    sock = redis_actions._open_redis_socket(
        "redis.internal",
        6380,
        1.0,
        use_tls=True,
        ca_file="ca.pem",
        cert_file="client.pem",
        key_file="client.key",
    )
    assert sock is not None
    assert calls["cafile"] == "ca.pem"
    assert calls["identity"] == ("client.pem", "client.key")
    assert calls["server_hostname"] == "redis.internal"


def test_redis_insecure_flag_selects_tls_transport() -> None:
    args = parse_args(["redis", "-t", "redis.internal", "--insecure"])
    ctx = SimpleNamespace(
        args=args,
        target=SimpleNamespace(scheme=None),
        host="redis.internal",
        port=6379,
        debug_emit=None,
    )
    state = redis_actions.redis_lifecycle_state_factory(ctx)
    assert state.use_tls is True
    assert state.insecure is True
    assert state.transport_mode == "tls"


def test_redis_invalid_utf8_bulk_values_are_lossless_base64() -> None:
    assert redis_actions._read_resp(_ReadSocket(b"$2\r\n\xff\x00\r\n")) == ("bulk", b"\xff\x00")
    assert redis_actions._format_redis_text(b"\xff\x00") == "base64:/wA="


def test_redis_stream_dump_queries_binary_keys_without_reencoding(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[tuple[str | bytes, ...]] = []

    def _send(_sock: object, *parts: str | bytes):
        commands.append(parts)
        if parts[0] == "SCAN":
            return "array", [b"0", [b"\xffkey"]]
        if parts == ("TYPE", b"\xffkey"):
            return "bulk", b"string"
        if parts == ("GET", b"\xffkey"):
            return "bulk", b"\x00\xff"
        pytest.fail(f"unexpected Redis command: {parts!r}")

    monkeypatch.setattr(redis_actions, "_send_cmd", _send)
    entries, error = redis_actions._stream_dump_redis_keys(object(), batch=10, delay_ms=0)
    assert error is None
    assert entries == [{"key": "base64:/2tleQ==", "value": "base64:AP8=", "error": None}]
    assert ("TYPE", b"\xffkey") in commands
    assert ("GET", b"\xffkey") in commands
