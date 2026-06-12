from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core import stage_redis as redis_stage
from tests.stage_runtime_helpers import patch_runner_for_legacy_target_fake, run_module_targets_for_test


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

    line_anon = redis_stage._format_record({**base, "status": "open_no_auth"}, "txt")
    assert "[+] anonymous access (keys:2)" in line_anon

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
    monkeypatch.setattr(redis_stage, "_scan_redis_keys", lambda *_args, **_kwargs: (["b", "a"], None))
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
    assert record["keys"] == ["b", "a"]
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
    assert bulk == ("bulk", "hello")
    assert null_bulk == ("null", None)
    assert array == ("array", ["one", "two"])

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
    monkeypatch.setattr(redis_stage, "_audit_redis_host", lambda *args, **kwargs: next(records))

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
    monkeypatch.setattr(redis_stage, "_audit_redis_host", lambda *args, **kwargs: next(records))

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
    assert emitted == []
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
    monkeypatch.setattr(redis_stage, "_audit_redis_host", lambda *args, **kwargs: next(records))

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
    monkeypatch: pytest.MonkeyPatch, debug: bool
) -> None:
    captured: dict[str, object] = {}

    def fake_audit_redis_targets(*_args, **kwargs):
        captured.update(kwargs)
        return (1, 0, 0, 0, 0, 1)

    patch_runner_for_legacy_target_fake(monkeypatch, "redis", fake_audit_redis_targets)

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
    assert rc == 0
    assert captured.get("suppress_connection_refused_status_lines") is (not debug)


def test_run_redis_stage_non_debug_suppresses_unreachable_summary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    patch_runner_for_legacy_target_fake(monkeypatch, "redis", lambda *_args, **_kwargs: (1, 0, 0, 0, 0, 1))

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
    assert rc == 0
    captured = capsys.readouterr()
    assert "all redis targets are unreachable" not in captured.out


def test_run_redis_stage_debug_shows_unreachable_summary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    patch_runner_for_legacy_target_fake(monkeypatch, "redis", lambda *_args, **_kwargs: (1, 0, 0, 0, 0, 1))

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
    assert rc == 0
    captured = capsys.readouterr()
    assert "all redis targets are unreachable" in captured.out


def test_run_redis_stage_multi_port_verbose_uses_single_global_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_calls: list[dict[str, object]] = []

    def fake_audit_redis_targets(*_args, **kwargs):
        captured_calls.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return (1, 1, 0, 0, 0, 0)

    patch_runner_for_legacy_target_fake(monkeypatch, "redis", fake_audit_redis_targets)
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
    assert rc == 0
    assert [bool(call["show_progress"]) for call in captured_calls] == [False, False, False]
    assert progress_totals == [3]
    assert progress_advances == [1, 1, 1]


def test_run_redis_stage_username_file_tries_all_pairs_and_disables_defcreds(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    creds_file = tmp_path / "creds.txt"
    creds_file.write_text("bad:bad\ngood:good\n", encoding="utf-8")
    captured_calls: list[dict[str, object]] = []

    def fake_audit_redis_targets(*_args, **kwargs):
        captured_calls.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return (1, 0, 0, 1, 0, 0)

    patch_runner_for_legacy_target_fake(monkeypatch, "redis", fake_audit_redis_targets)
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
    assert [(call["username"], call["password"]) for call in captured_calls] == [("bad", "bad"), ("good", "good")]
    assert [call["defcreds"] for call in captured_calls] == [False, False]
    assert [call["append_output"] for call in captured_calls] == [False, True]
    assert [call["show_progress"] for call in captured_calls] == [False, False]
    assert progress_totals == [2]
    assert progress_advances == [1, 1]


def test_run_redis_stage_username_file_prefilters_closed_hosts(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    creds_file = tmp_path / "creds.txt"
    creds_file.write_text("bad:bad\ngood:good\n", encoding="utf-8")
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("closed\nopen-a\nopen-b\n", encoding="utf-8")
    captured_calls: list[dict[str, object]] = []

    def fake_audit_redis_targets(*_args, **kwargs):
        captured_calls.append(kwargs)
        if kwargs.get("command_progress") is not None:
            kwargs["command_progress"].advance(len(kwargs.get("hosts", [])))
        return (1, 0, 0, 1, 0, 0)

    patch_runner_for_legacy_target_fake(monkeypatch, "redis", fake_audit_redis_targets)
    monkeypatch.setattr(
        "redposture_core.stage_runtime.filter_open_tcp_hosts_for_credential_file",
        lambda hosts, _port, **_kwargs: [host for host in hosts if host.startswith("open-")],
    )

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

    assert rc == 0
    assert [call["hosts"] for call in captured_calls] == [["open-a"], ["open-a"], ["open-b"], ["open-b"]]
    assert [(call["username"], call["password"]) for call in captured_calls] == [
        ("bad", "bad"),
        ("good", "good"),
        ("bad", "bad"),
        ("good", "good"),
    ]
    assert progress_totals == [4]
    assert progress_advances == [1, 1, 1, 1]


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
    def fake_stage_call(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        username: str | None,
        password: str | None,
        defcreds: bool,
        show_keys: bool,
        dump_keys: bool,
        query_key: str | None,
        *,
        run_deep_checks: bool,
        debug: bool,
        debug_emit,
    ) -> dict[str, object]:
        _ = (port, timeout, retries, username, password, defcreds, show_keys, dump_keys, query_key, debug, debug_emit)
        base = {
            "timestamp": "2026-03-27T00:00:00Z",
            "host": host,
            "port": 6379,
            "is_redis": True,
            "status": "open_no_auth",
            "auth_required": False,
            "provided_credentials": False,
            "default_credentials_attempted": False,
            "show_keys": bool(run_deep_checks),
            "dump_keys": False,
            "query_key": None,
            "keys": ["a"] if run_deep_checks else None,
            "key_values": None,
            "query_key_value": None,
            "error": None,
            "debug_events": [],
            "debug_events_streamed": True,
            "stages": [],
            "stage_durations_ms": {},
            "stage_attempts": {},
            "stage_failed_at": None,
        }
        return base

    monkeypatch.setattr(redis_stage, "_call_audit_redis_host_with_stage_debug", fake_stage_call)
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
