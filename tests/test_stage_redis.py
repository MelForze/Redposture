from __future__ import annotations

import pytest

from redposture_core import stage_redis as redis_stage


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


def test_is_connection_timeout_fail_record_detection() -> None:
    assert redis_stage._is_connection_timeout_fail_record({"status": "fail", "error": "connection timeout"})
    assert redis_stage._is_connection_timeout_fail_record({"status": "fail", "error": "socket timed out"})
    assert not redis_stage._is_connection_timeout_fail_record({"status": "open_no_auth", "error": "connection timeout"})
