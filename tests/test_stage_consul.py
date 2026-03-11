from __future__ import annotations

from redposture_core import stage_consul as consul


def _scope_fixture(ok_kv: bool, ok_services: bool, ok_agents: bool) -> dict[str, dict[str, object]]:
    return {
        "kv": {"ok": ok_kv, "count": 1 if ok_kv else 0, "status": 200 if ok_kv else 403, "error": "denied"},
        "services": {
            "ok": ok_services,
            "count": 2 if ok_services else 0,
            "status": 200 if ok_services else 403,
            "error": "denied",
        },
        "agents": {
            "ok": ok_agents,
            "count": 3 if ok_agents else 0,
            "status": 200 if ok_agents else 403,
            "error": "denied",
        },
    }


def test_scope_status_helpers() -> None:
    all_ok = _scope_fixture(True, True, True)
    none_ok = _scope_fixture(False, False, False)

    assert consul._all_scopes_ok(all_ok) is True
    assert consul._no_scopes_ok(all_ok) is False
    assert consul._all_scopes_ok(none_ok) is False
    assert consul._no_scopes_ok(none_ok) is True


def test_scope_suffix_helpers() -> None:
    scopes = _scope_fixture(True, False, True)
    counts = consul._scope_counts_suffix(scopes)
    bools = consul._scope_bools_suffix(scopes)
    assert "(kv:1)" in counts and "(services:0)" in counts and "(agents:3)" in counts
    assert "(kv:True)" in bools and "(services:False)" in bools and "(agents:True)" in bools


def test_scope_detail_lines_contains_errors_for_failed_scopes() -> None:
    scopes = _scope_fixture(True, False, False)
    lines = consul._scope_status_detail_lines("CONSUL\t127.0.0.1\t8500\t", scopes)
    assert len(lines) == 2
    assert all("err=denied" in line for line in lines)


def test_anonymous_acl_denied_with_filtered_empty() -> None:
    scopes_zero = {
        "kv": {"ok": False, "count": 0},
        "services": {"ok": False, "count": 0},
        "agents": {"ok": False, "count": 0},
    }
    record = {"anonymous_self_ok": False, "anonymous_self_error": "permission denied"}
    assert consul._anonymous_acl_denied_with_filtered_empty(record, scopes_zero) is True


def test_normalize_ssrf_helpers() -> None:
    assert consul._normalize_ssrf_path("/v1/agent/self?x=1") == ("/v1/agent/self", "x=1")
    urls = consul._normalize_ssrf_urls("127.0.0.1", "8500,8501", "/v1/status/leader")
    assert urls == [
        "http://127.0.0.1:8500/v1/status/leader",
        "http://127.0.0.1:8501/v1/status/leader",
    ]


def test_detect_line_for_fail_not_consul_and_detected() -> None:
    fail = consul._detect_line(
        {"host": "127.0.0.1", "port": 8500, "is_consul": False, "status": "fail", "error": "timeout"}, "txt"
    )
    assert "[!] connection failed err=timeout" in fail

    not_consul = consul._detect_line(
        {"host": "127.0.0.1", "port": 8500, "is_consul": False, "status": "not_consul"}, "txt"
    )
    assert "[-] not a Consul API" in not_consul

    detected = consul._detect_line(
        {
            "host": "127.0.0.1",
            "port": 8500,
            "is_consul": True,
            "version": "1.20.0",
            "anonymous_scopes": _scope_fixture(True, True, True),
            "anonymous_self_ok": True,
            "anonymous_self_error": "",
        },
        "txt",
    )
    assert "[*] Consul Agent" in detected
    assert "(auth required:False)" in detected


def test_summary_line_for_anonymous_access_and_partial() -> None:
    full = consul._summary_line(
        {
            "is_consul": True,
            "anonymous_scopes": _scope_fixture(True, True, True),
            "anonymous_self_ok": True,
            "anonymous_self_error": "",
            "rce": False,
        }
    )
    assert full is not None and full.startswith("[+] anonymous access")

    partial = consul._summary_line(
        {
            "is_consul": True,
            "anonymous_scopes": _scope_fixture(True, False, False),
            "anonymous_self_ok": True,
            "anonymous_self_error": "",
        }
    )
    assert partial is not None and partial.startswith("[!] anonymous partial access")


def test_auth_summary_line_token_valid_and_failed() -> None:
    ok_line = consul._auth_summary_line(
        {
            "auth_mode": "token",
            "auth_valid": True,
            "auth_scopes": _scope_fixture(True, True, False),
            "rce": False,
        }
    )
    assert ok_line is not None and ok_line.startswith("[+] token auth")

    fail_line = consul._auth_summary_line(
        {
            "auth_mode": "basic",
            "_username_display": "admin",
            "_password_display": "bad",
            "auth_valid": False,
            "auth_error": "denied",
            "auth_scopes": _scope_fixture(False, False, False),
        }
    )
    assert fail_line is not None and fail_line.startswith("[-] admin:bad failed")
    assert "err=denied" in fail_line


def test_bool_text() -> None:
    assert consul._bool_text(True) == "True"
    assert consul._bool_text(False) == "False"
    assert consul._bool_text(None) == "unknown"
