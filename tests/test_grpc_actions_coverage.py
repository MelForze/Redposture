from __future__ import annotations

import contextlib

import pytest

from redposture_core import stage_grpc as grpc


def test_friendly_error_helpers() -> None:
    assert isinstance(grpc._friendly_error_text("[Errno 61] Connection refused"), str)
    assert isinstance(grpc._friendly_error_from_exception(OSError("boom")), str)


def test_thread_debug_emitter_roundtrip() -> None:
    msgs: list[str] = []
    assert grpc._get_thread_debug_emitter() is None
    with contextlib.suppress(Exception), grpc._thread_debug_context(msgs.append):
        emitter = grpc._get_thread_debug_emitter()
        assert emitter is not None
        emitter("hello")
    assert grpc._get_thread_debug_emitter() is None
    assert "hello" in msgs


def test_format_status_label_all_branches() -> None:
    assert grpc._format_status_label("open_no_auth") == "anonymous access"
    assert grpc._format_status_label("valid_credentials") == "valid credentials"
    assert grpc._format_status_label("auth_required") == "authentication required"
    assert grpc._format_status_label("invalid_credentials_anonymous") == "invalid credentials (anonymous works)"
    assert grpc._format_status_label("not_grpc") == "not grpc"
    assert grpc._format_status_label("fail") == "fail"
    assert grpc._format_status_label("unknown_x") == "unknown_x"


def test_credential_label_branches() -> None:
    assert grpc._credential_label({"type": "token"}) == "token"
    assert grpc._credential_label({"type": "basic", "username": "admin", "password": "pw"}) == "admin:pw"
    assert grpc._credential_label({"type": "basic", "username": "", "password": ""}) == "user:<empty>"
    assert grpc._credential_label({"type": "weird"}) == "credentials"


def test_auth_attempt_success() -> None:
    assert grpc._auth_attempt_success(0, True) is True
    assert grpc._auth_attempt_success(None, True) is False
    assert grpc._auth_attempt_success(0, False) is False
    code = next(iter(grpc._GRPC_AUTH_CODES))
    assert grpc._auth_attempt_success(code, True) is False


def test_auth_attempt_entries_dedup_and_defcreds() -> None:
    token_only = grpc._auth_attempt_entries(token="t", username=None, password=None, defcreds=False)
    assert token_only == [{"type": "token", "token": "t", "source": "provided"}]

    basic_only = grpc._auth_attempt_entries(token=None, username="u", password="p", defcreds=False)
    assert basic_only[0]["type"] == "basic"
    assert basic_only[0]["username"] == "u"

    with_defaults = grpc._auth_attempt_entries(token=None, username=None, password=None, defcreds=True)
    assert any(entry["source"] == "defcreds" for entry in with_defaults)
    # provided + defcreds: provided stays first, no duplicate of an overlapping pair
    combined = grpc._auth_attempt_entries(token=None, username="admin", password="admin", defcreds=True)
    assert combined[0]["source"] == "provided"


def test_auth_required_helpers() -> None:
    # _auth_required_from_grpc_status: auth codes -> True, OK -> False, None -> None
    code = next(iter(grpc._GRPC_AUTH_CODES))
    assert grpc._auth_required_from_grpc_status(code) is True
    assert grpc._auth_required_from_grpc_status(0) is False
    assert grpc._auth_required_from_grpc_status(None) is None


def test_is_retryable_and_suppressed() -> None:
    assert grpc._is_suppressed_fail_record({"status": "fail"}) is True
    assert grpc._is_suppressed_fail_record({"status": "open_no_auth"}) is False


# ---- render / format functions (crafted records, no network) ----


def test_format_detect_record_branches() -> None:
    fail = {"status": "fail", "error": "[Errno 61] Connection refused", "host": "h", "port": 50051}
    assert "connection failed" in grpc._format_detect_record(fail, "txt")
    assert grpc._format_detect_record({"status": "fail", "host": "h", "port": 1}, "txt").endswith("connection failed")
    assert "not a gRPC service" in grpc._format_detect_record({"status": "not_grpc", "host": "h", "port": 1}, "txt")
    detected = {
        "status": "open_no_auth",
        "is_grpc": True,
        "auth_required": False,
        "transport_mode": "h2c",
        "protocol_flavor": "grpc",
        "host": "h",
        "port": 50051,
    }
    line = grpc._format_detect_record(detected, "txt")
    assert "gRPC Service" in line and "transport:h2c" in line
    assert '"detected": true' in grpc._format_detect_record(detected, "json")


def test_format_record_txt_and_json() -> None:
    rec = {
        "status": "valid_credentials",
        "host": "h",
        "port": 50051,
        "services": ["s1", "s2"],
        "methods": [{"service": "s1", "method": "m1"}],
    }
    assert grpc._format_record(rec, "json").startswith("{")
    assert isinstance(grpc._format_record(rec, "txt"), str)


def test_format_detail_records_empty_for_non_deep_status() -> None:
    assert grpc._format_detail_records({"status": "auth_required"}, "txt") == []
    assert grpc._format_detail_records({"status": "fail"}, "json") == []


def test_format_detail_records_rich_record() -> None:
    rec = {
        "status": "open_no_auth",
        "host": "h",
        "port": 50051,
        "reflection_enabled": True,
        "health_supported": True,
        "services": ["grpc.health.v1.Health", "my.Svc"],
        "methods": [{"service": "my.Svc", "method": "DoThing"}],
        "descriptors": [{"name": "my.proto"}],
        "health_checks": [{"service": "my.Svc", "status": "SERVING"}],
        "invoke_result": {"ok": True, "messages": ["{}"]},
    }
    json_lines = grpc._format_detail_records(rec, "json")
    assert any("grpc_reflection_services" in line for line in json_lines)
    assert any("grpc_invoke_result" in line for line in json_lines)
    txt_lines = grpc._format_detail_records(rec, "txt")
    assert isinstance(txt_lines, list) and txt_lines


# ---- _audit_grpc_host flow (mock detect + credentials, no network) ----


def _detect(**over: object) -> dict[str, object]:
    base: dict[str, object] = {"status": "open", "auth_required": False, "is_grpc": True, "transport_mode": "h2c"}
    base.update(over)
    return base


def test_audit_grpc_host_open_no_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(grpc, "_detect_grpc_target", lambda *_a, **_k: _detect())
    rec = grpc._audit_grpc_host(
        "h",
        50051,
        1.0,
        0,
        token=None,
        username=None,
        password=None,
        defcreds=False,
        preferred_scheme=None,
        run_deep_checks=False,
    )
    assert rec["status"] == "open_no_auth"
    assert rec["is_grpc"] is True


def test_audit_grpc_host_valid_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(grpc, "_detect_grpc_target", lambda *_a, **_k: _detect(auth_required=True))
    monkeypatch.setattr(
        grpc,
        "_try_credentials",
        lambda *_a, **_k: (True, {"type": "basic", "username": "u", "password": "p"}, {"call": {"is_grpc": True}}),
    )
    rec = grpc._audit_grpc_host(
        "h",
        50051,
        1.0,
        0,
        token=None,
        username="u",
        password="p",
        defcreds=False,
        preferred_scheme=None,
        run_deep_checks=False,
    )
    assert rec["status"] == "valid_credentials"


def test_audit_grpc_host_auth_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(grpc, "_detect_grpc_target", lambda *_a, **_k: _detect(auth_required=True))
    monkeypatch.setattr(grpc, "_try_credentials", lambda *_a, **_k: (False, None, {"call": {"is_grpc": True}}))
    rec = grpc._audit_grpc_host(
        "h",
        50051,
        1.0,
        0,
        token="bad",
        username=None,
        password=None,
        defcreds=False,
        preferred_scheme=None,
        run_deep_checks=False,
    )
    assert rec["status"] in {"auth_required", "invalid_credentials_anonymous"}


def test_audit_grpc_host_detect_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        grpc,
        "_detect_grpc_target",
        lambda *_a, **_k: {"status": "fail", "detect_error": "connection refused"},
    )
    rec = grpc._audit_grpc_host(
        "h",
        50051,
        1.0,
        0,
        token=None,
        username=None,
        password=None,
        defcreds=False,
        preferred_scheme=None,
        run_deep_checks=False,
    )
    assert rec["status"] == "fail"


# ---- _try_credentials (mock health/reflection calls) ----


def test_try_credentials_success_via_health(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(grpc, "_health_check_call", lambda *_a, **_k: {"grpc_status": 0, "call": {"is_grpc": True}})
    ok, cand, _attempt = grpc._try_credentials(
        "h",
        50051,
        timeout=1.0,
        use_tls=False,
        protocol_flavor="grpc",
        candidates=[{"type": "basic", "username": "u", "password": "p"}],
    )
    assert ok is True and cand is not None and cand["username"] == "u"


def test_try_credentials_reflection_path_and_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    auth_code = next(iter(grpc._GRPC_AUTH_CODES))
    monkeypatch.setattr(
        grpc, "_health_check_call", lambda *_a, **_k: {"grpc_status": auth_code, "call": {"is_grpc": True}}
    )
    monkeypatch.setattr(
        grpc,
        "_reflection_list_services_call",
        lambda *_a, **_k: {"grpc_status": 0, "call": {"is_grpc": True}},
    )
    ok, cand, _attempt = grpc._try_credentials(
        "h",
        50051,
        timeout=1.0,
        use_tls=False,
        protocol_flavor="grpc",
        candidates=[{"type": "basic", "username": "u", "password": "p"}],
    )
    assert ok is True  # reflection succeeded after health auth-fail


def test_try_credentials_grpc_web(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        grpc, "_grpc_web_health_check_call", lambda *_a, **_k: {"grpc_status": 0, "call": {"is_grpc": True}}
    )
    ok, _cand, _attempt = grpc._try_credentials(
        "h",
        50051,
        timeout=1.0,
        use_tls=False,
        protocol_flavor="grpc-web",
        candidates=[{"type": "token", "token": "t"}],
    )
    assert ok is True


def test_audit_grpc_host_deep_capabilities(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(grpc, "_detect_grpc_target", lambda *_a, **_k: _detect())
    monkeypatch.setattr(
        grpc,
        "_reflection_list_services_call",
        lambda *_a, **_k: {"reflection_enabled": True, "services": ["my.Svc"]},
    )
    monkeypatch.setattr(
        grpc,
        "_health_check_call",
        lambda *_a, **_k: {"health_supported": True, "grpc_status": 0, "serving_status": "SERVING"},
    )
    monkeypatch.setattr(
        grpc,
        "_reflection_file_descriptors_call",
        lambda *_a, **_k: {"descriptor_bytes": [b"proto-blob"]},
    )
    rec = grpc._audit_grpc_host(
        "h",
        50051,
        1.0,
        0,
        token=None,
        username=None,
        password=None,
        defcreds=False,
        preferred_scheme=None,
        run_deep_checks=True,
    )
    assert rec["status"] == "open_no_auth"
    assert rec.get("reflection_enabled") is True


# ---- _detect_grpc_target (mock health/reflection/grpc-web calls) ----


def test_detect_grpc_target_health_positive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        grpc,
        "_health_check_call",
        lambda *_a, **_k: {
            "call": {"is_grpc": True, "http_status": 200},
            "grpc_status": 0,
            "health_supported": True,
            "error": None,
        },
    )
    res = grpc._detect_grpc_target("h", 50051, timeout=1.0, preferred_scheme="http")
    assert res["is_grpc"] is True and res["protocol_flavor"] == "grpc"


def test_detect_grpc_target_grpc_web(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        grpc, "_health_check_call", lambda *_a, **_k: {"call": {"is_grpc": False, "transport_ok": True}, "error": None}
    )
    monkeypatch.setattr(
        grpc,
        "_reflection_list_services_call",
        lambda *_a, **_k: {"call": {"is_grpc": False, "transport_ok": True}, "error": None},
    )
    monkeypatch.setattr(
        grpc,
        "_grpc_web_health_check_call",
        lambda *_a, **_k: {"call": {"is_grpc_web": True, "http_status": 200}, "grpc_status": 0, "error": None},
    )
    res = grpc._detect_grpc_target("h", 50051, timeout=1.0, preferred_scheme="https")
    assert res["protocol_flavor"] == "grpc-web" and res["grpc_web_detected"] is True


def test_detect_grpc_target_not_grpc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        grpc, "_health_check_call", lambda *_a, **_k: {"call": {"is_grpc": False, "transport_ok": True}, "error": None}
    )
    monkeypatch.setattr(
        grpc,
        "_reflection_list_services_call",
        lambda *_a, **_k: {"call": {"is_grpc": False, "transport_ok": True}, "error": None},
    )
    monkeypatch.setattr(
        grpc,
        "_grpc_web_health_check_call",
        lambda *_a, **_k: {"call": {"is_grpc_web": False, "transport_ok": True}, "error": None},
    )
    res = grpc._detect_grpc_target("h", 50051, timeout=1.0, preferred_scheme=None)
    assert res["status"] == "not_grpc"


def test_detect_grpc_target_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    refused = {"call": {"is_grpc": False, "transport_ok": False}, "error": "connection refused"}
    monkeypatch.setattr(grpc, "_health_check_call", lambda *_a, **_k: refused)
    monkeypatch.setattr(grpc, "_reflection_list_services_call", lambda *_a, **_k: refused)
    monkeypatch.setattr(
        grpc,
        "_grpc_web_health_check_call",
        lambda *_a, **_k: {"call": {"is_grpc_web": False, "transport_ok": False}, "error": "connection refused"},
    )
    res = grpc._detect_grpc_target("h", 50051, timeout=1.0, preferred_scheme=None)
    assert res["status"] == "fail"
