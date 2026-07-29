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
    assert grpc._format_status_label("invalid_credentials") == "invalid credentials"
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
    assert grpc._access_from_grpc_status(0) == "anonymous"
    assert grpc._access_from_grpc_status(0, used_credentials=True) == "authenticated"
    assert grpc._access_from_grpc_status(code) == "auth_required"
    assert grpc._access_from_grpc_status(grpc._GRPC_UNIMPLEMENTED) == "unsupported"
    assert grpc._access_from_grpc_status(None) == "unknown"


def test_merge_access_distinguishes_auth_transition_from_mixed_acl() -> None:
    assert grpc._merge_access("auth_required", "authenticated") == "authenticated"
    assert grpc._merge_access("authenticated", "auth_required") == "mixed"


def test_is_retryable_and_suppressed() -> None:
    assert grpc._is_suppressed_fail_record({"status": "fail"}) is True
    assert grpc._is_suppressed_fail_record({"status": "open_no_auth"}) is False


def test_grpc_deep_gate_prioritizes_requested_action_over_credential_status() -> None:
    assert grpc.grpc_deep_gate({"status": "valid_credentials", "action_access_satisfied": False}) == (
        False,
        "grpc action access unresolved",
    )
    assert grpc.grpc_deep_gate({"status": "invalid_credentials", "action_access_satisfied": True}) == (
        True,
        "grpc action access satisfied",
    )
    assert grpc.grpc_deep_gate({"status": "detected"}) == (True, "status=detected")


# ---- render / format functions (crafted records, no network) ----


def test_format_detect_record_branches() -> None:
    fail = {"status": "fail", "error": "[Errno 61] Connection refused", "host": "h", "port": 50051}
    assert "connection failed" in grpc._format_detect_record(fail, "txt")
    assert grpc._format_detect_record({"status": "fail", "host": "h", "port": 1}, "txt").endswith("connection failed")
    assert "not a gRPC service" in grpc._format_detect_record({"status": "not_grpc", "host": "h", "port": 1}, "txt")
    detected = {
        "status": "detected",
        "is_grpc": True,
        "auth_required": None,
        "health_access": "anonymous",
        "reflection_access": "anonymous",
        "invoke_access": "not_tested",
        "transport_mode": "h2c",
        "protocol_flavor": "grpc",
        "reflection_enabled": True,
        "host": "h",
        "port": 50051,
    }
    line = grpc._format_detect_record(detected, "txt")
    assert "gRPC Service" in line and "transport:h2c" in line
    assert line.endswith("(reflection:enabled)")
    assert "health_access:" not in line
    assert "reflection_access:" not in line
    assert "invoke_access:" not in line
    assert "(reflection:disable)" in grpc._format_detect_record({**detected, "reflection_enabled": False}, "txt")
    assert "(reflection:unknown)" in grpc._format_detect_record({**detected, "reflection_enabled": None}, "txt")
    json_line = grpc._format_detect_record(detected, "json")
    assert '"detected": true' in json_line
    assert '"health_access": "anonymous"' in json_line


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
    weak = {**rec, "status": "weak_default_creds", "auth_used": {"type": "token", "source": "defcreds"}}
    assert grpc._format_record(weak, "txt").endswith("[+] token")


def test_format_record_renders_failed_token_type_and_source() -> None:
    line = grpc._format_record(
        {
            "host": "h",
            "port": 50051,
            "status": "invalid_credentials",
            "provided_credentials": True,
            "provided_credential_type": "token",
            "provided_credential_source": "default",
        },
        "txt",
    )
    assert line.endswith("[-] token (source:default)")
    assert "user:" not in line


def test_format_detail_records_empty_for_non_deep_status() -> None:
    assert grpc._format_detail_records({"status": "auth_required"}, "txt") == []
    assert grpc._format_detail_records({"status": "fail"}, "json") == []
    assert grpc._format_detail_records({"status": "open_no_auth", "analysis_performed": False}, "txt") == []


def test_format_detail_records_rich_record() -> None:
    rec = {
        "status": "open_no_auth",
        "host": "h",
        "port": 50051,
        "reflection_enabled": True,
        "analysis_performed": True,
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
    assert not any("Reflection (" in line for line in txt_lines)


# ---- _audit_grpc_host flow (mock detect + credentials, no network) ----


def _detect(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "status": "detected",
        "auth_required": None,
        "health_access": "anonymous",
        "reflection_access": "unknown",
        "invoke_access": "not_tested",
        "is_grpc": True,
        "transport_mode": "h2c",
    }
    base.update(over)
    return base


def test_audit_grpc_host_public_health_does_not_imply_endpoint_anonymous(monkeypatch: pytest.MonkeyPatch) -> None:
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
    assert rec["status"] == "detected"
    assert rec["is_grpc"] is True
    assert rec["health_access"] == "anonymous"
    assert rec["auth_required"] is None


def test_audit_grpc_host_valid_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        grpc,
        "_detect_grpc_target",
        lambda *_a, **_k: _detect(health_access="auth_required"),
    )
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
    monkeypatch.setattr(
        grpc,
        "_detect_grpc_target",
        lambda *_a, **_k: _detect(health_access="auth_required"),
    )
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
    assert rec["status"] == "invalid_credentials"
    assert rec["health_access"] == "auth_required"
    assert rec["auth_required"] is None


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
        "_reflection_capability_call",
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


def test_try_credentials_does_not_validate_credentials_via_public_health(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        grpc,
        "_health_check_call",
        lambda *_a, **_k: {"grpc_status": 0, "call": {"is_grpc": True}},
    )
    monkeypatch.setattr(
        grpc,
        "_reflection_capability_call",
        lambda *_a, **_k: {"grpc_status": 12, "call": {"is_grpc": True}},
    )
    ok, candidate, _attempt = grpc._try_credentials(
        "h",
        50051,
        timeout=1.0,
        use_tls=False,
        protocol_flavor="grpc",
        candidates=[{"type": "token", "token": "ignored"}],
        health_access="anonymous",
        reflection_access="unsupported",
    )
    assert ok is False
    assert candidate is None


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
    assert rec["status"] == "detected"
    assert rec.get("reflection_enabled") is True
    assert rec["analysis_performed"] is True


def test_audit_grpc_host_skips_inventory_without_analyze(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(grpc, "_detect_grpc_target", lambda *_a, **_k: _detect(reflection_enabled=True))

    def unexpected(*_args, **_kwargs):
        raise AssertionError("deep inventory must require --analyze")

    monkeypatch.setattr(grpc, "_reflection_list_services_call", unexpected)
    monkeypatch.setattr(grpc, "_reflection_file_descriptors_call", unexpected)
    monkeypatch.setattr(grpc, "_health_check_call", unexpected)

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
        analyze=False,
    )

    assert rec["status"] == "detected"
    assert rec["reflection_enabled"] is True
    assert rec["analysis_performed"] is False
    assert rec["services"] is None


def test_grpc_web_analysis_keeps_unprobed_reflection_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        grpc,
        "_detect_grpc_target",
        lambda *_a, **_k: _detect(protocol_flavor="grpc-web", reflection_enabled=None),
    )
    monkeypatch.setattr(
        grpc,
        "_grpc_web_health_check_call",
        lambda *_a, **_k: {
            "health_supported": True,
            "grpc_status": 0,
            "grpc_status_name": "OK",
            "serving_status": "SERVING",
            "error": None,
        },
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
        analyze=True,
    )

    assert rec["analysis_performed"] is True
    assert rec["reflection_enabled"] is None


@pytest.mark.parametrize(
    ("invoke_status", "expected_access", "expected_status", "expected_auth_required"),
    [
        (0, "authenticated", "valid_credentials", None),
        (16, "auth_required", "invalid_credentials", None),
    ],
)
def test_invoke_uses_explicit_credentials_and_classifies_its_own_access(
    monkeypatch: pytest.MonkeyPatch,
    invoke_status: int,
    expected_access: str,
    expected_status: str,
    expected_auth_required: bool | None,
) -> None:
    monkeypatch.setattr(
        grpc,
        "_detect_grpc_target",
        lambda *_a, **_k: _detect(reflection_access="unsupported", reflection_enabled=False),
    )
    monkeypatch.setattr(
        grpc,
        "_reflection_list_services_call",
        lambda *_a, **_k: {"reflection_enabled": False, "grpc_status": 12, "services": []},
    )
    monkeypatch.setattr(
        grpc,
        "_health_check_call",
        lambda *_a, **_k: {"health_supported": True, "grpc_status": 0, "serving_status": "SERVING"},
    )
    seen_authorization: list[str | None] = []

    def fake_invoke(*_args, **kwargs):
        seen_authorization.append(kwargs.get("authorization"))
        return {
            "path": "/demo.Service/Get",
            "status": "ok" if invoke_status == 0 else "grpc_error",
            "grpc_status": invoke_status,
            "grpc_status_name": "OK" if invoke_status == 0 else "UNAUTHENTICATED",
        }

    monkeypatch.setattr(grpc, "_invoke_unary_method", fake_invoke)
    rec = grpc._audit_grpc_host(
        "h",
        50051,
        1.0,
        0,
        token="secret",
        username=None,
        password=None,
        defcreds=False,
        preferred_scheme=None,
        run_deep_checks=True,
        analyze=True,
        invoke_path="/demo.Service/Get",
    )

    assert seen_authorization == ["Bearer secret"]
    assert rec["invoke_access"] == expected_access
    assert rec["status"] == expected_status
    assert rec["auth_required"] is expected_auth_required


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
    monkeypatch.setattr(
        grpc,
        "_reflection_capability_call",
        lambda *_a, **_k: {
            "call": {"is_grpc": True, "http_status": 200},
            "grpc_status": 0,
            "reflection_enabled": True,
            "error": None,
        },
    )
    res = grpc._detect_grpc_target("h", 50051, timeout=1.0, preferred_scheme="http")
    assert res["is_grpc"] is True and res["protocol_flavor"] == "grpc"
    assert res["reflection_enabled"] is True
    assert res["health_access"] == "anonymous"
    assert res["reflection_access"] == "anonymous"
    assert res["invoke_access"] == "not_tested"
    assert res["auth_required"] is None
    assert [item["probe"] for item in res["detect_probe_trace"]] == ["health", "reflection"]


def test_detect_reflection_embedded_auth_error_is_not_anonymous(monkeypatch: pytest.MonkeyPatch) -> None:
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
    monkeypatch.setattr(
        grpc,
        "_reflection_capability_call",
        lambda *_a, **_k: {
            "call": {"is_grpc": True, "http_status": 200},
            "grpc_status": 0,
            "embedded_error_code": 16,
            "reflection_enabled": None,
            "error": "16:authentication required",
        },
    )
    res = grpc._detect_grpc_target("h", 50051, timeout=1.0, preferred_scheme="http")
    assert res["health_access"] == "anonymous"
    assert res["reflection_access"] == "auth_required"
    assert res["auth_required"] is None


def test_detect_grpc_target_grpc_web(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        grpc, "_health_check_call", lambda *_a, **_k: {"call": {"is_grpc": False, "transport_ok": True}, "error": None}
    )
    monkeypatch.setattr(
        grpc,
        "_reflection_capability_call",
        lambda *_a, **_k: {"call": {"is_grpc": False, "transport_ok": True}, "error": None},
    )
    monkeypatch.setattr(
        grpc,
        "_grpc_web_health_check_call",
        lambda *_a, **_k: {"call": {"is_grpc_web": True, "http_status": 200}, "grpc_status": 0, "error": None},
    )
    res = grpc._detect_grpc_target("h", 50051, timeout=1.0, preferred_scheme="https")
    assert res["protocol_flavor"] == "grpc-web" and res["grpc_web_detected"] is True
    assert res["reflection_enabled"] is None


def test_detect_grpc_target_not_grpc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        grpc, "_health_check_call", lambda *_a, **_k: {"call": {"is_grpc": False, "transport_ok": True}, "error": None}
    )
    monkeypatch.setattr(
        grpc,
        "_reflection_capability_call",
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
    monkeypatch.setattr(grpc, "_reflection_capability_call", lambda *_a, **_k: refused)
    monkeypatch.setattr(
        grpc,
        "_grpc_web_health_check_call",
        lambda *_a, **_k: {"call": {"is_grpc_web": False, "transport_ok": False}, "error": "connection refused"},
    )
    res = grpc._detect_grpc_target("h", 50051, timeout=1.0, preferred_scheme=None)
    assert res["status"] == "fail"
