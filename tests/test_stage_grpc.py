from __future__ import annotations

import shutil
from types import SimpleNamespace

import pytest

import redposture_core.stage_grpc as grpc_stage
from redposture_core.stage_grpc import (
    _auth_attempt_entries,
    _decode_grpc_frames,
    _encode_grpc_frame,
    _extract_descriptors,
    _format_detail_records,
    _format_detect_record,
    _format_record,
    _merge_stage2_record,
    _nxc_prefix,
    _retry_delay,
    run_grpc_stage,
)
from tests.stage_runtime_helpers import patch_module_host_stage_for_test, run_module_targets_for_test


def test_grpc_frame_roundtrip_and_truncation() -> None:
    frame = _encode_grpc_frame(b"hello") + _encode_grpc_frame(b"world")
    messages, error = _decode_grpc_frames(frame)
    assert messages == [b"hello", b"world"]
    assert error is None

    truncated = frame[:-2]
    messages, error = _decode_grpc_frames(truncated)
    assert messages == [b"hello"]
    assert error == "truncated gRPC frame"


def test_auth_attempt_entries_token_priority_and_defcreds() -> None:
    entries = _auth_attempt_entries(token="tok", username="admin", password="admin", defcreds=True)
    assert entries[0]["type"] == "token"
    assert entries[0]["token"] == "tok"

    basic_labels = {(entry.get("username"), entry.get("password")) for entry in entries if entry.get("type") == "basic"}
    assert ("admin", "admin") in basic_labels
    assert ("root", "root") in basic_labels


def test_extract_descriptors_builds_full_method_entries() -> None:
    fd = grpc_stage.descriptor_pb2.FileDescriptorProto()
    fd.name = "demo.proto"
    fd.package = "demo"
    service = fd.service.add()
    service.name = "Greeter"
    method = service.method.add()
    method.name = "Ping"
    method.input_type = ".demo.PingRequest"
    method.output_type = ".demo.PingResponse"

    methods, descriptors = _extract_descriptors([fd.SerializeToString()])

    assert len(methods) == 1
    assert methods[0]["full_method"] == "/demo.Greeter/Ping"
    assert methods[0]["input_type"] == "demo.PingRequest"
    assert len(descriptors) == 1
    assert descriptors[0]["file"] == "demo.proto"


def test_record_formatters_cover_core_statuses() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 50051,
        "status": "detected",
        "is_grpc": True,
        "auth_required": None,
        "health_access": "anonymous",
        "reflection_access": "anonymous",
        "invoke_access": "not_tested",
        "transport_mode": "plaintext",
        "reflection_enabled": True,
        "analysis_performed": True,
        "health_supported": True,
        "services": ["grpc.health.v1.Health"],
        "methods": [{"full_method": "/grpc.health.v1.Health/Check"}],
        "descriptors": [{"file": "grpc_health/v1/health.proto", "package": "grpc.health.v1", "services": [{}]}],
        "health_checks": [{"service": "", "grpc_status_name": "OK", "serving_status": "SERVING"}],
    }

    detect_line = _format_detect_record(record, "txt")
    status_line = _format_record(record, "txt")
    detail_lines = _format_detail_records(record, "txt")

    assert detect_line.startswith(_nxc_prefix(record))
    assert "gRPC Service" in detect_line
    assert "(reflection:enabled)" in detect_line
    assert "health_access:" not in detect_line
    assert "reflection_access:" not in detect_line
    assert "invoke_access:" not in detect_line
    assert status_line == ""
    assert "anonymous access" not in "\n".join([detect_line, status_line, *detail_lines])
    assert not any("Reflection (" in line for line in detail_lines)
    assert "(services:" not in status_line
    assert "(methods:" not in status_line
    assert any("[*] 1 Services" in line for line in detail_lines)
    assert any("[*] 1 Methods" in line for line in detail_lines)
    assert any("[*] 1 Descriptors" in line for line in detail_lines)
    assert any("[*] 1 Health Checks" in line for line in detail_lines)
    assert any("service=grpc.health.v1.Health" in line for line in detail_lines)

    fail_line = _format_record({"host": "1.1.1.1", "port": 5000, "status": "fail", "error": "boom"}, "txt")
    assert "connection failed" in fail_line


def test_merge_stage2_record_preserves_debug_and_stages() -> None:
    detect = {
        "status": "open_no_auth",
        "debug_events": ["detect-1"],
        "debug_events_streamed": False,
        "stages": [{"stage_name": "detect_protocol"}],
        "stage_durations_ms": {"detect_protocol": 10},
        "stage_attempts": {"detect_protocol": 1},
    }
    deep = {
        "status": "open_no_auth",
        "debug_events": ["data-1"],
        "debug_events_streamed": True,
        "stages": [{"stage_name": "data"}],
        "stage_durations_ms": {"data": 20},
        "stage_attempts": {"data": 1},
    }

    merged = _merge_stage2_record(detect, deep)
    assert merged["debug_events"] == ["detect-1", "data-1"]
    assert merged["debug_events_streamed"] is True
    assert len(merged["stages"]) == 2
    assert merged["stage_durations_ms"]["detect_protocol"] == 10
    assert merged["stage_durations_ms"]["data"] == 20


def test_call_with_stage_debug_adds_stage_telemetry(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_audit(*_args, **_kwargs):
        return {
            "timestamp": "2026-01-01T00:00:00Z",
            "host": "127.0.0.1",
            "port": 50051,
            "status": "open_no_auth",
            "is_grpc": True,
            "auth_required": False,
            "stage_detect_ms": 3,
            "stage_auth_ms": 2,
            "stage_capabilities_ms": 1,
            "stage_data_ms": 4,
            "stage_attempts_used": 1,
        }

    monkeypatch.setattr(grpc_stage, "_audit_grpc_host", fake_audit)

    debug_lines: list[str] = []
    record = grpc_stage._call_audit_grpc_host_with_stage_debug(
        "127.0.0.1",
        50051,
        1.0,
        2,
        token=None,
        username=None,
        password=None,
        defcreds=False,
        preferred_scheme=None,
        debug=True,
        run_deep_checks=True,
        debug_emit=debug_lines.append,
    )

    assert "stages" in record
    assert record["stage_durations_ms"]["detect_protocol"] == 3
    assert any("stage_trace stage_name=detect_protocol" in line for line in debug_lines)
    assert any("stage_timing_summary" in line for line in debug_lines)


def test_audit_grpc_targets_two_pass_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, bool, bool]] = []

    def fake_call(
        host: str,
        port: int,
        timeout: float,
        retries: int,
        *,
        token: str | None,
        username: str | None,
        password: str | None,
        defcreds: bool,
        preferred_scheme: str | None,
        debug: bool,
        run_deep_checks: bool,
        analyze: bool,
        schema_descriptor_bytes=None,
        invoke_path=None,
        invoke_request_json=None,
        metadata=None,
        debug_emit=None,
    ):
        _ = (
            port,
            timeout,
            retries,
            token,
            username,
            password,
            defcreds,
            preferred_scheme,
            debug,
            schema_descriptor_bytes,
            invoke_path,
            invoke_request_json,
            metadata,
            debug_emit,
        )
        calls.append((host, run_deep_checks, analyze))
        if not (run_deep_checks and analyze):
            if host == "a":
                return {"host": host, "port": 50051, "status": "open_no_auth", "is_grpc": True}
            if host == "b":
                return {"host": host, "port": 50051, "status": "auth_required", "is_grpc": True}
            return {"host": host, "port": 50051, "status": "not_grpc", "is_grpc": False}

        return {
            "host": host,
            "port": 50051,
            "status": "open_no_auth",
            "is_grpc": True,
            "reflection_enabled": True,
            "health_supported": True,
            "services": [],
            "methods": [],
            "descriptors": [],
            "health_checks": [],
        }

    monkeypatch.setattr(grpc_stage, "_call_audit_grpc_host_with_stage_debug", fake_call)

    lines: list[str] = []
    total, anonymous, valid, auth_required, not_grpc, failed = run_module_targets_for_test(
        "grpc",
        hosts=["a", "b", "c"],
        port=50051,
        timeout=1.0,
        retries=0,
        workers=4,
        token=None,
        username=None,
        password=None,
        defcreds=False,
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        show_progress=False,
    )

    assert total == 3
    assert anonymous == 1
    assert valid == 0
    assert auth_required == 1
    assert not_grpc == 1
    assert failed == 0
    assert not any(run_deep and analyze for _host, run_deep, analyze in calls)
    assert any("gRPC Service" in line for line in lines)


def test_run_grpc_stage_respects_token_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []

    def fake_host_stage(**kwargs):
        captured.append(kwargs)
        authenticated = kwargs["token"] is not None
        return {
            "host": kwargs["host"],
            "port": kwargs["port"],
            "is_grpc": True,
            "status": "valid_credentials" if authenticated else "auth_required",
            "auth_required": not authenticated,
        }

    patch_module_host_stage_for_test(monkeypatch, "grpc", fake_host_stage)

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=4,
        token="tok",
        username="admin",
        password="admin",
        defcreds=False,
        port=50051,
        ports="",
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        invoke=None,
        data=None,
        meta=None,
        proto=None,
        proto_path=None,
        protoset=None,
        openapi=None,
        output=None,
        output_format="json",
    )

    rc = run_grpc_stage(args, logger=SimpleNamespace(log=lambda *a, **k: None))

    assert rc == 0
    assert captured
    assert captured[0]["token"] is None
    assert captured[0]["username"] is None
    assert captured[0]["password"] is None
    authenticated_calls = [call for call in captured if call["token"] == "tok"]
    assert authenticated_calls
    assert all(call["username"] is None and call["password"] is None for call in authenticated_calls)


def test_run_grpc_stage_rejects_missing_targets() -> None:
    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=4,
        token=None,
        username=None,
        password=None,
        defcreds=False,
        port=50051,
        ports="",
        targets=None,
        hosts=None,
        hosts_file=None,
        invoke=None,
        data=None,
        meta=None,
        proto=None,
        proto_path=None,
        protoset=None,
        openapi=None,
        output=None,
        output_format="txt",
    )
    rc = run_grpc_stage(args, logger=SimpleNamespace(log=lambda *a, **k: None))
    assert rc == 2


@pytest.mark.parametrize(
    ("analyze", "invoke", "openapi", "expected"),
    [
        (False, None, None, False),
        (True, None, None, True),
        (False, "/pkg.Service/Method", None, True),
        (False, None, "grpc.openapi.json", True),
    ],
)
def test_grpc_analysis_is_explicit_or_implied_by_actions(
    analyze: bool,
    invoke: str | None,
    openapi: str | None,
    expected: bool,
) -> None:
    options = grpc_stage._build_grpc_host_stage_options(
        SimpleNamespace(
            analyze=analyze,
            invoke=invoke,
            openapi=openapi,
            data=None,
            meta=None,
            proto=None,
            proto_path=None,
            protoset=None,
        )
    )

    assert options["analyze"] is expected


@pytest.mark.parametrize(
    ("overrides", "expected_error"),
    [
        ({"invoke": "pkg.Service/Method"}, "--invoke must use /package.Service/Method"),
        ({"data": '{"service":""}'}, "--data requires --invoke"),
        ({"meta": ["x-lab=1"]}, "--meta requires --invoke"),
        ({"invoke": "/pkg.Service/Method", "meta": ["bad key=value"]}, "invalid metadata key"),
        ({"proto_path": ["proto"]}, "--proto-path requires --proto"),
    ],
)
def test_run_grpc_stage_rejects_action_input_before_runner(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    overrides: dict[str, object],
    expected_error: str,
) -> None:
    args_data: dict[str, object] = {
        "debug": False,
        "timeout": 1.0,
        "retries": 0,
        "workers": 1,
        "token": None,
        "username": None,
        "password": None,
        "defcreds": False,
        "port": 50051,
        "ports": "",
        "targets": "127.0.0.1",
        "hosts": None,
        "hosts_file": None,
        "invoke": None,
        "data": None,
        "meta": None,
        "proto": None,
        "proto_path": None,
        "protoset": None,
        "openapi": None,
        "output": None,
        "output_format": "txt",
    }
    args_data.update(overrides)
    monkeypatch.setattr(
        "redposture_core.modules.grpc.stage.AuditCommandRunner.run_plan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("runner/network must not start")),
    )

    rc = run_grpc_stage(
        SimpleNamespace(**args_data),
        logger=SimpleNamespace(log=lambda *_args, **_kwargs: None),
    )

    assert rc == 2
    captured = capsys.readouterr()
    assert expected_error in captured.out + captured.err


def test_run_grpc_stage_rejects_missing_data_file_before_runner(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path,
) -> None:
    missing_file = tmp_path / "missing.json"
    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=1,
        token=None,
        username=None,
        password=None,
        defcreds=False,
        port=50051,
        ports="",
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        invoke="/pkg.Service/Method",
        data=f"@{missing_file}",
        meta=None,
        proto=None,
        proto_path=None,
        protoset=None,
        openapi=None,
        output=None,
        output_format="txt",
    )
    monkeypatch.setattr(
        "redposture_core.modules.grpc.stage.AuditCommandRunner.run_plan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("runner/network must not start")),
    )

    rc = run_grpc_stage(args, logger=SimpleNamespace(log=lambda *_args, **_kwargs: None))

    assert rc == 2
    captured = capsys.readouterr()
    assert str(missing_file) in captured.out + captured.err


def test_run_grpc_stage_prints_non_marker_lines_in_non_debug(monkeypatch: pytest.MonkeyPatch) -> None:
    class DummyConsole:
        instances: list[DummyConsole] = []

        def __init__(self, *args, **kwargs) -> None:
            _ = (args, kwargs)
            self.plain_lines: list[str] = []
            DummyConsole.instances.append(self)

        def plain(self, message: str) -> None:
            self.plain_lines.append(message)

        def warn(self, _message: str) -> None:
            return None

        def error(self, _message: str) -> None:
            return None

        def info(self, _message: str) -> None:
            return None

    def fake_host_stage(**kwargs):
        analysis_performed = bool(kwargs["run_deep_checks"] and kwargs["analyze"])
        return {
            "host": kwargs["host"],
            "port": kwargs["port"],
            "is_grpc": True,
            "status": "open_no_auth",
            "auth_required": False,
            "reflection_enabled": True,
            "analysis_performed": analysis_performed,
            "services": ["grpc.health.v1.Health"],
            "methods": [],
            "descriptors": [],
            "health_supported": True,
            "health_checks": [],
        }

    monkeypatch.setattr(grpc_stage, "Console", DummyConsole)
    monkeypatch.setattr(grpc_stage, "_render_colored_grpc_line", lambda _console, _line: False)
    patch_module_host_stage_for_test(monkeypatch, "grpc", fake_host_stage)

    args = SimpleNamespace(
        debug=False,
        timeout=1.0,
        retries=0,
        workers=4,
        token=None,
        username=None,
        password=None,
        defcreds=False,
        analyze=True,
        port=50051,
        ports="",
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        invoke=None,
        data=None,
        meta=None,
        proto=None,
        proto_path=None,
        protoset=None,
        openapi=None,
        output=None,
        output_format="txt",
    )

    rc = run_grpc_stage(args, logger=SimpleNamespace(log=lambda *a, **k: None))
    assert rc == 0
    assert DummyConsole.instances
    assert any("service=grpc.health.v1.Health" in line for line in DummyConsole.instances[0].plain_lines)


def test_invoke_unary_method_encodes_request_and_decodes_response(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_grpc_call(*_args, **kwargs):
        seen.update(kwargs)
        request = grpc_stage.grpc_health_pb2.HealthCheckRequest()
        request.ParseFromString(kwargs["payload"])
        assert request.service == "grpc.health.v1.Health"
        response = grpc_stage.grpc_health_pb2.HealthCheckResponse(
            status=grpc_stage.grpc_health_pb2.HealthCheckResponse.SERVING
        )
        return {"grpc_status": 0, "grpc_message": "", "messages": [response.SerializeToString()], "error": None}

    monkeypatch.setattr("redposture_core.clients.grpc._grpc_call", fake_grpc_call)

    result = grpc_stage._invoke_unary_method(
        "127.0.0.1",
        50051,
        timeout=1.0,
        use_tls=False,
        protocol_flavor="grpc",
        authorization="Bearer token",
        metadata=[("x-lab", "1")],
        descriptor_bytes=[grpc_stage.grpc_health_pb2.DESCRIPTOR.serialized_pb],
        invoke_path="/grpc.health.v1.Health/Check",
        request_json={"service": "grpc.health.v1.Health"},
    )

    assert result["status"] == "ok"
    assert result["response"] == {"status": "SERVING"}
    assert seen["metadata"] == [("x-lab", "1")]
    assert seen["authorization"] == "Bearer token"


def test_invoke_streaming_method_is_unsupported() -> None:
    result = grpc_stage._invoke_unary_method(
        "127.0.0.1",
        50051,
        timeout=1.0,
        use_tls=False,
        protocol_flavor="grpc",
        authorization=None,
        metadata=[],
        descriptor_bytes=[grpc_stage.grpc_health_pb2.DESCRIPTOR.serialized_pb],
        invoke_path="/grpc.health.v1.Health/Watch",
        request_json={},
    )

    assert result["status"] == "unsupported"
    assert result["error"] == "unsupported streaming method"


def test_parse_json_payload_source_inline_and_file(tmp_path) -> None:
    data_file = tmp_path / "payload.json"
    data_file.write_text('{"service":"svc"}', encoding="utf-8")

    assert grpc_stage._parse_json_payload_source('{"service":""}') == {"service": ""}
    assert grpc_stage._parse_json_payload_source(f"@{data_file}") == {"service": "svc"}
    assert grpc_stage._parse_json_payload_source(None) == {}


def test_parse_metadata_items_rejects_reserved_headers() -> None:
    assert grpc_stage._parse_metadata_items(["x-one=1", "x-two=2"]) == [("x-one", "1"), ("x-two", "2")]
    with pytest.raises(ValueError):
        grpc_stage._parse_metadata_items(["authorization=Bearer test"])


def test_protoset_load_and_openapi_generation(tmp_path) -> None:
    descriptor_set = grpc_stage.descriptor_pb2.FileDescriptorSet()
    fd = descriptor_set.file.add()
    fd.ParseFromString(grpc_stage.grpc_health_pb2.DESCRIPTOR.serialized_pb)
    protoset = tmp_path / "health.protoset"
    protoset.write_bytes(descriptor_set.SerializeToString())

    descriptor_bytes = grpc_stage._load_explicit_descriptor_bytes(None, None, [str(protoset)])
    document = grpc_stage._generate_openapi_document(descriptor_bytes)

    operation = document["paths"]["/grpc.health.v1.Health/Check"]["post"]
    assert operation["x-grpc-service"] == "grpc.health.v1.Health"
    assert operation["x-grpc-method"] == "Check"
    assert operation["x-grpc-streaming"] == {"client": False, "server": False}


def test_descriptor_pool_skips_duplicate_symbols_from_different_files() -> None:
    first = grpc_stage.descriptor_pb2.FileDescriptorProto()
    first.ParseFromString(grpc_stage.grpc_health_pb2.DESCRIPTOR.serialized_pb)
    second = grpc_stage.descriptor_pb2.FileDescriptorProto()
    second.CopyFrom(first)
    second.name = "alternate_health.proto"

    pool, errors = grpc_stage._descriptor_bytes_to_pool([first.SerializeToString(), second.SerializeToString()])

    assert errors == []
    assert pool.FindMessageTypeByName("grpc.health.v1.HealthCheckRequest").full_name == (
        "grpc.health.v1.HealthCheckRequest"
    )


def test_proto_compile_smoke_when_grpc_tools_available() -> None:
    if shutil.which("protoc") is None:
        pytest.importorskip("grpc_tools")
    descriptor_bytes = grpc_stage._compile_proto_files(
        ["redposture_core/proto/grpc_health.proto"],
        ["redposture_core/proto"],
    )
    methods, _descriptors = _extract_descriptors(descriptor_bytes)
    assert any(method["full_method"] == "/grpc.health.v1.Health/Check" for method in methods)


def test_detect_grpc_web_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def native_health(*_args, **_kwargs):
        return {"call": {"is_grpc": False, "transport_ok": False, "use_tls": False}, "error": "native failed"}

    def native_reflection(*_args, **_kwargs):
        return {"call": {"is_grpc": False, "transport_ok": False, "use_tls": False}, "error": "native failed"}

    def web_health(*_args, **_kwargs):
        return {
            "call": {"is_grpc": True, "is_grpc_web": True, "transport_ok": True, "http_status": 200},
            "grpc_status": 0,
            "health_supported": True,
            "error": None,
        }

    monkeypatch.setattr(grpc_stage, "_health_check_call", native_health)
    monkeypatch.setattr(grpc_stage, "_reflection_capability_call", native_reflection)
    monkeypatch.setattr(grpc_stage, "_grpc_web_health_check_call", web_health)

    result = grpc_stage._detect_grpc_target("127.0.0.1", 50071, timeout=1.0, preferred_scheme="http")

    assert result["is_grpc"] is True
    assert result["protocol_flavor"] == "grpc-web"
    assert result["grpc_web_detected"] is True


def test_render_colored_grpc_line_highlights_entities() -> None:
    class DummyConsole:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def _paint(self, text, color, _stream):
            return f"<{color}>{text}</{color}>"

        def plain(self, message: str) -> None:
            self.lines.append(message)

    console = DummyConsole()
    rendered = grpc_stage._render_colored_grpc_line(
        console,
        "GRPC    \t127.0.0.1\t50051\t service=grpc.health.v1.Health",
    )

    assert rendered is True
    assert "<orange>service=grpc.health.v1.Health</orange>" in console.lines[0]

    console = DummyConsole()
    rendered = grpc_stage._render_colored_grpc_line(
        console,
        "GRPC    \t127.0.0.1\t50051\t service=grpc.health.v1.Health grpc=OK status=SERVING",
    )

    assert rendered is True
    assert "<orange> service=grpc.health.v1.Health grpc=OK status=SERVING</orange>" in console.lines[0]
    assert "grpc=OK status=SERVING</orange>" in console.lines[0]

    console = DummyConsole()
    rendered = grpc_stage._render_colored_grpc_line(
        console,
        (
            "GRPC    \t127.0.0.1\t50051\t "
            "/grpc.health.v1.Health/Check input=grpc.health.v1.HealthCheckRequest "
            "output=grpc.health.v1.HealthCheckResponse client_stream=False server_stream=False"
        ),
    )

    assert rendered is True
    assert (
        "<orange> /grpc.health.v1.Health/Check input=grpc.health.v1.HealthCheckRequest "
        "output=grpc.health.v1.HealthCheckResponse client_stream=False server_stream=False</orange>"
    ) in console.lines[0]

    console = DummyConsole()
    rendered = grpc_stage._render_colored_grpc_line(
        console,
        "GRPC    \t127.0.0.1\t50051\t [*] 2 Services",
    )

    assert rendered is True
    assert "<orange>2 Services</orange>" not in console.lines[0]


def test_retry_delay_is_exponential_capped() -> None:
    assert _retry_delay(0) == pytest.approx(0.2)
    assert _retry_delay(1) == pytest.approx(0.4)
    assert _retry_delay(10) <= 1.5


# --- Wave 2 (gRPC actions coverage): pure-function unit tests ---------------------


def test_is_retryable_stage_error_recognizes_connection_prefixes() -> None:
    assert grpc_stage._is_retryable_stage_error("connection refused by remote") is True
    assert grpc_stage._is_retryable_stage_error("connection timeout after 5s") is True
    assert grpc_stage._is_retryable_stage_error("CONNECTION REFUSED on socket") is True
    assert grpc_stage._is_retryable_stage_error("permission denied") is False
    assert grpc_stage._is_retryable_stage_error(None) is False
    assert grpc_stage._is_retryable_stage_error("") is False
    assert grpc_stage._is_retryable_stage_error(0) is False


def test_credential_label_token_basic_and_fallback() -> None:
    assert grpc_stage._credential_label({"type": "token", "token": "abc"}) == "token"
    assert grpc_stage._credential_label({"type": "basic", "username": "u", "password": "p"}) == "u:p"
    # empty password rendered as <empty> sentinel
    assert grpc_stage._credential_label({"type": "basic", "username": "u", "password": ""}) == "u:<empty>"
    # missing username defaults to "user"
    assert grpc_stage._credential_label({"type": "basic", "password": "p"}) == "user:p"
    # unknown type falls back to "credentials"
    assert grpc_stage._credential_label({"type": "weird"}) == "credentials"
    assert grpc_stage._credential_label({}) == "credentials"


def test_format_status_label_known_and_unknown() -> None:
    assert grpc_stage._format_status_label("open_no_auth") == "anonymous access"
    assert grpc_stage._format_status_label("valid_credentials") == "valid credentials"
    assert grpc_stage._format_status_label("weak_default_creds") == "weak default credentials"
    assert grpc_stage._format_status_label("auth_required") == "authentication required"
    assert grpc_stage._format_status_label("invalid_credentials_anonymous") == "invalid credentials (anonymous works)"
    assert grpc_stage._format_status_label("not_grpc") == "not grpc"
    assert grpc_stage._format_status_label("fail") == "fail"
    # Unknown labels pass through unchanged
    assert grpc_stage._format_status_label("custom_state") == "custom_state"


def test_auth_required_text_three_states() -> None:
    assert grpc_stage._auth_required_text(True) == "True"
    assert grpc_stage._auth_required_text(False) == "False"
    assert grpc_stage._auth_required_text(None) == "unknown"
    # Non-boolean truthy values flow through "unknown" branch (not bool-True).
    assert grpc_stage._auth_required_text(1) == "unknown"
    assert grpc_stage._auth_required_text("True") == "unknown"


def test_auth_attempt_entries_token_precedes_basic_fallback() -> None:
    attempts = grpc_stage._auth_attempt_entries(token="t-token", username="u", password="p", defcreds=False)
    assert attempts == [
        {"type": "token", "token": "t-token", "source": "provided"},
        {"type": "basic", "username": "u", "password": "p", "source": "provided"},
    ]


def test_auth_attempt_entries_basic_only_when_both_username_and_password() -> None:
    attempts = grpc_stage._auth_attempt_entries(token=None, username="user", password="pass", defcreds=False)
    assert attempts == [{"type": "basic", "username": "user", "password": "pass", "source": "provided"}]
    # Missing password drops the basic attempt entirely.
    assert grpc_stage._auth_attempt_entries(token=None, username="user", password=None, defcreds=False) == []


def test_auth_attempt_entries_defcreds_appends_default_tokens_and_basics() -> None:
    attempts = grpc_stage._auth_attempt_entries(token=None, username=None, password=None, defcreds=True)
    assert [item["token"] for item in attempts if item["type"] == "token"] == [
        "admin",
        "token",
        "secret",
        "changeme",
        "grpc",
        "default-token",
    ]
    assert [(item["username"], item["password"]) for item in attempts if item["type"] == "basic"] == [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("root", "admin"),
        ("grpc", "grpc"),
        ("service", "service"),
        ("test", "test"),
        ("user", "password"),
        ("admin", "changeme"),
        ("root", "password"),
        ("grpc", "password"),
        ("grpc", "admin"),
        ("service", "password"),
        ("user", "user"),
        ("guest", "guest"),
        ("dev", "dev"),
    ]
    assert all(a["source"] == "defcreds" for a in attempts)


def test_auth_attempt_entries_deduplicates_identical_basic_provided_vs_defcreds() -> None:
    # If a provided credential matches one of the defcreds, the second entry is dropped.
    attempts = grpc_stage._auth_attempt_entries(token=None, username="user", password="user", defcreds=True)
    keys = [(a["type"], a.get("username") or a.get("token"), a.get("password")) for a in attempts]
    # No duplicate (basic, "user", "user") combinations even though both sources would produce one.
    assert keys.count(("basic", "user", "user")) == 1


def test_auth_required_from_grpc_status_classification() -> None:
    assert grpc_stage._auth_required_from_grpc_status(16) is True  # UNAUTHENTICATED
    assert grpc_stage._auth_required_from_grpc_status(7) is True  # PERMISSION_DENIED
    assert grpc_stage._auth_required_from_grpc_status(0) is False  # OK -> auth not required
    assert grpc_stage._auth_required_from_grpc_status(None) is None  # unknown
