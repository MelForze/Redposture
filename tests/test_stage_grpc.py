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
    audit_grpc_targets,
    run_grpc_stage,
)


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
        "status": "open_no_auth",
        "is_grpc": True,
        "auth_required": False,
        "transport_mode": "plaintext",
        "reflection_enabled": True,
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
    assert "anonymous access" in status_line
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
    calls: list[tuple[str, bool]] = []

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
        calls.append((host, run_deep_checks))
        if not run_deep_checks:
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

    monkeypatch.setattr(grpc_stage, "_call_audit_grpc_host_with_thread_debug", fake_call)

    lines: list[str] = []
    total, anonymous, valid, auth_required, not_grpc, failed = audit_grpc_targets(
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
    assert ("a", True) in calls
    assert ("b", True) not in calls
    assert ("c", True) not in calls
    assert any("gRPC Service" in line for line in lines)


def test_run_grpc_stage_respects_token_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []

    def fake_audit(**kwargs):
        captured.append(kwargs)
        return (1, 0, 0, 1, 0, 0)

    monkeypatch.setattr(grpc_stage, "audit_grpc_targets", fake_audit)

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
    assert captured[0]["token"] == "tok"
    assert captured[0]["username"] is None
    assert captured[0]["password"] is None


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

    def fake_audit(**kwargs):
        emit = kwargs["emit_line"]
        emit("GRPC    \t127.0.0.1\t50051\t service=grpc.health.v1.Health")
        return (1, 1, 0, 0, 0, 0)

    monkeypatch.setattr(grpc_stage, "Console", DummyConsole)
    monkeypatch.setattr(grpc_stage, "_render_colored_grpc_line", lambda _console, _line: False)
    monkeypatch.setattr(grpc_stage, "audit_grpc_targets", fake_audit)

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

    monkeypatch.setattr(grpc_stage, "_grpc_call", fake_grpc_call)

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
    monkeypatch.setattr(grpc_stage, "_reflection_list_services_call", native_reflection)
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


def test_retry_delay_is_exponential_capped() -> None:
    assert _retry_delay(0) == pytest.approx(0.2)
    assert _retry_delay(1) == pytest.approx(0.4)
    assert _retry_delay(10) <= 1.5
