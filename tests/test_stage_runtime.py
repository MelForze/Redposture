from __future__ import annotations

from redposture_core.stage_runtime import (
    AuditRecord,
    CapabilitySet,
    CredentialAttempt,
    LineOutputSink,
    StageTelemetryBuilder,
    StageTrace,
    TwoPassAuditRunner,
    format_pass_marker,
    format_retry_decision,
    format_stage2_gate,
    format_stage_trace,
    merge_stage_records,
    progress_total_from_groups,
    should_use_global_progress,
)


class _ProgressRecorder:
    def __init__(self) -> None:
        self.advanced = 0
        self.closed = False

    def advance(self, step: int = 1) -> None:
        self.advanced += step

    def set_total(self, total: int) -> None:
        return None

    def pause_for_output(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def test_merge_stage_records_combines_debug_and_stage_telemetry() -> None:
    detect = {
        "status": "auth_required",
        "debug_events": ["detect"],
        "debug_events_streamed": True,
        "stages": [{"stage_name": "detect_protocol", "result": "ok"}],
        "stage_durations_ms": {"detect_protocol": 10},
        "stage_attempts": {"detect_protocol": 2},
        "stage_failed_at": None,
    }
    deep = {
        "status": "valid_credentials",
        "debug_events": ["deep"],
        "debug_events_streamed": False,
        "stages": [{"stage_name": "data", "result": "ok"}],
        "stage_durations_ms": {"data": 20},
        "stage_attempts": {"data": 1},
        "stage_failed_at": "data",
    }

    merged = merge_stage_records(detect, deep)

    assert merged["status"] == "valid_credentials"
    assert merged["debug_events"] == ["detect", "deep"]
    assert merged["debug_events_streamed"] is True
    assert merged["stages"] == [
        {"stage_name": "detect_protocol", "result": "ok"},
        {"stage_name": "data", "result": "ok"},
    ]
    assert merged["stage_durations_ms"] == {"detect_protocol": 10, "data": 20}
    assert merged["stage_attempts"] == {"detect_protocol": 2, "data": 1}
    assert merged["stage_failed_at"] == "data"


def test_merge_stage_records_can_limit_deep_fields() -> None:
    merged = merge_stage_records(
        {"status": "auth_required", "version": "1.0"},
        {"status": "open_no_auth", "secret_detail": "skip"},
        deep_fields=("status",),
    )

    assert merged["status"] == "open_no_auth"
    assert merged["version"] == "1.0"
    assert "secret_detail" not in merged


def test_stage_runtime_debug_formatters_are_stable() -> None:
    assert (
        format_retry_decision("detect_protocol", 1, 4, 0.25, "timeout")
        == "retry_decision stage=detect_protocol attempt=1/4 backoff=0.25s reason=timeout"
    )
    assert (
        format_stage_trace("data", 2, 15, "ok")
        == "stage_trace stage_name=data attempt=2 duration_ms=15 result=ok error=-"
    )
    assert format_stage2_gate("127.0.0.1", 6379, "run", "status=open_no_auth") == (
        "127.0.0.1:6379 stage2_gate=run reason=status=open_no_auth"
    )
    assert format_pass_marker(1, "detect", "complete", targets=5, deep_candidates=2) == (
        "pass=1 detect complete targets=5 deep_candidates=2"
    )


def test_stage_telemetry_builder_buffers_and_attaches_debug_fields() -> None:
    streamed: list[str] = []
    telemetry = StageTelemetryBuilder(host="127.0.0.1", port=5432, attempts=3, debug=True, debug_emit=streamed.append)

    telemetry.retry("detect_protocol", 1, 0.2, "timeout")
    telemetry.stage("detect_protocol", "ok", duration_ms=5)
    telemetry.stage("data", "error", "permission denied", duration_ms=7)
    record = telemetry.attach({"status": "valid_credentials"}, status="valid_credentials", total_ms=12)

    assert any("retry_decision stage=detect_protocol" in event for event in record["debug_events"])
    assert any("stage_trace stage_name=data" in event for event in record["debug_events"])
    assert streamed and streamed[0].startswith("127.0.0.1:5432 ")
    assert record["stage_failed_at"] == "data"
    assert record["stage_durations_ms"] == {"detect_protocol": 5, "data": 7}
    assert record["stage_attempts"] == {"detect_protocol": 3, "data": 3}
    assert record["debug_events_streamed"] is True


def test_global_progress_policy_is_independent_from_output_destination() -> None:
    assert should_use_global_progress("txt", 1, 2) is True
    assert should_use_global_progress("txt", 2, 1) is True
    assert should_use_global_progress("txt", 1, 1) is True
    assert should_use_global_progress("txt", 0, 0) is False
    assert should_use_global_progress("json", 10, 10) is False
    assert progress_total_from_groups([["a", "b"], ["c"]], credential_runs=4) == 12
    assert progress_total_from_groups([(item for item in ("a", "b"))], credential_runs=2) == 4


def test_line_output_sink_emits_to_callback_and_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    emitted: list[str] = []
    callback_sink = LineOutputSink(None, emitted.append)
    callback_sink.emit_many([""])
    assert callback_sink.output_written is False
    callback_sink.emit_many(["one", "", "two"])
    assert emitted == ["one", "two"]
    assert callback_sink.output_written is True

    output_path = tmp_path / "nested" / "out.txt"
    file_sink = LineOutputSink(str(output_path), emitted.append)
    file_sink.emit_many(["first"])
    file_sink.emit_many(["second"])

    assert output_path.read_text(encoding="utf-8").splitlines() == ["first", "second"]
    assert emitted == ["one", "two"]


def test_typed_record_models_serialize_to_dicts() -> None:
    record = AuditRecord(
        host="127.0.0.1",
        port=9200,
        service="elastic",
        status="valid_credentials",
        auth_required=True,
        stages=(StageTrace("detect_protocol", duration_ms=3),),
        credentials=(CredentialAttempt(username="elastic", password="password", ok=True),),
        capabilities=CapabilitySet({"read": True, "write": False}, error="partial"),
        extra={"version": "8.13.4"},
    )

    payload = record.to_dict()

    assert payload["service"] == "elastic"
    assert payload["stages"] == [
        {"stage_name": "detect_protocol", "attempt": 1, "duration_ms": 3, "result": "ok", "error": None}
    ]
    assert payload["credential_attempts"][0]["username"] == "elastic"
    assert payload["capabilities"] == {"read": True, "write": False, "error": "partial"}
    assert payload["version"] == "8.13.4"


def test_two_pass_audit_runner_orders_detect_output_and_merges_deep_records() -> None:
    debug_events: list[str] = []
    emitted: list[str] = []
    progress = _ProgressRecorder()
    hosts = [(0, "a"), (1, "b"), (2, "c")]

    def detect(host: str) -> dict[str, object]:
        status = "open_no_auth" if host != "c" else "fail"
        return {"host": host, "port": 1234, "status": status, "is_service": host != "c"}

    def deep(host: str) -> dict[str, object]:
        return {"host": host, "port": 1234, "status": "open_no_auth", "deep": host}

    result = TwoPassAuditRunner(
        label="TEST",
        workers=2,
        debug_emit=debug_events.append,
        progress=progress,
        detected_name="service",
    ).run(
        hosts,
        detect_task=detect,
        deep_task=deep,
        is_detected=lambda record: bool(record.get("is_service")),
        deep_gate=lambda record: (
            str(record.get("host")) == "a",
            f"status={record.get('status')}",
        ),
        emit_detect=lambda record: emitted.append(str(record["host"])),
        not_detected_reason="not_service",
    )

    assert emitted == ["a", "b", "c"]
    assert result.detected_count == 2
    assert result.deep_candidates == [(0, "a")]
    assert result.final_records[0]["deep"] == "a"
    assert "deep" not in result.final_records[1]
    assert progress.advanced == 4
    assert debug_events[0] == "pass=1 detect start total=3"
    assert any("stage2_gate=skip reason=not_service" in event for event in debug_events)
    assert "pass=2 deep complete processed=1" in debug_events
