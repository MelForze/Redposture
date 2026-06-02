from __future__ import annotations

import pytest

from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    AuditRecord,
    CapabilitySet,
    CredentialAttempt,
    LineOutputSink,
    ModuleAuditSpec,
    ModuleRunSummary,
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
    validate_basic_module_args,
)


class _ProgressRecorder:
    def __init__(self) -> None:
        self.advanced = 0
        self.closed = False

    def advance(self, step: int = 1) -> None:
        self.advanced += step

    def set_total(self, total: int) -> None:
        return None

    def add_total(self, step: int = 1) -> None:
        return None

    def pause_for_output(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _ConsoleRecorder:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)


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


@pytest.mark.parametrize(
    "module",
    [
        "kafka",
        "registry",
        "postgres",
        "mongodb",
        "clickhouse",
        "zookeeper",
        "elastic",
        "grafana",
        "grpc",
        "kubeapi",
        "consul",
        "oracle",
        "proxmox",
    ],
)
def test_validate_basic_module_args_treats_empty_password_as_provided_for_auth_modules(module: str) -> None:
    console = _ConsoleRecorder()
    args = type(
        "Args",
        (),
        {
            "targets": "127.0.0.1",
            "hosts": None,
            "hosts_file": None,
            "timeout": 1.0,
            "retries": 0,
            "username": "empire",
            "password": "",
            "dump": False,
            "ports": None,
        },
    )()

    assert validate_basic_module_args(args, console, module=module, pure_http=module in {"registry"}) is None
    assert console.errors == []


def test_validate_basic_module_args_allows_redis_password_only_and_username_file_empty_password(tmp_path) -> None:  # type: ignore[no-untyped-def]
    console = _ConsoleRecorder()
    args = type(
        "Args",
        (),
        {
            "targets": "127.0.0.1",
            "hosts": None,
            "hosts_file": None,
            "timeout": 1.0,
            "retries": 0,
            "username": None,
            "password": "",
            "dump": False,
            "ports": None,
        },
    )()

    args.username = None
    assert validate_basic_module_args(args, console, module="redis") is None

    username_file = tmp_path / "users.txt"
    username_file.write_text("empire\n", encoding="utf-8")
    args.username = str(username_file)
    args.password = ""
    assert validate_basic_module_args(args, console, module="kafka") is None


def test_validate_basic_module_args_still_rejects_missing_password() -> None:
    console = _ConsoleRecorder()
    args = type(
        "Args",
        (),
        {
            "targets": "127.0.0.1",
            "hosts": None,
            "hosts_file": None,
            "timeout": 1.0,
            "retries": 0,
            "username": "empire",
            "password": None,
            "dump": False,
            "ports": None,
        },
    )()

    assert validate_basic_module_args(args, console, module="kafka") == 2
    assert "--username and --password must be set together" in console.errors[-1]


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


def test_audit_record_from_mapping_preserves_legacy_fields() -> None:
    record = AuditRecord.from_mapping(
        {
            "host": "127.0.0.1",
            "port": 6379,
            "module": "redis",
            "status": "open_no_auth",
            "auth_required": "false",
            "transport_mode": "plaintext",
            "stages": [{"stage": "detect_protocol", "duration_ms": 4}],
            "credential_attempts": [{"username": "default", "password": "redis", "ok": "true"}],
            "capabilities": {"read": True},
            "custom_field": "kept",
        },
        service="redis",
    )

    payload = record.to_dict()

    assert payload["service"] == "redis"
    assert payload["auth_required"] is False
    assert payload["transport"] == "plaintext"
    assert payload["stages"][0]["stage_name"] == "detect_protocol"
    assert payload["credential_attempts"][0]["ok"] is True
    assert payload["capabilities"] == {"read": True}
    assert payload["custom_field"] == "kept"


def test_audit_command_runner_requires_typed_hook_records() -> None:
    emitted: list[str] = []
    spec = ModuleAuditSpec(
        module="redis",
        label="REDIS",
        default_port=6379,
        detect=lambda host, port: AuditRecord(
            host=host,
            port=port,
            module="redis",
            service="redis",
            status="open_no_auth",
            auth_required=False,
            capabilities=CapabilitySet({"read": True}),
            extra={"legacy": "kept"},
        ),
        render=lambda record: [f"{record['host']}:{record['port']} {record['status']}"],
    )

    result = AuditCommandRunner(args=object(), spec=spec, emit_line=emitted.append).run_hosts(["127.0.0.1"])

    assert result.detected_count == 1
    assert isinstance(result.typed_records[0], AuditRecord)
    assert result.records[0]["service"] == "redis"
    assert result.records[0]["capabilities"] == {"read": True}
    assert result.records[0]["legacy"] == "kept"
    assert emitted == ["127.0.0.1:6379 open_no_auth"]


def test_audit_command_runner_rejects_dict_hook_records() -> None:
    spec = ModuleAuditSpec(
        module="redis",
        label="REDIS",
        default_port=6379,
        detect=lambda host, port: {"host": host, "port": port, "status": "open_no_auth"},  # type: ignore[return-value]
    )

    try:
        AuditCommandRunner(args=object(), spec=spec).run_hosts(["127.0.0.1"])
    except TypeError as exc:
        assert "hooks must return AuditRecord" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("dict hook result was accepted")


def test_audit_command_plan_tracks_targets_credentials_and_summary() -> None:
    plan = AuditCommandPlan(
        targets_by_port={6379: ("a", "b"), 6380: ("c",)},
        credential_runs=(
            AuditCredentialRun(username="admin", password="admin", source="file"),
            AuditCredentialRun(token="secret", source="token"),
        ),
        output_path="out.txt",
        workers=4,
    )

    assert plan.target_count == 3
    assert plan.credential_run_count == 2
    assert plan.total_work_units == 6
    assert plan.iter_targets() == [(0, "a", 6379), (1, "b", 6379), (2, "c", 6380)]
    assert plan.credential_runs[0].label == "admin:admin"
    assert plan.credential_runs[1].label == "token:token"
    assert plan.credential_runs[0].to_attempt(ok=True).ok is True

    summary = ModuleRunSummary.from_result(
        module="redis",
        plan=plan,
        result=type(
            "Result",
            (),
            {
                "detected_count": 2,
                "emitted_lines": 5,
            },
        )(),
    )

    assert summary.to_dict() == {
        "module": "redis",
        "attempted_targets": 3,
        "credential_runs": 2,
        "detected_count": 2,
        "emitted_lines": 5,
        "output_path": "out.txt",
    }


def test_audit_command_runner_run_plan_uses_one_typed_path_for_multi_port_targets() -> None:
    emitted: list[str] = []
    seen: list[tuple[str, int]] = []

    def detect(host: str, port: int) -> AuditRecord:
        seen.append((host, port))
        return AuditRecord(
            host=host,
            port=port,
            module="redis",
            service="redis",
            status="open_no_auth",
            auth_required=False,
        )

    spec = ModuleAuditSpec(
        module="redis",
        label="REDIS",
        default_port=6379,
        detect=detect,
        render=lambda record: [f"{record['host']}:{record['port']}"],
    )
    plan = AuditCommandPlan(targets_by_port={6379: ("a",), 6380: ("b",)}, output_format="txt")

    result = AuditCommandRunner(args=object(), spec=spec, emit_line=emitted.append).run_plan(plan)

    assert seen == [("a", 6379), ("b", 6380)]
    assert [record.port for record in result.typed_records] == [6379, 6380]
    assert result.detected_count == 2
    assert emitted == ["a:6379", "b:6380"]


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


def test_audit_model_optional_fields_and_render_events_are_serialized() -> None:
    from redposture_core.audit_models import RenderEvent, TargetSpec

    target = TargetSpec.from_mapping(
        {
            "raw": "https://example.test:8443/api?q=1#frag",
            "host": "example.test",
            "port": "8443",
            "scheme": "https",
            "path": "/api",
            "query": "q=1",
            "fragment": "frag",
            "source": "cli",
            "normalized_key": "example.test:8443",
        }
    )
    assert target.to_dict()["normalized_key"] == "example.test:8443"

    event = RenderEvent.from_mapping(
        {
            "kind": "finding",
            "fields": {"key": "value"},
            "severity": "high",
            "payload_role": "secret",
            "message": "found",
        }
    )
    assert event.to_dict() == {
        "kind": "finding",
        "fields": {"key": "value"},
        "severity": "high",
        "payload_role": "secret",
        "message": "found",
    }

    payload = AuditRecord.from_mapping(
        {
            "host": "127.0.0.1",
            "port": "443",
            "status": "open_no_auth",
            "auth_required": "yes",
            "target": target.to_dict(),
            "render_events": [event.to_dict(), "ignored"],
        },
        module="demo",
    ).to_dict()

    assert payload["auth_required"] is True
    assert payload["target"]["path"] == "/api"
    assert payload["render_events"][0]["message"] == "found"
    assert AuditRecord.from_mapping({"host": "h", "port": "", "status": "x"}).port == 0
    assert AuditRecord.from_mapping({"host": "h", "port": 1, "status": "x", "target": "raw"}).target == "raw"
    assert (
        AuditRecord.from_mapping({"host": "h", "port": 1, "status": "x", "auth_required": "no"}).auth_required is False
    )
