from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest

from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandResult,
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
    build_basic_audit_plan,
    command_result_exit_code,
    format_pass_marker,
    format_retry_decision,
    format_stage2_gate,
    format_stage_trace,
    install_record_callback,
    is_pre_detect_network_noise,
    is_pre_detect_operational_failure,
    merge_audit_credential_runs,
    merge_stage_records,
    progress_total_from_groups,
    run_basic_host_audit,
    should_use_global_progress,
    sort_default_audit_credential_runs,
    validate_basic_module_args,
)
from redposture_core.utils import ScanTargetSpec


class _ProgressRecorder:
    def __init__(self) -> None:
        self.advanced = 0
        self.added_total = 0
        self.closed = False

    def advance(self, step: int = 1) -> None:
        self.advanced += step

    def set_total(self, total: int) -> None:
        return None

    def add_total(self, step: int = 1) -> None:
        self.added_total += step

    def pause_for_output(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _ConsoleRecorder:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)


def test_merge_audit_credential_runs_splits_orders_and_deduplicates() -> None:
    runs = merge_audit_credential_runs(
        (
            AuditCredentialRun(
                username="admin",
                password="admin",
                token="provided-token",
            ),
            AuditCredentialRun(username="file-user", password="", source="file"),
        ),
        (
            AuditCredentialRun(token="provided-token", source="default"),
            AuditCredentialRun(username="admin", password="admin", source="default"),
            AuditCredentialRun(username="service", password="service", source="default"),
        ),
    )

    assert runs == (
        AuditCredentialRun(token="provided-token", source="provided"),
        AuditCredentialRun(username="admin", password="admin", source="provided"),
        AuditCredentialRun(username="file-user", password="", source="file"),
        AuditCredentialRun(username="service", password="service", source="default"),
    )


def test_merge_audit_credential_runs_handles_anonymous_and_empty_groups() -> None:
    assert merge_audit_credential_runs(()) == (AuditCredentialRun(source="anonymous"),)
    assert merge_audit_credential_runs(
        (AuditCredentialRun(source="anonymous"),),
        (AuditCredentialRun(username="root", password="root", source="default"),),
    ) == (AuditCredentialRun(username="root", password="root", source="default"),)


def test_sort_default_audit_credential_runs_orders_tokens_then_login_and_password() -> None:
    runs = (
        AuditCredentialRun(username="root", password="z", source="default"),
        AuditCredentialRun(username="Admin", password="z", source="default"),
        AuditCredentialRun(token="z-token", source="default"),
        AuditCredentialRun(username="admin", password="A", source="default"),
        AuditCredentialRun(username="admin", password="a", source="default"),
        AuditCredentialRun(token="A-token", source="default"),
        AuditCredentialRun(username=None, password="secret", source="default"),
        AuditCredentialRun(source="anonymous"),
    )

    assert sort_default_audit_credential_runs(runs) == (
        AuditCredentialRun(token="A-token", source="default"),
        AuditCredentialRun(token="z-token", source="default"),
        AuditCredentialRun(username=None, password="secret", source="default"),
        AuditCredentialRun(username="admin", password="A", source="default"),
        AuditCredentialRun(username="admin", password="a", source="default"),
        AuditCredentialRun(username="Admin", password="z", source="default"),
        AuditCredentialRun(username="root", password="z", source="default"),
        AuditCredentialRun(source="anonymous"),
    )


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


def test_validate_basic_module_args_allows_redis_password_only_and_username_file_empty_password(tmp_path) -> None:
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


def test_line_output_sink_emits_to_callback_and_file(tmp_path) -> None:
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

    # -o now tees: lines are written to the file AND echoed to the console callback.
    assert output_path.read_text(encoding="utf-8").splitlines() == ["first", "second"]
    assert emitted == ["one", "two", "first", "second"]


def test_line_output_sink_emit_stream_file_streams_in_bounded_batches(tmp_path) -> None:
    src = tmp_path / "stream.txt"
    src.write_text("a\nb\n\nc\n", encoding="utf-8")  # blank line is skipped
    emitted: list[str] = []
    batches: list[int] = []

    class _Sink(LineOutputSink):
        def emit_many(self, lines):
            lines = [line for line in lines if line]
            batches.append(len(lines))
            emitted.extend(lines)

    sink = _Sink(None, emitted.append)
    count = sink.emit_stream_file(str(src), batch=2)
    assert count == 3
    assert emitted == ["a", "b", "c"]
    assert batches == [2, 1]  # bounded to `batch` per flush -> never materialised whole


def test_line_output_sink_emit_stream_file_missing_path_is_noop() -> None:
    sink = LineOutputSink(None, lambda _line: None)
    assert sink.emit_stream_file("/nonexistent/redposture-stream.txt") == 0


def test_audit_command_runner_streams_explicit_lifecycle_in_completion_order(tmp_path) -> None:
    release_first = threading.Event()
    first_started = threading.Event()
    fast_emitted = threading.Event()
    output_path = tmp_path / "audit.txt"
    emitted: list[str] = []
    callbacks: list[str] = []

    def detect(ctx) -> AuditRecord:
        if ctx.host == "a":
            first_started.set()
            assert release_first.wait(timeout=5.0)
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="open_no_auth",
            extra={"is_demo": True},
        )

    def data(ctx, record: AuditRecord) -> AuditRecord:
        assert ctx.run_deep_checks is True
        return AuditRecord.from_mapping(
            {**record.to_dict(), "deep_host": ctx.host},
            module="demo",
            service="demo",
        )

    def emit(line: str) -> None:
        emitted.append(line)
        if line == "b:1234 detail":
            # LineOutputSink flushes the complete record to -o before teeing it.
            assert output_path.read_text(encoding="utf-8").splitlines() == [
                "b:1234 open_no_auth",
                "b:1234 detail",
            ]
            fast_emitted.set()

    spec = ModuleAuditSpec(
        module="demo",
        label="DEMO",
        default_port=1234,
        detect=detect,
        data=data,
        render=lambda record: [
            f"{record.host}:{record.port} {record.status}",
            f"{record.host}:{record.port} detail",
        ],
    )
    plan = AuditCommandPlan(
        targets_by_port={1234: ("a", "b")},
        output_path=str(output_path),
        output_format="txt",
        workers=2,
    )
    result_holder: list[AuditCommandResult | BaseException] = []
    args = SimpleNamespace(record_callback=lambda record: callbacks.append(str(record["host"])))

    def run() -> None:
        try:
            result_holder.append(AuditCommandRunner(args=args, spec=spec, emit_line=emit).run_plan(plan))
        except BaseException as exc:  # noqa: BLE001 - test thread must report failures
            result_holder.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    assert first_started.wait(timeout=5.0)
    if not fast_emitted.wait(timeout=5.0):
        release_first.set()
        thread.join(timeout=5.0)
        pytest.fail("completed explicit lifecycle was not flushed before the blocked target")

    assert emitted == ["b:1234 open_no_auth", "b:1234 detail"]
    assert callbacks == ["b"]
    assert thread.is_alive()
    release_first.set()
    thread.join(timeout=5.0)
    assert not thread.is_alive()
    assert result_holder and not isinstance(result_holder[0], BaseException)
    result = result_holder[0]
    assert isinstance(result, AuditCommandResult)
    assert [record["host"] for record in result.records] == ["b", "a"]
    assert callbacks == ["b", "a"]
    assert output_path.read_text(encoding="utf-8").splitlines() == [
        "b:1234 open_no_auth",
        "b:1234 detail",
        "a:1234 open_no_auth",
        "a:1234 detail",
    ]


def test_audit_command_runner_streams_monolithic_json_before_slow_detect_finishes(tmp_path) -> None:
    release_slow = threading.Event()
    slow_started = threading.Event()
    fast_emitted = threading.Event()
    output_path = tmp_path / "audit.jsonl"
    emitted: list[str] = []

    def host_stage(host, port, run_deep_checks):
        if host == "slow" and not run_deep_checks:
            slow_started.set()
            assert release_slow.wait(timeout=5.0)
        return {
            "host": host,
            "port": port,
            "module": "demo",
            "service": "demo",
            "status": "open_no_auth",
            "is_demo": True,
            "deep": bool(run_deep_checks),
        }

    def emit(line: str) -> None:
        emitted.append(line)
        if json.loads(line)["host"] == "fast":
            assert json.loads(output_path.read_text(encoding="utf-8").splitlines()[0])["host"] == "fast"
            fast_emitted.set()

    runner = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, host_stage=host_stage),
        emit_line=emit,
    )
    plan = AuditCommandPlan(
        targets_by_port={1234: ("slow", "fast")},
        output_path=str(output_path),
        output_format="json",
        workers=2,
    )
    result_holder: list[AuditCommandResult | BaseException] = []

    def run() -> None:
        try:
            result_holder.append(runner.run_plan(plan))
        except BaseException as exc:  # noqa: BLE001 - test thread must report failures
            result_holder.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    assert slow_started.wait(timeout=5.0)
    if not fast_emitted.wait(timeout=5.0):
        release_slow.set()
        thread.join(timeout=5.0)
        pytest.fail("completed monolithic lifecycle was not streamed as JSON")

    assert thread.is_alive()
    assert [json.loads(line)["host"] for line in emitted] == ["fast"]
    release_slow.set()
    thread.join(timeout=5.0)
    assert not thread.is_alive()
    assert result_holder and isinstance(result_holder[0], AuditCommandResult)
    result = result_holder[0]
    assert isinstance(result, AuditCommandResult)
    assert [record["host"] for record in result.records] == ["fast", "slow"]
    assert [json.loads(line)["host"] for line in emitted] == ["fast", "slow"]


def test_audit_command_runner_json_fail_records_emit_and_do_not_abort(tmp_path) -> None:
    output_path = tmp_path / "audit.jsonl"
    calls: list[str] = []

    def detect(ctx) -> AuditRecord:
        calls.append(ctx.host)
        if ctx.host == "bad":
            raise RuntimeError("malformed protocol frame")
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="not_service",
            extra={"is_demo": False},
        )

    spec = ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, detect=detect)
    plan = AuditCommandPlan(
        targets_by_port={1234: ("bad", "next")},
        output_path=str(output_path),
        output_format="json",
        workers=2,
    )

    result = AuditCommandRunner(args=object(), spec=spec, emit_line=lambda _line: None).run_plan(plan)

    assert sorted(calls) == ["bad", "next"]
    records_by_host = {record["host"]: record for record in result.records}
    assert records_by_host["bad"]["status"] == "fail"
    assert records_by_host["bad"]["error"] == "malformed protocol frame"
    assert records_by_host["next"]["status"] == "not_service"
    payloads = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    payloads_by_host = {payload["host"]: payload for payload in payloads if payload.get("type") != "summary"}
    assert payloads_by_host["bad"]["status"] == "fail"
    assert payloads_by_host["next"]["status"] == "not_service"
    assert payloads[-1]["status"] == "inconclusive"
    assert payloads[-1]["operational_failure_count"] == 1


def test_audit_command_runner_invokes_public_and_installed_record_callbacks() -> None:
    args = type("Args", (), {})()
    seen: list[tuple[str, str]] = []
    args.record_callback = lambda record: seen.append(("public", str(record["host"])))

    def detect(ctx) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="not_service",
            extra={"is_demo": False},
        )

    spec = ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, detect=detect)
    plan = AuditCommandPlan(targets_by_port={1234: ("a",)})

    with install_record_callback(args, lambda record: seen.append(("installed", str(record["host"])))):
        AuditCommandRunner(args=args, spec=spec, emit_line=lambda _line: None).run_plan(plan)

    assert seen == [("installed", "a"), ("public", "a")]


def test_audit_command_runner_records_multiple_failed_credentials() -> None:
    def detect(ctx) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="auth_required",
            auth_required=True,
            extra={"is_demo": True},
        )

    def auth(ctx, _detect_record: AuditRecord) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="auth_required",
            auth_required=True,
            extra={
                "is_demo": True,
                "provided_credentials": True,
                "provided_username": ctx.credential.username,
                "provided_password": ctx.credential.password,
            },
        )

    spec = ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, detect=detect, auth=auth)
    plan = AuditCommandPlan(
        targets_by_port={1234: ("a",)},
        credential_runs=(
            AuditCredentialRun(username="admin", password="admin", source="default"),
            AuditCredentialRun(username="demo", password="demo", source="default"),
        ),
    )

    result = AuditCommandRunner(args=object(), spec=spec, emit_line=lambda _line: None).run_plan(plan)

    assert len(result.records) == 1
    record = result.records[0]
    assert record["status"] == "auth_required"
    assert record["provided_username"] == "demo"
    assert record["attempted_credentials"] == [
        {"username": "admin", "password": "admin", "source": "default", "status": "auth_required"},
        {"username": "demo", "password": "demo", "source": "default", "status": "auth_required"},
    ]


def test_audit_command_runner_single_failed_credential_does_not_add_attempt_noise() -> None:
    def detect(ctx) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="auth_required",
            auth_required=True,
            extra={"is_demo": True},
        )

    def auth(ctx, _detect_record: AuditRecord) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="auth_required",
            auth_required=True,
            extra={
                "is_demo": True,
                "provided_credentials": True,
                "provided_username": ctx.credential.username,
                "provided_password": ctx.credential.password,
            },
        )

    spec = ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, detect=detect, auth=auth)
    plan = AuditCommandPlan(
        targets_by_port={1234: ("a",)},
        credential_runs=(AuditCredentialRun(username="admin", password="admin", source="provided"),),
    )

    result = AuditCommandRunner(args=object(), spec=spec, emit_line=lambda _line: None).run_plan(plan)

    assert len(result.records) == 1
    record = result.records[0]
    assert record["status"] == "auth_required"
    assert record["provided_username"] == "admin"
    assert "attempted_credentials" not in record


class _TinyLargeTargetPlan:
    target_count = 100_001
    no_port_count = 100_001
    explicit_port_counts: dict[int, int] = {}
    explicit_ports: tuple[int, ...] = ()

    def count_for_ports(self, ports: tuple[int, ...]) -> int:
        assert ports == (1234,)
        return self.target_count

    def execution_ports(self, ports: tuple[int, ...]) -> tuple[int, ...]:
        return ports

    def iter_specs(self):
        for host in ("a", "b", "c"):
            yield ScanTargetSpec(host=host, normalized_key=host)

    def iter_specs_for_port(self, port: int, matrix_ports: tuple[int, ...]):
        # Test plan has no explicit-port specs; every spec applies to any matrix port.
        if int(port) not in {int(p) for p in matrix_ports}:
            return
        yield from self.iter_specs()


def test_audit_command_runner_large_streaming_plan_uses_windows_and_truncates_retention(tmp_path) -> None:
    output_path = tmp_path / "audit.txt"

    def detect(ctx) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="not_service",
            extra={"is_demo": False},
        )

    spec = ModuleAuditSpec(
        module="demo",
        label="DEMO",
        default_port=1234,
        detect=detect,
        render=lambda record: [f"{record.host}:{record.port} {record.status}"],
    )
    plan = AuditCommandPlan(
        target_plan=_TinyLargeTargetPlan(),
        ports=(1234,),
        output_path=str(output_path),
        target_window_size=2,
    )

    result = AuditCommandRunner(args=object(), spec=spec, emit_line=lambda _line: None).run_plan(plan)

    assert output_path.read_text(encoding="utf-8").splitlines() == [
        "a:1234 not_service",
        "b:1234 not_service",
        "c:1234 not_service",
    ]
    assert result.record_count == 3
    assert result.status_counts == {"not_service": 3}
    assert result.records == []
    assert result.typed_records == []
    assert result.record_retention_truncated is True


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
        detect=lambda ctx: AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="redis",
            service="redis",
            status="open_no_auth",
            auth_required=False,
            capabilities=CapabilitySet({"read": True}),
            extra={"legacy": "kept"},
        ),
        render=lambda record: [f"{record.host}:{record.port} {record.status}"],
    )

    plan = AuditCommandPlan(targets_by_port={6379: ("127.0.0.1",)}, output_format="txt")
    result = AuditCommandRunner(args=object(), spec=spec, emit_line=emitted.append).run_plan(plan)

    assert result.detected_count == 1
    assert isinstance(result.typed_records[0], AuditRecord)
    assert result.records[0]["service"] == "redis"
    assert result.records[0]["capabilities"] == {"read": True}
    assert result.records[0]["legacy"] == "kept"
    assert emitted == ["127.0.0.1:6379 open_no_auth"]


def test_audit_command_runner_suppresses_pre_detect_noise_in_non_debug_txt() -> None:
    emitted: list[str] = []

    def detect(ctx) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="redis",
            service="redis",
            status="fail",
            extra={
                "is_redis": False,
                "error": "protocol closed before RESP reply (unexpected EOF)",
                "protocol_error": "unexpected EOF",
            },
        )

    spec = ModuleAuditSpec(
        module="redis",
        label="REDIS",
        default_port=6379,
        detect=detect,
        render=lambda record: [f"{record.host}:{record.port} {record.status} {record.extra.get('error')}"],
    )
    plan = AuditCommandPlan(targets_by_port={6379: ("127.0.0.1",)}, output_format="txt")

    result = AuditCommandRunner(args=object(), spec=spec, emit_line=emitted.append).run_plan(plan)

    assert emitted == [
        "[!] REDIS audit inconclusive: no service confirmed; 1/1 target unreachable or failed before detection"
    ]
    assert all("protocol closed" not in line and "unexpected EOF" not in line for line in emitted)
    assert result.emitted_lines == 1
    assert result.suppressed_records == 1
    assert result.operational_failure_count == 1
    assert result.inconclusive is True
    assert command_result_exit_code(result) == 1
    assert result.records[0]["protocol_error"] == "unexpected EOF"
    assert is_pre_detect_network_noise(result.typed_records[0]) is True
    assert is_pre_detect_operational_failure(result.typed_records[0]) is True


def test_credential_file_targets_are_not_tcp_prefiltered(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    creds = tmp_path / "creds.txt"
    creds.write_text("bad:bad\n", encoding="utf-8")
    monkeypatch.setattr(
        "redposture_core.stage_runtime.filter_open_tcp_hosts_for_credential_file",
        lambda *_args, **_kwargs: pytest.fail("credential-file TCP prefilter must not run"),
    )
    args = SimpleNamespace(
        targets="127.0.0.1,127.0.0.2",
        hosts=None,
        hosts_file=None,
        ports=None,
        port=6379,
        username=str(creds),
        password=None,
        timeout=0.1,
        retries=0,
        workers=1,
        proxy=None,
        output=None,
        output_format="txt",
        debug=False,
        defcreds=False,
    )
    plan = build_basic_audit_plan(args, default_port=6379)
    emitted: list[str] = []
    detect_calls: list[str] = []

    def detect(ctx) -> AuditRecord:
        detect_calls.append(ctx.host)
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="redis",
            service="redis",
            status="not_redis",
            extra={"is_redis": False},
        )

    spec = ModuleAuditSpec(
        module="redis",
        label="REDIS",
        default_port=6379,
        detect=detect,
        render=lambda _record: [],
    )

    result = AuditCommandRunner(args=object(), spec=spec, emit_line=emitted.append).run_plan(plan)

    assert plan.target_count == 2
    assert plan.requested_target_count is None
    assert sorted(detect_calls) == ["127.0.0.1", "127.0.0.2"]
    assert emitted == ["[*] No REDIS service detected on 2 target(s)"]
    assert result.emitted_lines == 1
    assert result.record_count == 2


def test_build_basic_audit_plan_uses_default_ports_when_port_not_specified() -> None:
    args = SimpleNamespace(
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        port=None,
        ports=None,
        timeout=0.1,
        retries=0,
        workers=1,
        output=None,
        output_format="txt",
        debug=False,
    )
    plan = build_basic_audit_plan(args, default_port=5432, default_ports=(5432, 6432, 15432))
    assert set(plan.ports) == {5432, 6432, 15432}


def test_build_basic_audit_plan_explicit_port_disables_fallback() -> None:
    args = SimpleNamespace(
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        port=5432,
        ports=None,
        timeout=0.1,
        retries=0,
        workers=1,
        output=None,
        output_format="txt",
        debug=False,
    )
    plan = build_basic_audit_plan(args, default_port=5432, default_ports=(5432, 6432, 15432))
    assert set(plan.ports) == {5432}


def test_build_basic_audit_plan_explicit_ports_disables_fallback() -> None:
    args = SimpleNamespace(
        targets="127.0.0.1",
        hosts=None,
        hosts_file=None,
        port=None,
        ports="5432,9999",
        timeout=0.1,
        retries=0,
        workers=1,
        output=None,
        output_format="txt",
        debug=False,
    )
    plan = build_basic_audit_plan(args, default_port=5432, default_ports=(5432, 6432, 15432))
    assert set(plan.ports) == {5432, 9999}


def test_build_basic_audit_plan_target_port_wins_over_implicit_defaults() -> None:
    args = SimpleNamespace(
        targets="grpc-a.internal:8085,grpc-b.internal",
        hosts=None,
        hosts_file=None,
        port=None,
        ports=None,
        _port_option_provided=False,
        timeout=0.1,
        retries=0,
        workers=1,
        output=None,
        output_format="txt",
        debug=False,
    )

    plan = build_basic_audit_plan(args, default_port=50051, default_ports=(50051, 50052))

    assert {(host, port) for _idx, host, port, _spec in plan.iter_target_specs()} == {
        ("grpc-a.internal", 8085),
        ("grpc-b.internal", 50051),
        ("grpc-b.internal", 50052),
    }
    assert plan.target_count == 3


def test_build_basic_audit_plan_explicit_cli_port_is_additive_for_bare_host_ports() -> None:
    args = SimpleNamespace(
        targets="grpc-a.internal:8085,grpc-b.internal:8001,grpc-b.internal:50051",
        hosts=None,
        hosts_file=None,
        port=50051,
        ports=None,
        _port_option_provided=True,
        timeout=0.1,
        retries=0,
        workers=1,
        output=None,
        output_format="txt",
        debug=False,
    )

    plan = build_basic_audit_plan(args, default_port=50051, default_ports=(50051, 50052))
    pairs = [(host, port) for _idx, host, port, _spec in plan.iter_target_specs()]

    assert set(pairs) == {
        ("grpc-a.internal", 8085),
        ("grpc-a.internal", 50051),
        ("grpc-b.internal", 8001),
        ("grpc-b.internal", 50051),
    }
    assert len(pairs) == len(set(pairs)) == 4
    assert plan.target_count == 4


def test_build_basic_audit_plan_url_port_still_overrides_explicit_cli_port() -> None:
    args = SimpleNamespace(
        targets="http://grpc.internal:8085/service",
        hosts=None,
        hosts_file=None,
        port=50051,
        ports=None,
        _port_option_provided=True,
        timeout=0.1,
        retries=0,
        workers=1,
        output=None,
        output_format="txt",
        debug=False,
    )

    plan = build_basic_audit_plan(args, default_port=50051)

    assert [(host, port) for _idx, host, port, _spec in plan.iter_target_specs()] == [("grpc.internal", 8085)]


def test_zero_record_json_emits_structured_summary() -> None:
    emitted: list[str] = []
    spec = ModuleAuditSpec(module="redis", label="REDIS", default_port=6379, render=lambda _record: [])
    plan = AuditCommandPlan(targets_by_port={}, requested_target_count=1, output_format="json")

    result = AuditCommandRunner(args=object(), spec=spec, emit_line=emitted.append).run_plan(plan)

    assert [json.loads(line) for line in emitted] == [
        {
            "type": "summary",
            "module": "redis",
            "service": "redis",
            "status": "no_results",
            "requested_targets": 1,
            "processed_targets": 0,
            "record_count": 0,
            "detected_count": 0,
            "reason": "no_service_detected",
        }
    ]
    assert result.emitted_lines == 1
    assert result.records == []
    assert result.typed_records == []


def _failing_auth_spec() -> ModuleAuditSpec:
    def auth(ctx, _detect_record) -> AuditRecord:
        # Every credential is rejected (status not in the deep gate's allowed set).
        return AuditRecord.from_mapping(
            {
                "host": ctx.host,
                "port": ctx.port,
                "service": "postgres",
                "module": "postgres",
                "status": "auth_required",
                "effective_username": ctx.credential.username,
            },
            module="postgres",
            service="postgres",
        )

    return ModuleAuditSpec(module="postgres", label="POSTGRES", default_port=5432, auth=auth)


def test_run_deep_lifecycle_attaches_attempted_credentials_when_all_fail() -> None:
    runner = AuditCommandRunner(args=type("A", (), {"defcreds": True})(), spec=_failing_auth_spec())
    detect_record = AuditRecord.from_mapping(
        {"host": "h", "port": 5432, "service": "postgres", "module": "postgres", "status": "auth_required"},
        module="postgres",
        service="postgres",
    )
    runs = (
        AuditCredentialRun(username="postgres", password="postgres", source="default"),
        AuditCredentialRun(username="pgbouncer", password="pgbouncer", source="default"),
    )

    record = runner._run_deep_lifecycle("h", 5432, None, detect_record, runs, None)

    attempts = record.extra.get("attempted_credentials")
    assert isinstance(attempts, list)
    assert [(a["username"], a["password"]) for a in attempts] == [
        ("postgres", "postgres"),
        ("pgbouncer", "pgbouncer"),
    ]


def test_run_deep_lifecycle_no_attempts_attached_when_single_credential() -> None:
    runner = AuditCommandRunner(args=type("A", (), {"defcreds": True})(), spec=_failing_auth_spec())
    detect_record = AuditRecord.from_mapping(
        {"host": "h", "port": 5432, "service": "postgres", "module": "postgres", "status": "auth_required"},
        module="postgres",
        service="postgres",
    )
    runs = (AuditCredentialRun(username="postgres", password="postgres", source="default"),)

    record = runner._run_deep_lifecycle("h", 5432, None, detect_record, runs, None)

    assert "attempted_credentials" not in record.extra


def test_audit_command_runner_keeps_pre_detect_noise_in_debug_txt() -> None:
    emitted: list[str] = []
    args = type("Args", (), {"debug": True})()

    def detect(ctx) -> AuditRecord:
        return AuditRecord.from_mapping(
            {
                "host": ctx.host,
                "port": ctx.port,
                "service": "kafka",
                "module": "kafka",
                "status": "fail",
                "is_kafka": False,
                "error": "connection reset by peer",
            },
            module="kafka",
            service="kafka",
        )

    spec = ModuleAuditSpec(
        module="kafka",
        label="KAFKA",
        default_port=9092,
        detect=detect,
        render=lambda record: [f"{record.host}:{record.port} {record.extra.get('error')}"],
    )
    plan = AuditCommandPlan(targets_by_port={9092: ("127.0.0.1",)}, output_format="txt")

    result = AuditCommandRunner(args=args, spec=spec, emit_line=emitted.append).run_plan(plan)

    assert emitted == [
        "127.0.0.1:9092 connection reset by peer",
        "[!] KAFKA audit inconclusive: no service confirmed; 1/1 target unreachable or failed before detection",
    ]
    assert result.suppressed_records == 0


def test_audit_command_runner_keeps_noise_diagnostics_in_json() -> None:
    emitted: list[str] = []

    def detect(ctx) -> AuditRecord:
        return AuditRecord.from_mapping(
            {
                "host": ctx.host,
                "port": ctx.port,
                "service": "grpc",
                "module": "grpc",
                "status": "fail",
                "is_grpc": False,
                "error": "connection timeout",
            },
            module="grpc",
            service="grpc",
        )

    spec = ModuleAuditSpec(module="grpc", label="GRPC", default_port=50051, detect=detect)
    plan = AuditCommandPlan(targets_by_port={50051: ("127.0.0.1",)}, output_format="json")

    result = AuditCommandRunner(args=object(), spec=spec, emit_line=emitted.append).run_plan(plan)

    assert len(emitted) == 2
    assert '"error": "connection timeout"' in emitted[0]
    summary = json.loads(emitted[1])
    assert summary["status"] == "inconclusive"
    assert summary["operational_failure_count"] == 1
    assert result.suppressed_records == 0


def test_audit_command_runner_does_not_suppress_detected_auth_or_data_errors() -> None:
    emitted: list[str] = []

    def detect(ctx) -> AuditRecord:
        return AuditRecord.from_mapping(
            {
                "host": ctx.host,
                "port": ctx.port,
                "service": "postgres",
                "module": "postgres",
                "status": "auth_required",
                "is_postgres": True,
                "error": "connection timeout while reading optional details",
            },
            module="postgres",
            service="postgres",
        )

    spec = ModuleAuditSpec(
        module="postgres",
        label="POSTGRES",
        default_port=5432,
        detect=detect,
        render=lambda record: [f"{record.host}:{record.port} {record.status}"],
    )
    plan = AuditCommandPlan(targets_by_port={5432: ("127.0.0.1",)}, output_format="txt")

    result = AuditCommandRunner(args=object(), spec=spec, emit_line=emitted.append).run_plan(plan)

    assert emitted == ["127.0.0.1:5432 auth_required"]
    assert result.suppressed_records == 0
    assert is_pre_detect_network_noise(result.typed_records[0]) is False


def test_audit_command_runner_rejects_dict_hook_records() -> None:
    spec = ModuleAuditSpec(
        module="redis",
        label="REDIS",
        default_port=6379,
        detect=lambda ctx: {  # type: ignore[return-value]
            "host": ctx.host,
            "port": ctx.port,
            "status": "open_no_auth",
        },
    )

    plan = AuditCommandPlan(targets_by_port={6379: ("127.0.0.1",)})
    try:
        AuditCommandRunner(args=object(), spec=spec).run_plan(plan)
    except TypeError as exc:
        assert "hooks must return AuditRecord" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("dict hook result was accepted")


def test_audit_command_runner_isolates_per_host_task_exceptions() -> None:
    def detect(ctx):
        if ctx.host == "bad":
            raise RuntimeError("boom on this host")
        return AuditRecord(host=ctx.host, port=ctx.port, module="redis", service="redis", status="open_no_auth")

    spec = ModuleAuditSpec(
        module="redis",
        label="REDIS",
        default_port=6379,
        detect=detect,
        render=lambda record: [f"{record.host} {record.status}"],
    )
    plan = AuditCommandPlan(targets_by_port={6379: ("good", "bad")}, output_format="txt")

    # One host raising an operational error must not abort the scan or escape run_plan.
    result = AuditCommandRunner(args=object(), spec=spec, emit_line=lambda _line: None).run_plan(plan)

    by_host = {record["host"]: record for record in result.records}
    assert by_host["good"]["status"] == "open_no_auth"
    assert by_host["bad"]["status"] == "fail"
    assert "boom on this host" in by_host["bad"]["error"]


def test_audit_command_runner_reraises_contract_typeerror_loudly() -> None:
    # A TypeError (typed-hook/spec contract violation) affects every host and must
    # stay loud rather than being isolated into per-host fail records.
    def detect(ctx):
        raise TypeError("contract violation")

    spec = ModuleAuditSpec(module="redis", label="REDIS", default_port=6379, detect=detect)
    plan = AuditCommandPlan(targets_by_port={6379: ("127.0.0.1",)})
    with pytest.raises(TypeError, match="contract violation"):
        AuditCommandRunner(args=object(), spec=spec, emit_line=lambda _line: None).run_plan(plan)


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
    assert list(plan.iter_targets()) == [(0, "a", 6379), (1, "b", 6379), (2, "c", 6380)]
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

    def detect(ctx) -> AuditRecord:
        seen.append((ctx.host, ctx.port))
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
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
        render=lambda record: [f"{record.host}:{record.port}"],
    )
    plan = AuditCommandPlan(targets_by_port={6379: ("a",), 6380: ("b",)}, output_format="txt")

    result = AuditCommandRunner(args=object(), spec=spec, emit_line=emitted.append).run_plan(plan)

    assert seen == [("a", 6379), ("b", 6380)]
    assert [record.port for record in result.typed_records] == [6379, 6380]
    assert result.detected_count == 2
    assert emitted == ["a:6379", "b:6380"]


def test_audit_command_runner_detects_once_auths_all_and_runs_data_once() -> None:
    debug_events: list[str] = []
    calls: list[tuple[str, str, str | None]] = []

    def detect(ctx) -> AuditRecord:
        calls.append(("detect", ctx.host, ctx.credential.username))
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="auth_required",
            extra={"is_demo": True},
        )

    def auth(ctx, record: AuditRecord) -> AuditRecord:
        calls.append(("auth", ctx.host, ctx.credential.username))
        status = "valid_credentials" if ctx.credential.username == "good" else "invalid_credentials"
        return AuditRecord.from_mapping({**record.to_dict(), "status": status}, module="demo", service="demo")

    def data(ctx, record: AuditRecord) -> AuditRecord:
        calls.append(("data", ctx.host, ctx.credential.username))
        return AuditRecord.from_mapping({**record.to_dict(), "deep": True}, module="demo", service="demo")

    spec = ModuleAuditSpec(
        module="demo",
        label="DEMO",
        default_port=1234,
        detect=detect,
        auth=auth,
        data=data,
        render=lambda record: [record.status],
    )
    plan = AuditCommandPlan(
        targets_by_port={1234: ("a",)},
        credential_runs=(
            AuditCredentialRun(username="bad", password="x", source="file"),
            AuditCredentialRun(username="good", password="x", source="file"),
        ),
    )
    args = type("Args", (), {"debug": True, "debug_emit": debug_events.append})()

    result = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _line: None).run_plan(plan)

    assert calls == [
        ("detect", "a", None),
        ("auth", "a", "bad"),
        ("auth", "a", "good"),
        ("data", "a", "good"),
    ]
    assert result.detected_count == 1
    assert result.records[0]["status"] == "valid_credentials"
    assert result.records[0]["deep"] is True
    assert debug_events[0] == "pass=1 detect start total=1 mode=pipeline"
    assert any("stage2_gate=run reason=status=valid_credentials" in event for event in debug_events)
    assert "pass=2 deep complete processed=1 mode=pipeline" in debug_events


def test_explicit_lifecycle_exhaustive_credentials_selects_first_success_for_deep() -> None:
    auth_users: list[str | None] = []
    capability_users: list[str | None] = []
    data_users: list[str | None] = []
    closed_states: list[object] = []
    lifecycle_state = object()

    def detect(ctx) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="open_no_auth",
            auth_required=False,
            extra={"is_demo": True},
        )

    def auth(ctx, _detect_record: AuditRecord) -> AuditRecord:
        auth_users.append(ctx.credential.username)
        assert ctx.lifecycle_state is lifecycle_state
        accepted = ctx.credential.username in {"first-success", "later-success"}
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="valid_credentials" if accepted else "auth_required",
            auth_required=not accepted,
            extra={
                "is_demo": True,
                "auth_valid": accepted,
                "accepted_username": ctx.credential.username if accepted else None,
            },
        )

    def capabilities(ctx, record: AuditRecord) -> AuditRecord:
        capability_users.append(ctx.credential.username)
        assert ctx.lifecycle_state is lifecycle_state
        return AuditRecord.from_mapping(
            {**record.to_dict(), "capability_username": ctx.credential.username},
            module="demo",
            service="demo",
        )

    def data(ctx, record: AuditRecord) -> AuditRecord:
        data_users.append(ctx.credential.username)
        assert ctx.lifecycle_state is lifecycle_state
        return AuditRecord.from_mapping(
            {**record.to_dict(), "data_username": ctx.credential.username},
            module="demo",
            service="demo",
        )

    spec = ModuleAuditSpec(
        module="demo",
        label="DEMO",
        default_port=1234,
        detect=detect,
        auth=auth,
        capabilities=capabilities,
        data=data,
        credential_gate=lambda _credential, record: (
            record.extra.get("auth_valid") is True,
            "verified",
        ),
        keep_anonymous_open_no_auth=True,
        continue_after_credential_success=True,
        credential_attempt_detail_fields=("auth_valid",),
        lifecycle_state_factory=lambda _ctx: lifecycle_state,
        lifecycle_state_close=closed_states.append,
    )
    credentials = (
        AuditCredentialRun(username="bad-before", password="x", source="default"),
        AuditCredentialRun(username="first-success", password="x", source="default"),
        AuditCredentialRun(username="later-success", password="x", source="default"),
        AuditCredentialRun(username="bad-after", password="x", source="default"),
    )

    result = AuditCommandRunner(
        args=SimpleNamespace(defcreds=True),
        spec=spec,
        emit_line=lambda _line: None,
    ).run_plan(AuditCommandPlan(targets_by_port={1234: ("host",)}, credential_runs=credentials))

    assert auth_users == ["bad-before", "first-success", "later-success", "bad-after"]
    assert capability_users == ["first-success"]
    assert data_users == ["first-success"]
    assert closed_states == [lifecycle_state]
    assert result.records[0]["accepted_username"] == "first-success"
    assert result.records[0]["capability_username"] == "first-success"
    assert result.records[0]["data_username"] == "first-success"
    assert [
        (attempt["username"], attempt["status"], attempt["auth_valid"])
        for attempt in result.records[0]["attempted_credentials"]
    ] == [
        ("bad-before", "auth_required", False),
        ("first-success", "valid_credentials", True),
        ("later-success", "valid_credentials", True),
        ("bad-after", "auth_required", False),
    ]


def test_explicit_lifecycle_default_still_stops_at_first_success() -> None:
    auth_users: list[str | None] = []
    data_users: list[str | None] = []

    def detect(ctx) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="auth_required",
            extra={"is_demo": True},
        )

    def auth(ctx, record: AuditRecord) -> AuditRecord:
        auth_users.append(ctx.credential.username)
        status = "valid_credentials" if ctx.credential.username == "winner" else "auth_required"
        return AuditRecord.from_mapping(
            {**record.to_dict(), "status": status},
            module="demo",
            service="demo",
        )

    def data(ctx, record: AuditRecord) -> AuditRecord:
        data_users.append(ctx.credential.username)
        return record

    credentials = (
        AuditCredentialRun(username="bad", password="x"),
        AuditCredentialRun(username="winner", password="x"),
        AuditCredentialRun(username="must-not-run", password="x"),
    )
    spec = ModuleAuditSpec(
        module="demo",
        label="DEMO",
        default_port=1234,
        detect=detect,
        auth=auth,
        data=data,
    )

    result = AuditCommandRunner(args=SimpleNamespace(), spec=spec, emit_line=lambda _line: None).run_plan(
        AuditCommandPlan(targets_by_port={1234: ("host",)}, credential_runs=credentials)
    )

    assert auth_users == ["bad", "winner"]
    assert data_users == ["winner"]
    assert result.records[0]["status"] == "valid_credentials"
    assert "attempted_credentials" not in result.records[0]


def test_audit_pipeline_progress_and_final_debug_counters_are_exact(monkeypatch) -> None:
    progress = _ProgressRecorder()
    debug_events: list[str] = []
    monkeypatch.setattr(
        "redposture_core.stage_runtime.start_command_progress",
        lambda *_args, **_kwargs: progress,
    )

    def detect(ctx) -> AuditRecord:
        detected = ctx.host != "missing"
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="open_no_auth" if detected else "not_demo",
            extra={"is_demo": detected},
        )

    result = AuditCommandRunner(
        args=SimpleNamespace(debug=True, debug_emit=debug_events.append),
        spec=ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, detect=detect),
        emit_line=lambda _line: None,
    ).run_plan(
        AuditCommandPlan(
            targets_by_port={1234: ("one", "missing", "two")},
            output_format="json",
            workers=2,
        )
    )

    assert result.detected_count == 2
    assert progress.advanced == 5  # three detect units plus two detected deep units
    assert progress.added_total == 2
    assert progress.closed is True
    assert debug_events[0] == "pass=1 detect start total=3 mode=pipeline"
    assert "pass=1 detect complete detected=2 deep_candidates=2 mode=pipeline" in debug_events
    assert "pass=2 deep complete processed=2 mode=pipeline" in debug_events


def test_audit_pipeline_never_exceeds_worker_limit() -> None:
    lock = threading.Lock()
    two_active = threading.Event()
    release = threading.Event()
    active = 0
    maximum_active = 0

    def make_state(ctx):
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
            if active == 2:
                two_active.set()
        return ctx.host

    def close_state(_state) -> None:
        nonlocal active
        with lock:
            active -= 1

    def detect(ctx) -> AuditRecord:
        if ctx.host in {"one", "two"}:
            assert release.wait(timeout=5.0)
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="open_no_auth",
            extra={"is_demo": True},
        )

    result_holder: list[AuditCommandResult | BaseException] = []
    runner = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(
            module="demo",
            label="DEMO",
            default_port=1234,
            detect=detect,
            lifecycle_state_factory=make_state,
            lifecycle_state_close=close_state,
        ),
        emit_line=lambda _line: None,
    )

    def run() -> None:
        try:
            result_holder.append(
                runner.run_plan(
                    AuditCommandPlan(
                        targets_by_port={1234: ("one", "two", "three", "four")},
                        output_format="json",
                        workers=2,
                    )
                )
            )
        except BaseException as exc:  # noqa: BLE001 - test thread must report failures
            result_holder.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    assert two_active.wait(timeout=5.0)
    assert maximum_active == 2
    release.set()
    thread.join(timeout=5.0)

    assert not thread.is_alive()
    assert result_holder and isinstance(result_holder[0], AuditCommandResult)
    assert maximum_active == 2
    assert active == 0


def test_audit_pipeline_streams_when_record_retention_is_disabled() -> None:
    callbacks: list[str] = []
    emitted: list[str] = []

    def detect(ctx) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="not_demo",
            extra={"is_demo": False},
        )

    result = AuditCommandRunner(
        args=SimpleNamespace(record_callback=lambda record: callbacks.append(str(record["host"]))),
        spec=ModuleAuditSpec(
            module="demo",
            label="DEMO",
            default_port=1234,
            detect=detect,
            record_retention_limit=0,
        ),
        emit_line=emitted.append,
    ).run_plan(
        AuditCommandPlan(
            targets_by_port={1234: ("one", "two")},
            output_format="json",
            workers=2,
        )
    )

    assert sorted(callbacks) == ["one", "two"]
    assert sorted(json.loads(line)["host"] for line in emitted) == ["one", "two"]
    assert result.records == []
    assert result.typed_records == []
    assert result.record_count == 2
    assert result.record_retention_truncated is True


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


def test_strict_host_stage_options_bind_exact_action_values() -> None:
    calls: list[dict[str, object]] = []

    def host_stage(
        host,
        port,
        timeout,
        retries,
        username,
        password,
        token,
        defcreds,
        credential_candidates,
        phase,
        run_deep_checks,
        debug,
        debug_emit,
        *,
        action,
        optional_action="legacy-default",
    ):
        calls.append(
            {
                "host": host,
                "port": port,
                "username": username,
                "password": password,
                "token": token,
                "defcreds": defcreds,
                "credential_candidates": credential_candidates,
                "phase": phase,
                "run_deep_checks": run_deep_checks,
                "action": action,
                "optional_action": optional_action,
            }
        )
        return {
            "host": host,
            "port": port,
            "module": "demo",
            "service": "demo",
            "status": "not_demo",
            "is_demo": False,
        }

    args = SimpleNamespace(
        timeout=2.0,
        retries=1,
        workers=1,
        username="must-not-leak",
        password="must-not-leak",
        token="must-not-leak",
        defcreds=True,
        debug=False,
    )
    spec = ModuleAuditSpec(
        module="demo",
        label="DEMO",
        default_port=1234,
        host_stage=host_stage,
        host_stage_options={"action": ["one", "two"], "optional_action": "explicit"},
    )
    plan = AuditCommandPlan(targets_by_port={1234: ("host",)})

    result = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _line: None).run_plan(plan)

    assert result.detected_count == 0
    assert calls == [
        {
            "host": "host",
            "port": 1234,
            "username": None,
            "password": None,
            "token": None,
            "defcreds": False,
            "credential_candidates": [],
            "phase": "detect",
            "run_deep_checks": False,
            "action": ["one", "two"],
            "optional_action": "explicit",
        }
    ]


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"action": "x"}, r"missing parameter\(s\): optional_action"),
        ({"action": "x", "optional_action": "y", "unknown": True}, r"unknown parameter\(s\): unknown"),
        (
            {"action": "x", "optional_action": "y", "timeout": 99},
            r"cannot override runtime parameter\(s\): timeout",
        ),
    ],
)
def test_strict_host_stage_options_reject_invalid_contracts(options, message) -> None:
    def host_stage(host, port, timeout, *, action, optional_action=None):
        return {"host": host, "port": port, "status": "not_demo"}

    spec = ModuleAuditSpec(
        module="demo",
        label="DEMO",
        default_port=1234,
        host_stage=host_stage,
        host_stage_options=options,
    )

    with pytest.raises(ValueError, match=message):
        AuditCommandRunner(args=SimpleNamespace(), spec=spec)


def test_monolithic_host_stage_credentials_are_isolated_by_phase() -> None:
    calls: list[dict[str, object]] = []

    def host_stage(
        host,
        port,
        username,
        password,
        token,
        api_token,
        apitoken,
        pve_api_token,
        api_key,
        defcreds,
        credential_candidates,
        phase,
        run_deep_checks,
    ):
        calls.append(
            {
                "phase": phase,
                "username": username,
                "password": password,
                "tokens": (token, api_token, apitoken, pve_api_token, api_key),
                "defcreds": defcreds,
                "credential_candidates": credential_candidates,
                "run_deep_checks": run_deep_checks,
            }
        )
        status = "auth_required" if phase == "detect" else "valid_credentials"
        return {
            "host": host,
            "port": port,
            "module": "demo",
            "service": "demo",
            "status": status,
            "is_demo": True,
        }

    args = SimpleNamespace(
        username="raw-user",
        password="raw-password",
        token="raw-token",
        api_token="raw-api-token",
        apitoken="raw-apitoken",
        pve_api_token="raw-pve-token",
        api_key="raw-api-key",
        defcreds=True,
        timeout=1.0,
        retries=0,
        workers=1,
        debug=False,
    )
    plan = AuditCommandPlan(
        targets_by_port={1234: ("host",)},
        credential_runs=(
            AuditCredentialRun(
                username="selected-user",
                password="selected-password",
                token="selected-token",
                source="provided",
            ),
        ),
    )
    spec = ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, host_stage=host_stage)

    result = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _line: None).run_plan(plan)

    assert result.detected_count == 1
    assert [call["phase"] for call in calls] == ["detect", "auth", "data"]
    assert calls[0] == {
        "phase": "detect",
        "username": None,
        "password": None,
        "tokens": (None, None, None, None, None),
        "defcreds": False,
        "credential_candidates": [],
        "run_deep_checks": False,
    }
    for call in calls[1:]:
        assert call["username"] == "selected-user"
        assert call["password"] == "selected-password"
        assert call["tokens"] == ("selected-token",) * 5
        assert call["defcreds"] is True
        assert call["credential_candidates"] == [
            {
                "username": "selected-user",
                "password": "selected-password",
                "source": "provided",
                "default": False,
            }
        ]


def test_credential_file_path_never_reaches_host_stage(tmp_path) -> None:
    credentials_path = tmp_path / "credentials.txt"
    credentials_path.write_text("file-user:file-password\n", encoding="utf-8")
    calls: list[tuple[str, object, object, object]] = []

    def host_stage(host, port, username, password, defcreds, phase):
        calls.append((phase, username, password, defcreds))
        return {
            "host": host,
            "port": port,
            "module": "demo",
            "service": "demo",
            "status": "auth_required" if phase == "detect" else "valid_credentials",
            "is_demo": True,
        }

    args = SimpleNamespace(
        targets="host",
        hosts=None,
        hosts_file=None,
        port=1234,
        ports=None,
        username=str(credentials_path),
        password=None,
        timeout=1.0,
        retries=0,
        workers=1,
        proxy=None,
        output=None,
        output_format="txt",
        debug=False,
        defcreds=True,
    )
    plan = build_basic_audit_plan(args, default_port=1234)
    spec = ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, host_stage=host_stage)

    AuditCommandRunner(args=args, spec=spec, emit_line=lambda _line: None).run_plan(plan)

    assert calls == [
        ("detect", None, None, False),
        ("auth", "file-user", "file-password", False),
        ("data", "file-user", "file-password", False),
    ]
    assert all(str(credentials_path) not in {str(username), str(password)} for _, username, password, _ in calls)


def test_hook_context_exposes_each_lifecycle_phase() -> None:
    phases: list[str] = []

    def detect(ctx) -> AuditRecord:
        phases.append(ctx.phase)
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="auth_required",
            extra={"is_demo": True},
        )

    def auth(ctx, record) -> AuditRecord:
        phases.append(ctx.phase)
        return AuditRecord.from_mapping({**record.to_dict(), "status": "valid_credentials"}, module="demo")

    def capabilities(ctx, record) -> AuditRecord:
        phases.append(ctx.phase)
        return record

    def data(ctx, record) -> AuditRecord:
        phases.append(ctx.phase)
        return record

    spec = ModuleAuditSpec(
        module="demo",
        label="DEMO",
        default_port=1234,
        detect=detect,
        auth=auth,
        capabilities=capabilities,
        data=data,
    )
    plan = AuditCommandPlan(
        targets_by_port={1234: ("host",)},
        credential_runs=(AuditCredentialRun(username="user", password="pass"),),
    )

    AuditCommandRunner(args=SimpleNamespace(), spec=spec, emit_line=lambda _line: None).run_plan(plan)

    assert phases == ["detect", "auth", "capabilities", "data"]


def test_detected_count_is_preserved_when_deep_phase_fails() -> None:
    def host_stage(host, port, phase, run_deep_checks):
        if phase == "data":
            raise RuntimeError("deep request failed")
        return {
            "host": host,
            "port": port,
            "module": "demo",
            "service": "demo",
            "status": "auth_required" if phase == "detect" else "valid_credentials",
            "is_demo": True,
        }

    spec = ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, host_stage=host_stage)
    plan = AuditCommandPlan(
        targets_by_port={1234: ("host",)},
        credential_runs=(AuditCredentialRun(username="user", password="pass"),),
        output_format="json",
    )

    result = AuditCommandRunner(args=SimpleNamespace(), spec=spec, emit_line=lambda _line: None).run_plan(plan)

    assert result.detected_count == 1
    assert result.records[0]["status"] == "fail"
    assert result.records[0]["is_demo"] is True
    assert result.records[0]["error"] == "deep request failed"
    assert result.records[0]["deep_error"] == "deep request failed"
    assert result.records[0]["detected_status"] == "auth_required"
    assert result.records[0]["detection_preserved"] is True


def test_deep_failure_txt_keeps_detected_service_and_never_emits_no_service() -> None:
    emitted: list[str] = []

    def detect(ctx) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="open_no_auth",
            extra={"is_demo": True},
        )

    def data(_ctx, _record) -> AuditRecord:
        raise TimeoutError("deep request timed out")

    spec = ModuleAuditSpec(
        module="demo",
        label="DEMO",
        default_port=1234,
        detect=detect,
        data=data,
        render=lambda record: [
            f"DEMO {record.host}:{record.port} status={record.status} "
            f"detected={record.extra.get('is_demo')} error={record.extra.get('error')}"
        ],
    )

    result = AuditCommandRunner(args=SimpleNamespace(), spec=spec, emit_line=emitted.append).run_plan(
        AuditCommandPlan(targets_by_port={1234: ("host",)}, output_format="txt")
    )

    assert result.detected_count == 1
    assert result.records[0]["is_demo"] is True
    assert result.records[0]["detection_preserved"] is True
    assert emitted == ["DEMO host:1234 status=fail detected=True error=deep request timed out"]
    assert all("No DEMO service detected" not in line for line in emitted)


def test_non_phase_host_stage_detects_anonymously_then_combines_auth_and_data() -> None:
    calls: list[dict[str, object]] = []

    def host_stage(
        host,
        port,
        username,
        password,
        credential_candidates,
        run_deep_checks,
    ):
        calls.append(
            {
                "host": host,
                "port": port,
                "username": username,
                "password": password,
                "credential_candidates": credential_candidates,
                "run_deep_checks": run_deep_checks,
            }
        )
        return {
            "host": host,
            "port": port,
            "module": "demo",
            "service": "demo",
            "status": "valid_credentials" if run_deep_checks else "auth_required",
            "is_demo": True,
            "deep": bool(run_deep_checks),
        }

    plan = AuditCommandPlan(
        targets_by_port={1234: ("host",)},
        credential_runs=(
            AuditCredentialRun(username="bad", password="bad", source="file"),
            AuditCredentialRun(username="good", password="good", source="file"),
        ),
    )
    runner = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, host_stage=host_stage),
        emit_line=lambda _line: None,
    )

    result = runner.run_plan(plan)

    assert runner._host_stage_is_monolithic is True
    assert result.detected_count == 1
    assert calls == [
        {
            "host": "host",
            "port": 1234,
            "username": None,
            "password": None,
            "credential_candidates": [],
            "run_deep_checks": False,
        },
        {
            "host": "host",
            "port": 1234,
            "username": "bad",
            "password": "bad",
            "credential_candidates": [
                {
                    "username": "bad",
                    "password": "bad",
                    "source": "file",
                    "default": False,
                },
                {
                    "username": "good",
                    "password": "good",
                    "source": "file",
                    "default": False,
                },
            ],
            "run_deep_checks": True,
        },
    ]


def test_monolithic_deep_exception_preserves_production_detect_evidence() -> None:
    calls: list[bool] = []

    def host_stage(host, port, username, password, run_deep_checks):
        calls.append(bool(run_deep_checks))
        if run_deep_checks:
            raise TimeoutError("data query timed out")
        assert username is None
        assert password is None
        return {
            "host": host,
            "port": port,
            "module": "demo",
            "service": "demo",
            "status": "auth_required",
            "is_demo": True,
        }

    runner = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, host_stage=host_stage),
        emit_line=lambda _line: None,
    )
    result = runner.run_plan(
        AuditCommandPlan(
            targets_by_port={1234: ("host",)},
            credential_runs=(AuditCredentialRun(username="user", password="pass"),),
            output_format="json",
        )
    )

    assert calls == [False, True]
    assert result.detected_count == 1
    assert result.records[0]["status"] == "fail"
    assert result.records[0]["is_demo"] is True
    assert result.records[0]["detected_status"] == "auth_required"
    assert result.records[0]["detection_preserved"] is True
    assert result.records[0]["deep_error"] == "data query timed out"


def test_monolithic_invalid_credentials_anonymous_stops_after_first_deep_action() -> None:
    calls: list[tuple[str | None, bool]] = []

    def host_stage(host, port, username, password, run_deep_checks):
        del password
        calls.append((username, bool(run_deep_checks)))
        return {
            "host": host,
            "port": port,
            "module": "demo",
            "service": "demo",
            "status": "invalid_credentials_anonymous" if run_deep_checks else "auth_required",
            "is_demo": True,
            "action_count": 1 if run_deep_checks else 0,
        }

    result = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, host_stage=host_stage),
        emit_line=lambda _line: None,
    ).run_plan(
        AuditCommandPlan(
            targets_by_port={1234: ("host",)},
            credential_runs=(
                AuditCredentialRun(username="bad-one", password="x", source="file"),
                AuditCredentialRun(username="bad-two", password="x", source="file"),
            ),
        )
    )

    assert calls == [(None, False), ("bad-one", True)]
    assert result.records[0]["status"] == "invalid_credentials_anonymous"
    assert result.records[0]["action_count"] == 1


def test_monolithic_exhaustive_credentials_retains_first_success_without_rerun() -> None:
    calls: list[tuple[str | None, bool]] = []
    closed_states: list[object] = []
    lifecycle_state = object()

    def host_stage(host, port, username, password, run_deep_checks):
        del password
        calls.append((username, bool(run_deep_checks)))
        accepted = username in {"first-success", "later-success"}
        return {
            "host": host,
            "port": port,
            "module": "demo",
            "service": "demo",
            "status": "valid_credentials" if accepted else "auth_required",
            "is_demo": True,
            "selected_username": username if accepted else None,
            "action_count": 1 if run_deep_checks else 0,
        }

    credentials = (
        AuditCredentialRun(username="bad-before", password="x", source="default"),
        AuditCredentialRun(username="first-success", password="x", source="default"),
        AuditCredentialRun(username="later-success", password="x", source="default"),
        AuditCredentialRun(username="bad-after", password="x", source="default"),
    )
    spec = ModuleAuditSpec(
        module="demo",
        label="DEMO",
        default_port=1234,
        host_stage=host_stage,
        continue_after_credential_success=True,
        lifecycle_state_factory=lambda _ctx: lifecycle_state,
        lifecycle_state_close=closed_states.append,
    )

    result = AuditCommandRunner(
        args=SimpleNamespace(defcreds=True),
        spec=spec,
        emit_line=lambda _line: None,
    ).run_plan(AuditCommandPlan(targets_by_port={1234: ("host",)}, credential_runs=credentials))

    assert calls == [
        (None, False),
        ("bad-before", True),
        ("first-success", True),
        ("later-success", True),
        ("bad-after", True),
    ]
    assert closed_states == [lifecycle_state]
    assert result.records[0]["status"] == "valid_credentials"
    assert result.records[0]["selected_username"] == "first-success"
    assert result.records[0]["action_count"] == 1
    assert [(attempt["username"], attempt["status"]) for attempt in result.records[0]["attempted_credentials"]] == [
        ("bad-before", "auth_required"),
        ("first-success", "valid_credentials"),
        ("later-success", "valid_credentials"),
        ("bad-after", "auth_required"),
    ]


def test_run_plan_outer_finally_closes_registered_lifecycle_state(monkeypatch) -> None:
    closed: list[object] = []
    state = object()
    runner = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(
            module="demo",
            label="DEMO",
            default_port=1234,
            detect=lambda ctx: AuditRecord(
                host=ctx.host,
                port=ctx.port,
                module="demo",
                service="demo",
                status="open_no_auth",
                extra={"is_demo": True},
            ),
            lifecycle_state_close=closed.append,
        ),
        emit_line=lambda _line: None,
    )
    runner._register_lifecycle_state(state)
    monkeypatch.setattr(
        runner,
        "_run_prepared_plan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(KeyboardInterrupt):
        runner.run_plan(AuditCommandPlan(targets_by_port={}))

    assert closed == [state]


def test_pipeline_cancellation_closes_states_and_suppresses_late_worker_output(tmp_path) -> None:
    blocked_started = threading.Event()
    release_blocked = threading.Event()
    blocked_worker_finished = threading.Event()
    closed: list[str] = []
    debug_events: list[str] = []
    callbacks: list[str] = []
    emitted: list[str] = []
    output_path = tmp_path / "cancelled.jsonl"

    def detect(ctx) -> AuditRecord:
        if ctx.host == "blocked":
            blocked_started.set()
            assert release_blocked.wait(timeout=5.0)
            return AuditRecord(
                host=ctx.host,
                port=ctx.port,
                module="demo",
                service="demo",
                status="open_no_auth",
                extra={"is_demo": True},
            )
        assert blocked_started.wait(timeout=5.0)
        raise TypeError("contract violation")

    spec = ModuleAuditSpec(
        module="demo",
        label="DEMO",
        default_port=1234,
        detect=detect,
        lifecycle_state_factory=lambda ctx: ctx.host,
        lifecycle_state_close=closed.append,
    )
    args = SimpleNamespace(
        debug=True,
        debug_emit=debug_events.append,
        record_callback=lambda record: callbacks.append(str(record["host"])),
    )
    runner = AuditCommandRunner(args=args, spec=spec, emit_line=emitted.append)
    run_target_pipeline = runner._run_target_pipeline

    def tracked_pipeline(host, port, target, credential_runs, debug_emit):
        try:
            return run_target_pipeline(host, port, target, credential_runs, debug_emit)
        finally:
            if host == "blocked":
                blocked_worker_finished.set()

    runner._run_target_pipeline = tracked_pipeline  # type: ignore[method-assign]

    with pytest.raises(TypeError, match="contract violation"):
        runner.run_plan(
            AuditCommandPlan(
                targets_by_port={1234: ("blocked", "bad")},
                output_path=str(output_path),
                output_format="json",
                workers=2,
            )
        )

    debug_count_after_cancel = len(debug_events)
    assert sorted(closed) == ["bad", "blocked"]
    assert callbacks == []
    assert emitted == []
    assert output_path.read_text(encoding="utf-8") == ""

    release_blocked.set()
    assert blocked_worker_finished.wait(timeout=5.0)
    assert len(debug_events) == debug_count_after_cancel
    assert callbacks == []
    assert emitted == []


def test_pipeline_closes_lifecycle_state_after_operational_detect_failure() -> None:
    closed: list[str] = []

    def detect(ctx) -> AuditRecord:
        if ctx.host == "bad":
            raise OSError("connection reset")
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="open_no_auth",
            extra={"is_demo": True},
        )

    result = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(
            module="demo",
            label="DEMO",
            default_port=1234,
            detect=detect,
            lifecycle_state_factory=lambda ctx: ctx.host,
            lifecycle_state_close=closed.append,
        ),
        emit_line=lambda _line: None,
    ).run_plan(
        AuditCommandPlan(
            targets_by_port={1234: ("good", "bad")},
            output_format="json",
            workers=2,
        )
    )

    assert sorted(closed) == ["bad", "good"]
    assert {record["host"]: record["status"] for record in result.records} == {
        "good": "open_no_auth",
        "bad": "fail",
    }


@pytest.mark.parametrize(
    ("status", "marker", "expected"),
    [
        ("fail", None, 0),
        ("unknown_timeout", None, 0),
        ("not_demo", None, 0),
        ("fail", True, 1),
        ("open", False, 0),
    ],
)
def test_detected_count_requires_meaningful_status_or_explicit_positive_marker(status, marker, expected) -> None:
    def detect(ctx) -> AuditRecord:
        extra = {} if marker is None else {"is_demo": marker}
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status=status,
            extra=extra,
        )

    spec = ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, detect=detect)
    result = AuditCommandRunner(args=SimpleNamespace(), spec=spec, emit_line=lambda _line: None).run_plan(
        AuditCommandPlan(targets_by_port={1234: ("host",)})
    )

    assert result.detected_count == expected


def test_zero_record_json_truncates_stale_output_and_append_preserves_existing_lines(tmp_path) -> None:
    output_path = tmp_path / "results.jsonl"
    output_path.write_text('{"stale":true}\n', encoding="utf-8")
    spec = ModuleAuditSpec(module="demo", label="DEMO", default_port=1234)

    result = AuditCommandRunner(args=SimpleNamespace(), spec=spec, emit_line=lambda _line: None).run_plan(
        AuditCommandPlan(
            targets_by_port={},
            requested_target_count=2,
            output_path=str(output_path),
            output_format="json",
        )
    )

    payloads = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    assert len(payloads) == 1
    assert payloads[0]["type"] == "summary"
    assert payloads[0]["requested_targets"] == 2
    assert result.record_count == 0

    AuditCommandRunner(args=SimpleNamespace(), spec=spec, emit_line=lambda _line: None).run_plan(
        AuditCommandPlan(
            targets_by_port={},
            requested_target_count=1,
            output_path=str(output_path),
            output_format="json",
            append=True,
        )
    )
    appended = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    assert [payload["requested_targets"] for payload in appended] == [2, 1]


def test_json_runner_keeps_debug_diagnostics_off_stdout(capsys) -> None:
    from redposture_core.console import Console

    console = Console(debug=True)
    args = SimpleNamespace(debug=True)
    args.debug_emit = console.info

    def detect(ctx) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="not_demo",
            extra={"is_demo": False},
        )

    AuditCommandRunner(
        args=args,
        spec=ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, detect=detect),
        console=console,
    ).run_plan(AuditCommandPlan(targets_by_port={1234: ("host",)}, output_format="json"))

    captured = capsys.readouterr()
    stdout_payloads = [json.loads(line) for line in captured.out.splitlines()]
    assert len(stdout_payloads) == 1
    assert stdout_payloads[0]["status"] == "not_demo"
    assert "pass=1 detect start" in captured.err
    assert "[*]" not in captured.out


def test_run_plan_closes_prepared_sink_when_lifecycle_setup_fails(monkeypatch, tmp_path) -> None:
    closed: list[str | None] = []
    real_close = LineOutputSink.close

    def recording_close(self) -> None:
        closed.append(self.output_path)
        real_close(self)

    monkeypatch.setattr(LineOutputSink, "close", recording_close)
    monkeypatch.setattr(
        "redposture_core.stage_runtime.start_command_progress",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("progress setup failed")),
    )
    output_path = tmp_path / "results.jsonl"
    runner = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(module="demo", label="DEMO", default_port=1234),
        emit_line=lambda _line: None,
    )

    with pytest.raises(RuntimeError, match="progress setup failed"):
        runner.run_plan(
            AuditCommandPlan(
                targets_by_port={},
                requested_target_count=1,
                output_path=str(output_path),
                output_format="json",
            )
        )

    assert closed == [str(output_path)]
    assert output_path.read_text(encoding="utf-8") == ""


def test_operational_detect_failure_emits_json_inconclusive_summary() -> None:
    emitted: list[str] = []

    def detect(_ctx) -> AuditRecord:
        raise OSError("connection refused")

    result = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, detect=detect),
        emit_line=emitted.append,
    ).run_plan(AuditCommandPlan(targets_by_port={1234: ("host",)}, output_format="json"))

    payloads = [json.loads(line) for line in emitted]
    assert [payload["status"] for payload in payloads] == ["fail", "inconclusive"]
    assert payloads[-1]["operational_failure_count"] == 1
    assert payloads[-1]["conclusive_negative_count"] == 0
    assert payloads[-1]["reason"] == "operational_failures_before_detection"
    assert result.inconclusive is True
    assert command_result_exit_code(result) == 1


def test_conclusive_negative_detection_remains_successful() -> None:
    emitted: list[str] = []

    def detect(ctx) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="not_demo",
            extra={"is_demo": False},
        )

    result = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, detect=detect),
        emit_line=emitted.append,
    ).run_plan(AuditCommandPlan(targets_by_port={1234: ("host",)}, output_format="txt"))

    assert emitted == ["[*] No DEMO service detected on target"]
    assert result.operational_failure_count == 0
    assert result.inconclusive is False
    assert command_result_exit_code(result) == 0


def test_failed_detect_trace_with_conclusive_wrong_service_is_not_operational() -> None:
    def detect(ctx) -> AuditRecord:
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="fail",
            extra={
                "is_demo": False,
                "error": "service is not demo",
                "stages": [
                    {
                        "stage_name": "detect_protocol",
                        "attempt": 1,
                        "duration_ms": 1,
                        "result": "error",
                        "error": "service is not demo",
                    }
                ],
            },
        )

    result = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, detect=detect),
        emit_line=lambda _line: None,
    ).run_plan(AuditCommandPlan(targets_by_port={1234: ("host",)}, output_format="txt"))

    assert result.operational_failure_count == 0
    assert command_result_exit_code(result) == 0


def test_mixed_detected_and_operational_failure_emits_partial_summary_and_nonzero() -> None:
    emitted: list[str] = []

    def detect(ctx) -> AuditRecord:
        if ctx.host == "down":
            raise OSError("connection refused")
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="open_no_auth",
            extra={"is_demo": True},
        )

    result = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, detect=detect),
        emit_line=emitted.append,
    ).run_plan(AuditCommandPlan(targets_by_port={1234: ("up", "down")}, output_format="json"))

    payloads = [json.loads(line) for line in emitted]
    assert payloads[-1]["status"] == "partial"
    assert payloads[-1]["detected_count"] == 1
    assert payloads[-1]["operational_failure_count"] == 1
    assert command_result_exit_code(result) == 1


def test_mixed_detected_and_operational_failure_hides_txt_aggregate_and_keeps_nonzero() -> None:
    emitted: list[str] = []

    def detect(ctx) -> AuditRecord:
        if ctx.host == "down":
            raise OSError("connection refused")
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="open_no_auth",
            extra={"is_demo": True},
        )

    result = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(
            module="demo",
            label="DEMO",
            default_port=1234,
            detect=detect,
            render=lambda record: [f"DEMO {record.host} detected"],
        ),
        emit_line=emitted.append,
    ).run_plan(AuditCommandPlan(targets_by_port={1234: ("up", "down")}, output_format="txt"))

    assert result.detected_count == 1
    assert result.operational_failure_count == 1
    assert command_result_exit_code(result) == 1
    assert emitted == ["DEMO up detected"]
    assert all("audit partial" not in line and "No DEMO service" not in line for line in emitted)


def test_run_basic_host_audit_returns_nonzero_for_inconclusive_result() -> None:
    class ConsoleRecorder:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def set_structured_output(self, _enabled: bool) -> None:
            return None

        def plain(self, message: str) -> None:
            self.lines.append(message)

        def info(self, message: str) -> None:
            self.lines.append(message)

        def warn(self, message: str) -> None:
            self.lines.append(message)

        def error(self, message: str) -> None:
            self.lines.append(message)

    console = ConsoleRecorder()

    def detect(_ctx) -> AuditRecord:
        raise TimeoutError("connection timeout")

    args = SimpleNamespace(output_format="txt", output=None, debug=False, workers=1)
    rc = run_basic_host_audit(
        args,
        logger=None,
        console=console,
        label="DEMO",
        validate=lambda _args, _console: None,
        build_plan=lambda _args: AuditCommandPlan(targets_by_port={1234: ("host",)}, output_format="txt"),
        build_spec=lambda _args: ModuleAuditSpec(module="demo", label="DEMO", default_port=1234, detect=detect),
    )

    assert rc == 1
    assert console.lines == [
        "[!] DEMO audit inconclusive: no service confirmed; 1/1 target unreachable or failed before detection"
    ]


def test_run_basic_host_audit_does_not_claim_all_unreachable_after_detection() -> None:
    class ConsoleRecorder:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def set_structured_output(self, _enabled: bool) -> None:
            return None

        def plain(self, message: str) -> None:
            self.lines.append(message)

        def info(self, message: str) -> None:
            self.lines.append(message)

        def warn(self, message: str) -> None:
            self.lines.append(message)

        def error(self, message: str) -> None:
            self.lines.append(message)

    def detect(ctx) -> AuditRecord:
        if ctx.host == "down":
            raise TimeoutError("connection timeout")
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="open_no_auth",
            extra={"is_demo": True},
        )

    console = ConsoleRecorder()
    args = SimpleNamespace(output_format="txt", output=None, debug=True, workers=1)
    rc = run_basic_host_audit(
        args,
        logger=None,
        console=console,
        label="DEMO",
        validate=lambda _args, _console: None,
        build_plan=lambda _args: AuditCommandPlan(
            targets_by_port={1234: ("up", "down")},
            output_format="txt",
        ),
        build_spec=lambda _args: ModuleAuditSpec(
            module="demo",
            label="DEMO",
            default_port=1234,
            detect=detect,
            render=lambda record: [f"DEMO {record.host} status={record.status}"],
        ),
    )

    assert rc == 1
    assert all("all demo targets are unreachable" not in line for line in console.lines)
