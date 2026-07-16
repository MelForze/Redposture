from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    AuditHookContext,
    AuditRecord,
    ModuleAuditSpec,
    StageTrace,
)

_CANONICAL_STAGE_NAMES = [
    "detect_protocol",
    "auth_inference_credentials",
    "access_capabilities",
    "data",
]


def _record(
    ctx: AuditHookContext,
    status: str,
    *,
    detected: bool = True,
    stages: tuple[StageTrace, ...] = (),
) -> AuditRecord:
    return AuditRecord(
        host=ctx.host,
        port=ctx.port,
        module="demo",
        service="demo",
        status=status,
        stages=stages,
        extra={"is_demo": detected},
    )


def _run(
    spec: ModuleAuditSpec,
    *,
    args: SimpleNamespace | None = None,
    credentials: tuple[AuditCredentialRun, ...] = (
        AuditCredentialRun(username="user", password="pass", source="direct"),
    ),
):
    return AuditCommandRunner(
        args=args or SimpleNamespace(defcreds=False),
        spec=spec,
        emit_line=lambda _line: None,
    ).run_plan(
        AuditCommandPlan(
            targets_by_port={1234: ("host",)},
            credential_runs=credentials,
            output_format="json",
        )
    )


def _stages(result) -> list[dict[str, object]]:
    stages = result.records[0].get("stages")
    assert isinstance(stages, list)
    return stages


def test_runtime_instruments_no_stage_explicit_hooks_once_in_canonical_order() -> None:
    calls: list[str] = []

    def detect(ctx: AuditHookContext) -> AuditRecord:
        calls.append("detect")
        return _record(ctx, "auth_required")

    def auth(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        calls.append("auth")
        return replace(record, status="valid_credentials")

    def capabilities(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        calls.append("capabilities")
        return record

    def data(ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        calls.append("data")
        return record

    result = _run(
        ModuleAuditSpec(
            module="demo",
            label="DEMO",
            default_port=1234,
            detect=detect,
            auth=auth,
            capabilities=capabilities,
            data=data,
        )
    )

    stages = _stages(result)
    assert calls == ["detect", "auth", "capabilities", "data"]
    assert [stage["stage_name"] for stage in stages] == _CANONICAL_STAGE_NAMES
    assert [stage["result"] for stage in stages] == ["ok", "ok", "ok", "ok"]
    assert all(stage["attempt"] == 1 for stage in stages)


def test_module_owned_phase_stages_are_preserved_without_runtime_duplicates() -> None:
    expected = (
        StageTrace("detect_protocol", attempt=2, duration_ms=17, result="module_detect"),
        StageTrace("auth_inference_credentials", duration_ms=19, result="module_auth"),
        StageTrace("access_capabilities", duration_ms=23, result="module_capabilities"),
        StageTrace("data", duration_ms=29, result="module_data"),
    )

    def detect(ctx: AuditHookContext) -> AuditRecord:
        return _record(ctx, "auth_required", stages=expected[:1])

    def auth(_ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        return replace(record, status="valid_credentials", stages=expected[:2])

    def capabilities(_ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        return replace(record, stages=expected[:3])

    def data(_ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        return replace(record, stages=expected)

    result = _run(
        ModuleAuditSpec(
            module="demo",
            label="DEMO",
            default_port=1234,
            detect=detect,
            auth=auth,
            capabilities=capabilities,
            data=data,
        )
    )

    assert _stages(result) == [stage.to_dict() for stage in expected]


def test_anonymous_open_shortcut_has_logical_auth_trace_without_auth_hook_call() -> None:
    calls: list[str] = []

    def detect(ctx: AuditHookContext) -> AuditRecord:
        calls.append("detect")
        return _record(ctx, "open_no_auth")

    def auth(_ctx: AuditHookContext, _record: AuditRecord) -> AuditRecord:
        raise AssertionError("anonymous-open shortcut must not make an auth request")

    def capabilities(_ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        calls.append("capabilities")
        return record

    def data(_ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        calls.append("data")
        return record

    result = _run(
        ModuleAuditSpec(
            module="demo",
            label="DEMO",
            default_port=1234,
            detect=detect,
            auth=auth,
            capabilities=capabilities,
            data=data,
            keep_anonymous_open_no_auth=True,
        ),
        args=SimpleNamespace(defcreds=True),
        credentials=(AuditCredentialRun(username="admin", password="admin", source="default"),),
    )

    stages = _stages(result)
    assert calls == ["detect", "capabilities", "data"]
    assert [stage["stage_name"] for stage in stages] == _CANONICAL_STAGE_NAMES
    assert stages[1]["result"] == "ok"


def test_failed_deep_gate_emits_runtime_capability_and_data_skip_stages() -> None:
    calls: list[str] = []

    def detect(ctx: AuditHookContext) -> AuditRecord:
        calls.append("detect")
        return _record(ctx, "auth_required")

    def auth(_ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        calls.append("auth")
        return replace(record, status="invalid_credentials")

    def must_not_run(_ctx: AuditHookContext, _record: AuditRecord) -> AuditRecord:
        raise AssertionError("deep hook ran after the authentication gate closed")

    result = _run(
        ModuleAuditSpec(
            module="demo",
            label="DEMO",
            default_port=1234,
            detect=detect,
            auth=auth,
            capabilities=must_not_run,
            data=must_not_run,
        )
    )

    stages = _stages(result)
    assert calls == ["detect", "auth"]
    assert [stage["stage_name"] for stage in stages] == _CANONICAL_STAGE_NAMES
    assert [stage["result"] for stage in stages] == ["ok", "ok", "skip", "skip"]
    assert [stage["error"] for stage in stages[2:]] == ["deep checks disabled", "deep checks disabled"]


def test_data_exception_preserves_detection_and_marks_data_stage_error() -> None:
    calls: list[str] = []

    def detect(ctx: AuditHookContext) -> AuditRecord:
        calls.append("detect")
        return _record(ctx, "auth_required")

    def auth(_ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        calls.append("auth")
        return replace(record, status="valid_credentials")

    def capabilities(_ctx: AuditHookContext, record: AuditRecord) -> AuditRecord:
        calls.append("capabilities")
        return record

    def data(_ctx: AuditHookContext, _record: AuditRecord) -> AuditRecord:
        calls.append("data")
        raise RuntimeError("data request exploded")

    result = _run(
        ModuleAuditSpec(
            module="demo",
            label="DEMO",
            default_port=1234,
            detect=detect,
            auth=auth,
            capabilities=capabilities,
            data=data,
        )
    )

    stages = _stages(result)
    assert calls == ["detect", "auth", "capabilities", "data"]
    assert result.detected_count == 1
    assert result.records[0]["status"] == "fail"
    assert result.records[0]["is_demo"] is True
    assert result.records[0]["detection_preserved"] is True
    assert [stage["stage_name"] for stage in stages] == _CANONICAL_STAGE_NAMES
    assert [stage["result"] for stage in stages] == ["ok", "ok", "ok", "error"]
    assert stages[-1]["error"] == "data request exploded"
    assert result.records[0]["stage_failed_at"] == "data"


def test_detect_exception_has_terminal_error_stage_and_no_false_detection() -> None:
    def detect(_ctx: AuditHookContext) -> AuditRecord:
        raise ConnectionError("protocol handshake failed")

    result = _run(
        ModuleAuditSpec(
            module="demo",
            label="DEMO",
            default_port=1234,
            detect=detect,
        )
    )

    stages = _stages(result)
    assert result.detected_count == 0
    assert result.records[0]["status"] == "fail"
    assert result.records[0]["is_demo"] is False
    assert [stage["stage_name"] for stage in stages] == ["detect_protocol"]
    assert stages[0]["result"] == "error"
    assert stages[0]["error"] == "protocol handshake failed"
    assert result.records[0]["stage_failed_at"] == "detect_protocol"


def test_not_detected_terminal_record_has_successful_detect_stage_only() -> None:
    calls: list[str] = []

    def detect(ctx: AuditHookContext) -> AuditRecord:
        calls.append("detect")
        return _record(ctx, "not_demo", detected=False)

    def must_not_run(_ctx: AuditHookContext, _record: AuditRecord) -> AuditRecord:
        raise AssertionError("deep lifecycle ran for a non-detected target")

    result = _run(
        ModuleAuditSpec(
            module="demo",
            label="DEMO",
            default_port=1234,
            detect=detect,
            auth=must_not_run,
            capabilities=must_not_run,
            data=must_not_run,
        )
    )

    stages = _stages(result)
    assert calls == ["detect"]
    assert result.detected_count == 0
    assert [stage["stage_name"] for stage in stages] == ["detect_protocol"]
    assert stages[0]["result"] == "ok"
