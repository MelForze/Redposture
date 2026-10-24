"""Large scans keep the same verdict and telemetry while avoiding copies."""

from __future__ import annotations

import pytest

from redposture_core.audit_models import AuditRecord, StageTrace, TargetSpec
from redposture_core.stage_runtime import (
    _attach_runtime_phase_trace,
    is_pre_detect_network_noise,
    is_pre_detect_operational_failure,
)


@pytest.mark.parametrize(
    ("payload", "failure", "noise"),
    [
        ({"status": "not_service", "is_demo": False}, False, False),
        ({"status": "not_service", "is_demo": False, "error": "connection timed out"}, True, True),
        (
            {
                "status": "not_service",
                "is_demo": False,
                "stages": [{"stage_name": "detect_protocol", "error": "proxy connect timeout"}],
            },
            True,
            True,
        ),
        ({"status": "open_no_auth", "is_demo": True, "error": "connection timed out"}, False, False),
        ({"status": "not_service", "is_demo": False, "detection_status": "transport_failure"}, True, False),
    ],
)
def test_typed_and_mapping_pre_detect_classifiers_agree(payload: dict, failure: bool, noise: bool) -> None:
    full = {"host": "example", "port": 1234, "module": "demo", "service": "demo", **payload}
    record = AuditRecord.from_mapping(full)
    assert is_pre_detect_operational_failure(record) is failure
    assert is_pre_detect_operational_failure(full) is failure
    assert is_pre_detect_network_noise(record) is noise
    assert is_pre_detect_network_noise(full) is noise


def test_phase_trace_carries_prior_and_preserves_record_fields() -> None:
    target = TargetSpec(raw="http://example/path", host="example", path="/path")
    prior = AuditRecord(
        host="example",
        port=1234,
        module="demo",
        service="demo",
        status="open_no_auth",
        target=target,
        stages=(StageTrace(stage_name="detect_protocol", attempt=2, duration_ms=17),),
        extra={"stage_durations_ms": {"detect_protocol": 17}, "stage_attempts": {"detect_protocol": 2}},
    )
    current = AuditRecord(
        host="example",
        port=1234,
        module="demo",
        service="demo",
        status="fail",
        target=target,
        extra={"error": "auth failed", "stage_attempts": {"custom": 3}},
    )
    result, added = _attach_runtime_phase_trace(
        current, phase="auth", duration_ms=21, result="error", error="auth failed", prior=prior
    )
    assert added is True
    assert result.target.to_dict() == target.to_dict()
    assert [stage.stage_name for stage in result.stages] == ["detect_protocol", "auth_inference_credentials"]
    assert result.extra["stage_durations_ms"] == {"detect_protocol": 17, "auth_inference_credentials": 21}
    assert result.extra["stage_attempts"] == {"detect_protocol": 2, "custom": 3, "auth_inference_credentials": 1}
    assert result.extra["stage_failed_at"] == "auth_inference_credentials"
    assert result.extra["timestamp"]
    assert current.stages == ()
    assert prior.extra["stage_attempts"] == {"detect_protocol": 2}


def test_module_owned_stage_trace_is_not_replaced() -> None:
    owned = StageTrace(stage_name="detect_protocol", attempt=3, duration_ms=8, result="timeout")
    record = AuditRecord(
        host="example",
        port=1234,
        module="demo",
        service="demo",
        status="not_service",
        stages=(owned,),
        extra={"stage_attempts": {"detect_protocol": 3}},
    )
    result, added = _attach_runtime_phase_trace(record, phase="detect", duration_ms=100, result="ok")
    assert added is False
    assert result.stages == (owned,)
    assert result.extra["stage_attempts"] == {"detect_protocol": 3}
