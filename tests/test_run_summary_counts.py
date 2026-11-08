"""Known positives are never counted as conclusive negative observations."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    ModuleAuditSpec,
    command_result_exit_code,
)


@pytest.mark.parametrize("workers", [1, 4])
@pytest.mark.parametrize("retention", [0, 100])
@pytest.mark.parametrize(
    "hosts,expected",
    [
        (("positive", "negative", "unreachable"), 1),
        (("positive", "positive-second", "unreachable"), 0),
        (("negative", "unreachable"), 1),
        (("unreachable",), 0),
        (("positive", "positive-operational", "negative", "unreachable"), 1),
        (("positive", "negative", "native-unreachable"), 1),
        (("native-unreachable",), 0),
    ],
)
def test_partial_json_counts_only_verified_non_services_as_conclusive_negatives(workers, retention, hosts, expected):
    lines = []

    def detect(ctx):
        if ctx.host == "unreachable":
            raise OSError("connection refused")
        if ctx.host == "native-unreachable":
            return AuditRecord(
                host=ctx.host,
                port=ctx.port,
                module="demo",
                service="demo",
                status="fail",
                extra={
                    "is_demo": False,
                    "error_kind": "transport_error",
                    "failure_phase": "connect",
                    "error": "[Errno 111] Connect call failed ('127.32.3.229', 58297)",
                },
            )
        positive = ctx.host.startswith("positive")
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="demo",
            service="demo",
            status="open" if positive else "not_demo",
            extra={"is_demo": positive, "operational_failure": ctx.host == "positive-operational"},
        )

    runner = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(
            module="demo", label="DEMO", default_port=1234, detect=detect, record_retention_limit=retention
        ),
        emit_line=lines.append,
    )
    result = runner.run_plan(AuditCommandPlan(targets_by_port={1234: hosts}, workers=workers, output_format="json"))
    decoded = [json.loads(line) for line in lines]
    summary = decoded[-1]
    records = decoded[:-1]
    assert summary["type"] == "summary"
    assert len(records) == summary["record_count"] == len(hosts)
    assert summary["detected_count"] == sum(host.startswith("positive") for host in hosts)
    assert summary["operational_failure_count"] == sum(
        host in {"unreachable", "native-unreachable", "positive-operational"} for host in hosts
    )
    assert summary["conclusive_negative_count"] == expected
    assert summary["conclusive_negative_count"] == sum(
        row.get("is_demo") is False
        and not row.get("operational_failure")
        and row.get("error_kind") != "transport_error"
        for row in records
    )
    assert command_result_exit_code(result) == 1
    assert all("\x1b" not in line for line in lines)


def test_companion_ui_record_is_not_a_negative_or_an_extra_detected_root(monkeypatch):
    from dataclasses import replace

    from redposture_core.targeting import ScanTargetSpec

    surfaces = []

    class CompanionRunner(AuditCommandRunner):
        def _additional_surface_target(self, record, target, port):
            surfaces.append((record.host, target.surface_hint))
            if record.host == "positive" and target.surface_hint is None:
                return replace(target, surface_hint="ui")
            return None

    def detect(ctx):
        if ctx.host == "unreachable":
            raise OSError("connection refused")
        ui = ctx.target.surface_hint == "ui"
        positive = ctx.host == "positive"
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="redis",
            service="redis",
            status="open" if positive else "not_redis",
            extra={"is_redis": positive and not ui, "is_ui": ui, "surface": "ui" if ui else "backend"},
        )

    monkeypatch.setattr(
        "redposture_core.web_panels.detect_panel",
        lambda _module, ctx: (
            detect(ctx).to_dict() if ctx.host == "positive" and ctx.target.surface_hint == "ui" else None
        ),
    )
    lines = []
    result = CompanionRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(
            module="redis",
            label="REDIS",
            default_port=1234,
            detect=detect,
            auth=lambda _ctx, record: record,
        ),
        emit_line=lines.append,
    ).run_plan(
        AuditCommandPlan(
            target_specs_by_port={
                1234: tuple(
                    ScanTargetSpec(host, explicit_port=1234) for host in ("positive", "negative", "unreachable")
                )
            },
            workers=2,
            output_format="json",
        )
    )
    decoded = [json.loads(line) for line in lines]
    assert result.detected_count == 1 and result.record_count == 4, (surfaces, result.records)
    summary = decoded[-1]
    assert summary["requested_targets"] == 3
    assert summary["detected_count"] == 1
    assert summary["record_count"] == 4
    assert summary["operational_failure_count"] == 1
    assert summary["conclusive_negative_count"] == 1
    assert sum(row.get("is_ui") is True for row in decoded[:-1]) == 1


@pytest.mark.parametrize("positive", [False, True])
@pytest.mark.parametrize("code", [49, 61, 111])
def test_native_transport_evidence_is_not_dependent_on_os_error_wording(positive, code):
    from redposture_core.stage_runtime import is_pre_detect_network_noise, is_pre_detect_operational_failure

    row = AuditRecord(
        host="host",
        port=1234,
        module="demo",
        service="demo",
        status="fail",
        extra={
            "is_demo": positive,
            "error_kind": "transport_error",
            "failure_phase": "connect",
            "error": f"[Errno {code}] Connect call failed ('127.0.0.1', 1234)",
        },
    )
    assert is_pre_detect_operational_failure(row) is (not positive)
    assert is_pre_detect_network_noise(row) is (not positive)
