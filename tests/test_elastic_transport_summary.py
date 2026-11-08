"""Transport errors must never become clean negative observations or exit zero."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.modules.elastic import actions
from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    ModuleAuditSpec,
    command_result_exit_code,
)


@pytest.mark.parametrize(
    "message",
    [
        "http=[Errno 111] Connect call failed ('127.32.0.3', 54321)",
        "https=[Errno 61] Connect call failed ('127.32.0.3', 54321)",
        "http=transport failed without a known English phrase",
    ],
)
@pytest.mark.parametrize("mixed", [False, True])
def test_failed_root_transport_has_partial_or_inconclusive_summary(monkeypatch, message, mixed):
    calls = []

    def failed(*args, **kwargs):
        calls.append(args)
        return 0, b"", {}, message, "http", False, False

    monkeypatch.setattr(actions, "_request_with_tls_fallback", failed)
    lines = []

    def detect(ctx):
        if ctx.host == "positive":
            return AuditRecord(
                host=ctx.host,
                port=ctx.port,
                module="elastic",
                service="elastic",
                status="open_no_auth",
                extra={"is_elastic": True},
            )
        if ctx.host == "foreign":
            return AuditRecord(
                host=ctx.host,
                port=ctx.port,
                module="elastic",
                service="elastic",
                status="not_elastic",
                extra={"is_elastic": False},
            )
        record = actions._audit_elastic_host(
            ctx.host, ctx.port, 1, 0, None, None, None, None, False, False, False, False, False, run_deep_checks=False
        )
        return AuditRecord.from_mapping(record, module="elastic", service="elastic")

    hosts = ("positive", "foreign", "unreachable") if mixed else ("unreachable",)
    runner = AuditCommandRunner(
        args=SimpleNamespace(),
        spec=ModuleAuditSpec(module="elastic", label="ELASTIC", default_port=9200, detect=detect),
        emit_line=lines.append,
    )
    result = runner.run_plan(AuditCommandPlan(targets_by_port={9200: hosts}, workers=1, output_format="json"))
    assert len(calls) == 1
    assert command_result_exit_code(result) == 1
    summary = json.loads(lines[-1])
    assert summary["type"] == "summary" and summary["status"] == ("partial" if mixed else "inconclusive")
    assert summary["detected_count"] == int(mixed) and summary["operational_failure_count"] == 1
    assert summary["conclusive_negative_count"] == int(mixed)
