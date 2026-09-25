"""Common JSON/NDJSON contract exercised for every registered audit module."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import (
    AuditRecord,
    CapabilitySet,
    CredentialAttempt,
    RenderEvent,
    StageTrace,
    TargetSpec,
)
from redposture_core.module_registry import AUDIT_MODULE_NAMES
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, ModuleAuditSpec


def _assert_common_record_schema(payload: dict[str, object], module: str) -> None:
    assert payload["host"] == "127.0.0.1"
    assert payload["port"] == 1234
    assert payload["module"] == module
    assert payload["service"] == module
    assert payload["status"] == "open_no_auth"
    assert payload["auth_required"] is False
    assert payload["transport"] == "https"
    assert isinstance(payload["target"], dict)
    assert isinstance(payload["stages"], list)
    assert isinstance(payload["credential_attempts"], list)
    assert isinstance(payload["capabilities"], dict)
    assert isinstance(payload["render_events"], list)
    assert payload["extension"] == {"nested": [1, True, None]}


@pytest.mark.parametrize("module", AUDIT_MODULE_NAMES)
def test_every_audit_module_preserves_the_common_json_record_schema(module: str) -> None:
    callbacks: list[dict[str, object]] = []
    lines: list[str] = []

    def detect(_ctx: object) -> AuditRecord:
        return AuditRecord(
            host="127.0.0.1",
            port=1234,
            module=module,
            service=module,
            status="open_no_auth",
            auth_required=False,
            target=TargetSpec(raw="https://127.0.0.1:1234/base", host="127.0.0.1", port=1234, scheme="https"),
            transport="https",
            stages=(StageTrace("detect_protocol", duration_ms=1),),
            credentials=(CredentialAttempt(username="anonymous", ok=True),),
            capabilities=CapabilitySet({"read": True, "write": False}),
            render_events=(RenderEvent(kind="detail", fields={"name": "sample"}),),
            extra={"extension": {"nested": [1, True, None]}, "confirmed": True},
        )

    result = AuditCommandRunner(
        args=SimpleNamespace(debug=False, record_callback=callbacks.append),
        spec=ModuleAuditSpec(
            module=module,
            label=module.upper(),
            default_port=1234,
            detect=detect,
            is_detected=lambda record: record.extra.get("confirmed") is True,
            deep_gate=lambda _record: (False, "schema-only fixture"),
        ),
        emit_line=lines.append,
    ).run_plan(AuditCommandPlan(targets_by_port={1234: ("127.0.0.1",)}, workers=1, output_format="json"))

    decoded = [json.loads(line) for line in lines]
    record_payloads = [item for item in decoded if item.get("type") != "summary"]
    assert len(record_payloads) == 1
    _assert_common_record_schema(record_payloads[0], module)
    assert callbacks == record_payloads
    assert result.records == record_payloads
    assert result.typed_records[0].to_dict() == record_payloads[0]


def test_from_mapping_does_not_duplicate_common_fields_into_extensions() -> None:
    record = AuditRecord.from_mapping(
        {"host": "host", "port": 1, "module": "demo", "service": "demo", "status": "ok", "custom": True}
    )

    assert record.extra == {"custom": True}
    assert record.to_dict()["host"] == "host"
