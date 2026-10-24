"""Work-plan streaming and UI session continuity through the command runtime."""

from __future__ import annotations

from itertools import islice
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditCredentialRun, ModuleAuditSpec
from redposture_core.targeting import StreamingTargetPlan, stream_scan_target_specs


@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize(
    "credentials", [(), (AuditCredentialRun(),), (AuditCredentialRun("qa", ""), AuditCredentialRun(token="qa-token"))]
)
def test_work_items_are_the_endpoint_credential_cartesian_product_once(
    streaming: bool, credentials: tuple[AuditCredentialRun, ...]
) -> None:
    hosts = ("192.0.2.1", "192.0.2.2")
    kwargs: dict[str, Any] = (
        {"target_plan": stream_scan_target_specs(",".join(hosts)), "ports": (2181, 6379)}
        if streaming
        else {"targets_by_port": {2181: hosts, 6379: hosts}}
    )
    plan = AuditCommandPlan(**kwargs, credential_runs=credentials)
    expected = [
        (host, port, credential)
        for port in (2181, 6379)
        for host in hosts
        for credential in credentials or (AuditCredentialRun(),)
    ]
    rows = list(plan.iter_work_items())
    assert [(host, port, credential) for _, host, port, credential, _ in rows] == expected
    assert [row[0] for row in rows] == list(range(len(expected)))
    assert plan.total_work_units == len(expected)
    assert plan.unique_host_count == 2


@pytest.mark.parametrize("window_size", [1, 2, 3, 20])
def test_target_windows_preserve_every_endpoint_and_final_short_window(window_size: int) -> None:
    plan = AuditCommandPlan(targets_by_port={80: ("192.0.2.1", "192.0.2.2"), 443: ("192.0.2.1",)})
    windows = list(plan.iter_target_windows(window_size))
    assert [(i, host, port) for window in windows for i, host, port, _ in window] == [
        (0, "192.0.2.1", 80),
        (1, "192.0.2.2", 80),
        (2, "192.0.2.1", 443),
    ]
    assert all(0 < len(window) <= window_size for window in windows)
    assert plan.first_target_spec() == windows[0][0]


def test_large_target_stream_does_not_expand_past_the_first_requested_window(monkeypatch: pytest.MonkeyPatch) -> None:
    original = StreamingTargetPlan.iter_specs_for_port
    consumed = 0

    def guarded(self: StreamingTargetPlan, port: int, ports: tuple[int, ...]):
        nonlocal consumed
        for spec in original(self, port, ports):
            consumed += 1
            assert consumed <= 2, "runtime expanded the large network before yielding the first window"
            yield spec

    monkeypatch.setattr(StreamingTargetPlan, "iter_specs_for_port", guarded)
    plan = AuditCommandPlan(target_plan=stream_scan_target_specs("10.0.0.0/8"), ports=(80, 443))
    first = next(plan.iter_target_windows(2))
    assert [(host, port) for _, host, port, _ in first] == [("10.0.0.1", 80), ("10.0.0.2", 80)]
    assert consumed == 2


def test_streaming_work_iterator_stops_before_consuming_unused_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    original = StreamingTargetPlan.iter_specs_for_port
    consumed = 0

    def guarded(self: StreamingTargetPlan, port: int, ports: tuple[int, ...]):
        nonlocal consumed
        for spec in original(self, port, ports):
            consumed += 1
            assert consumed <= 3
            yield spec

    monkeypatch.setattr(StreamingTargetPlan, "iter_specs_for_port", guarded)
    credentials = (AuditCredentialRun("qa", "one"), AuditCredentialRun("qa", "two"))
    plan = AuditCommandPlan(
        target_plan=stream_scan_target_specs("10.0.0.0/8"), ports=(443,), credential_runs=credentials
    )
    rows = list(islice(plan.iter_work_items(), 6))
    assert [row[0] for row in rows] == list(range(6))
    assert [row[3] for row in rows] == list(credentials) * 3
    assert consumed == 3


def test_empty_command_plan_has_no_first_target_or_work() -> None:
    plan = AuditCommandPlan(credential_runs=(AuditCredentialRun("qa", "qa"),))
    assert plan.first_target_spec() is None
    assert list(plan.iter_target_windows()) == []
    assert list(plan.iter_work_items()) == []
    with pytest.raises(ValueError, match="exactly one target"):
        plan.require_single_target_spec()


@pytest.mark.parametrize("session_kind", ["cookie", "token", "authorization"])
def test_command_ui_authentication_session_reaches_inventory_without_backend_auth(
    monkeypatch: pytest.MonkeyPatch, session_kind: str
) -> None:
    from redposture_core import web_panels

    calls: list[str] = []
    state = SimpleNamespace()

    def detect(_module: str, ctx: Any) -> dict[str, Any]:
        calls.append("detect-ui")
        return {
            "host": ctx.host,
            "port": ctx.port,
            "surface": "ui",
            "is_ui": True,
            "is_redis": False,
            "ui_product": "redis_insight",
            "status": "auth_required",
            "auth_required": True,
            "credential_verification_status": "available",
            "ui": {},
        }

    def authenticate(ctx: Any, record: dict[str, Any]) -> dict[str, Any]:
        assert (ctx.credential.username, ctx.credential.password) == ("proxy-user", "proxy-password")
        calls.append("auth-ui")
        return {
            **record,
            "status": "valid_credentials",
            "provided_credentials_ok": True,
            "ui": {"session_" + session_kind: "only-ui-session"},
        }

    def inventory(_ctx: Any, record: dict[str, Any]) -> dict[str, Any]:
        assert record["ui"]["session_" + session_kind] == "only-ui-session"
        calls.append("inventory-ui")
        return {**record, "ui": {**record["ui"], "inventory": {"connections": {"count": 1}}}}

    def backend(*_args: Any) -> AuditRecord:
        raise AssertionError("UI credentials or UI inventory must not be sent to the Redis backend")

    monkeypatch.setattr(web_panels, "detect_panel", detect)
    monkeypatch.setattr(web_panels, "authenticate_panel", authenticate)
    monkeypatch.setattr(web_panels, "enumerate_panel", inventory)
    spec = ModuleAuditSpec(
        module="redis",
        label="REDIS",
        default_port=5540,
        detect=backend,
        auth=backend,
        data=backend,
        lifecycle_state_factory=lambda _ctx: state,
    )
    emitted: list[str] = []
    result = AuditCommandRunner(args=SimpleNamespace(debug=False), spec=spec, emit_line=emitted.append).run_plan(
        AuditCommandPlan(
            targets_by_port={5540: ("192.0.2.1",)},
            workers=1,
            output_format="json",
            credential_runs=(AuditCredentialRun("proxy-user", "proxy-password"),),
        )
    )
    assert calls == ["detect-ui", "auth-ui", "inventory-ui"]
    assert result.detected_count == 1
    record = result.records[0]
    assert record["surface"] == "ui" and record["is_redis"] is False
    assert record["ui"]["inventory"]["connections"]["count"] == 1
    assert "only-ui-session" not in "\n".join(emitted)
    assert not any(key.startswith("session_") for key in record["ui"])
