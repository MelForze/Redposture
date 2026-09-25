"""Generated lifecycle contracts for the shared audit state machine."""

from __future__ import annotations

import itertools
from types import SimpleNamespace

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.stage_runtime import (
    AuditCommandPlan,
    AuditCommandRunner,
    AuditCredentialRun,
    ModuleAuditSpec,
)


def _record(status: str, *, detected: bool = True, accepted: bool = False) -> AuditRecord:
    return AuditRecord(
        host="target",
        port=8443,
        module="model",
        service="model",
        status=status,
        auth_required=status != "open_no_auth",
        extra={"detected": detected, "accepted": accepted},
    )


@pytest.mark.parametrize(
    ("detected", "auth_outcomes", "continue_error", "continue_success", "deep_failure"),
    [
        (detected, outcomes, continue_error, continue_success, deep_failure)
        for detected, outcomes, continue_error, continue_success, deep_failure in itertools.product(
            (False, True),
            (("reject", "accept"), ("error", "accept"), ("accept", "reject"), ("reject", "reject")),
            (False, True),
            (False, True),
            (None, "capabilities", "data"),
        )
    ],
)
def test_audit_lifecycle_state_machine_invariants(
    detected: bool,
    auth_outcomes: tuple[str, str],
    continue_error: bool,
    continue_success: bool,
    deep_failure: str | None,
) -> None:
    events: list[str] = []
    closed: list[object] = []
    state = object()

    def detect(ctx: object) -> AuditRecord:
        assert ctx.lifecycle_state is state
        events.append("detect")
        return _record("auth_required" if detected else "not_model", detected=detected)

    def auth(ctx: object, _prior: AuditRecord) -> AuditRecord:
        assert ctx.lifecycle_state is state
        index = int(str(ctx.credential.username).removeprefix("user"))
        outcome = auth_outcomes[index]
        events.append(f"auth:{index}:{outcome}")
        if outcome == "error":
            raise OSError("auth transport failed")
        return _record(
            "valid_credentials" if outcome == "accept" else "invalid_credentials", accepted=outcome == "accept"
        )

    def capabilities(ctx: object, record: AuditRecord) -> AuditRecord:
        assert ctx.lifecycle_state is state
        events.append(f"capabilities:{ctx.credential.username}")
        if deep_failure == "capabilities":
            raise OSError("capability failed")
        return record

    def data(ctx: object, record: AuditRecord) -> AuditRecord:
        assert ctx.lifecycle_state is state
        events.append(f"data:{ctx.credential.username}")
        if deep_failure == "data":
            raise OSError("data failed")
        return record

    spec = ModuleAuditSpec(
        module="model",
        label="MODEL",
        default_port=8443,
        detect=detect,
        auth=auth,
        capabilities=capabilities,
        data=data,
        lifecycle_state_factory=lambda _ctx: state,
        lifecycle_state_close=closed.append,
        is_detected=lambda record: record.extra.get("detected") is True,
        credential_gate=lambda _credential, record: (
            record.extra.get("accepted") is True,
            "accepted" if record.extra.get("accepted") is True else "rejected",
        ),
        deep_gate=lambda record: (
            record.extra.get("accepted") is True,
            "accepted" if record.extra.get("accepted") is True else "rejected",
        ),
        continue_after_credential_error=continue_error,
        continue_after_credential_success=continue_success,
        record_all_credential_attempts=True,
    )
    plan = AuditCommandPlan(
        targets_by_port={8443: ("target",)},
        credential_runs=(
            AuditCredentialRun(username="user0", password="secret"),
            AuditCredentialRun(username="user1", password="secret"),
        ),
        workers=1,
    )
    result = AuditCommandRunner(args=SimpleNamespace(debug=False), spec=spec, emit_line=lambda _line: None).run_plan(
        plan
    )

    assert len(result.typed_records) == 1
    assert events[0] == "detect"
    assert closed == [state]
    if not detected:
        assert events == ["detect"]
        return

    auth_events = [event for event in events if event.startswith("auth:")]
    capability_events = [event for event in events if event.startswith("capabilities:")]
    data_events = [event for event in events if event.startswith("data:")]
    assert len(capability_events) <= 1
    assert len(data_events) <= 1
    assert not data_events or capability_events

    accepted_indices = [index for index, outcome in enumerate(auth_outcomes) if outcome == "accept"]
    reachable_accept = next(
        (
            index
            for index in accepted_indices
            if all(outcome != "error" or continue_error for outcome in auth_outcomes[: index + 1])
        ),
        None,
    )
    if reachable_accept is None:
        assert not capability_events and not data_events
    else:
        owner = f"user{reachable_accept}"
        assert capability_events == [f"capabilities:{owner}"]
        if deep_failure != "capabilities":
            assert data_events == [f"data:{owner}"]
        else:
            assert not data_events
        if not continue_success:
            assert len(auth_events) == reachable_accept + 1


def test_detect_exception_closes_state_once_and_never_enters_auth() -> None:
    closed: list[object] = []
    state = object()

    def fail_detect(_ctx: object) -> AuditRecord:
        raise ConnectionError("detect failed")

    spec = ModuleAuditSpec(
        module="model",
        label="MODEL",
        default_port=8443,
        detect=fail_detect,
        auth=lambda *_args: pytest.fail("auth ran after failed detection"),
        lifecycle_state_factory=lambda _ctx: state,
        lifecycle_state_close=closed.append,
    )
    result = AuditCommandRunner(args=SimpleNamespace(debug=False), spec=spec, emit_line=lambda _line: None).run_plan(
        AuditCommandPlan(targets_by_port={8443: ("target",)}, workers=1)
    )

    assert result.typed_records[0].status == "fail"
    assert closed == [state]
