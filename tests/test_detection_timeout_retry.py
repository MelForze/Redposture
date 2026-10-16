from __future__ import annotations

from types import SimpleNamespace

from redposture_core.audit_models import AuditRecord
from redposture_core.stage_runtime import AuditCommandRunner, ModuleAuditSpec


def _record(status: str, *, error: str | None = None, detected: bool = False) -> AuditRecord:
    return AuditRecord(
        host="slow.example",
        port=443,
        module="grafana",
        service="grafana",
        status=status,
        extra={"is_grafana": detected, "error": error},
    )


def test_only_timed_out_detect_gets_one_longer_retry() -> None:
    seen: list[float] = []

    def detect(ctx):
        seen.append(ctx.args.timeout)
        return (
            _record("fail", error="connection timeout")
            if ctx.args.timeout == 3.0
            else _record("auth_required", detected=True)
        )

    args = SimpleNamespace(timeout=3.0, retries=0)
    runner = AuditCommandRunner(
        args=args,
        spec=ModuleAuditSpec(module="grafana", label="GRAFANA", default_port=3000, detect=detect),
        emit_line=lambda _line: None,
    )
    result = runner._run_detect_with_state("slow.example", 443, None, None)
    assert result.record.extra["is_grafana"] is True
    assert seen == [3.0, 7.0]
    assert args.timeout == 3.0


def test_definite_negative_and_already_extended_timeout_do_not_escalate() -> None:
    for error, timeout in (("connection refused", 3.0), ("connection timeout", 7.0)):
        seen: list[float] = []

        def detect(ctx, *, _seen=seen, _error=error):
            _seen.append(ctx.args.timeout)
            return _record("fail", error=_error)

        runner = AuditCommandRunner(
            args=SimpleNamespace(timeout=timeout, retries=0),
            spec=ModuleAuditSpec(module="grafana", label="GRAFANA", default_port=3000, detect=detect),
            emit_line=lambda _line: None,
        )
        runner._run_detect_with_state("slow.example", 443, None, None)
        assert seen == [timeout]


def test_retry_replaces_timed_out_lifecycle_state_without_leaking_it() -> None:
    states: list[object] = []

    class State:
        def __init__(self) -> None:
            self.closed = False
            states.append(self)

        def close(self) -> None:
            self.closed = True

    def detect(ctx):
        return (
            _record("fail", error="connection timeout")
            if ctx.args.timeout == 3.0
            else _record("auth_required", detected=True)
        )

    runner = AuditCommandRunner(
        args=SimpleNamespace(timeout=3.0, retries=0),
        spec=ModuleAuditSpec(
            module="grafana",
            label="GRAFANA",
            default_port=3000,
            detect=detect,
            lifecycle_state_factory=lambda _ctx: State(),
            lifecycle_state_close=lambda state: state.close(),
        ),
        emit_line=lambda _line: None,
    )
    outcome = runner._run_detect_with_state("slow.example", 443, None, None)
    assert len(states) == 2
    assert states[0].closed is True
    assert outcome.lifecycle_state is states[1]
    assert states[1].closed is False
    runner._close_lifecycle_state(outcome.lifecycle_state)
