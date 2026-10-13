"""Model-based failures across the shared detect/auth/data lifecycle."""

from __future__ import annotations

from collections import Counter
from types import SimpleNamespace

from hypothesis import given, settings
from hypothesis import strategies as st

from redposture_core.audit_models import AuditRecord
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditCredentialRun, ModuleAuditSpec


@settings(max_examples=250, deadline=None)
@given(states=st.lists(st.sampled_from(("valid", "invalid", "timeout", "foreign")), min_size=1, max_size=8))
def test_mixed_target_lifecycle_never_authenticates_foreign_or_reuses_failed_identity(states: list[str]) -> None:
    expected = {f"target-{index}": state for index, state in enumerate(states)}
    calls: Counter[tuple[str, str]] = Counter()

    def record(host: str, status: str, **extra: object) -> AuditRecord:
        return AuditRecord.from_mapping(
            {"host": host, "port": 49123, "status": status, "is_demo": status != "not_service", **extra},
            module="demo",
            service="demo",
        )

    def detect(ctx: object) -> AuditRecord:
        host = str(ctx.host)
        calls[(host, "detect")] += 1
        return record(host, "not_service" if expected[host] == "foreign" else "auth_required")

    def auth(ctx: object, _prior: AuditRecord) -> AuditRecord:
        host = str(ctx.host)
        calls[(host, "auth")] += 1
        if expected[host] == "timeout":
            raise TimeoutError("injected auth timeout")
        if expected[host] == "valid":
            return record(host, "valid_credentials", provided_credentials_ok=True)
        return record(host, "auth_required", provided_credentials_ok=False)

    def data(ctx: object, prior: AuditRecord) -> AuditRecord:
        host = str(ctx.host)
        calls[(host, "data")] += 1
        return prior

    spec = ModuleAuditSpec(
        module="demo",
        label="DEMO",
        default_port=49123,
        detect=detect,
        auth=auth,
        data=data,
        is_detected=lambda item: item.extra.get("is_demo") is True,
        render=lambda _item: [],
        continue_after_credential_error=True,
    )
    runner = AuditCommandRunner(args=SimpleNamespace(debug=False), spec=spec, emit_line=lambda _line: None)
    runner.run_plan(
        AuditCommandPlan(
            targets_by_port={49123: tuple(expected)},
            credential_runs=(AuditCredentialRun("alice", "secret", source="provided"),),
            workers=3,
        )
    )
    for host, state in expected.items():
        assert calls[(host, "detect")] == 1
        assert calls[(host, "auth")] == (0 if state == "foreign" else 1)
        assert calls[(host, "data")] == (1 if state == "valid" else 0)
