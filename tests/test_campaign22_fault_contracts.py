"""Campaign 22: rights matrices and resource teardown under phase faults.

The opt-in tests assert the required contract and intentionally fail for defects;
they do not bless the observed behavior as an expected result.
"""

from __future__ import annotations

import json
from itertools import product
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core.audit_models import AuditRecord
from redposture_core.clients.minio_api import MinioResponse
from redposture_core.modules.consul import actions as consul
from redposture_core.modules.minio import actions as minio
from redposture_core.modules.registry import actions as registry
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditCredentialRun, ModuleAuditSpec


def _admin_response(state: str, *, account: bool = False) -> MinioResponse:
    if state == "denied":
        return MinioResponse(403, {}, b"Access Denied")
    if state == "unknown":
        return MinioResponse(0, {}, b"", transport_error="timeout")
    return MinioResponse(200, {}, b'{"AccountName":"qa"}' if account else b"{}")


@pytest.mark.parametrize("account,users,policies", list(product(("ok", "denied", "unknown"), repeat=3)))
def test_minio_admin_rights_are_separate_from_caller_identity(account: str, users: str, policies: str) -> None:
    calls: list[str] = []

    def probe(name: str, state: str) -> MinioResponse:
        calls.append(name)
        return _admin_response(state, account=name == "accountinfo")

    client = SimpleNamespace(
        account_info=lambda **kw: probe("accountinfo", account),
        list_users=lambda **kw: probe("list_users", users),
        list_canned_policies=lambda **kw: probe("list_canned_policies", policies),
    )
    capability = minio.classify_admin_capability(client)
    # Independent decision table: listing one's own account is never admin proof.
    if users == policies == "ok":
        expected = "confirmed"
    elif "ok" in (users, policies):
        expected = "partial"
    elif "denied" in (users, policies) and account != "unknown":
        expected = "not_confirmed"
    else:
        expected = "unknown"
    assert capability.capability == expected
    assert capability.identity_kind == ("s3_user" if account == "ok" else "unknown")
    assert capability.evidence == {"accountinfo": account, "list_users": users, "list_canned_policies": policies}
    assert calls == ["accountinfo", "list_users", "list_canned_policies"]


@pytest.mark.parametrize("capped", ["users", "policies", "both"])
def test_minio_incomplete_admin_json_does_not_promote_privileges(capped: str) -> None:
    users_capped = capped in {"users", "both"}
    policies_capped = capped in {"policies", "both"}
    users = MinioResponse(200, {}, b'{"user":{"status":' if users_capped else b"{}", truncated=users_capped)
    policies = MinioResponse(
        200, {}, b'{"readOnly":{"policy":' if policies_capped else b"{}", truncated=policies_capped
    )
    client = SimpleNamespace(
        account_info=lambda **kw: _admin_response("ok", account=True),
        list_users=lambda **kw: users,
        list_canned_policies=lambda **kw: policies,
    )
    capability = minio.classify_admin_capability(client)
    assert capability.capability == ("unknown" if capped == "both" else "partial")
    assert capability.evidence["list_users"] == ("unknown" if users.truncated else "ok")
    assert capability.evidence["list_canned_policies"] == ("unknown" if policies.truncated else "ok")


@pytest.mark.parametrize("scope", ["kv", "services", "agents"])
@pytest.mark.parametrize("anonymous", ["public-empty", "public-populated", "denied-401", "denied-403"])
@pytest.mark.parametrize("authenticated", ["public-empty", "public-populated", "denied-403", "timeout"])
def test_consul_basic_matrix_requires_a_new_successful_scope(
    monkeypatch: pytest.MonkeyPatch, scope: str, anonymous: str, authenticated: str
) -> None:
    count_fn, populated = {
        "kv": (consul._count_kv_keys, ["app/password"]),
        "services": (consul._count_services, {"api": []}),
        "agents": (consul._count_agents, [{"Name": "node"}]),
    }[scope]
    empty: Any = {} if scope == "services" else []

    def read(state: str) -> dict[str, Any]:
        response = {
            "public-empty": (200, empty, None, False, False),
            "public-populated": (200, populated, None, False, False),
            "denied-401": (401, None, None, False, False),
            "denied-403": (403, None, None, False, False),
            "timeout": (0, None, "timeout", False, False),
        }[state]
        monkeypatch.setattr(consul, "_consul_get_json_any", lambda *a, **kw: response)
        return consul._scope_probe("qa", 8500, "/selected", 1, scheme="http", insecure=False, count_fn=count_fn)

    baseline = read(anonymous)
    with_credentials = read(authenticated)
    verdict = consul._basic_credential_verdict(
        {scope: baseline}, {scope: with_credentials}, {"ok": False, "status": 403}, {"ok": False, "status": 403}
    )
    expected = True if anonymous.startswith("denied") and authenticated.startswith("public") else None
    assert verdict is expected
    if anonymous.startswith("public"):
        assert baseline["count"] == (0 if anonymous.endswith("empty") else 1)


@pytest.mark.parametrize("scope", ["kv", "services", "agents"])
@pytest.mark.parametrize("fault", ["timeout", "server", "malformed"])
def test_consul_unknown_anonymous_probe_cannot_prove_basic_credentials(
    monkeypatch: pytest.MonkeyPatch, scope: str, fault: str
) -> None:
    response = {
        "timeout": (0, None, "timeout", False, False),
        "server": (503, None, None, False, False),
        "malformed": (200, None, None, False, False),
    }[fault]
    monkeypatch.setattr(consul, "_consul_get_json_any", lambda *a, **kw: response)
    count_fn = {"kv": consul._count_kv_keys, "services": consul._count_services, "agents": consul._count_agents}[scope]
    unknown = consul._scope_probe("qa", 8500, "/selected", 1, scheme="http", insecure=False, count_fn=count_fn)
    assert unknown["error"] and unknown["count"] is None
    verdict = consul._basic_credential_verdict(
        {scope: unknown}, {scope: {"ok": True, "status": 200, "count": 0}}, {}, {}
    )
    assert verdict is None, "a recovered/public endpoint does not prove that the supplied Basic pair was accepted"


@pytest.mark.parametrize("module", ["consul", "registry", "minio"])
@pytest.mark.parametrize("phase", ["detect", "auth", "data"])
@pytest.mark.parametrize("close_raises", [False, True])
def test_real_module_state_closes_every_target_after_phase_and_cleanup_faults(
    monkeypatch: pytest.MonkeyPatch, module: str, phase: str, close_raises: bool
) -> None:
    states: dict[str, Any] = {}
    closed: list[str] = []
    calls: list[tuple[str, str]] = []

    class Pool:
        def __init__(self, host: str) -> None:
            self.host = host

        def close(self) -> None:
            closed.append(self.host)
            if close_raises and self.host == "faulty":
                raise OSError("injected close failure")

    def make_state(ctx: Any) -> Any:
        pool = Pool(ctx.host)
        if module == "minio":
            monkeypatch.setattr(minio, "HttpSessionPool", lambda **kw: pool)
            state: Any = minio.MinioLifecycleState(SimpleNamespace(), ctx.host, ctx.port, scheme="https")
        else:
            cls = consul.ConsulLifecycleState if module == "consul" else registry.RegistryLifecycleState
            state = cls(http=pool)
        states[ctx.host] = state
        return state

    def run_phase(ctx: Any, stage: str) -> AuditRecord:
        calls.append((ctx.host, stage))
        assert ctx.lifecycle_state is states[ctx.host]
        if ctx.host == "faulty" and stage == phase:
            raise TimeoutError(f"injected {stage} failure")
        return AuditRecord.from_mapping(
            {
                "host": ctx.host,
                "port": ctx.port,
                "status": "auth_required" if stage == "detect" else "valid_credentials",
                "is_campaign": True,
                "provided_credentials_ok": stage != "detect",
                "completed_data": stage == "data",
            },
            module="campaign",
            service="campaign",
        )

    spec = ModuleAuditSpec(
        module="campaign",
        label="CAMPAIGN",
        default_port=49123,
        detect=lambda ctx: run_phase(ctx, "detect"),
        auth=lambda ctx, prior: run_phase(ctx, "auth"),
        data=lambda ctx, prior: run_phase(ctx, "data"),
        is_detected=lambda record: record.extra.get("is_campaign") is True,
        lifecycle_state_factory=make_state,
        lifecycle_state_close=lambda state: state.close(),
        render=lambda record: [],
    )
    outcome = AuditCommandRunner(args=SimpleNamespace(debug=False), spec=spec, emit_line=lambda line: None).run_plan(
        AuditCommandPlan(
            targets_by_port={49123: ("faulty", "healthy")},
            workers=1,
            credential_runs=(AuditCredentialRun("qa", "password", source="provided"),),
        )
    )
    assert sorted(closed) == ["faulty", "healthy"]
    assert calls.count(("healthy", "data")) == 1
    if phase != "data":
        assert ("faulty", "data") not in calls
    healthy = next(record for record in outcome.records if record["host"] == "healthy")
    assert healthy["completed_data"] is True
    # Exported records must remain JSON serializable after resource cleanup.
    json.dumps(outcome.records)
