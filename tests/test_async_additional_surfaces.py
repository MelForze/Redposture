"""Both surfaces are detected asynchronously, credentials remain synchronous."""

import asyncio
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from redposture_core import web_panels
from redposture_core.audit_models import AuditRecord
from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, AuditCredentialRun, ModuleAuditSpec
from redposture_core.targeting import ScanTargetSpec


@pytest.mark.parametrize("accepted", [False, True])
@pytest.mark.parametrize("ui_first", [False, True])
@pytest.mark.parametrize("panel_present", [False, True])
def test_additional_surface_uses_async_once_and_keeps_sync_auth(monkeypatch, ui_first, panel_present, accepted):
    seen = []
    closed = []
    states = []
    authcalls = []

    class State:
        pass

    def state(ctx):
        value = State()
        states.append(value)
        return value

    def backend(ctx):
        pytest.fail("synchronous backend detection repeated")

    async def native(ctx, http):
        seen.append((ctx.host, "backend", threading.current_thread().name))
        await asyncio.sleep(0)
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="mongodb",
            service="mongodb",
            status="auth_required",
            auth_required=True,
            extra={"is_mongodb": True},
        )

    async def panel(module, ctx, http):
        seen.append((ctx.host, "ui", threading.current_thread().name))
        await asyncio.sleep(0)
        if not panel_present:
            return None
        return {
            "host": ctx.host,
            "port": ctx.port,
            "module": "mongodb",
            "service": "mongodb",
            "status": "auth_required",
            "auth_required": True,
            "surface": "ui",
            "is_ui": True,
            "ui_product": "mongo_express",
            "credential_verification_status": "available",
            "ui": {"endpoint": f"http://{ctx.host}:{ctx.port}", "auth_required": True},
            "detection_status": "confirmed",
            "detection_signals": ["mongo_express_page"],
        }

    def auth(ctx, record):
        authcalls.append(
            (ctx.host, "backend", threading.current_thread().name, ctx.credential.username, ctx.credential.password)
        )
        return replace(
            record,
            status="valid_credentials" if accepted else "auth_required",
            extra={**record.extra, "provided_credentials_ok": accepted},
        )

    def ui_auth(ctx, record):
        authcalls.append(
            (ctx.host, "ui", threading.current_thread().name, ctx.credential.username, ctx.credential.password)
        )
        return {
            **record,
            "status": "valid_credentials" if accepted else "auth_required",
            "provided_credentials_ok": accepted,
        }

    monkeypatch.setattr(web_panels, "authenticate_panel", ui_auth)
    monkeypatch.setattr(web_panels, "detect_panel_async", panel)
    monkeypatch.setattr(web_panels, "detect_panel", lambda *a: pytest.fail("sync panel repeated"))
    spec = ModuleAuditSpec(
        module="mongodb",
        label="MONGODB",
        default_port=27017,
        detect=backend,
        auth=auth,
        detect_async=native,
        async_detect_sync_hook=backend,
        lifecycle_state_factory=state,
        lifecycle_state_close=closed.append,
        is_detected=lambda r: r.extra.get("is_mongodb") is True,
        render=lambda r: [f"MONGODB {r.status}"],
    )
    targets = tuple(
        ScanTargetSpec(host=f"198.18.0.{i + 1}", explicit_port=27017, scheme="http" if ui_first else None)
        for i in range(32)
    )
    plan = AuditCommandPlan(
        target_specs_by_port={27017: targets},
        output_format="json",
        workers=2,
        credential_runs=(AuditCredentialRun(username="qa", password="pass", source="provided"),),
    )
    args = SimpleNamespace(debug=False, timeout=1, retries=0)
    result = AuditCommandRunner(args=args, spec=spec, emit_line=lambda _: None).run_plan(plan)
    assert result.record_count == 32 * (2 if panel_present else 1)
    assert len(seen) == 64
    assert all(name == "redposture-async-detect" for _, _, name in seen)
    for target in targets:
        assert [surface for host, surface, _ in seen if host == target.host] == (
            ["ui", "backend"] if ui_first else ["backend", "ui"]
        )
    assert len(closed) == len(states) and set(closed) == set(states)

    assert len(authcalls) == result.record_count
    assert all(
        name != "redposture-async-detect" and username == "qa" and password == "pass"
        for _, _, name, username, password in authcalls
    )
    assert all(row["status"] == ("valid_credentials" if accepted else "auth_required") for row in result.records)


def test_unsupported_secondary_surface_falls_back_once(monkeypatch):
    from redposture_core.clients.async_http_detect import AsyncHttpFallback

    calls = []

    def backend(ctx):
        pytest.fail("backend was already detected asynchronously")

    async def native(ctx, http):
        calls.append((ctx.host, "backend"))
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="mongodb",
            service="mongodb",
            status="auth_required",
            auth_required=True,
            extra={"is_mongodb": True},
        )

    async def asyncpanel(module, ctx, http):
        calls.append((ctx.host, "async_ui"))
        raise AsyncHttpFallback("unsupported fixture framing")

    def panel(module, ctx):
        calls.append((ctx.host, "sync_ui"))
        return {
            "host": ctx.host,
            "port": ctx.port,
            "module": "mongodb",
            "service": "mongodb",
            "status": "auth_required",
            "auth_required": True,
            "surface": "ui",
            "is_ui": True,
            "ui_product": "mongo_express",
            "ui": {"auth_required": True},
        }

    monkeypatch.setattr(web_panels, "detect_panel_async", asyncpanel)
    monkeypatch.setattr(web_panels, "detect_panel", panel)
    spec = ModuleAuditSpec(
        module="mongodb",
        label="MONGODB",
        default_port=27017,
        detect=backend,
        detect_async=native,
        async_detect_sync_hook=backend,
        is_detected=lambda r: r.extra.get("is_mongodb") is True,
        render=lambda r: [],
    )
    targets = tuple(ScanTargetSpec(host=f"198.18.0.{i + 1}", explicit_port=27017) for i in range(32))
    result = AuditCommandRunner(
        args=SimpleNamespace(debug=False, timeout=1, retries=0), spec=spec, emit_line=lambda _: None
    ).run_plan(AuditCommandPlan(target_specs_by_port={27017: targets}, workers=2, output_format="json"))
    assert result.record_count == 64
    for target in targets:
        assert [surface for host, surface in calls if host == target.host] == ["backend", "async_ui", "sync_ui"]


def test_cancel_during_secondary_detect_closes_both_states(monkeypatch):
    states = []
    closed = []

    def factory(ctx):
        state = object()
        states.append(state)
        return state

    def backend(ctx):
        pytest.fail("unexpected synchronous detection")

    async def native(ctx, http):
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="mongodb",
            service="mongodb",
            status="auth_required",
            auth_required=True,
            extra={"is_mongodb": True},
        )

    async def panel(module, ctx, http):
        if ctx.host != "198.18.0.1":
            await asyncio.sleep(30)
        return None

    monkeypatch.setattr(web_panels, "detect_panel_async", panel)

    def stop(row):
        raise RuntimeError("stop fixture run")

    spec = ModuleAuditSpec(
        module="mongodb",
        label="MONGODB",
        default_port=27017,
        detect=backend,
        detect_async=native,
        async_detect_sync_hook=backend,
        lifecycle_state_factory=factory,
        lifecycle_state_close=closed.append,
        is_detected=lambda r: r.extra.get("is_mongodb") is True,
        render=lambda r: [],
    )
    targets = tuple(ScanTargetSpec(host=f"198.18.0.{i + 1}", explicit_port=27017) for i in range(32))
    runner = AuditCommandRunner(
        args=SimpleNamespace(debug=False, timeout=1, retries=0, _record_callback=stop),
        spec=spec,
        emit_line=lambda _: None,
    )
    with pytest.raises(RuntimeError, match="stop fixture run"):
        runner.run_plan(AuditCommandPlan(target_specs_by_port={27017: targets}, workers=2, output_format="json"))
    assert len(closed) == len(states) and set(closed) == set(states)


def test_primary_auth_does_not_wait_for_slow_secondary_ui(monkeypatch):
    authenticated = threading.Event()
    observations = []

    def backend(ctx):
        pytest.fail("unexpected sync detect")

    async def native(ctx, http):
        return AuditRecord(
            host=ctx.host,
            port=ctx.port,
            module="mongodb",
            service="mongodb",
            status="auth_required",
            auth_required=True,
            extra={"is_mongodb": True},
        )

    async def panel(module, ctx, http):
        deadline = asyncio.get_running_loop().time() + 0.3
        while not authenticated.is_set() and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.001)
        observations.append(authenticated.is_set())
        return None

    def auth(ctx, record):
        authenticated.set()
        return replace(record, extra={**record.extra, "provided_credentials_ok": False})

    monkeypatch.setattr(web_panels, "detect_panel_async", panel)
    spec = ModuleAuditSpec(
        module="mongodb",
        label="MONGODB",
        default_port=27017,
        detect=backend,
        auth=auth,
        detect_async=native,
        async_detect_sync_hook=backend,
        is_detected=lambda r: r.extra.get("is_mongodb") is True,
        render=lambda r: [],
    )
    targets = tuple(ScanTargetSpec(host=f"198.18.0.{i + 1}", explicit_port=27017) for i in range(32))
    runner = AuditCommandRunner(
        args=SimpleNamespace(debug=False, timeout=1, retries=0), spec=spec, emit_line=lambda _: None
    )
    result = runner.run_plan(
        AuditCommandPlan(
            target_specs_by_port={27017: targets},
            workers=2,
            output_format="json",
            credential_runs=(AuditCredentialRun(username="qa", password="bad"),),
        )
    )
    assert result.record_count == 32
    assert len(observations) == 32 and all(observations)
