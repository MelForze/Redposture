"""Driver numeric resolution must never create default-executor DNS jobs."""

from __future__ import annotations

import asyncio
import socket
from types import SimpleNamespace

import pytest


def test_numeric_resolution_avoids_executor_and_never_resolves_hostnames(monkeypatch):
    from redposture_core.clients.async_http_detect import AsyncHttpFallback
    from redposture_core.clients.async_resolver import numeric_getaddrinfo, resolver_fallbacks

    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "run_in_executor", lambda *a, **kw: pytest.fail("DNS executor was used"))
        got = await numeric_getaddrinfo("127.0.0.1", 27017, type=socket.SOCK_STREAM)
        assert got[0][4] == ("127.0.0.1", 27017)
        failures = []
        token = resolver_fallbacks.set(failures)
        try:
            with pytest.raises(AsyncHttpFallback):
                await numeric_getaddrinfo("replica.internal", 27017)
            assert failures == ["replica.internal"]
        finally:
            resolver_fallbacks.reset(token)

    asyncio.run(run())


def test_swallowed_driver_resolution_failure_gets_legacy_verification_for_its_target_only():
    from redposture_core.audit_models import AuditRecord
    from redposture_core.clients.async_resolver import numeric_getaddrinfo
    from redposture_core.stage_runtime import AuditCommandPlan, AuditCommandRunner, ModuleAuditSpec

    assert callable(numeric_getaddrinfo)
    sync_calls = []

    def sync(ctx):
        sync_calls.append(ctx.host)
        return AuditRecord(
            host=ctx.host, port=1, module="probe", service="probe", status="detected", extra={"is_probe": True}
        )

    async def native(ctx, http):
        if int(ctx.host) % 2:

            async def driver():
                try:
                    await asyncio.get_running_loop().getaddrinfo("replica.internal", 27017)
                except Exception:
                    pass

            await asyncio.create_task(driver())
        await asyncio.sleep(0)
        return AuditRecord(
            host=ctx.host, port=1, module="probe", service="probe", status="not_service", extra={"is_probe": False}
        )

    spec = ModuleAuditSpec(
        module="probe",
        label="PROBE",
        default_port=1,
        detect=sync,
        detect_async=native,
        async_detect_sync_hook=sync,
        is_detected=lambda r: r.extra.get("is_probe") is True,
    )
    plan = AuditCommandPlan(
        targets_by_port={1: tuple(str(i) for i in range(40))}, ports=(1,), workers=2, output_format="json"
    )
    result = AuditCommandRunner(
        args=SimpleNamespace(timeout=1, retries=0), spec=spec, emit_line=lambda _: None
    ).run_plan(plan)
    assert result.detected_count == 20
    assert set(sync_calls) == {str(i) for i in range(1, 40, 2)}
