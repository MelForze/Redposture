"""Native detection must decline custom session factories before construction."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from redposture_core.clients.async_http_detect import AsyncHttpFallback
from redposture_core.modules.grpc import actions, stage
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext


@pytest.mark.parametrize("override", ["session_provider", "session_class_alias"])
def test_grpc_native_custom_session_override_falls_back_before_call(override, monkeypatch):
    args = SimpleNamespace(timeout=0.1, retries=0, plaintext=True)
    spec = stage.build_grpc_spec(args)
    ctx = AuditHookContext(
        args=args, logger=None, host="127.0.0.1", port=1, credential=AuditCredentialRun(), phase="detect"
    )
    assert spec.lifecycle_state_factory is not None
    ctx = replace(ctx, lifecycle_state=spec.lifecycle_state_factory(ctx))

    def forbidden(*args, **kwargs):
        pytest.fail("custom session provider executed on event loop")

    if override == "session_provider":
        monkeypatch.setattr(actions.GrpcLifecycleState, "session_for", forbidden)
    else:
        monkeypatch.setattr(actions, "_GrpcH2Session", forbidden)

    async def run():
        assert spec.detect_async is not None
        with pytest.raises(AsyncHttpFallback):
            await spec.detect_async(ctx, None)
        assert not ctx.lifecycle_state.sessions

    asyncio.run(run())
