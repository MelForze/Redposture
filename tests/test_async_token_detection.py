"""Sync/async detection must execute the same fingerprint decision tree."""

from __future__ import annotations

import asyncio
import importlib

import pytest

from tests.test_token_audit_modules import context, replies


@pytest.mark.parametrize("module", ["nomad", "jupyter", "vault"])
@pytest.mark.parametrize("negative", [False, True])
def test_async_scenario_matches_sync_record_and_request_sequence(module, negative):
    from redposture_core.detection_steps import run_async_requests

    actions = importlib.import_module(f"redposture_core.modules.{module}.actions")
    routes = replies(module) if not negative else {"/": (200, {"ordinary": "application"})}
    sync = context(routes)
    expected = actions.detect_record(sync)
    async_ctx = context(routes)
    actual_calls = []

    async def send(base, path):
        actual_calls.append(base + path)
        return async_ctx.lifecycle_state.http.request("GET", base + path, headers={"Accept": "application/json"})

    got = asyncio.run(run_async_requests(actions.detect_requests(async_ctx), send))
    assert got == expected
    assert async_ctx.lifecycle_state.http.calls == sync.lifecycle_state.http.calls
    assert got["is_" + module] is (not negative)


def test_unsupported_async_transport_bypasses_coroutine_for_proxy_and_preload(monkeypatch):
    from types import SimpleNamespace

    from redposture_core.async_detection import async_detection_allowed

    assert async_detection_allowed(SimpleNamespace(_proxy_config=None))
    assert not async_detection_allowed(SimpleNamespace(_proxy_config=object()))
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/tmp/libproxychains.dylib")
    assert not async_detection_allowed(SimpleNamespace(_proxy_config=None))


def test_exporters_without_args_respect_active_global_proxy_context():
    from redposture_core.async_detection import async_detection_allowed
    from redposture_core.network_proxy import parse_proxy_config, proxy_socket_context

    proxy, error = parse_proxy_config("socks5://127.0.0.1:9050")
    assert error is None
    with proxy_socket_context(proxy):
        assert not async_detection_allowed(None)


@pytest.mark.parametrize("truncated,error", [(True, None), (False, "content decoding failed")])
@pytest.mark.parametrize("module", ["nomad", "jupyter", "vault"])
def test_incomplete_native_fingerprint_requests_sync_verification(module, truncated, error):
    from redposture_core.clients.async_http_detect import AsyncHttpFallback
    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.detection_steps import with_async_http_detection
    from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext, ModuleAuditSpec

    actions = importlib.import_module(f"redposture_core.modules.{module}.actions")

    class NativeHttp:
        async def get(self, *args, **kwargs):
            return HttpResponse(status=200, body=b'{"version":"1"}', headers={}, truncated=truncated, error=error)

    spec = with_async_http_detection(
        ModuleAuditSpec(module=module, label=module, default_port=80, detect=actions.detect_record),
        actions,
        api_prefixes=(),
    )
    ctx = AuditHookContext(
        host="127.0.0.1", port=80, logger=None, args=context({}).args, credential=AuditCredentialRun(source="anonymous")
    )
    with pytest.raises(AsyncHttpFallback):
        asyncio.run(spec.detect_async(ctx, NativeHttp()))
