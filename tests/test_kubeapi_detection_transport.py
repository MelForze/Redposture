"""Kube native detection must preserve pooled policy and custom-client fallback."""

from __future__ import annotations

import asyncio
from contextlib import closing

import pytest

from redposture_core.clients.async_http_detect import AsyncHttpFallback
from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.detection_io import run_async
from redposture_core.modules.kubeapi.detection import http_response_steps
from tests.test_async_kubeapi_detection import Native


@pytest.mark.parametrize("status", [200, 401, 403])
def test_pool_policy_and_access_response_survive_native_detection(monkeypatch, status):
    url = "https://kube.local:6443/mounted/version"
    headers = {"Authorization": "Bearer qa-token", "X-Tenant": "qa"}
    response = HttpResponse(status, b'{"kind":"Status"}', {}, request_url=url, final_url=url)
    options = {"headers": headers, "timeout": 0.75, "response_size_cap": 4096, "retries": 5}
    calls = []

    with closing(HttpSessionPool(timeout=3, insecure=True, retries=4)) as pool:
        monkeypatch.setattr(pool, "request", lambda *_a, **_kw: pytest.fail("sync request on event loop"))

        def respond(actual_url, actual_headers):
            calls.append((actual_url, actual_headers))
            assert native.timeout == 0.75
            # The outer detector owns retries; the native read must not multiply them.
            assert native.retries == 0
            assert native.max_bytes == 4096
            assert native.ssl_context is pool._target_context()
            return response

        native = Native(respond)
        native.retries = 7
        saved = (native.timeout, native.retries, native.max_bytes, native.ssl_context)
        result = asyncio.run(run_async(http_response_steps(pool, "GET", url, **options), native, {}))

        assert result is response
        assert calls == [(url, headers)]
        assert (native.timeout, native.retries, native.max_bytes, native.ssl_context) == saved
        assert pool.default_retries == 4
        assert options["retries"] == 5


def test_custom_client_requests_sync_fallback_before_any_io():
    class CustomClient:
        def request(self, *_args, **_options):
            pytest.fail("custom synchronous client called by native detector")

    def respond(*_args):
        pytest.fail("native HTTP called for an unsupported custom client")

    with pytest.raises(AsyncHttpFallback, match="Kube detection transport override"):
        asyncio.run(
            run_async(http_response_steps(CustomClient(), "GET", "https://kube.local/version"), Native(respond), {})
        )
