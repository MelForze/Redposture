"""State-rich HTTP detectors must preserve access evidence and cached payloads."""

from __future__ import annotations

import asyncio
import importlib
import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.clients.tls_cache import shared_client_ssl_context
from tests.test_stage_consul import _consul_args


@pytest.mark.parametrize("module", ["consul", "proxmox"])
@pytest.mark.parametrize("case", ["positive", "negative", "denied"])
def test_detect_and_state_parity(monkeypatch, module, case):
    stage = importlib.import_module(f"redposture_core.modules.{module}.stage")
    actions = stage.actions
    calls = []

    def response(url, headers):
        data: Any
        calls.append((url, headers))
        path = urlsplit(url).path
        code, data, h = 404, {}, {}
        if case != "negative":
            code = 200
            if module == "consul":
                data = {
                    "/v1/status/leader": "127.0.0.1:8300",
                    "/v1/status/peers": ["127.0.0.1:8300"],
                    "/v1/kv/": ["qa"],
                    "/v1/catalog/services": {"consul": []},
                    "/v1/agent/members": [{"Name": "qa"}],
                    "/v1/agent/self": {"Config": {"Version": "1.20.0"}},
                }.get(path, {})
                h = {"X-Consul-Index": "1"}
            else:
                data = {"data": [{"subdir": "ticket"}]}
                h = {"Server": "pve-api-daemon/3.0"}
            if case == "denied":
                code = 403
                data = (
                    {"error": "permission denied"}
                    if module == "consul"
                    else {"data": None, "errors": {"permission": "denied"}}
                )
        return HttpResponse(code, json.dumps(data).encode(), h, request_url=url, final_url=url)

    monkeypatch.setattr(HttpSessionPool, "request", lambda self, method, url, **kw: response(url, kw.get("headers")))
    monkeypatch.setattr(actions, "utc_now_iso", lambda: "fixed")
    args = (
        _consul_args(timeout=1, retries=0) if module == "consul" else SimpleNamespace(timeout=1, retries=0, https=False)
    )
    spec = getattr(stage, f"build_{module}_spec")(args)
    ctx = SimpleNamespace(
        host="127.0.0.1",
        port=8500 if module == "consul" else 8006,
        args=args,
        target=None,
        credential=SimpleNamespace(username=None, password=None, token=None, source="anonymous"),
        debug_emit=None,
    )
    ctx.lifecycle_state = spec.lifecycle_state_factory(ctx)
    expected = spec.detect(ctx).to_dict()
    expected_calls = calls[:]
    ctx.lifecycle_state.close()
    calls.clear()
    ctx.lifecycle_state = spec.lifecycle_state_factory(ctx)

    class Native:
        timeout = 1
        retries = 0
        max_bytes = 262144
        ssl_context = shared_client_ssl_context(insecure=True)

        async def close(self):
            pass

        async def get(self, url, *, headers=None):
            return response(url, headers)

    assert spec.detect_async is not None
    got = asyncio.run(spec.detect_async(ctx, Native())).to_dict()
    for rec in (expected, got):
        for key in ("elapsed_ms", "stages", "stage_durations_ms", "stage_timings_ms"):
            rec.pop(key, None)
    assert got == expected
    assert calls == expected_calls
    assert got["is_" + module] is (case != "negative")
    ctx.lifecycle_state.close()
