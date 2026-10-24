"""Parity includes lifecycle state and all requested anonymous probes."""

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


@pytest.mark.parametrize("module", ["grafana", "qdrant", "gitlab"])
@pytest.mark.parametrize("positive", [True, False])
def test_native_continuations_preserve_record_requests_and_origin(monkeypatch, module, positive):
    from redposture_core.detection_io import run_async

    actions = importlib.import_module(f"redposture_core.modules.{module}.actions")
    calls = []

    def response(url, headers):
        payload: Any
        calls.append((url, headers))
        path = urlsplit(url).path
        payload = {"ordinary": "application"}
        if positive:
            if module == "grafana":
                payload = {"database": "ok", "version": "11.2.0", "commit": "abcdef"} if path == "/api/health" else []
            elif module == "qdrant":
                payload = (
                    {"title": "qdrant", "version": "1.11.0"}
                    if path == "/"
                    else {"result": {"collections": []}, "status": "ok", "time": 0.1}
                )
            else:
                payload = {"version": "17.4.0", "revision": "abcdef"} if path.endswith("/version") else {}
        return HttpResponse(200, json.dumps(payload).encode(), {}, final_url=url)

    def request(self, method, url, **options):
        assert method == "GET"
        return response(url, options.get("headers"))

    monkeypatch.setattr(HttpSessionPool, "request", request)
    monkeypatch.setattr(actions, "utc_now_iso", lambda: "2026-10-24T00:00:00Z")
    options = {
        "show_datasources": False,
        "check_urls": [],
        "show_collections": False,
        "dump_requested": False,
        "dump_limit": None,
        "collection_name": None,
        "ssrf_urls": [],
        "project_filters": [],
        "clone": False,
        "clone_dir": "unused",
    }
    args = SimpleNamespace(timeout=1, retries=0)
    ctx = SimpleNamespace(host="127.0.0.1", port=8080, target=None, args=args)
    factory = getattr(actions, f"{module}_lifecycle_state_factory")
    ctx.lifecycle_state = factory(ctx)
    expected = getattr(actions, f"detect_{module}")(ctx, options)
    expected_calls = calls[:]
    expected_scheme = ctx.lifecycle_state.scheme
    ctx.lifecycle_state.close()
    calls.clear()
    ctx.lifecycle_state = factory(ctx)

    class Native:
        timeout = 1
        retries = 0
        max_bytes = 262144
        ssl_context = shared_client_ssl_context(insecure=True)

        async def close(self):
            pass

        async def get(self, url, *, headers=None):
            return response(url, headers)

    activate = getattr(actions, f"_activate_{module}_transport")
    got = asyncio.run(
        run_async(
            getattr(actions, f"_detect_{module}_steps")(ctx, options),
            Native(),
            actions._ASYNC_DETECT_STEPS,
            activate=lambda: activate(ctx.lifecycle_state),
        )
    )
    expected.pop("elapsed_ms", None)
    got.pop("elapsed_ms", None)
    assert got == expected
    assert calls == expected_calls
    assert ctx.lifecycle_state.scheme == expected_scheme
    assert got[f"is_{module}"] is positive
    ctx.lifecycle_state.close()
