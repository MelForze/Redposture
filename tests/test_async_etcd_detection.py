"""Etcd native detection retains v2 counts and read-only v3 POST probes."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.clients.tls_cache import shared_client_ssl_context
from redposture_core.modules.etcd import actions, stage
from redposture_core.stage_runtime import AuditCredentialRun, AuditHookContext, _invoke_host_stage
from tests.test_stage_etcd import _etcd_args


@pytest.mark.parametrize("case", ["v2", "v3", "auth", "negative"])
def test_readonly_detect_record_and_exact_requests_match(monkeypatch, case):
    calls = []

    def response(method, url, headers, body):
        data: Any
        calls.append((method, url, headers, body))
        path = urlsplit(url).path
        code, data = 404, {}
        if case != "negative":
            if path == "/version":
                code, data = (
                    200,
                    {
                        "etcdserver": "2.3.8" if case == "v2" else "3.5.14",
                        "etcdcluster": "2.3.0" if case == "v2" else "3.5.0",
                    },
                )
            if path == "/v2/keys" and case == "v2":
                code, data = 200, {"action": "get", "node": {"dir": True, "nodes": [{"key": "/qa", "value": "yes"}]}}
            if path.endswith("/auth/status"):
                code, data = 200, {"enabled": case == "auth"}
            if path.endswith("/kv/range"):
                code, data = 200, {"count": "4"}
        return HttpResponse(code, json.dumps(data).encode(), {}, request_url=url, final_url=url)

    monkeypatch.setattr(
        HttpSessionPool,
        "request",
        lambda self, method, url, **kw: response(method, url, kw.get("headers"), kw.get("body")),
    )
    monkeypatch.setattr(actions, "utc_now_iso", lambda: "fixed")
    args = _etcd_args()
    spec = stage.build_etcd_spec(args)
    assert spec.detect is None
    ctx = AuditHookContext(
        host="127.0.0.1",
        port=2379,
        args=args,
        logger=None,
        credential=AuditCredentialRun(source="anonymous"),
        phase="detect",
    )
    actions._ETCD_V3_PREFIX_CACHE.clear()
    expected = _invoke_host_stage(spec.host_stage, module="etcd", ctx=ctx, run_deep_checks=False).to_dict()
    expected_calls = calls[:]
    calls.clear()
    actions._ETCD_V3_PREFIX_CACHE.clear()

    class Native:
        timeout = 1
        retries = 0
        max_bytes = 262144
        ssl_context = shared_client_ssl_context(insecure=True)

        async def close(self):
            pass

        async def get(self, url, *, headers=None):
            return response("GET", url, headers, None)

        async def request(self, method, url, *, headers=None, body=None, **kw):
            return response(method, url, headers, body)

    assert spec.detect_async is not None
    got = asyncio.run(spec.detect_async(ctx, Native())).to_dict()
    for rec in (expected, got):
        for key in ("elapsed_ms", "stages", "stage_durations_ms", "stage_timing_total_ms"):
            rec.pop(key, None)
    assert got == expected
    assert calls == expected_calls
    assert got["is_etcd"] is (case != "negative")
    assert all("auth/authenticate" not in call[1] for call in calls)
