"""Native typed-client detection retains state and every original access probe."""

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
from redposture_core.detection_io import run_async


@pytest.mark.parametrize("module", ["airflow", "rabbitmq", "minio"])
@pytest.mark.parametrize("case", ["positive", "negative", "denied", "offline"])
def test_record_requests_and_state_match(monkeypatch, module, case):
    actions = importlib.import_module(f"redposture_core.modules.{module}.actions")
    calls = []

    def response(url, headers):
        body: Any
        data: Any
        calls.append((url, headers))
        path = urlsplit(url).path
        if case == "offline":
            return HttpResponse(0, b"", {}, error="connection refused")
        code, body, h = 404, b"{}", {}
        if case != "negative":
            code = 200
            if module == "airflow":
                data = (
                    {"version": "3.0.2", "git_version": "abc"}
                    if path.endswith("/version")
                    else {"dags": [], "variables": [], "connections": [], "total_entries": 0}
                )
                body = json.dumps(data).encode()
            elif module == "rabbitmq":
                data = (
                    {"rabbitmq_version": "4.0.1", "erlang_version": "27"}
                    if path == "/api/overview"
                    else {"name": "guest", "tags": ["administrator"]}
                    if path == "/api/whoami"
                    else []
                )
                body = json.dumps(data).encode()
            else:
                code, body, h = 403, b"<Error><Code>AccessDenied</Code></Error>", {"Server": "MinIO"}
                if path == "/minio/health/live":
                    code, body = 200, b""
            if case == "denied" and (("/version" not in path and module == "airflow") or module == "rabbitmq"):
                code = 401
                body = b'{"error":"unauthorized"}'
                h = {"WWW-Authenticate": 'Basic realm="RabbitMQ"'} if module == "rabbitmq" else {}
        return HttpResponse(code, body, h, request_url=url, final_url=url)

    monkeypatch.setattr(HttpSessionPool, "request", lambda self, method, url, **kw: response(url, kw.get("headers")))
    ctx = SimpleNamespace(
        host="127.0.0.1",
        port=8080,
        target=None,
        args=SimpleNamespace(timeout=1, retries=0),
        credential=SimpleNamespace(username=None, password=None, token=None),
    )
    factory = (
        actions.RabbitMQLifecycleState
        if module == "rabbitmq"
        else getattr(actions, f"{module}_lifecycle_state_factory")
    )
    ctx.lifecycle_state = factory(ctx)
    expected = actions.detect_record(ctx)
    expected_calls = calls[:]
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

    original = actions.detect_record
    got = asyncio.run(run_async(actions._ASYNC_DETECT_STEPS[original](ctx), Native(), actions._ASYNC_DETECT_STEPS))
    assert got == expected
    assert calls == expected_calls
    assert got["is_" + module] is (case not in ("negative", "offline"))
    ctx.lifecycle_state.close()
