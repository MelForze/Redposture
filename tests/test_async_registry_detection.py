"""Registry vendor detection keeps its anonymous product proofs and caches."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.http_session import HttpSessionPool
from redposture_core.clients.tls_cache import shared_client_ssl_context
from redposture_core.detection_io import run_async
from redposture_core.modules.registry import actions


@pytest.mark.parametrize("product", ["docker-registry", "harbor", "nexus", "gitlab"])
@pytest.mark.parametrize("positive", [True, False])
def test_all_vendor_records_and_requests_match(monkeypatch, product, positive):
    calls = []

    def response(url, headers):
        body: Any
        calls.append((url, headers))
        path = urlsplit(url).path
        code, body, headers = 404, {}, {}
        if positive:
            if path == "/v2/" and product != "nexus":
                code = 200
                headers = {"Docker-Distribution-Api-Version": "registry/2.0"}
                if product == "gitlab":
                    code = 401
                    headers["WWW-Authenticate"] = (
                        'Bearer realm="http://127.0.0.1:8080/jwt/auth",service="container_registry"'
                    )
            if path == "/api/v2.0/systeminfo" and product == "harbor":
                code, body = 200, {"harbor_version": "v2.11.0"}
            if path == "/api/v2.0/projects":
                code, body = 200, []
            if path == "/service/rest/v1/status" and product == "nexus":
                code, headers = (
                    401,
                    {
                        "Server": "Nexus/3.70.1-02",
                        "WWW-Authenticate": 'Basic realm="Sonatype Nexus Repository Manager"',
                    },
                )
        return HttpResponse(code, json.dumps(body).encode(), headers, final_url=url)

    monkeypatch.setattr(HttpSessionPool, "request", lambda self, method, url, **kw: response(url, kw.get("headers")))
    monkeypatch.setattr(actions, "utc_now_iso", lambda: "fixed")
    args = SimpleNamespace(timeout=1, retries=0)
    ctx = SimpleNamespace(
        host="127.0.0.1",
        port=8080,
        args=args,
        target=None,
        credential=SimpleNamespace(username=None, password=None, token=None),
    )
    opts = {
        "product": product,
        "nexus": product == "nexus",
        "harbor": product == "harbor",
        "gitlab": product == "gitlab",
        "docker": product == "docker-registry",
        "show_images": False,
        "show_repositories": False,
        "show_tags": False,
        "repository": None,
        "tag": None,
        "metadata": False,
        "assets": False,
        "asset": None,
        "inspect": False,
        "image": None,
        "download": False,
        "download_dir": ".",
        "console": None,
    }
    ctx.lifecycle_state = actions.registry_lifecycle_state_factory(ctx)
    actions._BEARER_TOKEN_CACHE.clear()
    expected = actions.detect_registry(ctx, opts)
    expected_calls = calls[:]
    ctx.lifecycle_state.close()
    calls.clear()
    ctx.lifecycle_state = actions.registry_lifecycle_state_factory(ctx)
    actions._BEARER_TOKEN_CACHE.clear()

    class Native:
        timeout = 1
        retries = 0
        max_bytes = 262144
        ssl_context = shared_client_ssl_context(insecure=True)

        async def close(self):
            pass

        async def get(self, url, *, headers=None):
            return response(url, headers)

    got = asyncio.run(
        run_async(
            actions._detect_registry_steps(ctx, opts),
            Native(),
            actions._ASYNC_DETECT_STEPS,
            activate=lambda: actions._activate_registry_transport(ctx.lifecycle_state),
        )
    )
    for record in (expected, got):
        record.pop("stages", None)
        record.pop("stage_durations_ms", None)
    assert got == expected
    assert calls == expected_calls
    assert got["is_registry"] is positive
    ctx.lifecycle_state.close()
