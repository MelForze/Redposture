"""Generic business API envelopes are not product identity evidence."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.clients.tls_cache import shared_client_ssl_context
from redposture_core.modules.proxmox import actions as pve
from redposture_core.modules.proxmox import stage as pve_stage
from redposture_core.modules.qdrant import actions as qdrant
from redposture_core.modules.qdrant import stage as qdrant_stage


@pytest.mark.parametrize("payload", [{"data": {"clustername": "business-cluster"}}, {"data": {"cap": {}}}])
def test_proxmox_generic_field_is_not_identity(payload):
    assert not pve._looks_like_proxmox_response(200, json.dumps(payload).encode(), {})


@pytest.mark.parametrize("version_ok", [False, True])
def test_proxmox_weak_access_needs_independent_version_proof(monkeypatch, version_ok):
    calls = []

    def request(_host, _port, path, *_args, **_kwargs):
        calls.append(path)
        data = {"clustername": "business-cluster"}
        if path == "/version" and version_ok:
            data = {"version": "8.2.2", "release": "8.2", "repoid": "abc1234"}
        return 200, json.dumps({"data": data}).encode(), {}, None

    monkeypatch.setattr(pve, "_proxmox_request", request)
    ctx = SimpleNamespace(
        host="qa", port=8006, args=SimpleNamespace(timeout=1, retries=0, https=False), target=None, lifecycle_state=None
    )
    result = pve_stage._proxmox_detect(ctx).to_dict()
    assert result["is_proxmox"] is version_ok
    assert calls == ["/access", "/version"]
    assert result["checked_endpoints"] == 2
    if not version_ok:
        assert result["detection_status"] == "unverified" and result["operational_failure"]
        assert result["auth_required"] is None


def test_proxmox_branded_access_keeps_single_request(monkeypatch):
    calls = []

    def request(_host, _port, path, *_args, **_kwargs):
        calls.append(path)
        return 401, b'{"data":null}', {"Server": "pve-api-daemon"}, None

    monkeypatch.setattr(pve, "_proxmox_request", request)
    ctx = SimpleNamespace(
        host="qa", port=8006, args=SimpleNamespace(timeout=1, retries=0, https=False), target=None, lifecycle_state=None
    )
    assert pve_stage._proxmox_detect(ctx).to_dict()["is_proxmox"]
    assert calls == ["/access"]


@pytest.mark.parametrize(
    "payload",
    [
        {"result": {"collections": []}, "status": "ok"},
        {"status": {"error": "Unknown method"}, "time": 0.001},
        {"status": {"error": "Invalid API key"}},
    ],
)
def test_qdrant_generic_envelope_is_not_identity(payload):
    assert not qdrant._qdrant_looks_like_response(payload)


@pytest.mark.parametrize("branded_root,branded_info", [(False, False), (False, True), (True, False)])
def test_qdrant_weak_collections_needs_product_info(monkeypatch, branded_root, branded_info):
    generic = {"result": {"collections": []}, "status": "ok"}
    branded = {"title": "qdrant - vector search engine", "version": "1.12.0"}
    calls = []
    monkeypatch.setattr(qdrant, "_qdrant_get_root_info", lambda *_a, **_k: (200, branded if branded_root else {}, None))
    monkeypatch.setattr(qdrant, "_qdrant_get_collections", lambda *_a, **_k: (200, generic, None))

    def request(_host, _port, method, path, *_args, **_kwargs):
        calls.append((method, path))
        return 200, branded if branded_info else generic, None

    monkeypatch.setattr(qdrant, "_http_json_request", request)
    ctx = SimpleNamespace(
        host="qa", port=6333, args=SimpleNamespace(timeout=1, retries=0), lifecycle_state=qdrant.QdrantLifecycleState()
    )
    options = dict(show_collections=False, dump_requested=False, dump_limit=None, collection_name=None, ssrf_urls=[])
    result = qdrant.detect_qdrant(ctx, options)
    assert result["is_qdrant"] is (branded_root or branded_info)
    if not (branded_root or branded_info):
        assert result["detection_status"] == "unverified" and result["operational_failure"]
    assert calls == ([] if branded_root else [("GET", "/service/info")])


@pytest.mark.parametrize("module", ["proxmox", "qdrant"])
@pytest.mark.parametrize("confirmed", [False, True])
def test_async_correlates_weak_api_without_changing_identity_rules(module, confirmed):
    calls = []

    class Native:
        timeout = 1
        retries = 0
        max_bytes = 262144
        ssl_context = shared_client_ssl_context(insecure=True)

        async def close(self):
            pass

        async def get(self, url, *, headers=None, **kwargs):
            path = urlsplit(url).path
            calls.append(path)
            payload: dict[str, Any]
            if module == "proxmox":
                payload = {"data": {"clustername": "business"}}
                if path.endswith("/version") and confirmed:
                    payload = {"data": {"version": "8.2.2", "release": "8.2", "repoid": "abc1234"}}
            else:
                payload = {"result": {"collections": []}, "status": "ok"}
                if path == "/service/info" and confirmed:
                    payload = {"title": "qdrant - vector search engine", "version": "1.12.0"}
            return HttpResponse(200, json.dumps(payload).encode(), {}, request_url=url, final_url=url)

    args = SimpleNamespace(timeout=1, retries=0, https=False)
    ctx = SimpleNamespace(host="127.0.0.1", port=8006, args=args, target=None, lifecycle_state=None)
    spec = pve_stage.build_proxmox_spec(args) if module == "proxmox" else qdrant_stage.build_qdrant_spec(args)
    assert spec.lifecycle_state_factory is not None and spec.detect_async is not None
    ctx.lifecycle_state = spec.lifecycle_state_factory(ctx)
    try:
        result = asyncio.run(spec.detect_async(ctx, Native())).to_dict()
    finally:
        ctx.lifecycle_state.close()
    assert calls == (
        ["/api2/json/access", "/api2/json/version"] if module == "proxmox" else ["/", "/collections", "/service/info"]
    )
    assert result["is_" + module] is confirmed
    if not confirmed:
        assert result["detection_status"] == "unverified"
