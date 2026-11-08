"""KV enumeration and individual values have independent ACL evidence."""

from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest

from redposture_core.clients.http_api import HttpResponse
from redposture_core.modules.consul import actions
from redposture_core.storage_discovery import DiscoveryCollector


@pytest.mark.parametrize("denied", [None, "catalog", "values"])
def test_kv_catalog_and_actual_values_are_not_confused(monkeypatch, denied):
    calls = []
    ctx = SimpleNamespace(host="qa", port=8500, args=SimpleNamespace(discover_time=30))
    c = DiscoveryCollector("consul", ctx, {"status": "open_no_auth"})

    class Pool:
        def request_stream(self, method, url, *, on_chunk, **kwargs):
            assert method == "GET"
            status = 403 if denied == "catalog" else 200
            if kwargs.get("on_response"):
                kwargs["on_response"](status, {})
            on_chunk(b'["app/password"]')
            return HttpResponse(status, b"", {})

    state = actions.ConsulLifecycleState(http=Pool(), discovery_collector=c)
    monkeypatch.setattr(actions._THREAD_LOCAL_LIFECYCLE, "state", state, raising=False)

    def get(host, port, path, timeout, **kwargs):
        calls.append(path)
        assert path == "/v1/kv/app/password"
        return (
            403 if denied == "values" else 200,
            [{"Key": "app/password", "Value": base64.b64encode(b"inactive-consul!42").decode()}],
            None,
            False,
            False,
        )

    monkeypatch.setattr(actions, "_consul_get_json_any", get)
    _, error = actions._consul_kv_dump("qa", 8500, 1, scheme="http", insecure=True)
    result = c.result()
    rows = {r["id"]: r for r in result["sources"]}
    assert rows["consul.kv_catalog"]["read"] == int(denied != "catalog")
    assert rows["consul.kv_catalog"]["denied"] == int(denied == "catalog")
    if denied != "catalog":
        assert rows["consul.kv_values"]["read"] == int(denied is None)
        assert rows["consul.kv_values"]["denied"] == int(denied == "values")
    else:
        assert calls == []
    assert bool(error) == bool(denied)
    if denied is None:
        assert result["status"] == "complete" and all(r["complete"] for r in rows.values())
        assert [f["value"] for f in result["findings"]] == ["inactive-consul!42"]
    else:
        assert result["status"] != "complete" and not result["findings"]
