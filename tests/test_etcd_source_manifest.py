"""Selected v2/v3 reads retain API-specific access and completion evidence."""

from __future__ import annotations

import base64
import json
import time
from types import SimpleNamespace

import pytest

from redposture_core.modules.etcd import actions
from redposture_core.storage_discovery import DiscoveryCollector


@pytest.mark.parametrize("api", ["v2", "v3"])
@pytest.mark.parametrize("status", [200, 403, 500])
def test_selected_key_reports_actual_api_and_no_findings_from_denial(monkeypatch, api, status):
    def encode(value):
        return base64.b64encode(value.encode()).decode()

    payload = (
        {"node": {"key": "/password", "value": "inactive-etcd!42"}}
        if api == "v2"
        else {"kvs": [{"key": encode("/password"), "value": encode("inactive-etcd!42")}]}
    )
    monkeypatch.setattr(actions, "_http_json_request", lambda *a, **kw: (status, json.dumps(payload)))
    c = DiscoveryCollector(
        "etcd",
        SimpleNamespace(host="qa", port=2379, args=SimpleNamespace(discover_time=30)),
        {"status": "open_no_auth"},
    )
    budget = actions._EtcdDiscoveryBudget(time.monotonic() + 30, 2**63 - 1, c)
    method = actions._dump_v2_key if api == "v2" else actions._dump_v3_key
    _, error = method("qa", 2379, "/password", 1, discovery_budget=budget)
    rows = {r["id"]: r for r in c.result()["sources"]}
    active = rows["etcd." + api + "_values"]
    assert active["requested"] == 1 and active["read"] == int(status == 200)
    assert active["denied"] == int(status == 403) and active["complete"] == (status == 200)
    assert rows["etcd." + ("v3" if api == "v2" else "v2") + "_values"]["requested"] == 0
    assert bool(error) == (status != 200)
    assert [f["value"] for f in c.result()["findings"]] == (["inactive-etcd!42"] if status == 200 else [])
