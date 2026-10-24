"""Regressions found by independent review and the real Portainer fixture."""

from __future__ import annotations

import json
from types import SimpleNamespace

from redposture_core import web_panels
from redposture_core.clients.http_api import HttpResponse
from redposture_core.data_discovery import inspect_record
from redposture_core.modules.portainer import actions


def test_remaining_discovery_time_is_passed_to_each_http_read(monkeypatch):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    timeouts = []

    def get(pool, base, path, **kwargs):
        timeouts.append(kwargs.get("timeout"))
        payload = [{"Id": 1, "Name": "qa"}] if path.startswith("/api/endpoints?") else []
        return HttpResponse(200, json.dumps(payload).encode(), {})

    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(
        args=SimpleNamespace(discover=True, containers=True, discover_time=0.25, discover_max_bytes=5000, timeout=5)
    )
    result = web_panels.enumerate_panel(ctx, {"ui_product": "portainer", "ui": {"endpoint": "http://qa"}})
    assert result["ui"]["inventory"]["containers"]["count"] == 0
    assert timeouts and all(isinstance(value, float) and 0 < value <= 0.25 for value in timeouts)


def test_generated_volume_resource_id_is_not_a_discovery_secret(monkeypatch):
    item = {
        "Name": "qa-metadata",
        "Driver": "local",
        "ResourceID": "qa-metadata_1bf58832-3500-49c1-9e1c-2976c9bd5f9f",
        "Labels": {"qa_password": "warehouse-test-secret-827341"},
    }

    def enumerate_panel(ctx, panel):
        return {
            **panel,
            "ui": {**panel["ui"], "inventory": {"volumes": {"records": [item], "count": 1, "partial": False}}},
        }

    monkeypatch.setattr(web_panels, "enumerate_panel", enumerate_panel)
    ctx = SimpleNamespace(args=SimpleNamespace(discover=True), lifecycle_state=None)
    result = actions.data_record(ctx, {"status": "open_no_auth", "ui_product": "portainer", "ui": {}})
    findings = inspect_record("portainer", result)["findings"]
    assert any(f["type"] == "password" for f in findings)
    assert not any("ResourceID" in f["object_path"] for f in findings)
    assert result["ui"]["inventory"] == {}  # implicit inventory stays hidden
    assert item["ResourceID"].startswith("qa-metadata_")  # scan projection never mutates inventory


def test_failed_portainer_transport_is_retryable_and_never_confirmed(monkeypatch):
    monkeypatch.setattr(web_panels, "HttpSessionPool", lambda **kw: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(web_panels, "_get", lambda *args, **kwargs: HttpResponse(0, b"", {}, error="timed out"))
    ctx = SimpleNamespace(
        host="qa", port=9000, args=SimpleNamespace(timeout=0.2), target=SimpleNamespace(scheme="http", path="")
    )
    result = actions.detect_record(ctx)
    assert result["is_portainer"] is False
    assert result["detection_status"] == "transport_failure"
    assert result["detection_signals"] == ["portainer.probe"]
