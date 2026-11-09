"""Report actual source access separately from hidden Swarm secret values."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from typing import Any

import pytest

from redposture_core import web_panels
from redposture_core.clients import http_session
from redposture_core.clients.http_api import HttpResponse
from redposture_core.storage_discovery import DiscoveryCollector, discover_portainer_sources


def run(monkeypatch, *, denied=None, malformed=False, inactive=False, cancel=False):
    from redposture_core.scheduler import NestedSchedulerCancelled

    cancelled = [False]

    class Pool:
        def __init__(self, **kwargs):
            pass

        def close(self):
            pass

        def request_stream(self, method, url, *, on_response, on_chunk, **kwargs):
            if "/docker/images/" in url:
                response = get(self, "http://qa", url.removeprefix("http://qa"))
                on_response(response.status, response.headers)
                on_chunk(response.body)
                return HttpResponse(response.status, b"", response.headers)
            assert method == "GET" and "follow=0" in url
            status = 403 if denied == "logs" else 200
            on_response(status, {})
            on_chunk(b'password="inactive-log!42"\n')
            if cancel:
                cancelled[0] = True
                on_chunk(b"ordinary later data")
            return HttpResponse(status, b"", {})

    routes: dict[str, tuple[str, Any]] = {
        "/api/stacks": ("stacks", [{"Id": 1}]),
        "/api/stacks/1/file": ("file", {"StackFileContent": 'password="inactive-stack!42"'}),
        "/api/endpoints/2/docker/containers/c/json": ("inspect", {"Config": {"Tty": True}}),
        "/api/endpoints/2/docker/images/i/json": ("image", {"Config": {}}),
        "/api/endpoints/2/docker/configs": ("configs", [{"ID": "cfg"}]),
        "/api/endpoints/2/docker/configs/cfg": (
            "config",
            {
                "Spec": {
                    "Data": "!invalid" if malformed else base64.b64encode(b'password="inactive-config!42"').decode()
                }
            },
        ),
        "/api/endpoints/2/docker/secrets": ("secrets", [{"ID": "secret", "Spec": {"Name": "metadata-only"}}]),
        "/api/endpoints/2/docker/info": ("info", {"Swarm": {"LocalNodeState": "inactive"}}),
    }

    def get(pool, base, path, **kwargs):
        kind, value = routes[path]
        status = 403 if denied == kind else 503 if inactive and kind == "configs" else 200
        return HttpResponse(status, json.dumps(value).encode(), {})

    monkeypatch.setattr(http_session, "HttpSessionPool", Pool)
    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(
        host="qa", port=9000, args=SimpleNamespace(discover_time=30, timeout=1), cancelled=lambda: cancelled[0]
    )
    record = {"status": "valid_credentials", "ui": {"endpoint": "http://qa"}}
    c = DiscoveryCollector("portainer", ctx, record)
    try:
        discover_portainer_sources(
            ctx,
            record,
            {
                "environments": {"records": [{"Id": 2}]},
                "containers": {"records": [{"environment": 2, "Id": "c"}]},
                "images": {"records": [{"environment": 2, "Id": "i"}]},
            },
            c,
        )
    except NestedSchedulerCancelled:
        assert cancel
    return c.result()


def test_manifest_covers_existing_content_and_metadata_without_claiming_secret_values(monkeypatch):
    result = run(monkeypatch)
    rows = {r["id"]: r for r in result["sources"]}
    assert {
        "portainer." + name
        for name in (
            "environment_metadata",
            "container_catalog",
            "stack_catalog",
            "stack_files",
            "container_inspect",
            "image_catalog",
            "image_inspect",
            "container_logs",
            "swarm_config_catalog",
            "swarm_config_contents",
            "swarm_secret_metadata",
            "swarm_secret_values",
        )
    } == set(rows)
    assert all(r["read"] == 1 and r["complete"] for k, r in rows.items() if k != "portainer.swarm_secret_values")
    hidden = rows["portainer.swarm_secret_values"]
    assert not hidden["implemented"] and hidden["unsupported"] and not hidden["read"] and not hidden["complete"]
    assert {f["value"] for f in result["findings"]} == {"inactive-log!42", "inactive-stack!42", "inactive-config!42"}
    assert result["status"] == "partial"


@pytest.mark.parametrize(
    "denied,kind",
    [
        ("stacks", "stack_catalog"),
        ("file", "stack_files"),
        ("inspect", "container_inspect"),
        ("logs", "container_logs"),
        ("configs", "swarm_config_catalog"),
        ("config", "swarm_config_contents"),
        ("secrets", "swarm_secret_metadata"),
    ],
)
def test_source_denial_is_not_read_or_complete(monkeypatch, denied, kind):
    result = run(monkeypatch, denied=denied)
    row = next(r for r in result["sources"] if r["id"] == "portainer." + kind)
    assert row["denied"] == 1 and row["read"] == 0 and not row["complete"]
    assert result["status"] == "partial"


def test_invalid_config_data_does_not_count_as_read_content(monkeypatch):
    result = run(monkeypatch, malformed=True)
    row = next(r for r in result["sources"] if r["id"] == "portainer.swarm_config_contents")
    assert row["read"] == 0 and not row["complete"]
    assert result["status"] == "partial"


def test_standalone_docker_has_no_swarm_content_to_read(monkeypatch):
    result = run(monkeypatch, inactive=True)
    rows = {r["id"]: r for r in result["sources"]}
    assert result["status"] == "complete"
    assert rows["portainer.swarm_config_catalog"]["unsupported"]
    assert not rows["portainer.swarm_config_catalog"]["complete"]
    assert rows["portainer.swarm_secret_values"]["requested"] == 0


def test_cancelled_logs_are_incomplete_and_repeat_rereads_every_source(monkeypatch):
    result = run(monkeypatch, cancel=True)
    rows = {r["id"]: r for r in result["sources"]}
    assert result["status"] == "partial" and not rows["portainer.container_logs"]["complete"]
    assert rows["portainer.stack_files"]["complete"]  # Earlier sources stay complete.
    assert rows["portainer.swarm_config_catalog"]["requested"] == 0
    assert {f["value"] for f in result["findings"]} == {"inactive-stack!42", "inactive-log!42"}
    for _ in range(2):
        result = run(monkeypatch)
        rows = {r["id"]: r for r in result["sources"]}
        assert rows["portainer.container_logs"]["complete"]
        assert rows["portainer.swarm_config_contents"]["read"] == 1
        assert {f["value"] for f in result["findings"]} == {
            "inactive-stack!42",
            "inactive-log!42",
            "inactive-config!42",
        }
