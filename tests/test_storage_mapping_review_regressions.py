"""Integration boundaries must inspect disk mappings without eager copies or lost pages."""

from __future__ import annotations

import json
import tracemalloc
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from redposture_core import storage_discovery as storage
from redposture_core.clients.http_api import HttpResponse
from redposture_core.discovery_json import DiskJSONDocument
from redposture_core.discovery_spool import SpoolingRecords


def test_distinct_streamed_gitlab_pages_are_not_compared_as_empty_lists():
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80)
    collector = storage.DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})
    calls = []

    def get(path, _cap):
        calls.append(path)
        return 200, b"[", {"x-redposture-truncated": "true"}, None

    def stream_page(path, _source):
        page = int(parse_qs(urlsplit(path).query)["page"][0])
        rows = SpoolingRecords()
        document = DiskJSONDocument()
        document.feed(json.dumps({"id": page, "path": f"project-{page}"}).encode())
        rows.append(document.finish())
        document.close()
        rows.finish()
        return rows, {"x-next-page": str(page + 1) if page < 3 else ""}

    rows = list(storage._pages(collector, get, "/projects", "projects", size=1, stream_page=stream_page))
    assert [row["id"] for row in rows] == [1, 2, 3]
    assert len(calls) == 3
    assert collector.result()["partial_reasons"] == []


def test_reordered_fields_in_repeated_streamed_page_still_stop_the_walk():
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=30), host="qa", port=80)
    collector = storage.DiscoveryCollector("gitlab", ctx, {"status": "open_no_auth"})

    def get(_path, _cap):
        return 200, b"[", {"x-redposture-truncated": "true"}, None

    def stream_page(path, _source):
        page = int(parse_qs(urlsplit(path).query)["page"][0])
        rows = SpoolingRecords()
        document = DiskJSONDocument()
        document.feed(json.dumps({"id": 1, "path": "same"} if page == 1 else {"path": "same", "id": 1}).encode())
        rows.append(document.finish())
        document.close()
        rows.finish()
        return rows, {"x-next-page": str(page + 1)}

    rows = list(storage._pages(collector, get, "/projects", "projects", size=1, stream_page=stream_page))
    assert [row["id"] for row in rows] == [1]
    assert collector.result()["partial_reasons"] == ["projects: repeated_page"]


def test_portainer_config_metadata_projection_does_not_rebuild_wide_spec(monkeypatch):
    from redposture_core import web_panels
    from redposture_core.clients import http_session

    detail_path = "/api/endpoints/2/docker/configs/cfg-wide"
    peak = 0

    class Pool:
        def __init__(self, **_kwargs):
            pass

        def close(self):
            pass

        def request_stream(self, _method, url, *, on_chunk, on_response, **_kwargs):
            assert url.endswith(detail_path)
            on_response(200, {})
            on_chunk(b'{"ID":"cfg-wide","Spec":{')
            for index in range(1000):
                on_chunk(f'"field_{index:05d}":"'.encode())
                on_chunk(b"v" * 50000)
                on_chunk(b'",')
            on_chunk(b'"Data":"","password":"kept-secret"}}')
            # Measure only the projection, after network/parser allocation.
            tracemalloc.start()
            return HttpResponse(200, b"", {})

    def get(_pool, _base, path, **_kwargs):
        if path == detail_path:
            return HttpResponse(200, b"{", {}, truncated=True)
        data = [{"ID": "cfg-wide"}] if path.endswith("/docker/configs") else []
        return HttpResponse(200, json.dumps(data).encode(), {})

    monkeypatch.setattr(http_session, "HttpSessionPool", Pool)
    monkeypatch.setattr(web_panels, "_get", get)
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=90, timeout=1, secure=False), host="qa", port=9000)
    record = {"status": "valid_credentials", "ui": {"endpoint": "http://qa:9000", "session_token": "token"}}
    inventory = {"environments": {"records": [{"Id": 2, "Name": "local"}]}, "containers": {"records": []}}
    collector = storage.DiscoveryCollector("portainer", ctx, record)
    original_add = collector.add

    def measured_add(source, value, **kwargs):
        nonlocal peak
        if source.endswith("/config/cfg-wide/metadata"):
            _current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            assert len(value["Spec"]) == 1001
            assert "Data" not in value["Spec"]
        return original_add(source, value, **kwargs)

    monkeypatch.setattr(collector, "add", measured_add)
    try:
        storage.discover_portainer_sources(ctx, record, inventory, collector)
    finally:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
    report = collector.result()
    assert report["status"] == "complete", report["partial_reasons"]
    assert [item["value"] for item in report["findings"]] == ["kept-secret"]
    assert peak < 8_000_000, f"Config metadata projection materialized {peak} heap bytes"
