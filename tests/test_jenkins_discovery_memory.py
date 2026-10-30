"""Large Jenkins catalogs keep exact source data without retaining it in RAM."""

from __future__ import annotations

import json
import re
import tracemalloc
from types import SimpleNamespace
from typing import Any

from redposture_core.clients.http_api import HttpResponse
from redposture_core.discovery_spool import SpoolingRecords
from redposture_core.modules.jenkins import actions, render, stage
from redposture_core.storage_discovery import DiscoveryCollector


def test_paged_jenkins_catalog_memory_does_not_grow_with_all_pages(monkeypatch, record_testsuite_property):
    def get(_client, _base, path, _basic=None):
        page = re.search(r"\{(\d+),(\d+)\}$", path)
        if page is None:
            return HttpResponse(200, b'{"jobs":[', {}, truncated=True)
        start, end = map(int, page.groups())
        jobs = [{"name": f"job-{index:05d}", "url": "x" * 4096} for index in range(start, min(end, 10000))]
        return HttpResponse(200, json.dumps({"jobs": jobs}).encode(), {})

    monkeypatch.setattr(actions, "_get", get)
    ctx = SimpleNamespace(args=SimpleNamespace(discover_time=60), host="qa", port=8080)
    collector = DiscoveryCollector("jenkins", ctx, {"status": "open_no_auth"})
    tracemalloc.start()
    try:
        jobs, _response = actions._discovery_jobs(
            object(), "http://qa", "/api/json?tree=jobs[name,url]", None, collector
        )
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert jobs is not None and len(jobs) == 10000
    assert jobs[-1]["name"] == "job-09999"
    assert collector.result()["partial_reasons"] == []
    record_testsuite_property("jenkins_catalog_peak_traced_bytes", peak)
    assert peak < 12_000_000, f"catalog retained {peak} traced bytes"


def test_discovery_keeps_all_configs_and_late_finding_with_bounded_memory(monkeypatch, record_testsuite_property):
    def get(_client, _base, path, _basic=None):
        if path.startswith("/api/json"):
            jobs = [{"name": f"job-{index:05d}"} for index in range(8000)]
            return HttpResponse(200, json.dumps({"jobs": jobs}).encode(), {})
        value = b"<project/>" + b" " * 9216
        if "job-07999" in path:
            value += b"\nAPI_TOKEN=glpat-abcdefghijklmnopqrstuv\n"
        return HttpResponse(200, value, {})

    monkeypatch.setattr(actions, "_client", lambda _ctx: object())
    monkeypatch.setattr(actions, "_get", get)
    ctx = SimpleNamespace(
        args=SimpleNamespace(show_jobs=True, discover=True, discover_time=120),
        credential=None,
        host="qa",
        port=8080,
    )
    tracemalloc.start()
    try:
        result = actions.data_record(ctx, {"api_endpoint": "http://qa", "status": "open_no_auth"})
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result["content_discovery"]["status"] == "complete"
    assert len(result["jobs"]) == len(result["job_configs"]) == 8000
    assert result["job_configs"][-1]["job"] == "job-07999"
    assert any(item["value"] == "glpat-abcdefghijklmnopqrstuv" for item in result["content_discovery"]["findings"])
    record_testsuite_property("jenkins_sources_peak_traced_bytes", peak)
    assert peak < 24_000_000, f"sources retained {peak} traced bytes"


def test_failed_later_catalog_page_preserves_completed_jobs_and_their_findings(monkeypatch):
    def get(_client, _base, path, _basic=None):
        if path.endswith("/config.xml"):
            return HttpResponse(200, b"API_TOKEN=glpat-abcdefghijklmnopqrstuv", {})
        page = re.search(r"\{(\d+),(\d+)\}$", path)
        if page is None:
            return HttpResponse(200, b'{"jobs":[', {}, truncated=True)
        if int(page.group(1)):
            return HttpResponse(503, b"unavailable", {})
        return HttpResponse(
            200, json.dumps({"jobs": [{"name": f"job-{index:03d}"} for index in range(100)]}).encode(), {}
        )

    monkeypatch.setattr(actions, "_client", lambda _ctx: object())
    monkeypatch.setattr(actions, "_get", get)
    ctx = SimpleNamespace(
        args=SimpleNamespace(show_jobs=True, discover=True, discover_time=30), credential=None, host="qa", port=8080
    )
    result = actions.data_record(ctx, {"api_endpoint": "http://qa", "status": "open_no_auth"})
    assert result["content_discovery"]["status"] == "partial"
    assert len(result["jobs"]) == 100
    assert any(item["value"] == "glpat-abcdefghijklmnopqrstuv" for item in result["content_discovery"]["findings"])


def test_interrupted_build_log_keeps_complete_early_finding_and_marks_partial(monkeypatch):
    token = "glpat-abcdefghijklmnopqrstuv"
    streamed = []

    class Pool:
        def request(self, _method, url, **_kwargs):
            path = url.removeprefix("http://qa")
            if path.startswith("/api/json?tree=jobs"):
                body = {"jobs": [{"name": "demo", "firstBuild": {"number": 1}, "lastBuild": {"number": 1}}]}
                return HttpResponse(200, json.dumps(body).encode(), {})
            if path.endswith("/injectedEnvVars/api/json"):
                return HttpResponse(200, b'{"envMap":{}}', {})
            raise AssertionError(path)

        def request_stream(self, _method, url, *, on_chunk, **_kwargs):
            streamed.append(url)
            if url.endswith("/config.xml"):
                on_chunk(b"<project/>")
                return HttpResponse(200, b"", {})
            assert url.endswith("/1/consoleText")
            on_chunk(f"API_TOKEN={token}\n".encode())
            return HttpResponse(200, b"", {}, error="unexpected EOF", truncated=True)

    client = actions.ScopedHttpClient(Pool(), 1024 * 1024)
    monkeypatch.setattr(actions, "_client", lambda _ctx: client)
    ctx = SimpleNamespace(
        args=SimpleNamespace(show_jobs=True, discover=True, discover_time=30, timeout=1),
        credential=None,
        host="qa",
        port=8080,
    )
    result = actions.data_record(ctx, {"api_endpoint": "http://qa", "status": "open_no_auth"})
    report = result["content_discovery"]
    assert report["status"] == "partial"
    assert any(item["value"] == token for item in report["findings"])
    assert any("unexpected EOF" in reason for reason in report["partial_reasons"])
    assert any(path.endswith("/1/consoleText") for path in streamed)


def test_discovery_inventory_emits_every_row_in_bounded_batches():
    jobs = SpoolingRecords()
    for index in range(30000):
        jobs.append({"name": f"job-{index:05d}-" + "x" * 240, "color": "blue"})
    jobs.finish()
    record = {"host": "qa", "port": 8080, "jobs_requested": True, "jobs": jobs, "jobs_count": len(jobs)}
    observed: dict[str, Any] = {"count": 0, "max_batch": 0, "first": None, "last": None}

    def emit(lines):
        observed["count"] += len(lines)
        observed["max_batch"] = max(observed["max_batch"], len(lines))
        if observed["first"] is None:
            observed["first"] = lines[0]
        observed["last"] = lines[-1]
        assert all("\x1b[" not in line for line in lines)

    ctx = SimpleNamespace(args=SimpleNamespace(discover=True, output_format="txt"), live_emit=emit)
    tracemalloc.start()
    try:
        stage._emit_discovery_inventory(ctx, record)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert observed["count"] == 30001
    assert observed["max_batch"] <= 256
    assert "Jobs Enumeration (jobs:30000)" in observed["first"]
    assert "job-29999-" in observed["last"]
    assert peak < 4_000_000
    assert render._format_inventory_records(record, "txt") == []


def test_specific_token_in_job_config_is_not_repeated_as_generic_secret(monkeypatch):
    def get(_client, _base, path, _basic=None):
        if path.startswith("/api/json"):
            return HttpResponse(200, b'{"jobs":[{"name":"qa"}]}', {})
        return HttpResponse(200, b"API_TOKEN=glpat-abcdefghijklmnopqrstuv", {})

    monkeypatch.setattr(actions, "_client", lambda _ctx: object())
    monkeypatch.setattr(actions, "_get", get)
    ctx = SimpleNamespace(
        args=SimpleNamespace(show_jobs=True, discover=True, discover_time=30), credential=None, host="qa", port=8080
    )
    result = actions.data_record(ctx, {"api_endpoint": "http://qa", "status": "open_no_auth"})
    findings = result["content_discovery"]["findings"]
    assert [(item["type"], item["value"]) for item in findings] == [("gitlab_token", "glpat-abcdefghijklmnopqrstuv")]
