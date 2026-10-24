"""Async exporter prefetch must retain the original scanner's verdicts."""

from __future__ import annotations

import pytest

from redposture_core.exporters import discover


@pytest.mark.parametrize(
    "status,body",
    [
        (404, "no exporter"),
        (200, "ordinary web page"),
        (200, '# HELP node_exporter_build_info build\nnode_exporter_build_info{version="1"} 1\n'),
    ],
)
def test_prefetched_scan_has_identical_result_and_does_not_refetch_metrics(status, body):
    from redposture_core.constants import DISCOVERY_EXPORTERS
    from redposture_core.exporters.async_detect import scan_with_prefetched_metrics

    exporters = [e for e in DISCOVERY_EXPORTERS if e["name"] == "node_exporter"]
    details = {
        "status": status,
        "body": body,
        "elapsed_ms": 1,
        "content_type": "text/plain",
        "error": None,
        "truncated": False,
    }
    baseline = discover.scan_presence_port_task(
        "qa", 9100, exporters, 1, 0, http_get_details_fn=lambda *a, **k: details
    )
    got = scan_with_prefetched_metrics("qa", 9100, exporters, 1, 0, "http", details)
    for record in [baseline[0], got[0]]:
        record.pop("timestamp")
    assert got == baseline


def test_prefetch_errors_retain_original_negative_verdict():
    from redposture_core.exporters.async_detect import scan_with_prefetched_metrics

    details = {
        "status": None,
        "body": "",
        "elapsed_ms": 1,
        "content_type": "",
        "error": "connection refused",
        "truncated": False,
    }
    record, hit = scan_with_prefetched_metrics("qa", 9100, [], 1, 0, "http", details)
    assert record["detected"] is False and record["error"] == "connection refused" and hit is None


def test_exporter_prefetch_preserves_small_constant_timeout_and_eof_retry(monkeypatch):
    import asyncio

    from redposture_core.clients.async_http_detect import AsyncDetectionHttp
    from redposture_core.clients.http_api import HttpResponse
    from redposture_core.exporters.async_detect import prefetch_metrics

    seen = []

    async def once(self, url, timeout, headers):
        seen.append(timeout)
        if len(seen) == 1:
            raise asyncio.IncompleteReadError(b"partial", 50)
        return HttpResponse(status=200, body=b"metrics", headers={})

    monkeypatch.setattr(AsyncDetectionHttp, "_once", once)
    result = asyncio.run(prefetch_metrics("127.0.0.1", 9100, "http", 0.025, 1))
    assert seen == [0.025, 0.025]
    assert result["status"] == 200 and result["body"] == "metrics"


@pytest.mark.parametrize("max_inflight", [None, 6])
def test_collect_scales_detect_only_and_respects_explicit_inflight(monkeypatch, tmp_path, max_inflight):
    import asyncio
    import json
    import threading
    import time

    from redposture_core.constants import DISCOVERY_EXPORTERS
    from redposture_core.exporters import async_detect
    from redposture_core.exporters.collect import collect_exporter_debug_data
    from tests.test_collect_streaming import fetch_result

    active = peak = 0
    deep_active = deep_peak = 0
    lock = threading.Lock()

    async def prefetch(*args):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.02)
        active -= 1
        return dict(
            status=200,
            body='node_exporter_build_info{version="1"} 1\n',
            elapsed_ms=1,
            content_type="text/plain",
            error=None,
            truncated=False,
        )

    def fetch(*args, **kwargs):
        nonlocal deep_active, deep_peak
        with lock:
            deep_active += 1
            deep_peak = max(deep_peak, deep_active)
        try:
            time.sleep(0.005)
            return fetch_result(*args, **kwargs)
        finally:
            with lock:
                deep_active -= 1

    monkeypatch.setattr(async_detect, "prefetch_metrics", prefetch)
    exporters = [e for e in DISCOVERY_EXPORTERS if e["name"] == "node_exporter"]
    stats = {}
    output = tmp_path / "collect.jsonl"
    result = collect_exporter_debug_data(
        None,
        [],
        timeout=1,
        output_path=str(output),
        workers=2,
        retries=0,
        collect_exporters=exporters,
        collect_debug_endpoints=("/debug/vars",),
        adaptive_collect=False,
        scan_work_items=((f"10.0.0.{i}", 9100, "http") for i in range(40)),
        scan_work_items_count=40,
        discovery_exporters=exporters,
        stats_sink=stats,
        emit_line=lambda _: None,
        collect_task_fn=fetch,
        max_inflight_requests=max_inflight,
    )
    assert result == (40, 40)
    assert 2 < peak <= (6 if max_inflight else 40)
    assert deep_peak == 2
    records = [json.loads(line) for line in output.read_text().splitlines()]
    hosts = [r["host"] for r in records if "host" in r]
    assert len(hosts) == len(set(hosts)) == 40
