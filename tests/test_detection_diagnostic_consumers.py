"""Fallback telemetry must preserve exporter results and synchronous work."""

from __future__ import annotations

import pytest

from redposture_core import async_detection
from redposture_core.clients.async_http_detect import AsyncHttpFallback
from redposture_core.exporters import async_detect, collect, discover, trigger


async def unsupported(*args, **kwargs):
    failure = AsyncHttpFallback("ambiguous HTTP framing")
    failure.native_requests = 2
    raise failure


def scan(host, port, exporters, timeout, retries, **kwargs):
    from tests.test_collect_streaming import scan_result

    return scan_result(host, port)


@pytest.mark.parametrize("workflow", ["presence", "collect"])
def test_exporter_fallback_counters_reach_stats_and_keep_all_results(monkeypatch, tmp_path, workflow):
    from tests.test_collect_streaming import fetch_result

    monkeypatch.setattr(async_detection, "async_detection_allowed", lambda _: True)
    monkeypatch.setattr(async_detect, "prefetch_metrics", unsupported)
    monkeypatch.setattr(async_detect, "prefetch_discovery", unsupported)
    monkeypatch.setattr(discover, "scan_presence_port_task", scan)
    monkeypatch.setattr(discover, "_NATIVE_SCAN_TASK", scan)
    monkeypatch.setattr(collect, "_NATIVE_SCAN_TASK", scan)
    hosts = [f"qa-{i}" for i in range(40)]
    exporters = [{"name": "node_exporter", "port": 9100, "markers": ["node_exporter_build_info"]}]
    stats = {}
    if workflow == "presence":
        presence_result = discover.scan_exporter_presence(
            hosts,
            1,
            None,
            workers=2,
            retries=0,
            discovery_exporters=exporters,
            show_progress=False,
            emit_summary=False,
            stats_sink=stats,
        )
        assert presence_result[:2] == (40, 40) and set(presence_result[2]) == set(hosts)
    else:
        result = collect.collect_exporter_debug_data(
            None,
            [],
            timeout=1,
            output_path=str(tmp_path / "collect.jsonl"),
            workers=2,
            retries=0,
            collect_exporters=exporters,
            collect_debug_endpoints=("/debug/vars",),
            adaptive_collect=False,
            scan_work_items=((host, 9100, "http") for host in hosts),
            scan_work_items_count=40,
            discovery_exporters=exporters,
            stats_sink=stats,
            emit_line=lambda _: None,
            collect_task_fn=fetch_result,
        )
        assert result == (40, 40)
    assert stats["fallback_framing_count"] == stats["fallback_sync_work_count"] == 40
    assert stats["fallback_framing_http_requests"] == 80
    assert stats["fallback_sync_work_worker_us"] > 0


@pytest.mark.parametrize("truncated", [False, True])
def test_trigger_fallback_summary_keeps_events_and_does_not_run_actions(monkeypatch, truncated):
    from redposture_core.exporters import http_client

    monkeypatch.setattr(async_detection, "async_detection_allowed", lambda _: True)

    async def clipped(*args, **kwargs):
        result = async_detect.PrefetchedResponse(
            {"status": 200, "body": "prefix", "truncated": True}, raw_body=b"prefix"
        )
        result.native_requests = 2
        return result

    monkeypatch.setattr(async_detect, "prefetch_metrics", clipped if truncated else unsupported)
    monkeypatch.setattr(http_client, "http_get_text", lambda *a: (200, "mysql_exporter_build_info 1\n"))
    events = []
    exporter = {
        "name": "mysql_exporter",
        "port": 9104,
        "detect_path": "/metrics",
        "markers": ["mysql_exporter_build_info"],
        "trigger_path": "/probe",
        "target_fmt": "{our_host}:3306",
    }
    result = trigger.scan_exporters_and_trigger(
        None,
        [f"qa-{i}" for i in range(40)],
        [],
        1,
        workers=2,
        retries=0,
        trigger_exporters=[exporter],
        emit_stage_event=events.append,
    )
    assert result["detected_exporters"] == 40
    summaries = "\n".join(event["summary"] for event in events if event["kind"] == "detect_fallback_summary")
    assert (
        f"category={'body_limit' if truncated else 'framing'} count=40" in summaries and "http_requests=80" in summaries
    )
    assert "category=sync_work count=40" in summaries
