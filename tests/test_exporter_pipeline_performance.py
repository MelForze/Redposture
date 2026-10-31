"""Exporter speedups must preserve native recovery, action order and exact bodies."""

from __future__ import annotations

import asyncio
import json
import threading
from collections import Counter
from urllib.parse import urlsplit

import pytest

from redposture_core import async_detection
from redposture_core.clients.async_http_detect import AsyncDetectionHttp
from redposture_core.clients.http_api import HttpResponse
from redposture_core.exporters import async_detect, collect, http_client, trigger

EXPORTER = {
    "name": "mysqld_exporter",
    "port": 9104,
    "detect_path": "/metrics",
    "markers": ["mysql_exporter_build_info"],
    "trigger_path": "/probe",
    "target_fmt": "{our_host}:3306",
    "explicit_profile": True,
}


def details(body="mysql_exporter_build_info 1\n", **kw):
    return dict(status=200, body=body, error=None, truncated=False, content_type="text/plain", elapsed_ms=1, **kw)


@pytest.mark.parametrize("retries", [0, 1])
def test_trigger_error_recovery_remains_native_with_same_budgets(monkeypatch, retries):
    attempts = Counter()

    async def prefetch(host, port, scheme, timeout, request_retries, tls_context=None, **kw):
        assert (timeout, request_retries) == (0.2, retries)
        attempts[host] += 1
        row = details()
        if attempts[host] == 1:
            row.update(status=None, body="", error="timed out")
        return row

    monkeypatch.setattr(async_detect, "prefetch_metrics", prefetch)
    monkeypatch.setattr(async_detection, "async_detection_allowed", lambda _: True)
    monkeypatch.setattr(http_client, "http_get_text", lambda *a: pytest.fail("sync detect replay"))
    hosts = [f"127.0.0.{i + 1}" for i in range(40)]
    result = trigger.scan_exporters_and_trigger(
        None, hosts, [], 0.2, workers=2, retries=retries, trigger_exporters=[EXPORTER]
    )
    assert result["detected_exporters"] == 40
    assert attempts == Counter({host: 2 for host in hosts})


def test_trigger_action_starts_before_last_detect_and_stays_sync(monkeypatch):
    action_started = threading.Event()
    phases = []

    async def prefetch(host, *a, **kw):
        if host == "127.0.0.40":
            for _ in range(500):
                if action_started.is_set():
                    break
                await asyncio.sleep(0.001)
            assert action_started.is_set(), "trigger waited for the entire detect pass"
        return details()

    def request(url, timeout, retries):
        assert urlsplit(url).path == "/probe"
        phases.append(threading.current_thread().name)
        action_started.set()
        return 200, "probe_success 1\n"

    monkeypatch.setattr(async_detect, "prefetch_metrics", prefetch)
    monkeypatch.setattr(async_detection, "async_detection_allowed", lambda _: True)
    monkeypatch.setattr(http_client, "http_get_text", request)
    result = trigger.scan_exporters_and_trigger(
        None,
        [f"127.0.0.{i + 1}" for i in range(40)],
        ["127.0.0.1"],
        0.2,
        workers=2,
        retries=0,
        trigger_exporters=[EXPORTER],
    )
    assert result["detected_exporters"] == result["triggered"] == result["attempted"] == 40
    assert phases and all(name != "redposture-async-detect" for name in phases)


def test_trigger_real_keepalive_pool_serves_detect_and_actions():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    connections, paths = set(), []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            connections.add(self.client_address)
            paths.append(urlsplit(self.path).path)
            body = b"mysql_exporter_build_info 1\n" if paths[-1] == "/metrics" else b"probe_success 1\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        result = trigger.scan_exporters_and_trigger(
            None,
            ["127.0.0.1"],
            ["127.0.0.1", "127.0.0.2"],
            1,
            workers=1,
            retries=0,
            trigger_exporters=[{**EXPORTER, "port": server.server_port}],
        )
        assert result["triggered"] == 2
        assert paths == ["/metrics", "/probe", "/probe"]
        assert len(connections) == 1, "same exporter reconnected for each request"
        assert http_client.get_active_http_pool() is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()


@pytest.mark.parametrize("fingerprint", [False, True])
def test_collect_native_fingerprints_and_complete_response_reuse(monkeypatch, tmp_path, fingerprint):
    paths, threads = Counter(), []
    exporters = [
        {
            "name": "alpha",
            "port": 9104,
            "markers": ["alpha_build_info"],
            "weak_markers": ["shared_value"],
            "fingerprint_vars": ["alpha-component"],
        }
    ]
    if fingerprint:
        exporters.append(
            {
                "name": "beta",
                "port": 9104,
                "markers": ["beta_build_info"],
                "weak_markers": ["shared_value"],
                "fingerprint_vars": ["beta-component"],
            }
        )
    bodies = {
        "/metrics": b"shared_value 1\n" if fingerprint else b"alpha_build_info 1\n",
        "/debug/vars": b'{"component":"alpha-component","unicode":"\\xe2\\x82\\xac"}',
        "/debug/pprof/cmdline?debug=1": b"alpha-component\\x00--serve",
    }

    async def wire(self, url, timeout, headers):
        path = url.split(":9104", 1)[1]
        paths[(urlsplit(url).hostname, path)] += 1
        threads.append(threading.current_thread().name)
        return HttpResponse(200, bodies[path], {"Content-Type": "text/plain"})

    def sync_get(url, **kw):
        path = url.split(":9104", 1)[1]
        paths[(urlsplit(url).hostname, path)] += 1
        return http_client.HTTPResponseDetails(details(bodies[path].decode()), raw_body=bodies[path])

    monkeypatch.setattr(AsyncDetectionHttp, "_once", wire)
    from redposture_core.exporters.http_pool import HTTPConnectionPool

    def pool_get(self, url, timeout, **kw):
        response = sync_get(url)
        return 200, response.raw_body, "text/plain", None, False, {"Content-Type": "text/plain"}

    monkeypatch.setattr(HTTPConnectionPool, "_get_once", pool_get)
    monkeypatch.setattr(collect, "http_get_details", sync_get)
    monkeypatch.setattr(async_detect, "http_get_details", sync_get)
    monkeypatch.setattr(async_detection, "async_detection_allowed", lambda _: True)
    sink, records = tmp_path / "out.jsonl", []
    result = collect.collect_exporter_debug_data(
        None,
        [],
        1,
        str(sink),
        workers=2,
        retries=0,
        collect_exporters=exporters,
        discovery_exporters=exporters,
        collect_debug_endpoints=tuple(bodies),
        emit_summary=False,
        record_callback=records.append,
        save_responses_dir=str(tmp_path / "raw"),
        emit_line=lambda _: None,
        scan_work_items=((f"127.0.0.{i + 1}", 9104, "http") for i in range(40)),
        scan_work_items_count=40,
    )
    assert result == (120, 120)
    assert paths == Counter({(f"127.0.0.{i + 1}", path): 1 for i in range(40) for path in bodies})
    assert len(records) == 120
    assert all(r["body"].encode() == bodies[r["endpoint"]] for r in records)
    if fingerprint:
        assert len(threads) == 120, "fingerprint HTTP left the native detector"
    assert all(name == "redposture-async-detect" for name in threads)
    saved = [json.loads(line) for line in sink.read_text().splitlines()]
    assert len(saved) == 120 and all("\\x1b" not in str(r) for r in saved)


def test_trigger_recovery_large_complete_response_does_not_add_third_request(monkeypatch):
    calls = Counter()
    body = b"# ordinary " + b"x" * (300 * 1024) + b"\nmysql_exporter_build_info 1\n"

    async def wire(self, url, timeout, headers):
        calls[url] += 1
        if calls[url] == 1:
            raise TimeoutError("timed out")
        return HttpResponse(200, body[: self.max_bytes], {}, truncated=len(body) > self.max_bytes)

    monkeypatch.setattr(AsyncDetectionHttp, "_once", wire)
    monkeypatch.setattr(async_detection, "async_detection_allowed", lambda _: True)
    monkeypatch.setattr(http_client, "http_get_text", lambda *a: pytest.fail("extra sync recovery request"))
    result = trigger.scan_exporters_and_trigger(
        None, [f"127.0.0.{i + 1}" for i in range(40)], [], 0.1, workers=2, retries=0, trigger_exporters=[EXPORTER]
    )
    assert result["detected_exporters"] == 40
    assert set(calls.values()) == {2}


@pytest.mark.parametrize("fault", ["truncated", "denied", "server_error", "timeout"])
def test_collect_never_reuses_partial_or_failed_fingerprint(monkeypatch, tmp_path, fault):
    from redposture_core.exporters.http_pool import HTTPConnectionPool

    exporter = {
        "name": "alpha",
        "port": 9104,
        "markers": ["alpha_info"],
        "weak_markers": ["shared_value"],
        "fingerprint_cmdline": ["alpha-component"],
    }
    calls = Counter()
    metrics = b"shared_value 1\n"
    cmdline = b"alpha-component\x00--serve"

    async def wire(self, url, timeout, headers):
        path = url.split(":9104", 1)[1]
        calls[("native", path)] += 1
        if path == "/metrics":
            return HttpResponse(200, metrics, {})
        if path.startswith("/debug/pprof/cmdline"):
            return HttpResponse(200, cmdline, {})
        if fault == "timeout":
            raise TimeoutError("timed out")
        return HttpResponse(
            403 if fault == "denied" else 500 if fault == "server_error" else 200,
            b"prefix",
            {},
            truncated=fault == "truncated",
        )

    def sync_get(self, url, timeout, **kw):
        path = url.split(":9104", 1)[1]
        calls[("sync", path)] += 1
        assert path == "/debug/vars", "complete observations were fetched twice"
        return 200, b"full vars", "text/plain", None, False, {}

    monkeypatch.setattr(AsyncDetectionHttp, "_once", wire)
    monkeypatch.setattr(HTTPConnectionPool, "_get_once", sync_get)
    monkeypatch.setattr(async_detection, "async_detection_allowed", lambda _: True)
    records = []
    result = collect.collect_exporter_debug_data(
        None,
        [],
        1,
        None,
        workers=2,
        retries=0,
        collect_exporters=[exporter],
        discovery_exporters=[exporter],
        collect_debug_endpoints=("/metrics", "/debug/vars", "/debug/pprof/cmdline?debug=1"),
        emit_summary=False,
        emit_line=lambda _: None,
        record_callback=records.append,
        scan_work_items=((f"127.0.0.{i + 1}", 9104, "http") for i in range(40)),
        scan_work_items_count=40,
    )
    assert result == (120, 120)
    assert calls == Counter(
        {
            ("native", "/metrics"): 40,
            ("native", "/debug/vars"): 40,
            ("native", "/debug/pprof/cmdline?debug=1"): 40,
            ("sync", "/debug/vars"): 40,
        }
    )
    assert len(records) == 120
    assert all(r["body"] == "full vars" for r in records if r["endpoint"] == "/debug/vars")
    assert all(r.get("raw_body") == cmdline for r in records if "cmdline" in r["endpoint"])


@pytest.mark.parametrize("verdict", ["strong", "weak", "ambiguous", "foreign", "denied", "metrics_only"])
def test_async_full_discovery_matches_original_classifier(monkeypatch, verdict):
    from redposture_core.exporters import discover

    exporter = {
        "name": "alpha",
        "port": 9104,
        "markers": ["alpha_info"],
        "weak_markers": ["shared_value"],
        "fingerprint_vars": ["alpha-component"],
    }
    exporters = [exporter]
    if verdict == "ambiguous":
        exporters.append({**exporter, "name": "beta"})
    body = {
        "strong": b"alpha_info 1\n",
        "weak": b"shared_value 1\n",
        "ambiguous": b"shared_value 1\n",
        "foreign": b"<html>ordinary service</html>",
        "denied": b"alpha_info 1\n",
        "metrics_only": b"other_metric 1\n",
    }[verdict]
    responses = {
        "/metrics": (403 if verdict == "denied" else 200, body),
        "/debug/vars": (200, b"alpha-component"),
        "/debug/pprof/cmdline?debug=1": (404, b""),
    }
    before, after = [], []

    def original(url, timeout, retries, *, max_bytes):
        path = url.split(":9104", 1)[1]
        before.append((path, max_bytes))
        status, raw = responses[path]
        return http_client.HTTPResponseDetails(
            {**details(raw.decode()), "status": status, "elapsed_ms": 0}, raw_body=raw
        )

    async def wire(self, url, timeout, headers):
        path = url.split(":9104", 1)[1]
        after.append((path, self.max_bytes))
        status, raw = responses[path]
        return HttpResponse(status, raw, {"Content-Type": "text/plain"})

    expected = discover.scan_presence_port_task("127.0.0.1", 9104, exporters, 1, 0, http_get_details_fn=original)
    monkeypatch.setattr(AsyncDetectionHttp, "_once", wire)
    actual = asyncio.run(async_detect.prefetch_discovery("127.0.0.1", 9104, "http", 1, 0, exporters))
    for record in (expected[0], actual[0]):
        record.pop("timestamp")
        record.pop("elapsed_ms")
    assert actual == expected
    assert actual[0]["detected"] is (verdict in {"strong", "weak", "metrics_only"})
    assert before == after


def test_full_async_discovery_cancellation_closes_client_and_clears_context(monkeypatch):
    opened, closed = asyncio.Event(), []
    original_close = AsyncDetectionHttp.close

    async def wire(self, url, timeout, headers):
        if url.endswith("/metrics"):
            return HttpResponse(200, b"shared_value 1\n", {})
        opened.set()
        await asyncio.Future()

    async def close(self):
        closed.append(self)
        await original_close(self)

    monkeypatch.setattr(AsyncDetectionHttp, "_once", wire)
    monkeypatch.setattr(AsyncDetectionHttp, "close", close)

    async def run():
        task = asyncio.create_task(
            async_detect.prefetch_discovery(
                "127.0.0.1",
                9104,
                "http",
                1,
                0,
                [{"name": "alpha", "weak_markers": ["shared_value"], "markers": ["alpha_info"]}],
            )
        )
        await asyncio.wait_for(opened.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert async_detect._PREFETCH_CLIENT.get() is None

    asyncio.run(run())
    assert len(closed) == 1


def test_collect_classifier_error_is_isolated_to_target(monkeypatch):
    from redposture_core.exporters import discover

    async def prefetch(*a, **kw):
        return details("alpha_info 1\n")

    def score(*a, **kw):
        raise ValueError("invalid candidate metadata")

    monkeypatch.setattr(async_detect, "prefetch_metrics", prefetch)
    monkeypatch.setattr(discover, "score_metrics_candidate", score)
    monkeypatch.setattr(async_detection, "async_detection_allowed", lambda _: True)
    exporter = {"name": "alpha", "port": 9104, "markers": ["alpha_info"]}
    stats = {}
    result = collect.collect_exporter_debug_data(
        None,
        [],
        1,
        None,
        workers=2,
        retries=0,
        collect_exporters=[exporter],
        discovery_exporters=[exporter],
        stats_sink=stats,
        emit_summary=False,
        emit_line=lambda _: None,
        scan_work_items=((f"127.0.0.{i + 1}", 9104, "http") for i in range(40)),
        scan_work_items_count=40,
    )
    assert result == (0, 0)
    assert stats["discovery_checks"] == stats["discovery_errors"] == 40
