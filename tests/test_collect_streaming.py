from __future__ import annotations

import argparse
import json
import threading
from collections import Counter
from functools import partial
from pathlib import Path

import pytest

from redposture_core import stage_collect
from redposture_core.exporters import collect as workflow
from redposture_core.exporters import discover
from redposture_core.logger import AttemptLogger

PROFILES = {
    "discovery_exporters": [{"name": "node_exporter", "port": 9100, "markers": ("node_marker",)}],
    "collect_exporters": [{"name": "node_exporter", "port": 9100}],
    "collect_debug_endpoints": ["/debug/vars"],
}


def args_for(path: Path, output: Path, **options: object) -> argparse.Namespace:
    return argparse.Namespace(
        **{
            "debug": False,
            "timeout": 1.0,
            "workers": 4,
            "retries": 0,
            "targets": str(path),
            "hosts": None,
            "hosts_file": None,
            "profiles_file": None,
            "output": str(output),
            "output_format": "json",
            "save_responses_dir": None,
            "deep": False,
            "pprof_seconds": 5,
            "trace_seconds": 2,
            "resume": False,
            "checkpoint_file": None,
            "max_inflight": 8,
            "adaptive_collect": True,
            "collect_exporters_filter": None,
            **options,
        }
    )


def scan_result(host: str, port: int, *, scheme: str = "http", error: str | None = None):
    record = {
        "timestamp": "2026-10-24T00:00:00Z",
        "host": host,
        "exporter": "node_exporter",
        "port": port,
        "url": f"{scheme}://{host}:{port}/metrics",
        "detected": error is None,
        "method": "marker",
        "status": 200 if error is None else None,
        "marker_hit": "node_marker",
        "elapsed_ms": 0,
        "content_type": "text/plain",
        "error": error,
        "truncated": False,
        "body": "node_marker 1",
    }
    hit = {key: record[key] for key in ("exporter", "port", "url", "status", "method")}
    return record, hit if error is None else None


def fetch_result(host: str, exporter: str, port: int, endpoint: str, *_args, scheme="http"):
    return {
        "timestamp": "2026-10-24T00:00:00Z",
        "host": host,
        "exporter": exporter,
        "port": port,
        "endpoint": endpoint,
        "url": f"{scheme}://{host}:{port}{endpoint}",
        "ok": True,
        "status": 200,
        "elapsed_ms": 0,
        "content_type": "text/plain",
        "error": None,
        "truncated": False,
        "body": "ordinary fixture data",
    }, True


def test_large_collect_crosses_old_window_and_emits_before_slow_discovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # One slow job must not gate target 4097 or the first positive's data.
    hosts = [f"10.1.{i // 256}.{i % 256}" for i in range(4097)]
    path = tmp_path / "hosts.txt"
    path.write_text("\n".join(hosts))
    output = tmp_path / "results.jsonl"
    monkeypatch.setattr(stage_collect, "DEFAULT_MAX_NETWORK_HOSTS", 1)
    monkeypatch.setattr(stage_collect, "load_profiles", lambda _: PROFILES)
    later = threading.Event()
    fetched = threading.Event()
    observed_before_slow_finished = []

    def scan(host, port, *_a, scheme="http", **_k):
        if host == hosts[0]:
            reached_later = later.wait(3)
            reached_data = fetched.wait(3) if reached_later else fetched.is_set()
            observed_before_slow_finished.append((reached_later, reached_data))
        if host == hosts[-1]:
            later.set()
        return scan_result(host, port, scheme=scheme)

    def fetch(*a, **kw):
        fetched.set()
        return fetch_result(*a, **kw)

    monkeypatch.setattr(discover, "scan_presence_port_task", scan)
    monkeypatch.setattr(
        stage_collect,
        "collect_exporter_debug_data",
        partial(workflow.collect_exporter_debug_data, collect_task_fn=fetch),
    )
    assert stage_collect.run_collect_stage(args_for(path, output), AttemptLogger()) == 0
    assert observed_before_slow_finished == [(True, True)]
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    records = [row for row in rows if row.get("endpoint")]
    assert Counter(row["host"] for row in records) == Counter(hosts)
    assert rows[-1]["requests"] == rows[-1]["success"] == 4097


def test_streaming_collect_consumes_bounded_roots_and_preserves_scheme(tmp_path: Path) -> None:
    released = threading.Event()
    consumed = 0
    observed = []

    def items():
        nonlocal consumed
        for i in range(100):
            consumed += 1
            assert consumed <= 4 or released.is_set(), "eagerly consumed discovery inputs"
            yield str(i), 443 if i % 2 else 80, "https" if i % 2 else "http"

    def scan(host, port, *_a, scheme="http", **_kw):
        observed.append((host, port, scheme))
        if host == "0":
            released.set()
        return scan_result(host, port, scheme=scheme)

    output = tmp_path / "output.jsonl"
    stats = {}
    assert workflow.collect_exporter_debug_data(
        None,
        [],
        1,
        str(output),
        workers=2,
        max_inflight_requests=4,
        collect_exporters=PROFILES["collect_exporters"],
        collect_debug_endpoints=["/debug/vars"],
        scan_work_items=items(),
        scan_work_items_count=100,
        scan_task_fn=scan,
        discovery_exporters=PROFILES["discovery_exporters"],
        collect_task_fn=fetch_result,
        stats_sink=stats,
    ) == (100, 100)
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert len(observed) == 100
    assert all(row["url"].startswith("https:" if int(row["host"]) % 2 else "http:") for row in rows[:-1])
    assert stats["discovery_checks"] == stats["discovery_found"] == 100


@pytest.mark.parametrize("output_format", ["txt", "json"])
def test_large_collect_resume_restores_output_and_retries_failed_job(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    output_format: str,
) -> None:
    path = tmp_path / "hosts.txt"
    path.write_text("10.1.0.1\n10.1.0.2\n")
    output = tmp_path / "results"
    checkpoint = tmp_path / "checkpoint.jsonl"
    raw = tmp_path / "raw"
    checkpoint.write_text(
        json.dumps(
            {
                "host": "10.1.0.1",
                "exporter": "node_exporter",
                "port": 9100,
                "endpoint": "/debug/vars",
                "ok": True,
                "record": fetch_result("10.1.0.1", "node_exporter", 9100, "/debug/vars")[0],
            }
        )
        + "\n"
        + json.dumps(
            {
                "host": "10.1.0.2",
                "exporter": "node_exporter",
                "port": 9100,
                "endpoint": "/debug/vars",
                "ok": False,
            }
        )
        + "\n"
    )
    monkeypatch.setattr(stage_collect, "DEFAULT_MAX_NETWORK_HOSTS", 1)
    monkeypatch.setattr(stage_collect, "load_profiles", lambda _: PROFILES)
    monkeypatch.setattr(
        discover, "scan_presence_port_task", lambda host, port, *_a, **kw: scan_result(host, port, **kw)
    )
    fetched = []

    def fetch(*a, **kw):
        fetched.append(a[0])
        return fetch_result(*a, **kw)

    monkeypatch.setattr(
        stage_collect,
        "collect_exporter_debug_data",
        partial(workflow.collect_exporter_debug_data, collect_task_fn=fetch),
    )
    args = args_for(
        path,
        output,
        resume=True,
        checkpoint_file=str(checkpoint),
        output_format=output_format,
        save_responses_dir=str(raw),
    )
    assert stage_collect.run_collect_stage(args, AttemptLogger()) == 0
    assert fetched == ["10.1.0.2"]
    assert "\x1b" not in output.read_text()
    if output_format == "json":
        rows = [json.loads(line) for line in output.read_text().splitlines()]
        assert Counter(row["host"] for row in rows if row.get("endpoint")) == Counter(["10.1.0.1", "10.1.0.2"])
        assert rows[-1]["requests"] == rows[-1]["success"] == 2
    index_rows = [json.loads(line) for line in (raw / "index.jsonl").read_text().splitlines()]
    assert len(index_rows) == 1 and index_rows[0]["host"] == "10.1.0.2"
    # A second resume must not re-fetch or duplicate the successful rows.
    before = output.read_text()
    assert stage_collect.run_collect_stage(args, AttemptLogger()) == 0
    assert fetched == ["10.1.0.2"]
    assert output.read_text().count("10.1.0.2") == before.count("10.1.0.2")


def test_streaming_discovery_error_keeps_other_findings_and_counts(tmp_path: Path) -> None:
    def scan(host, port, *_a, **kw):
        if host == "bad":
            raise TimeoutError("fixture timeout")
        return scan_result(host, port, **kw)

    stats = {}
    output = tmp_path / "result"
    assert workflow.collect_exporter_debug_data(
        None,
        [],
        1,
        str(output),
        workers=2,
        collect_exporters=PROFILES["collect_exporters"],
        collect_debug_endpoints=["/debug/vars"],
        scan_work_items=iter([("bad", 9100, "http"), ("good", 9100, "http")]),
        scan_work_items_count=2,
        discovery_exporters=PROFILES["discovery_exporters"],
        scan_task_fn=scan,
        collect_task_fn=fetch_result,
        stats_sink=stats,
    ) == (1, 1)
    assert stats["discovery_checks"] == 2 and stats["discovery_errors"] == 1
    assert stats["discovery_found"] == 1
    assert json.loads(output.read_text().splitlines()[0])["host"] == "good"


def test_streaming_output_failure_closes_source_and_shared_pool(tmp_path: Path) -> None:
    from redposture_core.exporters.http_pool import HTTPConnectionPool

    closed = []
    pools = []

    class Pool(HTTPConnectionPool):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            pools.append(self)

        def close(self):
            closed.append("pool")
            super().close()

    def items():
        try:
            for i in range(100):
                yield str(i), 9100, "http"
        finally:
            closed.append("source")

    def emit(_line):
        raise OSError("fixture output failure")

    with pytest.raises(OSError, match="fixture output failure"):
        workflow.collect_exporter_debug_data(
            None,
            [],
            1,
            str(tmp_path / "output"),
            output_format="txt",
            emit_line=emit,
            workers=1,
            max_inflight_requests=2,
            scan_work_items=items(),
            scan_work_items_count=100,
            discovery_exporters=PROFILES["discovery_exporters"],
            scan_task_fn=lambda host, port, *_a, **kw: scan_result(host, port, **kw),
            collect_task_fn=fetch_result,
            pool_cls=Pool,
        )
    assert len(pools) == 1
    assert closed == ["source", "pool"]


def test_large_collect_endpoint_matrix_deduplicates_paths_and_preserves_ports(tmp_path: Path) -> None:
    from redposture_core.targeting import stream_scan_target_specs

    plan = stream_scan_target_specs(
        "http://example.test:9100/a,http://example.test:9100/b,https://example.test:9443/a,example.test:9200"
    )
    assert list(stage_collect._iter_collect_scan_items(plan, (9100,))) == [
        ("example.test", 9100, "http"),
        ("example.test", 9443, "https"),
        ("example.test", 9200, "http"),
    ]


def test_large_collect_real_http_emits_fast_data_while_another_scan_waits(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    ready = threading.Event()
    slow_observed = []
    requests = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            requests.append((self.server.server_port, self.path))
            if self.server is servers[0] and self.path == "/metrics":
                slow_observed.append(ready.wait(3))
            if self.server is servers[1] and self.path == "/debug/vars":
                ready.set()
            body = b"node_marker 1\n" if self.path == "/metrics" else b"ordinary data\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a):
            pass

    servers = []
    threads = []
    try:
        for _ in range(2):
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            servers.append(server)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        path = tmp_path / "hosts.txt"
        path.write_text("\n".join(f"http://127.0.0.1:{server.server_port}" for server in servers))
        monkeypatch.setattr(stage_collect, "DEFAULT_MAX_NETWORK_HOSTS", 1)
        monkeypatch.setattr(stage_collect, "load_profiles", lambda _: PROFILES)
        output = tmp_path / "results"
        assert stage_collect.run_collect_stage(args_for(path, output), AttemptLogger()) == 0
        assert slow_observed == [True]
        assert Counter(requests) == Counter(
            {(server.server_port, endpoint): 1 for server in servers for endpoint in ("/metrics", "/debug/vars")}
        )
        records = [json.loads(line) for line in output.read_text().splitlines()]
        assert records[-1]["requests"] == records[-1]["success"] == 2
        assert "\x1b" not in output.read_text()
    finally:
        ready.set()
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(2)
