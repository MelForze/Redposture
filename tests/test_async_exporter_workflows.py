"""All exporter discovery entry points reuse native prefetch with sync scoring."""

from __future__ import annotations

import threading

import pytest

from redposture_core.exporters import async_detect, discover, trigger


def test_scan_presence_uses_native_prefetch_with_exact_results(monkeypatch):
    seen = []

    async def prefetch(host, port, scheme, timeout, retries, tls_context=None):
        seen.append((host, threading.current_thread().name))
        return {
            "status": 200,
            "body": "node_exporter_build_info 1\n",
            "elapsed_ms": 1,
            "content_type": "text/plain",
            "error": None,
            "truncated": False,
        }

    monkeypatch.setattr(async_detect, "prefetch_metrics", prefetch)
    hosts = [f"127.0.0.{i + 1}" for i in range(40)]
    exporter = {"name": "node_exporter", "port": 9100, "markers": ["node_exporter_build_info"]}
    got = discover.scan_exporter_presence(
        hosts, 1, None, workers=2, retries=0, discovery_exporters=[exporter], show_progress=False, emit_summary=False
    )
    assert got[:2] == (40, 40)
    assert set(got[2]) == set(hosts)
    assert len(seen) == 40
    assert all(name == "redposture-async-detect" for _, name in seen)


def test_trigger_native_detection_never_prefetches_callback_action(monkeypatch):
    seen = []

    async def prefetch(host, port, scheme, timeout, retries, tls_context=None, *, path="/metrics"):
        seen.append((host, port, path, threading.current_thread().name))
        return {
            "status": 200,
            "body": "mysql_exporter_build_info 1\n",
            "elapsed_ms": 1,
            "content_type": "text/plain",
            "error": None,
            "truncated": False,
        }

    monkeypatch.setattr(async_detect, "prefetch_metrics", prefetch)
    exporter = {
        "name": "mysql_exporter",
        "port": 9104,
        "detect_path": "/metrics",
        "markers": ["mysql_exporter_build_info"],
        "trigger_path": "/probe",
        "target_fmt": "{our_host}:3306",
    }
    hosts = [f"127.0.0.{i + 1}" for i in range(40)]
    got = trigger.scan_exporters_and_trigger(None, hosts, [], 1, workers=2, retries=0, trigger_exporters=[exporter])
    assert got["detected_exporters"] == 40
    assert len(seen) == 40 and all(row[2] == "/metrics" for row in seen)
    assert all(row[3] == "redposture-async-detect" for row in seen)


def test_trigger_closes_detection_iterator_if_callback_fails(monkeypatch):
    from redposture_core.async_detection import AsyncDetectScheduler

    class Results:
        closed = False

        def __iter__(self):
            return self

        def __next__(self):
            return ("127.0.0.1", {"name": "mysql_exporter", "port": 9104}), {
                "detected": True,
                "exporter": "mysql_exporter",
            }

        def close(self):
            self.closed = True

    results = Results()
    monkeypatch.setattr(AsyncDetectScheduler, "iter_completed", lambda *args, **kwargs: results)

    def fail(amount):
        raise RuntimeError("output unavailable")

    exporter = {
        "name": "mysql_exporter",
        "port": 9104,
        "detect_path": "/metrics",
        "markers": ["mysql_exporter_build_info"],
        "trigger_path": "/probe",
        "target_fmt": "{our_host}:3306",
    }
    with pytest.raises(RuntimeError, match="output unavailable"):
        trigger.scan_exporters_and_trigger(
            None, ["127.0.0.1"] * 40, [], 1, workers=2, retries=0, trigger_exporters=[exporter], progress_advance=fail
        )
    assert results.closed
