from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from redposture_core.scanner import collect_exporter_debug_data


def test_collect_output_is_emitted_as_soon_as_requests_complete(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
        # Force out-of-order completion to ensure final output is explicitly sorted.
        if "/debug/vars" in url:
            time.sleep(0.03)
        else:
            time.sleep(0.005)
        return {
            "status": 200,
            "body": "ok",
            "content_type": "text/plain",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    lines: list[str] = []
    total, success = collect_exporter_debug_data(
        logger=None,
        hosts=["10.0.0.2", "10.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        emit_line=lines.append,
        workers=4,
        retries=0,
        collect_exporters=[{"name": "node_exporter", "port": 9100}],
        collect_debug_endpoints=["/debug/vars", "/debug/pprof/cmdline?debug=1"],
        found_by_host={
            "10.0.0.2": [{"exporter": "node_exporter", "port": 9100}],
            "10.0.0.1": [{"exporter": "node_exporter", "port": 9100}],
        },
    )

    assert total == 4
    assert success == 4

    payloads = [json.loads(line) for line in lines]
    records = [item for item in payloads if item.get("type") != "summary"]
    positions = {(str(item.get("host")), str(item.get("endpoint"))): idx for idx, item in enumerate(records)}
    assert positions[("10.0.0.2", "/debug/pprof/cmdline?debug=1")] < positions[("10.0.0.2", "/debug/vars")]
    assert positions[("10.0.0.1", "/debug/pprof/cmdline?debug=1")] < positions[("10.0.0.1", "/debug/vars")]


def test_collect_txt_line_contains_display_name_and_full_url(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
        return {
            "status": 200,
            "body": "ok",
            "content_type": "text/plain",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    lines: list[str] = []
    total, success = collect_exporter_debug_data(
        logger=None,
        hosts=["10.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        workers=1,
        retries=0,
        collect_exporters=[{"name": "node_exporter", "port": 9100}],
        collect_debug_endpoints=["/debug/vars"],
        found_by_host={"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]},
    )

    assert total == 1
    assert success == 1
    hit_lines = [line for line in lines if "[+] " in line and line.startswith("COLLECT")]
    assert hit_lines
    assert "Node Exporter" in hit_lines[0]
    assert "url=http://10.0.0.1:9100/debug/vars" in hit_lines[0]


@pytest.mark.parametrize(
    ("exporter_name", "display_name", "port"),
    [
        ("nats_exporter", "NATS Exporter", 7777),
        ("statsd_exporter", "StatsD Exporter", 9102),
        ("mysqld_exporter", "MySQLd Exporter", 9104),
        ("haproxy_exporter", "HAProxy Exporter", 9101),
        ("memcached_exporter", "Memcached Exporter", 9150),
        ("nginx_exporter", "Nginx Exporter", 9113),
        ("elasticsearch_exporter", "Elasticsearch Exporter", 9114),
        ("snmp_exporter", "SNMP Exporter", 9117),
        ("apache_exporter", "Apache Exporter", 9117),
        ("bind_exporter", "BIND Exporter", 9119),
        ("ceph_exporter", "Ceph Exporter", 9128),
        ("varnish_exporter", "Varnish Exporter", 9131),
        ("windows_exporter", "Windows Exporter", 9182),
        ("ipmi_exporter", "IPMI Exporter", 9290),
        ("rabbitmq_exporter", "RabbitMQ Exporter", 9419),
        ("sql_exporter", "SQL Exporter", 9399),
        ("pgbackrest_exporter", "pgBackRest Exporter", 9854),
        ("victoriametrics_exporter", "VictoriaMetrics Exporter", 8428),
    ],
)
def test_collect_txt_line_contains_display_name_for_new_exporters(
    monkeypatch, exporter_name: str, display_name: str, port: int
) -> None:  # type: ignore[no-untyped-def]
    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
        return {
            "status": 200,
            "body": "ok",
            "content_type": "text/plain",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    lines: list[str] = []
    total, success = collect_exporter_debug_data(
        logger=None,
        hosts=["10.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="txt",
        emit_line=lines.append,
        workers=1,
        retries=0,
        collect_exporters=[{"name": exporter_name, "port": port}],
        collect_debug_endpoints=["/debug/vars"],
        found_by_host={"10.0.0.1": [{"exporter": exporter_name, "port": port}]},
    )

    assert total == 1
    assert success == 1
    hit_lines = [line for line in lines if "[+] " in line and line.startswith("COLLECT")]
    assert hit_lines
    assert display_name in hit_lines[0]
    assert f"url=http://10.0.0.1:{port}/debug/vars" in hit_lines[0]


def test_collect_can_save_raw_responses_and_index(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
        return {
            "status": 200,
            "body": "password=redis\nuser=redis\n",
            "content_type": "text/plain",
            "elapsed_ms": 2,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    save_dir = tmp_path / "collect_raw"
    total, success = collect_exporter_debug_data(
        logger=None,
        hosts=["10.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="txt",
        emit_line=None,
        workers=1,
        retries=0,
        collect_exporters=[{"name": "node_exporter", "port": 9100}],
        collect_debug_endpoints=["/debug/vars", "/debug/pprof/cmdline?debug=1"],
        found_by_host={"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]},
        save_responses_dir=str(save_dir),
    )

    assert total == 2
    assert success == 2
    index_path = save_dir / "index.jsonl"
    assert index_path.exists()

    index_lines = [line for line in index_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(index_lines) == 2
    payload = json.loads(index_lines[0])
    response_file = str(payload.get("response_file") or "")
    assert response_file.endswith(".txt")
    saved_file = save_dir / response_file
    assert saved_file.exists()
    assert "password=redis" in saved_file.read_text(encoding="utf-8")


def test_collect_skips_deep_pprof_when_pprof_index_is_unavailable(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    called_urls: list[str] = []

    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
        called_urls.append(url)
        if url.endswith("/debug/pprof/"):
            return {
                "status": 404,
                "body": "not found",
                "content_type": "text/plain",
                "elapsed_ms": 1,
                "truncated": False,
                "error": None,
            }
        if "/debug/pprof/goroutine?debug=1" in url:
            raise AssertionError("deep pprof endpoint must be skipped when pprof index is unavailable")
        return {
            "status": 200,
            "body": "ok",
            "content_type": "text/plain",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    lines: list[str] = []
    total, success = collect_exporter_debug_data(
        logger=None,
        hosts=["10.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        emit_line=lines.append,
        workers=2,
        retries=0,
        collect_exporters=[{"name": "node_exporter", "port": 9100}],
        collect_debug_endpoints=["/debug/vars", "/debug/pprof/", "/debug/pprof/goroutine?debug=1", "/metrics"],
        found_by_host={"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]},
    )

    assert total == 3
    assert success == 2
    assert all("/debug/pprof/goroutine?debug=1" not in url for url in called_urls)

    payloads = [json.loads(line) for line in lines]
    records = [item for item in payloads if item.get("type") != "summary"]
    endpoints = [str(item.get("endpoint")) for item in records]
    assert sorted(endpoints) == sorted(["/debug/vars", "/debug/pprof/", "/metrics"])


def test_collect_reuses_pprof_probe_response_without_duplicate_request(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    call_count: dict[str, int] = {}

    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
        call_count[url] = call_count.get(url, 0) + 1
        return {
            "status": 200,
            "body": "ok",
            "content_type": "text/plain",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    lines: list[str] = []
    total, success = collect_exporter_debug_data(
        logger=None,
        hosts=["10.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        emit_line=lines.append,
        workers=2,
        retries=0,
        collect_exporters=[{"name": "node_exporter", "port": 9100}],
        collect_debug_endpoints=["/debug/vars", "/debug/pprof/", "/debug/pprof/goroutine?debug=1"],
        found_by_host={"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]},
    )

    assert total == 3
    assert success == 3
    assert call_count["http://10.0.0.1:9100/debug/pprof/"] == 1

    payloads = [json.loads(line) for line in lines]
    records = [item for item in payloads if item.get("type") != "summary"]
    endpoints = [str(item.get("endpoint")) for item in records]
    assert sorted(endpoints) == sorted(["/debug/vars", "/debug/pprof/", "/debug/pprof/goroutine?debug=1"])


def test_collect_disables_pprof_preflight_for_large_target_sets(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("redposture_core.scanner._COLLECT_PPROF_PREFLIGHT_MAX_TARGETS", 1)

    called_urls: list[str] = []

    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
        called_urls.append(url)
        if url.endswith("/debug/pprof/"):
            return {
                "status": 404,
                "body": "not found",
                "content_type": "text/plain",
                "elapsed_ms": 1,
                "truncated": False,
                "error": None,
            }
        return {
            "status": 200,
            "body": "ok",
            "content_type": "text/plain",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    total, success = collect_exporter_debug_data(
        logger=None,
        hosts=["10.0.0.1", "10.0.0.2"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        emit_line=None,
        workers=2,
        retries=0,
        collect_exporters=[{"name": "node_exporter", "port": 9100}],
        collect_debug_endpoints=["/debug/pprof/", "/debug/pprof/goroutine?debug=1"],
        found_by_host={
            "10.0.0.1": [{"exporter": "node_exporter", "port": 9100}],
            "10.0.0.2": [{"exporter": "node_exporter", "port": 9100}],
        },
    )

    assert total == 4
    assert success == 2
    assert sum(1 for url in called_urls if url.endswith("/debug/pprof/goroutine?debug=1")) == 2


def test_collect_resume_skips_completed_jobs(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    called_urls: list[str] = []

    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
        _ = (timeout, retries)
        called_urls.append(url)
        return {
            "status": 200,
            "body": "ok",
            "content_type": "text/plain",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    checkpoint = tmp_path / "collect.ckpt.jsonl"
    completed = {("10.0.0.1", "node_exporter", 9100, "/debug/vars")}
    total, success = collect_exporter_debug_data(
        logger=None,
        hosts=["10.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        emit_line=None,
        workers=2,
        retries=0,
        collect_exporters=[{"name": "node_exporter", "port": 9100}],
        collect_debug_endpoints=["/debug/vars", "/metrics"],
        found_by_host={"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]},
        resume_completed_jobs=completed,
        checkpoint_path=str(checkpoint),
        checkpoint_mode="w",
    )

    assert total == 1
    assert success == 1
    assert called_urls == ["http://10.0.0.1:9100/metrics"]
    assert checkpoint.exists()


def test_collect_writes_checkpoint_records(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
        _ = (url, timeout, retries)
        return {
            "status": 200,
            "body": "ok",
            "content_type": "text/plain",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    checkpoint = tmp_path / "collect.ckpt.jsonl"
    total, success = collect_exporter_debug_data(
        logger=None,
        hosts=["10.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        emit_line=None,
        workers=1,
        retries=0,
        collect_exporters=[{"name": "node_exporter", "port": 9100}],
        collect_debug_endpoints=["/debug/vars"],
        found_by_host={"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]},
        checkpoint_path=str(checkpoint),
        checkpoint_mode="w",
    )

    assert total == 1
    assert success == 1
    payloads = [json.loads(line) for line in checkpoint.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(payloads) == 1
    assert payloads[0]["host"] == "10.0.0.1"
    assert payloads[0]["exporter"] == "node_exporter"
    assert payloads[0]["port"] == 9100
    assert payloads[0]["endpoint"] == "/debug/vars"


def test_collect_adaptive_preflight_collapses_stale_targets(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    called_urls: list[str] = []

    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
        _ = (timeout, retries)
        called_urls.append(url)
        if url.endswith("/metrics"):
            return {
                "status": 503,
                "body": "service unavailable",
                "content_type": "text/plain",
                "elapsed_ms": 1,
                "truncated": False,
                "error": None,
            }
        if url.endswith("/debug/vars"):
            return {
                "status": 404,
                "body": "not found",
                "content_type": "text/plain",
                "elapsed_ms": 1,
                "truncated": False,
                "error": None,
            }
        if url.endswith("/debug/pprof/"):
            return {
                "status": 404,
                "body": "not found",
                "content_type": "text/plain",
                "elapsed_ms": 1,
                "truncated": False,
                "error": None,
            }
        if "/debug/pprof/goroutine?debug=1" in url:
            raise AssertionError("deep pprof endpoint must be skipped for stale targets")
        return {
            "status": 404,
            "body": "not found",
            "content_type": "text/plain",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    total, success = collect_exporter_debug_data(
        logger=None,
        hosts=["10.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        emit_line=None,
        workers=1,
        retries=0,
        collect_exporters=[{"name": "node_exporter", "port": 9100}],
        collect_debug_endpoints=["/metrics", "/debug/vars", "/debug/pprof/", "/debug/pprof/goroutine?debug=1"],
        found_by_host={"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]},
        adaptive_collect=True,
    )

    assert total == 3
    assert success == 0
    assert all("/debug/pprof/goroutine?debug=1" not in item for item in called_urls)


def test_collect_record_callback_runs_in_postprocess_thread(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
        _ = (url, timeout, retries)
        return {
            "status": 200,
            "body": "ok",
            "content_type": "text/plain",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    callback_threads: list[str] = []

    def callback(_record: dict[str, object]) -> None:
        callback_threads.append(threading.current_thread().name)

    total, success = collect_exporter_debug_data(
        logger=None,
        hosts=["10.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        emit_line=None,
        workers=1,
        retries=0,
        collect_exporters=[{"name": "node_exporter", "port": 9100}],
        collect_debug_endpoints=["/debug/vars", "/metrics"],
        found_by_host={"10.0.0.1": [{"exporter": "node_exporter", "port": 9100}]},
        record_callback=callback,
    )

    assert total == 2
    assert success == 2
    assert callback_threads == ["collect-postprocess", "collect-postprocess"]
