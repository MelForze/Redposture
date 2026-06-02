from __future__ import annotations

import threading
import time

from redposture_core import scanner
from redposture_core.constants import DISCOVERY_EXPORTERS
from redposture_core.scanner import scan_exporter_presence


def test_fetch_fingerprint_bodies_runs_endpoints_in_parallel(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    active = 0
    max_active = 0
    lock = threading.Lock()

    def fake_http_get_details(url: str, timeout: float, retries: int = 1, **kwargs) -> dict[str, object]:
        _ = (url, timeout, retries, kwargs)
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
        try:
            time.sleep(0.03)
            if "/debug/vars" in url:
                return {"status": 200, "body": '{"name":"vars"}', "content_type": "application/json", "elapsed_ms": 1}
            return {"status": 200, "body": "cmdline", "content_type": "text/plain", "elapsed_ms": 1}
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    vars_body, cmdline_body = scanner._fetch_fingerprint_bodies("127.0.0.1", 9100, timeout=1.0, retries=0)
    assert vars_body == '{"name":"vars"}'
    assert cmdline_body == "cmdline"
    assert max_active >= 2


def test_scan_uses_metrics_only_for_clear_winner(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    called_urls: list[str] = []

    def fake_http_get_details(url: str, timeout: float, retries: int = 1, **kwargs) -> dict[str, object]:
        _ = (timeout, retries)
        called_urls.append(url)
        if "/debug/vars" in url or "/debug/pprof/cmdline" in url:
            raise AssertionError("fingerprint endpoints must not be called for clear metrics winner")
        return {
            "status": 200,
            "body": (
                "# HELP node_exporter_build_info Build information\nnode_exporter_build_info 1\nnode_uname_info 1\n"
            ),
            "content_type": "text/plain; version=0.0.4",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    discovery_exporters = [
        {
            "name": "node_exporter",
            "port": 9101,
            "markers": ("node_exporter_build_info", "node_uname_info"),
            "strong_markers": ("node_exporter_build_info", "node_uname_info"),
            "fingerprint_vars": ("runtime_config", "node_exporter"),
            "fingerprint_cmdline": ("node_exporter",),
        },
        {
            "name": "haproxy_exporter",
            "port": 9101,
            "markers": ("haproxy_exporter_build_info", "haproxy_up"),
            "strong_markers": ("haproxy_exporter_build_info", "haproxy_up"),
            "fingerprint_vars": ("haproxy",),
            "fingerprint_cmdline": ("haproxy_exporter",),
        },
    ]

    checks, found, by_host = scan_exporter_presence(
        hosts=["127.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=1,
        retries=0,
        discovery_exporters=discovery_exporters,
        custom_ports=[9101],
    )

    assert checks == 1
    assert found == 1
    hits = by_host["127.0.0.1"]
    assert len(hits) == 1
    assert hits[0]["exporter"] == "node_exporter"
    assert hits[0]["method"] == "marker"
    assert all("/metrics" in url for url in called_urls)


def test_scan_uses_fingerprint_tiebreak_for_conflicting_markers(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    called_urls: list[str] = []

    def fake_http_get_details(url: str, timeout: float, retries: int = 1, **kwargs) -> dict[str, object]:
        _ = (timeout, retries)
        called_urls.append(url)
        if url.endswith("/metrics"):
            return {
                "status": 200,
                "body": (
                    "# HELP node_exporter_build_info Build information\n"
                    "node_exporter_build_info 1\n"
                    "# HELP haproxy_exporter_build_info Build information\n"
                    "haproxy_exporter_build_info 1\n"
                ),
                "content_type": "text/plain; version=0.0.4",
                "elapsed_ms": 2,
                "truncated": False,
                "error": None,
            }
        if "/debug/vars" in url:
            return {
                "status": 200,
                "body": '{"haproxy":{"username":"haproxy_monitor","password":"HAProxyRead!2026"}}',
                "content_type": "application/json",
                "elapsed_ms": 2,
                "truncated": False,
                "error": None,
            }
        if "/debug/pprof/cmdline" in url:
            return {
                "status": 200,
                "body": "haproxy_exporter\x00--haproxy.scrape-uri=https://haproxy.internal/stats;csv\x00",
                "content_type": "text/plain",
                "elapsed_ms": 2,
                "truncated": False,
                "error": None,
            }
        return {
            "status": 404,
            "body": "",
            "content_type": "text/plain",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    discovery_exporters = [
        {
            "name": "node_exporter",
            "port": 9101,
            "markers": ("node_exporter_build_info",),
            "strong_markers": ("node_exporter_build_info",),
            "fingerprint_vars": ("runtime_config", "node_exporter"),
            "fingerprint_cmdline": ("node_exporter", "--collector."),
        },
        {
            "name": "haproxy_exporter",
            "port": 9101,
            "markers": ("haproxy_exporter_build_info",),
            "strong_markers": ("haproxy_exporter_build_info",),
            "fingerprint_vars": ("haproxy", "haproxy_monitor"),
            "fingerprint_cmdline": ("haproxy_exporter", "--haproxy.scrape-uri="),
        },
    ]

    checks, found, by_host = scan_exporter_presence(
        hosts=["127.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=1,
        retries=0,
        discovery_exporters=discovery_exporters,
        custom_ports=[9101],
    )

    assert checks == 1
    assert found == 1
    hits = by_host["127.0.0.1"]
    assert len(hits) == 1
    assert hits[0]["exporter"] == "haproxy_exporter"
    assert hits[0]["method"] == "fingerprint"
    assert any("/debug/vars" in url for url in called_urls)
    assert any("/debug/pprof/cmdline" in url for url in called_urls)


def test_scan_returns_unknown_for_unresolved_conflict(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_http_get_details(url: str, timeout: float, retries: int = 1, **kwargs) -> dict[str, object]:
        _ = (timeout, retries)
        if url.endswith("/metrics"):
            return {
                "status": 200,
                "body": (
                    "# HELP apache_exporter_build_info Build information\n"
                    "apache_exporter_build_info 1\n"
                    "# HELP snmp_exporter_build_info Build information\n"
                    "snmp_exporter_build_info 1\n"
                ),
                "content_type": "text/plain; version=0.0.4",
                "elapsed_ms": 1,
                "truncated": False,
                "error": None,
            }
        return {
            "status": 200,
            "body": "{}",
            "content_type": "application/json",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    discovery_exporters = [
        {
            "name": "apache_exporter",
            "port": 9117,
            "markers": ("apache_exporter_build_info",),
            "strong_markers": ("apache_exporter_build_info",),
            "fingerprint_vars": ("apache",),
            "fingerprint_cmdline": ("apache_exporter",),
        },
        {
            "name": "snmp_exporter",
            "port": 9117,
            "markers": ("snmp_exporter_build_info",),
            "strong_markers": ("snmp_exporter_build_info",),
            "fingerprint_vars": ("snmp",),
            "fingerprint_cmdline": ("snmp_exporter",),
        },
    ]

    checks, found, by_host = scan_exporter_presence(
        hosts=["127.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=1,
        retries=0,
        discovery_exporters=discovery_exporters,
        custom_ports=[9117],
    )

    assert checks == 1
    assert found == 0
    assert by_host["127.0.0.1"] == []


def test_scan_uses_marker_fallback_when_top_candidate_has_stronger_metrics(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    called_urls: list[str] = []

    def fake_http_get_details(url: str, timeout: float, retries: int = 1, **kwargs) -> dict[str, object]:
        _ = (timeout, retries)
        called_urls.append(url)
        if url.endswith("/metrics"):
            return {
                "status": 200,
                "body": (
                    "# HELP alpha_build_info Build information\n"
                    "alpha_build_info 1\n"
                    "beta_hint_one 1\n"
                    "beta_hint_two 1\n"
                    "beta_hint_three 1\n"
                ),
                "content_type": "text/plain; version=0.0.4",
                "elapsed_ms": 1,
                "truncated": False,
                "error": None,
            }
        return {
            "status": 200,
            "body": "{}",
            "content_type": "application/json",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    discovery_exporters = [
        {
            "name": "alpha_exporter",
            "port": 9200,
            "markers": ("alpha_build_info",),
            "strong_markers": ("alpha_build_info",),
            "fingerprint_vars": ("alpha",),
            "fingerprint_cmdline": ("alpha_exporter",),
        },
        {
            "name": "beta_exporter",
            "port": 9200,
            "markers": ("beta_build_info",),
            "strong_markers": ("beta_build_info",),
            "weak_markers": ("beta_hint_one", "beta_hint_two", "beta_hint_three"),
            "fingerprint_vars": ("beta",),
            "fingerprint_cmdline": ("beta_exporter",),
        },
    ]

    checks, found, by_host = scan_exporter_presence(
        hosts=["127.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=1,
        retries=0,
        discovery_exporters=discovery_exporters,
        custom_ports=[9200],
    )

    assert checks == 1
    assert found == 1
    hits = by_host["127.0.0.1"]
    assert len(hits) == 1
    assert hits[0]["exporter"] == "alpha_exporter"
    assert hits[0]["method"] == "marker"
    assert all("/debug/vars" not in url and "/debug/pprof/cmdline" not in url for url in called_urls)


def test_scan_detects_single_weak_candidate_without_fingerprint_endpoints(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    called_urls: list[str] = []

    def fake_http_get_details(url: str, timeout: float, retries: int = 1, **kwargs) -> dict[str, object]:
        _ = (timeout, retries)
        called_urls.append(url)
        if "/debug/vars" in url or "/debug/pprof/cmdline" in url:
            raise AssertionError("fingerprint endpoints must not be called for confident weak-only match")
        return {
            "status": 200,
            "body": ("redis_memory_used_bytes 1024\nredis_connected_clients 14\nredis_keyspace_hits_total 77\n"),
            "content_type": "text/plain; version=0.0.4",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    discovery_exporters = [
        {
            "name": "redis_exporter",
            "port": 9201,
            "markers": ("redis_up",),
            "weak_markers": ("redis_memory_", "redis_connected_", "redis_keyspace_"),
            "fingerprint_vars": ("redis",),
            "fingerprint_cmdline": ("redis_exporter",),
        }
    ]

    checks, found, by_host = scan_exporter_presence(
        hosts=["127.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=1,
        retries=0,
        discovery_exporters=discovery_exporters,
        custom_ports=[9201],
    )

    assert checks == 1
    assert found == 1
    hits = by_host["127.0.0.1"]
    assert len(hits) == 1
    assert hits[0]["exporter"] == "redis_exporter"
    assert hits[0]["method"] == "marker"
    assert all("/debug/vars" not in url and "/debug/pprof/cmdline" not in url for url in called_urls)


def test_scan_uses_fingerprint_only_when_metrics_are_generic_but_cmdline_identifies_exporter(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    called_urls: list[str] = []

    def fake_http_get_details(url: str, timeout: float, retries: int = 1, **kwargs) -> dict[str, object]:
        _ = (timeout, retries)
        called_urls.append(url)
        if url.endswith("/metrics"):
            return {
                "status": 200,
                "body": ("process_start_time_seconds 1700000000\npromhttp_metric_handler_requests_total 18\n"),
                "content_type": "text/plain; version=0.0.4",
                "elapsed_ms": 1,
                "truncated": False,
                "error": None,
            }
        if "/debug/vars" in url:
            return {
                "status": 200,
                "body": '{"listen":":9202"}',
                "content_type": "application/json",
                "elapsed_ms": 1,
                "truncated": False,
                "error": None,
            }
        if "/debug/pprof/cmdline" in url:
            return {
                "status": 200,
                "body": "mongodb_exporter\x00--mongodb.uri=mongodb://mongo:secret@db.internal/admin\x00",
                "content_type": "text/plain",
                "elapsed_ms": 1,
                "truncated": False,
                "error": None,
            }
        return {
            "status": 404,
            "body": "",
            "content_type": "text/plain",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    discovery_exporters = [
        {
            "name": "mongodb_exporter",
            "port": 9202,
            "markers": ("mongodb_exporter_build_info",),
            "fingerprint_vars": ("mongodb",),
            "fingerprint_cmdline": ("mongodb_exporter", "--mongodb.uri="),
        },
        {
            "name": "redis_exporter",
            "port": 9202,
            "markers": ("redis_exporter_build_info",),
            "fingerprint_vars": ("redis",),
            "fingerprint_cmdline": ("redis_exporter", "--redis.addr="),
        },
    ]

    checks, found, by_host = scan_exporter_presence(
        hosts=["127.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=1,
        retries=0,
        discovery_exporters=discovery_exporters,
        custom_ports=[9202],
    )

    assert checks == 1
    assert found == 1
    hits = by_host["127.0.0.1"]
    assert len(hits) == 1
    assert hits[0]["exporter"] == "mongodb_exporter"
    assert hits[0]["method"] == "fingerprint"
    assert any("/debug/vars" in url for url in called_urls)
    assert any("/debug/pprof/cmdline" in url for url in called_urls)


def test_scan_uses_unique_port_fallback_for_generic_prometheus_metrics(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_http_get_details(url: str, timeout: float, retries: int = 1, **kwargs) -> dict[str, object]:
        _ = (timeout, retries)
        if url.endswith("/metrics"):
            return {
                "status": 200,
                "body": ("process_cpu_seconds_total 1.5\ngo_memstats_alloc_bytes 2048\n"),
                "content_type": "text/plain; version=0.0.4",
                "elapsed_ms": 1,
                "truncated": False,
                "error": None,
            }
        return {
            "status": 200,
            "body": "{}",
            "content_type": "application/json",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    discovery_exporters = [
        {
            "name": "blackbox_exporter",
            "port": 9203,
            "markers": ("blackbox_exporter_build_info",),
            "fingerprint_vars": ("blackbox",),
            "fingerprint_cmdline": ("blackbox_exporter",),
        }
    ]

    checks, found, by_host = scan_exporter_presence(
        hosts=["127.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=1,
        retries=0,
        discovery_exporters=discovery_exporters,
        custom_ports=[9203],
    )

    assert checks == 1
    assert found == 1
    hits = by_host["127.0.0.1"]
    assert len(hits) == 1
    assert hits[0]["exporter"] == "blackbox_exporter"
    assert hits[0]["method"] == "metrics"


def test_scan_detects_node_exporter_from_production_node_metrics(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_http_get_details(url: str, timeout: float, retries: int = 1, **kwargs) -> dict[str, object]:
        _ = (timeout, retries, kwargs)
        if url.endswith("/metrics"):
            return {
                "status": 200,
                "body": (
                    "# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.\n"
                    'node_cpu_seconds_total{cpu="0",mode="idle"} 12345\n'
                    'node_filesystem_avail_bytes{mountpoint="/"} 987654321\n'
                    "node_memory_MemAvailable_bytes 123456789\n"
                    'node_network_receive_bytes_total{device="eth0"} 777\n'
                    "node_boot_time_seconds 1700000000\n"
                ),
                "content_type": "text/plain; version=0.0.4",
                "elapsed_ms": 1,
                "truncated": False,
                "error": None,
            }
        raise AssertionError("strong node metrics should not require fingerprint endpoints")

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    checks, found, by_host = scan_exporter_presence(
        hosts=["127.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=1,
        retries=0,
        discovery_exporters=list(DISCOVERY_EXPORTERS),
        custom_ports=[9100],
    )

    assert checks == 1
    assert found == 1
    hits = by_host["127.0.0.1"]
    assert hits == [
        {
            "exporter": "node_exporter",
            "port": 9100,
            "url": "http://127.0.0.1:9100/metrics",
            "status": 200,
            "method": "marker",
        }
    ]


def test_scan_does_not_classify_haproxy_as_node_on_shared_port(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_http_get_details(url: str, timeout: float, retries: int = 1, **kwargs) -> dict[str, object]:
        _ = (timeout, retries, kwargs)
        if url.endswith("/metrics"):
            return {
                "status": 200,
                "body": (
                    "# HELP haproxy_up Whether HAProxy was successfully scraped.\n"
                    "haproxy_up 1\n"
                    'haproxy_frontend_http_requests_total{proxy="edge"} 42\n'
                    "haproxy_exporter_build_info 1\n"
                ),
                "content_type": "text/plain; version=0.0.4",
                "elapsed_ms": 1,
                "truncated": False,
                "error": None,
            }
        raise AssertionError("clear HAProxy markers should not require fingerprint endpoints")

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    _checks, found, by_host = scan_exporter_presence(
        hosts=["127.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=1,
        retries=0,
        discovery_exporters=list(DISCOVERY_EXPORTERS),
        custom_ports=[9101],
    )

    assert found == 1
    assert by_host["127.0.0.1"][0]["exporter"] == "haproxy_exporter"


def test_scan_keeps_generic_prometheus_metrics_unknown_with_multiple_profiles(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_http_get_details(url: str, timeout: float, retries: int = 1, **kwargs) -> dict[str, object]:
        _ = (timeout, retries, kwargs)
        if url.endswith("/metrics"):
            return {
                "status": 200,
                "body": "process_cpu_seconds_total 1.5\ngo_memstats_alloc_bytes 2048\n",
                "content_type": "text/plain; version=0.0.4",
                "elapsed_ms": 1,
                "truncated": False,
                "error": None,
            }
        return {
            "status": 200,
            "body": "{}",
            "content_type": "application/json",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    checks, found, by_host = scan_exporter_presence(
        hosts=["127.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=1,
        retries=0,
        discovery_exporters=list(DISCOVERY_EXPORTERS),
        custom_ports=[9100],
    )

    assert checks == 1
    assert found == 0
    assert by_host["127.0.0.1"] == []
