from __future__ import annotations

from redposture_core.scanner import scan_exporter_presence


def test_scan_uses_metrics_only_for_clear_winner(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    called_urls: list[str] = []

    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
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

    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
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
    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
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
