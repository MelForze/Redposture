from __future__ import annotations

from redposture_core.scanner import scan_exporter_presence


def test_scan_exporter_presence_detects_known_exporter_on_custom_port(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
        if ":19400/" in url:
            return {
                "status": 200,
                "body": "# HELP postgres_exporter_build_info info\npostgres_exporter_build_info 1\n",
                "content_type": "text/plain; version=0.0.4",
                "elapsed_ms": 3,
                "truncated": False,
                "error": None,
            }
        return {
            "status": 404,
            "body": "not found",
            "content_type": "text/plain",
            "elapsed_ms": 2,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    discovery_exporters = [
        {"name": "postgres_exporter", "port": 9187, "markers": ("postgres_exporter_build_info", "pg_up")},
        {"name": "redis_exporter", "port": 9121, "markers": ("redis_exporter_build_info", "redis_up")},
    ]

    checks, found, by_host = scan_exporter_presence(
        hosts=["127.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=2,
        retries=0,
        discovery_exporters=discovery_exporters,
        custom_ports=[19400, 19401],
    )

    assert checks == 2
    assert found == 1
    hits = by_host["127.0.0.1"]
    assert len(hits) == 1
    assert hits[0]["exporter"] == "postgres_exporter"
    assert hits[0]["port"] == 19400


def test_scan_exporter_presence_classifies_by_markers_not_expected_port(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
        if ":9100/" in url:
            return {
                "status": 200,
                "body": "# HELP redis_exporter_build_info info\nredis_exporter_build_info 1\n",
                "content_type": "text/plain; version=0.0.4",
                "elapsed_ms": 2,
                "truncated": False,
                "error": None,
            }
        return {
            "status": 404,
            "body": "not found",
            "content_type": "text/plain",
            "elapsed_ms": 1,
            "truncated": False,
            "error": None,
        }

    monkeypatch.setattr("redposture_core.scanner.http_get_details", fake_http_get_details)

    discovery_exporters = [
        {"name": "node_exporter", "port": 9100, "markers": ("node_exporter_build_info", "node_uname_info")},
        {"name": "redis_exporter", "port": 9121, "markers": ("redis_exporter_build_info", "redis_up")},
    ]

    checks, found, by_host = scan_exporter_presence(
        hosts=["127.0.0.1"],
        timeout=1.0,
        output_path=None,
        output_format="json",
        logger=None,
        emit_line=None,
        workers=2,
        retries=0,
        discovery_exporters=discovery_exporters,
        custom_ports=None,
    )

    assert checks == 2
    assert found == 1
    hits = by_host["127.0.0.1"]
    assert len(hits) == 1
    assert hits[0]["exporter"] == "redis_exporter"
    assert hits[0]["port"] == 9100
