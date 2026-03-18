from __future__ import annotations

import pytest

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


@pytest.mark.parametrize(
    ("exporter_name", "marker", "port"),
    [
        ("nats_exporter", "nats_up", 7777),
        ("statsd_exporter", "statsd_exporter_lines_total", 9102),
        ("mysqld_exporter", "mysqld_exporter_build_info", 9104),
        ("haproxy_exporter", "haproxy_up", 9101),
        ("memcached_exporter", "memcached_up", 9150),
        ("nginx_exporter", "nginx_exporter_build_info", 9113),
        ("elasticsearch_exporter", "elasticsearch_cluster_health_status", 9114),
        ("snmp_exporter", "snmp_scrape_duration_seconds", 9117),
        ("apache_exporter", "apache_up", 9117),
        ("bind_exporter", "bind_up", 9119),
        ("ceph_exporter", "ceph_health_status", 9128),
        ("varnish_exporter", "varnish_up", 9131),
        ("windows_exporter", "windows_cs_hostname", 9182),
        ("ipmi_exporter", "ipmi_scrape_duration_seconds", 9290),
        ("rabbitmq_exporter", "rabbitmq_up", 9419),
        ("sql_exporter", "sql_exporter_scrape_duration_seconds", 9399),
    ],
)
def test_scan_exporter_presence_detects_new_exporters_by_marker(
    monkeypatch, exporter_name: str, marker: str, port: int
) -> None:  # type: ignore[no-untyped-def]
    def fake_http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, object]:
        if f":{port}/" in url:
            return {
                "status": 200,
                "body": f"# HELP {marker} info\n{marker} 1\n",
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
        {"name": "nats_exporter", "port": 7777, "markers": ("nats_exporter_build_info", "nats_up")},
        {
            "name": "statsd_exporter",
            "port": 9102,
            "markers": ("statsd_exporter_build_info", "statsd_exporter_lines_total"),
        },
        {"name": "mysqld_exporter", "port": 9104, "markers": ("mysqld_exporter_build_info", "mysql_up")},
        {"name": "haproxy_exporter", "port": 9101, "markers": ("haproxy_exporter_build_info", "haproxy_up")},
        {"name": "memcached_exporter", "port": 9150, "markers": ("memcached_exporter_build_info", "memcached_up")},
        {
            "name": "elasticsearch_exporter",
            "port": 9114,
            "markers": ("elasticsearch_exporter_build_info", "elasticsearch_cluster_health_status"),
        },
        {"name": "nginx_exporter", "port": 9113, "markers": ("nginx_exporter_build_info", "nginx_connections_active")},
        {"name": "apache_exporter", "port": 9117, "markers": ("apache_exporter_build_info", "apache_up")},
        {"name": "bind_exporter", "port": 9119, "markers": ("bind_exporter_build_info", "bind_up")},
        {"name": "ceph_exporter", "port": 9128, "markers": ("ceph_exporter_build_info", "ceph_health_status")},
        {"name": "varnish_exporter", "port": 9131, "markers": ("varnish_exporter_build_info", "varnish_up")},
        {"name": "rabbitmq_exporter", "port": 9419, "markers": ("rabbitmq_exporter_build_info", "rabbitmq_up")},
        {"name": "windows_exporter", "port": 9182, "markers": ("windows_exporter_build_info", "windows_cs_hostname")},
        {
            "name": "snmp_exporter",
            "port": 9117,
            "markers": ("snmp_exporter_build_info", "snmp_scrape_duration_seconds"),
        },
        {
            "name": "ipmi_exporter",
            "port": 9290,
            "markers": ("ipmi_exporter_build_info", "ipmi_scrape_duration_seconds"),
        },
        {
            "name": "sql_exporter",
            "port": 9399,
            "markers": ("sql_exporter_build_info", "sql_exporter_scrape_duration_seconds"),
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
        custom_ports=[port],
    )

    assert checks == 1
    assert found == 1
    hits = by_host["127.0.0.1"]
    assert len(hits) == 1
    assert hits[0]["exporter"] == exporter_name
    assert hits[0]["port"] == port
