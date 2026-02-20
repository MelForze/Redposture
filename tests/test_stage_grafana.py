from __future__ import annotations

from redposture_core.stage_grafana import _format_check_detail_records, _normalize_check_urls, _split_check_target_url


def test_normalize_check_urls_builds_cartesian_product_for_targets_and_ports() -> None:
    urls = _normalize_check_urls("host.docker.internal,127.0.0.1", "9115,9187")
    assert urls == [
        "http://host.docker.internal:9115/",
        "http://host.docker.internal:9187/",
        "http://127.0.0.1:9115/",
        "http://127.0.0.1:9187/",
    ]


def test_normalize_check_urls_keeps_target_port_when_ssrf_port_is_not_set() -> None:
    urls = _normalize_check_urls("http://127.0.0.1:3000/probe", None)
    assert urls == ["http://127.0.0.1:3000/probe"]


def test_normalize_check_urls_applies_ssrf_path_override() -> None:
    urls = _normalize_check_urls("host.docker.internal,127.0.0.1", "9115,9187", "/debug/vars?full=1")
    assert urls == [
        "http://host.docker.internal:9115/debug/vars?full=1",
        "http://host.docker.internal:9187/debug/vars?full=1",
        "http://127.0.0.1:9115/debug/vars?full=1",
        "http://127.0.0.1:9187/debug/vars?full=1",
    ]


def test_normalize_check_urls_expands_cidr_targets() -> None:
    urls = _normalize_check_urls("192.168.65.0/30", "9115,9187")
    assert urls == [
        "http://192.168.65.1:9115/",
        "http://192.168.65.1:9187/",
        "http://192.168.65.2:9115/",
        "http://192.168.65.2:9187/",
    ]


def test_split_check_target_url_splits_base_and_upstream_path() -> None:
    split = _split_check_target_url("http://host.docker.internal:9115/debug/vars?x=1")
    assert split == ("http://host.docker.internal:9115", "/debug/vars?x=1")


def test_format_check_detail_records_includes_proxy_request_line() -> None:
    record = {
        "host": "127.0.0.1",
        "port": 3000,
        "check_results": [
            {
                "target_url": "http://host.docker.internal:9115/debug/vars",
                "probe_proxy_path": "/api/datasources/proxy/12/debug/vars",
                "create_ok": True,
                "probe_ok": True,
                "probe_status": 200,
                "probe_elapsed_ms": 5,
                "probe_sample": "{\"ok\":1}",
                "cleanup_ok": True,
            }
        ],
    }
    lines = _format_check_detail_records(record, "txt")
    assert any("proxy request: GET /api/datasources/proxy/12/debug/vars" in line for line in lines)
