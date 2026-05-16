from __future__ import annotations

from redposture_core.exporters.detection import build_scan_error_record, looks_like_prometheus_metrics


def test_looks_like_prometheus_metrics_detects_help_and_metric_lines() -> None:
    assert looks_like_prometheus_metrics("# HELP up demo\n# TYPE up gauge\nup 1\n") is True
    assert looks_like_prometheus_metrics('http_requests_total{method="GET"} 42\n') is True
    assert looks_like_prometheus_metrics("not metrics\n") is False
    assert looks_like_prometheus_metrics("") is False


def test_build_scan_error_record_keeps_existing_contract() -> None:
    record = build_scan_error_record("10.0.0.1", 9100, RuntimeError("boom"))

    assert record["host"] == "10.0.0.1"
    assert record["port"] == 9100
    assert record["url"] == "http://10.0.0.1:9100/metrics"
    assert record["detected"] is False
    assert record["error"] == "boom"
    assert record["body"] == ""
