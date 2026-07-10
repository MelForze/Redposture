from __future__ import annotations

from redposture_core.exporters.discovery_logic import (
    as_token_tuple,
    needs_fingerprint_tiebreak,
    resolve_prometheus_port_fallback,
    score_fingerprint_candidate,
    score_metrics_candidate,
    select_fingerprint_candidates,
)
from redposture_core.exporters.workflows import (
    build_scan_work_items,
    canonical_scan_host_key,
    iter_scan_work_items,
    scan_work_item_count,
)


def test_token_tuple_deduplicates_and_ignores_empty_values() -> None:
    assert as_token_tuple(" marker ") == ("marker",)
    assert as_token_tuple(["a", "", "a", None, "b"]) == ("a", "b")
    assert as_token_tuple(123) == ()


def test_metrics_scoring_uses_strong_weak_and_negative_markers() -> None:
    exporter = {
        "name": "demo_exporter",
        "markers": ("demo_build_info",),
        "strong_markers": ("demo_build_info",),
        "weak_markers": ("demo_",),
        "negative_markers": ("not_demo",),
    }

    candidate = score_metrics_candidate(exporter, "demo_build_info 1\ndemo_metric 2\n")
    assert candidate is not None
    assert candidate["name"] == "demo_exporter"
    assert candidate["score"] == 125
    assert candidate["marker_hit"] == "demo_build_info"

    assert score_metrics_candidate(exporter, "not_demo 1\n") is None


def test_fingerprint_tiebreak_and_selection_policy() -> None:
    strong = {"score": 100, "strong_count": 1}
    weak = {"score": 25, "strong_count": 0}
    close = {"score": 90, "strong_count": 1}

    assert needs_fingerprint_tiebreak([strong]) is False
    assert needs_fingerprint_tiebreak([weak]) is True
    assert needs_fingerprint_tiebreak([strong, close]) is True
    assert select_fingerprint_candidates([strong, close, weak]) == [strong, close]


def test_fingerprint_score_and_port_fallback() -> None:
    exporter = {"fingerprint_vars": ("rabbitmq",), "fingerprint_cmdline": ("rabbitmq_exporter",)}
    assert score_fingerprint_candidate(exporter, '{"rabbitmq":{}}', "rabbitmq_exporter --web.listen-address=:9419") == (
        45,
        2,
    )

    assert resolve_prometheus_port_fallback([{"name": "one"}, {"name": "one"}])["name"] == "one"
    assert resolve_prometheus_port_fallback([{"name": "one"}, {"name": "two"}]) is None


def test_scan_work_items_canonicalize_and_dedupe_hosts() -> None:
    assert canonical_scan_host_key("Example.COM.") == "example.com"
    assert build_scan_work_items(["Example.COM.", "example.com", "", "Other"], [9100, 9100, 9200]) == [
        ("Example.COM.", 9100),
        ("Example.COM.", 9200),
        ("Other", 9100),
        ("Other", 9200),
    ]


def test_scan_work_item_iterator_is_lazy_and_matches_compatibility_helper() -> None:
    hosts = ["Example.COM.", "example.com", "Other"]
    ports = [9100, 9100, 9200]

    assert scan_work_item_count(hosts, ports) == 4
    assert list(iter_scan_work_items(hosts, ports)) == build_scan_work_items(hosts, ports)
