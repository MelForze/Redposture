from __future__ import annotations

from redposture_core.exporters.workflows import (
    build_collect_targets,
    collect_max_inflight,
    completed_jobs_by_target,
    dedupe_collect_targets,
    scan_max_inflight,
    should_preflight_collect,
    sort_collect_targets,
)


def test_scan_and_collect_inflight_helpers_are_bounded() -> None:
    assert scan_max_inflight(1) == 12
    assert scan_max_inflight(500) == 2048
    assert collect_max_inflight(4, None) == 64
    assert collect_max_inflight(10, 3) == 10
    assert collect_max_inflight(10, 30) == 30


def test_collect_target_build_dedupe_and_sort() -> None:
    exporters = [{"name": "redis_exporter", "port": 9121}, {"name": "postgres_exporter", "port": 9187}]
    assert build_collect_targets(["b", "a"], exporters, None) == [
        ("b", "redis_exporter", 9121),
        ("b", "postgres_exporter", 9187),
        ("a", "redis_exporter", 9121),
        ("a", "postgres_exporter", 9187),
    ]

    found = {
        "b": [
            {"exporter": "redis_exporter", "port": 9121},
            {"exporter": "redis_exporter", "port": "bad"},
            {"exporter": "unknown_exporter", "port": 1},
        ],
        "a": [{"exporter": "postgres_exporter", "port": "9187"}],
    }
    targets = build_collect_targets(["b", "a"], exporters, found)
    assert targets == [("b", "redis_exporter", 9121), ("a", "postgres_exporter", 9187)]

    duplicate_targets = [("a", "x", 1), ("a", "x", 1), ("b", "x", 1), ("a", "y", 2)]
    assert dedupe_collect_targets(duplicate_targets) == [("a", "x", 1), ("b", "x", 1), ("a", "y", 2)]
    assert sort_collect_targets(["b", "a"], dedupe_collect_targets(duplicate_targets)) == [
        ("b", "x", 1),
        ("a", "x", 1),
        ("a", "y", 2),
    ]


def test_completed_jobs_and_preflight_policy() -> None:
    completed = {
        ("10.0.0.1", "redis_exporter", 9121, "/metrics"),
        ("10.0.0.1", "redis_exporter", 9121, "/debug/vars"),
    }
    assert completed_jobs_by_target(completed) == {("10.0.0.1", "redis_exporter", 9121): {"/metrics", "/debug/vars"}}

    assert should_preflight_collect(adaptive_collect=True, target_count=1, endpoints=("/metrics",)) is True
    assert should_preflight_collect(adaptive_collect=False, target_count=1, endpoints=("/metrics",)) is False
    assert should_preflight_collect(adaptive_collect=True, target_count=1001, endpoints=("/metrics",)) is False
    assert should_preflight_collect(adaptive_collect=True, target_count=1, endpoints=("/custom",)) is False
