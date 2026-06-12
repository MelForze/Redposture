"""Shared workflow helpers for exporter scan/collect orchestration."""

from __future__ import annotations

from typing import Any

from .http_pool import HTTP_POOL_MAX_IDLE_PER_HOST, HTTP_POOL_MAX_IDLE_TOTAL, HTTPConnectionPool

COLLECT_PPROF_PREFLIGHT_MAX_TARGETS = 1000
SCAN_MAX_INFLIGHT_FACTOR = 12
SCAN_MAX_INFLIGHT_HARD_CAP = 2048


def build_exporter_http_pool(max_workers: int, pool_cls: type[HTTPConnectionPool] = HTTPConnectionPool) -> Any:
    workers = max(1, int(max_workers))
    return pool_cls(
        max_idle_total=max(workers * 16, HTTP_POOL_MAX_IDLE_TOTAL),
        max_idle_per_host=max(HTTP_POOL_MAX_IDLE_PER_HOST, min(workers, 8)),
    )


def scan_max_inflight(
    workers: int,
    *,
    factor: int = SCAN_MAX_INFLIGHT_FACTOR,
    hard_cap: int = SCAN_MAX_INFLIGHT_HARD_CAP,
) -> int:
    max_workers = max(1, int(workers))
    max_inflight = max_workers * max(1, int(factor))
    max_inflight = min(max_inflight, max(1, int(hard_cap)))
    return max(max_workers, max_inflight)


def canonical_scan_host_key(host: str) -> str:
    raw = str(host or "").strip()
    if not raw:
        return ""
    return raw.rstrip(".").lower()


def build_scan_work_items(hosts: list[str], ports: list[int]) -> list[tuple[str, int]]:
    items: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for host in hosts:
        host_display = str(host or "").strip()
        host_key = canonical_scan_host_key(host_display)
        if not host_key:
            continue
        for port in ports:
            port_value = int(port)
            item_key = (host_key, port_value)
            if item_key in seen:
                continue
            seen.add(item_key)
            items.append((host_display, port_value))
    return items


def collect_max_inflight(workers: int, max_inflight_requests: int | None = None) -> int:
    max_workers = max(1, int(workers))
    if max_inflight_requests is None:
        return max(max_workers * 16, max_workers)
    return max(max_workers, int(max_inflight_requests))


def build_collect_targets(
    hosts: list[str],
    exporters: list[dict[str, Any]],
    found_by_host: dict[str, list[dict[str, Any]]] | None,
) -> list[tuple[str, str, int]]:
    if found_by_host is None:
        return [(host, str(exporter["name"]), int(exporter["port"])) for host in hosts for exporter in exporters]

    enabled_exporters = {str(item.get("name") or "") for item in exporters}
    collect_targets: list[tuple[str, str, int]] = []
    for host in hosts:
        for hit in found_by_host.get(host, []):
            exporter_name = str(hit.get("exporter") or "")
            if exporter_name not in enabled_exporters:
                continue
            try:
                port = int(hit.get("port", ""))
            except (TypeError, ValueError):
                continue
            collect_targets.append((host, exporter_name, port))
    return collect_targets


def dedupe_collect_targets(targets: list[tuple[str, str, int]]) -> list[tuple[str, str, int]]:
    unique_targets: list[tuple[str, str, int]] = []
    seen_targets: set[tuple[str, str, int]] = set()
    for item in targets:
        if item in seen_targets:
            continue
        seen_targets.add(item)
        unique_targets.append(item)
    return unique_targets


def sort_collect_targets(hosts: list[str], targets: list[tuple[str, str, int]]) -> list[tuple[str, str, int]]:
    host_rank = {host: idx for idx, host in enumerate(hosts)}
    return sorted(
        targets,
        key=lambda item: (
            host_rank.get(str(item[0]), 10**9),
            str(item[0]),
            int(item[2]),
            str(item[1]),
        ),
    )


def completed_jobs_by_target(
    completed_jobs: set[tuple[str, str, int, str]] | None,
) -> dict[tuple[str, str, int], set[str]]:
    completed_by_target: dict[tuple[str, str, int], set[str]] = {}
    for host, exporter_name, port, endpoint in completed_jobs or set():
        completed_by_target.setdefault((host, exporter_name, int(port)), set()).add(endpoint)
    return completed_by_target


def should_preflight_collect(
    *,
    adaptive_collect: bool,
    target_count: int,
    endpoints: tuple[str, ...],
    max_targets: int = COLLECT_PPROF_PREFLIGHT_MAX_TARGETS,
) -> bool:
    return (
        adaptive_collect
        and target_count <= max_targets
        and any(item in endpoints for item in ("/debug/pprof/", "/debug/vars", "/metrics"))
    )


__all__ = [
    "COLLECT_PPROF_PREFLIGHT_MAX_TARGETS",
    "SCAN_MAX_INFLIGHT_FACTOR",
    "SCAN_MAX_INFLIGHT_HARD_CAP",
    "build_collect_targets",
    "build_exporter_http_pool",
    "build_scan_work_items",
    "canonical_scan_host_key",
    "collect_max_inflight",
    "completed_jobs_by_target",
    "dedupe_collect_targets",
    "scan_max_inflight",
    "should_preflight_collect",
    "sort_collect_targets",
]
