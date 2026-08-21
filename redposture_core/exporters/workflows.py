"""Shared workflow helpers for exporter scan/collect orchestration."""

from __future__ import annotations

import ssl
from collections.abc import Iterator
from typing import Any

from .http_pool import HTTP_POOL_MAX_IDLE_PER_HOST, HTTP_POOL_MAX_IDLE_TOTAL, HTTPConnectionPool

COLLECT_PPROF_PREFLIGHT_MAX_TARGETS = 1000
SCAN_MAX_INFLIGHT_FACTOR = 12
SCAN_MAX_INFLIGHT_HARD_CAP = 2048


def build_exporter_http_pool(
    max_workers: int,
    pool_cls: type[HTTPConnectionPool] = HTTPConnectionPool,
    *,
    tls_context: ssl.SSLContext | None = None,
) -> Any:
    workers = max(1, int(max_workers))
    kwargs: dict[str, Any] = {
        "max_idle_total": max(workers * 16, HTTP_POOL_MAX_IDLE_TOTAL),
        "max_idle_per_host": max(HTTP_POOL_MAX_IDLE_PER_HOST, min(workers, 8)),
    }
    if tls_context is not None:
        kwargs["tls_context"] = tls_context
    return pool_cls(**kwargs)


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


def _scan_hosts_and_ports(hosts: list[str], ports: list[int]) -> tuple[list[str], list[int]]:
    """Return de-duplicated scan dimensions while preserving caller order."""

    unique_hosts: list[str] = []
    seen_hosts: set[str] = set()
    for host in hosts:
        host_display = str(host or "").strip()
        host_key = canonical_scan_host_key(host_display)
        if not host_key or host_key in seen_hosts:
            continue
        seen_hosts.add(host_key)
        unique_hosts.append(host_display)

    unique_ports: list[int] = []
    seen_ports: set[int] = set()
    for port in ports:
        port_value = int(port)
        if port_value in seen_ports:
            continue
        seen_ports.add(port_value)
        unique_ports.append(port_value)
    return unique_hosts, unique_ports


def iter_scan_work_items(hosts: list[str], ports: list[int]) -> Iterator[tuple[str, int]]:
    """Yield unique host/port jobs lazily in the established scan order."""

    unique_hosts, unique_ports = _scan_hosts_and_ports(hosts, ports)
    for host_display in unique_hosts:
        for port_value in unique_ports:
            yield host_display, port_value


def scan_work_item_count(hosts: list[str], ports: list[int]) -> int:
    """Return the exact job count without materializing the host/port matrix."""

    unique_hosts, unique_ports = _scan_hosts_and_ports(hosts, ports)
    return len(unique_hosts) * len(unique_ports)


def build_scan_work_items(hosts: list[str], ports: list[int]) -> list[tuple[str, int]]:
    """Compatibility helper for callers that explicitly require a list."""

    return list(iter_scan_work_items(hosts, ports))


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
    "iter_scan_work_items",
    "scan_work_item_count",
    "scan_max_inflight",
    "should_preflight_collect",
    "sort_collect_targets",
]
