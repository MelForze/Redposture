"""Exporter discovery workflow implementation."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from ..constants import DISCOVERY_EXPORTERS
from ..logger import AttemptLogger
from ..scheduler import BoundedScheduler
from ..stage_runtime import start_audit_progress
from ..utils import utc_now_iso
from .detection import build_scan_error_record, looks_like_prometheus_metrics
from .discovery_logic import (
    fetch_fingerprint_bodies,
    resolve_best_exporter_candidate,
    resolve_fingerprint_only_candidate,
    resolve_prometheus_port_fallback,
    score_metrics_candidate,
)
from .http_client import http_get_details
from .http_pool import HTTPConnectionPool, activate_http_pool
from .output import emit_line as emit_output_line
from .output import format_scan_record
from .postprocess import AsyncPostprocessWorker
from .workflows import build_exporter_http_pool, iter_scan_work_items, scan_max_inflight, scan_work_item_count

HttpGetDetails = Callable[..., dict[str, Any]]
ScanTask = Callable[[str, int, list[dict[str, Any]], float, int], tuple[dict[str, Any], dict[str, Any] | None]]
ActivatePool = Callable[[Any], Any]

SCAN_RESPONSE_BODY_MAX_BYTES = 256 * 1024
SCAN_FINGERPRINT_BODY_MAX_BYTES = 128 * 1024
WEAK_CANDIDATE_CONFIDENCE_SCORE = 50


def scan_presence_task(
    host: str,
    exporter: dict[str, Any],
    timeout: float,
    retries: int,
    *,
    http_get_details_fn: HttpGetDetails = http_get_details,
    response_body_max_bytes: int = SCAN_RESPONSE_BODY_MAX_BYTES,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    exporter_name = str(exporter["name"])
    port = int(exporter["port"])
    url = f"http://{host}:{port}/metrics"
    result = http_get_details_fn(url, timeout=timeout, retries=retries, max_bytes=response_body_max_bytes)

    status = result["status"]
    body = str(result["body"] or "")
    markers = tuple(str(item) for item in exporter["markers"])
    marker_hit = next((marker for marker in markers if marker in body), None)

    # B4/B5 fix: honor `negative_markers` — when a body clearly belongs to a
    # different exporter that shares this port (snmp_exporter/apache_exporter
    # on 9117, node_exporter/haproxy_exporter on 9101), don't produce a
    # cross-labelled hit. Previously the negative_markers metadata was
    # declared but never consulted in the presence scan.
    negative_markers = tuple(str(item) for item in exporter.get("negative_markers") or ())
    if marker_hit and any(neg in body for neg in negative_markers):
        marker_hit = None

    is_prometheus_like = looks_like_prometheus_metrics(body)
    is_http_ok = status is not None and int(status) < 400
    detected = bool(is_http_ok and marker_hit)
    if not detected and is_http_ok and is_prometheus_like and not negative_markers:
        # Fall back to "prometheus-shaped body without strong marker" ONLY when
        # the exporter has no cross-labelling risk. Ports with shared exporters
        # must have a real marker match to count.
        detected = True
    detection_method = "marker" if marker_hit else ("metrics" if detected else "none")

    record = {
        "timestamp": utc_now_iso(),
        "host": host,
        "exporter": exporter_name,
        "port": port,
        "url": url,
        "detected": detected,
        "method": detection_method,
        "status": status,
        "marker_hit": marker_hit,
        "elapsed_ms": result["elapsed_ms"],
        "content_type": result["content_type"],
        "error": result["error"],
        "truncated": result["truncated"],
        "body": body,
    }
    if not detected:
        return record, None
    return (
        record,
        {
            "exporter": exporter_name,
            "port": port,
            "url": url,
            "status": status,
            "method": detection_method,
        },
    )


def fetch_fingerprint_bodies_default(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    *,
    http_get_details_fn: HttpGetDetails = http_get_details,
    fingerprint_body_max_bytes: int = SCAN_FINGERPRINT_BODY_MAX_BYTES,
) -> tuple[str, str]:
    return fetch_fingerprint_bodies(
        host,
        port,
        timeout,
        retries,
        http_get_details_fn=http_get_details_fn,
        max_bytes=fingerprint_body_max_bytes,
    )


def scan_presence_port_task(
    host: str,
    port: int,
    exporters: list[dict[str, Any]],
    timeout: float,
    retries: int,
    *,
    http_get_details_fn: HttpGetDetails = http_get_details,
    fetch_fingerprint_bodies_fn: Callable[[str, int, float, int], tuple[str, str]] | None = None,
    response_body_max_bytes: int = SCAN_RESPONSE_BODY_MAX_BYTES,
    weak_candidate_confidence_score: int = WEAK_CANDIDATE_CONFIDENCE_SCORE,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    url = f"http://{host}:{port}/metrics"
    result = http_get_details_fn(url, timeout=timeout, retries=retries, max_bytes=response_body_max_bytes)

    status = result["status"]
    body = str(result["body"] or "")
    is_http_ok = status is not None and int(status) < 400
    is_prometheus_like = looks_like_prometheus_metrics(body)
    if not is_http_ok:
        record = {
            "timestamp": utc_now_iso(),
            "host": host,
            "exporter": "unknown",
            "port": port,
            "url": url,
            "detected": False,
            "method": "none",
            "status": status,
            "marker_hit": None,
            "elapsed_ms": result["elapsed_ms"],
            "content_type": result["content_type"],
            "error": result["error"],
            "truncated": result["truncated"],
            "body": body,
        }
        return record, None

    candidates: list[dict[str, Any]] = []
    exporters_by_name: dict[str, dict[str, Any]] = {}
    for exporter in exporters:
        exporter_name = str(exporter.get("name") or "").strip()
        if not exporter_name:
            continue
        exporters_by_name.setdefault(exporter_name, exporter)
        candidate = score_metrics_candidate(exporter, body)
        if candidate is None:
            continue
        candidates.append(candidate)

    candidates_by_name: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        name = str(candidate.get("name") or "")
        previous = candidates_by_name.get(name)
        if previous is None or int(candidate.get("score") or 0) > int(previous.get("score") or 0):
            candidates_by_name[name] = candidate
    candidates = list(candidates_by_name.values())

    candidates.sort(
        key=lambda item: (
            int(item.get("score") or 0),
            int(item.get("strong_count") or 0),
            int(item.get("weak_count") or 0),
        ),
        reverse=True,
    )

    if fetch_fingerprint_bodies_fn is None:

        def _fetch_fingerprint_bodies_with_client(h: str, p: int, t: float, r: int) -> tuple[str, str]:
            return fetch_fingerprint_bodies_default(
                h,
                p,
                t,
                r,
                http_get_details_fn=http_get_details_fn,
            )

        fetch_fingerprint_bodies_fn = _fetch_fingerprint_bodies_with_client

    if candidates:
        winner, method, resolution = resolve_best_exporter_candidate(
            host=host,
            port=port,
            candidates=candidates,
            exporters_by_name=exporters_by_name,
            timeout=timeout,
            retries=retries,
            fetch_fingerprint_bodies_fn=fetch_fingerprint_bodies_fn,
            weak_confidence_score=weak_candidate_confidence_score,
        )
    elif is_prometheus_like:
        winner, method, resolution = resolve_fingerprint_only_candidate(
            host=host,
            port=port,
            exporters=exporters,
            timeout=timeout,
            retries=retries,
            fetch_fingerprint_bodies_fn=fetch_fingerprint_bodies_fn,
        )
        if winner is None:
            winner = resolve_prometheus_port_fallback(exporters)
            if winner is not None:
                method = "metrics"
                resolution = "prometheus_unique_port_fallback"
    else:
        winner, method, resolution = None, "none", "no_markers"

    detected = winner is not None
    exporter_name = str((winner or {}).get("name") or "unknown")
    if winner is not None:
        marker_hit = str(winner.get("marker_hit") or "")
    elif candidates:
        marker_hit = str(candidates[0].get("marker_hit") or "")
    else:
        marker_hit = None
    candidate_scores = [
        {
            "name": str(candidate.get("name") or ""),
            "score": int(candidate.get("score") or 0),
            "strong": int(candidate.get("strong_count") or 0),
            "weak": int(candidate.get("weak_count") or 0),
            "negative": int(candidate.get("negative_count") or 0),
            "marker": candidate.get("marker_hit"),
        }
        for candidate in candidates
    ]

    record = {
        "timestamp": utc_now_iso(),
        "host": host,
        "exporter": exporter_name,
        "port": port,
        "url": url,
        "detected": detected,
        "method": method,
        "status": status,
        "marker_hit": marker_hit,
        "candidate_count": len(candidates),
        "candidate_scores": candidate_scores,
        "resolution": resolution,
        "elapsed_ms": result["elapsed_ms"],
        "content_type": result["content_type"],
        "error": result["error"],
        "truncated": result["truncated"],
        "body": body,
    }
    if not detected:
        return record, None
    return (
        record,
        {
            "exporter": exporter_name,
            "port": port,
            "url": url,
            "status": status,
            "method": method,
        },
    )


def scan_exporter_presence(
    hosts: list[str],
    timeout: float,
    output_path: str | None,
    output_format: str = "json",
    logger: AttemptLogger | None = None,
    emit_line: Callable[[str], None] | None = None,
    workers: int = 10,
    retries: int = 3,
    discovery_exporters: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
    custom_ports: list[int] | tuple[int, ...] | None = None,
    emit_summary: bool = True,
    show_progress: bool = False,
    progress_leave: bool = True,
    output_mode: str = "w",
    progress_owner: Any = None,
    *,
    scan_task_fn: ScanTask | None = None,
    pool_cls: type[HTTPConnectionPool] = HTTPConnectionPool,
    activate_pool_fn: ActivatePool = activate_http_pool,
    postprocess_worker_cls: type[AsyncPostprocessWorker] = AsyncPostprocessWorker,
) -> tuple[int, int, dict[str, list[dict[str, Any]]]]:
    exporters = list(discovery_exporters or DISCOVERY_EXPORTERS)
    if custom_ports:
        ports = list(dict.fromkeys(int(port) for port in custom_ports))
    else:
        ports = list(
            dict.fromkeys(int(port_raw) for exporter in exporters if (port_raw := exporter.get("port")) is not None)
        )
    total_checks = 0
    total_found = 0
    found_by_host: dict[str, list[dict[str, Any]]] = {str(host): [] for host in hosts}
    max_workers = max(1, workers)
    max_inflight = scan_max_inflight(max_workers)
    work_item_count = scan_work_item_count(hosts, ports)
    scan_task = scan_task_fn or scan_presence_port_task

    out_fh: Any = None
    postprocess_worker: AsyncPostprocessWorker | None = None

    def _log_scan_record(record: dict[str, Any]) -> None:
        if logger is None:
            return
        logger.log(
            "scan",
            (str(record["host"]), int(record["port"])),
            exporter=str(record["exporter"]),
            detected=bool(record["detected"]),
            method=str(record["method"]),
            status=record["status"],
            error=record["error"],
            output=output_path,
        )

    def _process_scan_side_effects(payload: tuple[str, dict[str, Any]]) -> None:
        line, record = payload
        emit_output_line(out_fh, None, line)
        _log_scan_record(record)

    def _finalize_postprocess() -> None:
        nonlocal postprocess_worker
        if postprocess_worker is None:
            return
        postprocess_worker.close()
        postprocess_worker = None

    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, output_mode, encoding="utf-8")
    if out_fh is not None or logger is not None:
        postprocess_worker = postprocess_worker_cls(
            _process_scan_side_effects,
            name="scan-postprocess",
            max_queue_size=max_inflight,
        )

    try:
        progress = start_audit_progress(
            "SCAN", work_item_count, enabled=show_progress, leave=progress_leave, owner=progress_owner
        )
        try:
            pool = build_exporter_http_pool(max_workers, pool_cls)
            with activate_pool_fn(pool):
                scheduler: BoundedScheduler[tuple[str, int], tuple[dict[str, Any], dict[str, Any] | None]] = (
                    BoundedScheduler(max_workers=max_workers, max_inflight=max_inflight)
                )

                def _scan_item(item: tuple[str, int]) -> tuple[dict[str, Any], dict[str, Any] | None]:
                    host, port = item
                    try:
                        return scan_task(host, port, exporters, timeout, retries)
                    except Exception as exc:
                        return build_scan_error_record(host, port, exc), None

                for _item, result in scheduler.iter_completed(iter_scan_work_items(hosts, ports), _scan_item):
                    record, hit = result
                    total_checks += 1
                    if hit is not None:
                        total_found += 1
                        found_by_host.setdefault(str(record["host"]), []).append(hit)

                    line = format_scan_record(record, output_format)
                    progress.pause_for_output()
                    if emit_line is not None:
                        emit_line(line)
                    progress.advance()

                    if postprocess_worker is not None:
                        postprocess_worker.put((line, record))
                        postprocess_worker.raise_if_failed()
                    else:
                        emit_output_line(out_fh, None, line)
                        _log_scan_record(record)
        finally:
            progress.close()
        _finalize_postprocess()

        if emit_summary:
            summary = {
                "timestamp": utc_now_iso(),
                "type": "summary",
                "hosts": len(hosts),
                "checks": total_checks,
                "found": total_found,
                "output_path": output_path,
                "found_exporters_by_host": {
                    host: [str(item["exporter"]) for item in hits] for host, hits in found_by_host.items()
                },
            }
            emit_output_line(out_fh, emit_line, format_scan_record(summary, output_format))
    finally:
        _finalize_postprocess()
        if out_fh is not None:
            out_fh.close()

    return total_checks, total_found, found_by_host


__all__ = [
    "SCAN_FINGERPRINT_BODY_MAX_BYTES",
    "SCAN_RESPONSE_BODY_MAX_BYTES",
    "WEAK_CANDIDATE_CONFIDENCE_SCORE",
    "fetch_fingerprint_bodies_default",
    "scan_exporter_presence",
    "scan_presence_port_task",
    "scan_presence_task",
]
