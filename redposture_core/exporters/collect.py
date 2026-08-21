"""Exporter collect workflow implementation."""

from __future__ import annotations

import json
import os
import ssl
from collections.abc import Callable
from typing import Any

from ..constants import COLLECT_DEBUG_ENDPOINTS, COLLECT_EXPORTERS
from ..logger import AttemptLogger
from ..scheduler import BoundedScheduler
from ..stage_runtime import start_audit_progress
from ..utils import utc_now_iso
from .artifacts import save_collect_body
from .http_client import activate_exporter_tls_context, build_http_url, http_get_details
from .http_pool import HTTPConnectionPool, activate_http_pool
from .output import emit_line as emit_output_line
from .output import format_collect_record
from .postprocess import AsyncPostprocessWorker
from .workflows import (
    COLLECT_PPROF_PREFLIGHT_MAX_TARGETS,
    build_collect_targets,
    build_exporter_http_pool,
    collect_max_inflight,
    completed_jobs_by_target,
    dedupe_collect_targets,
    should_preflight_collect,
    sort_collect_targets,
)

HttpGetDetails = Callable[..., dict[str, Any]]
CollectTask = Callable[[str, str, int, str, float, int], tuple[dict[str, Any], bool]]
PlanCollect = Callable[
    [str, str, int, tuple[str, ...], float, int, bool, set[str] | None],
    tuple[tuple[str, ...], dict[str, tuple[dict[str, Any], bool]]],
]
ActivatePool = Callable[[Any], Any]


def collect_task(
    host: str,
    exporter_name: str,
    port: int,
    endpoint: str,
    timeout: float,
    retries: int,
    *,
    scheme: str = "http",
    http_get_details_fn: HttpGetDetails = http_get_details,
) -> tuple[dict[str, Any], bool]:
    url = build_http_url(host, port, endpoint, scheme=scheme)
    result = http_get_details_fn(url, timeout=timeout, retries=retries)
    status = result["status"]
    ok = status is not None and 200 <= int(status) < 300

    record = {
        "timestamp": utc_now_iso(),
        "host": host,
        "exporter": exporter_name,
        "port": port,
        "endpoint": endpoint,
        "url": url,
        "ok": ok,
        "status": status,
        "elapsed_ms": result["elapsed_ms"],
        "content_type": result["content_type"],
        "error": result["error"],
        "truncated": result["truncated"],
        "body": result["body"],
    }
    raw_body = getattr(result, "raw_body", result.get("raw_body"))
    if isinstance(raw_body, bytes):
        record["raw_body"] = raw_body
    return record, ok


def is_pprof_endpoint(endpoint: str) -> bool:
    raw = str(endpoint or "").split("?", 1)[0]
    return raw == "/debug/pprof" or raw == "/debug/pprof/" or raw.startswith("/debug/pprof/")


def plan_collect_endpoints_for_target(
    host: str,
    exporter_name: str,
    port: int,
    endpoints: tuple[str, ...],
    timeout: float,
    retries: int,
    adaptive_collect: bool = True,
    completed_endpoints: set[str] | None = None,
    *,
    scheme: str = "http",
    collect_task_fn: CollectTask = collect_task,
) -> tuple[tuple[str, ...], dict[str, tuple[dict[str, Any], bool]]]:
    prefetched: dict[str, tuple[dict[str, Any], bool]] = {}
    prefetch_candidates: list[str] = []
    completed = completed_endpoints or set()

    # Adaptive preflight:
    # - /debug/pprof/ controls deeper pprof expansion.
    # - /metrics + /debug/vars give cheap liveness signals and allow skipping
    #   deep endpoint fan-out on stale targets.
    if "/debug/pprof/" in endpoints and "/debug/pprof/" not in completed:
        prefetch_candidates.append("/debug/pprof/")
    if adaptive_collect and "/metrics" in endpoints and "/debug/vars" in endpoints:
        if "/metrics" not in completed:
            prefetch_candidates.append("/metrics")
        if "/debug/vars" not in completed:
            prefetch_candidates.append("/debug/vars")

    for endpoint in prefetch_candidates:
        if collect_task_fn is collect_task:
            prefetched[endpoint] = collect_task(
                host,
                exporter_name,
                port,
                endpoint,
                timeout,
                retries,
                scheme=scheme,
            )
        else:
            prefetched[endpoint] = collect_task_fn(
                host,
                exporter_name,
                port,
                endpoint,
                timeout,
                retries,
            )

    # A failed index is not proof that individual pprof handlers are absent:
    # Go applications can register handlers without exposing the index (or
    # protect the index independently).  Keep all requested endpoints and use
    # preflight only to reuse responses for endpoints that were actually read.
    return tuple(endpoints), prefetched


def collect_exporter_debug_data(
    logger: AttemptLogger | None,
    hosts: list[str],
    timeout: float,
    output_path: str | None,
    output_format: str = "json",
    emit_line: Callable[[str], None] | None = None,
    workers: int = 10,
    retries: int = 3,
    collect_exporters: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
    collect_debug_endpoints: list[str] | tuple[str, ...] | None = None,
    found_by_host: dict[str, list[dict[str, Any]]] | None = None,
    save_responses_dir: str | None = None,
    records_sink: list[dict[str, Any]] | None = None,
    record_callback: Callable[[dict[str, Any]], None] | None = None,
    output_mode: str = "w",
    index_mode: str = "w",
    emit_summary: bool = True,
    adaptive_collect: bool = True,
    max_inflight_requests: int | None = None,
    resume_completed_jobs: set[tuple[str, str, int, str]] | None = None,
    checkpoint_path: str | None = None,
    checkpoint_mode: str = "a",
    stats_sink: dict[str, int] | None = None,
    progress_owner: Any = None,
    scheme: str = "http",
    tls_context: ssl.SSLContext | None = None,
    *,
    collect_task_fn: CollectTask = collect_task,
    plan_collect_fn: PlanCollect | None = None,
    pool_cls: type[HTTPConnectionPool] = HTTPConnectionPool,
    activate_pool_fn: ActivatePool = activate_http_pool,
    postprocess_worker_cls: type[AsyncPostprocessWorker] = AsyncPostprocessWorker,
    preflight_max_targets: int = COLLECT_PPROF_PREFLIGHT_MAX_TARGETS,
) -> tuple[int, int]:
    exporters = list(collect_exporters or COLLECT_EXPORTERS)
    endpoints = tuple(collect_debug_endpoints or COLLECT_DEBUG_ENDPOINTS)
    plan_collect = plan_collect_fn or plan_collect_endpoints_for_target
    total = 0
    success = 0
    transport_errors = 0
    max_workers = max(1, workers)
    max_inflight = collect_max_inflight(max_workers, max_inflight_requests)

    out_fh: Any = None
    index_fh: Any = None
    checkpoint_fh: Any = None
    postprocess_worker: AsyncPostprocessWorker | None = None

    def _finalize_postprocess() -> None:
        nonlocal postprocess_worker
        if postprocess_worker is None:
            return
        postprocess_worker.close()
        postprocess_worker = None

    def _process_collect_side_effects(
        payload: tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None],
    ) -> None:
        callback_record, index_payload, checkpoint_payload = payload
        if callback_record is not None and record_callback is not None:
            record_callback(callback_record)
        if index_payload is not None and index_fh is not None:
            index_fh.write(json.dumps(index_payload, ensure_ascii=False) + "\n")
        if checkpoint_payload is not None and checkpoint_fh is not None:
            checkpoint_fh.write(json.dumps(checkpoint_payload, ensure_ascii=False) + "\n")
            checkpoint_fh.flush()

    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, output_mode, encoding="utf-8")
    if save_responses_dir:
        os.makedirs(save_responses_dir, exist_ok=True)
        index_path = os.path.join(save_responses_dir, "index.jsonl")
        index_fh = open(index_path, index_mode, encoding="utf-8")
    if checkpoint_path:
        os.makedirs(os.path.dirname(checkpoint_path) or ".", exist_ok=True)
        checkpoint_fh = open(checkpoint_path, checkpoint_mode, encoding="utf-8")
    if record_callback is not None or index_fh is not None or checkpoint_fh is not None:
        postprocess_worker = postprocess_worker_cls(
            _process_collect_side_effects,
            name="collect-postprocess",
            max_queue_size=max_inflight,
        )

    try:
        collect_targets = sort_collect_targets(
            hosts,
            dedupe_collect_targets(build_collect_targets(hosts, exporters, found_by_host)),
        )

        completed_jobs = resume_completed_jobs or set()
        completed_by_target = completed_jobs_by_target(completed_jobs)
        skipped_jobs = 0
        preflight_enabled = should_preflight_collect(
            adaptive_collect=adaptive_collect,
            target_count=len(collect_targets),
            endpoints=endpoints,
            max_targets=preflight_max_targets,
        )

        target_plans: dict[tuple[str, str, int], tuple[tuple[str, ...], dict[str, tuple[dict[str, Any], bool]]]] = {}

        def _process_record(
            record: dict[str, Any],
            ok: bool,
            *,
            pause_before_emit: Callable[[], None] | None = None,
        ) -> None:
            nonlocal total, success, transport_errors
            response_file, response_size = (None, 0)
            index_payload: dict[str, Any] | None = None
            checkpoint_payload: dict[str, Any] | None = None
            total += 1
            if ok:
                success += 1
            if record.get("error"):
                transport_errors += 1
            if save_responses_dir:
                response_file, response_size = save_collect_body(save_responses_dir, record)
                if response_file is not None:
                    record["response_file"] = response_file
                if index_fh is not None:
                    index_payload = {
                        "timestamp": record.get("timestamp"),
                        "host": record.get("host"),
                        "exporter": record.get("exporter"),
                        "port": record.get("port"),
                        "endpoint": record.get("endpoint"),
                        "url": record.get("url"),
                        "ok": bool(record.get("ok")),
                        "status": record.get("status"),
                        "error": record.get("error"),
                        "truncated": bool(record.get("truncated")),
                        "response_file": response_file,
                        "response_size": response_size,
                    }
            if records_sink is not None:
                records_sink.append(
                    {
                        "host": str(record.get("host") or "-"),
                        "port": record.get("port"),
                        "exporter": str(record.get("exporter") or "-"),
                        "endpoint": str(record.get("endpoint") or "-"),
                        "url": str(record.get("url") or "-"),
                        "status": record.get("status"),
                        "error": record.get("error"),
                        "ok": bool(record.get("ok")),
                        "body": str(record.get("body") or ""),
                    }
                )
            if checkpoint_fh is not None:
                checkpoint_payload = {
                    "host": str(record.get("host") or ""),
                    "exporter": str(record.get("exporter") or ""),
                    "port": int(record.get("port") or 0),
                    "endpoint": str(record.get("endpoint") or ""),
                    "status": record.get("status"),
                    "ok": bool(record.get("ok")),
                    "timestamp": record.get("timestamp"),
                    # Preserve the exact logical record required to rebuild
                    # cumulative validation state on a resumed run.  Binary
                    # response bytes live in the raw artifact and are not
                    # duplicated into JSONL checkpoints.
                    "record": {key: value for key, value in record.items() if key != "raw_body"},
                }
            if postprocess_worker is not None:
                postprocess_worker.put(
                    (record if record_callback is not None else None, index_payload, checkpoint_payload)
                )
                postprocess_worker.raise_if_failed()
            else:
                if record_callback is not None:
                    record_callback(record)
                if index_payload is not None and index_fh is not None:
                    index_fh.write(json.dumps(index_payload, ensure_ascii=False) + "\n")
                if checkpoint_payload is not None and checkpoint_fh is not None:
                    checkpoint_fh.write(json.dumps(checkpoint_payload, ensure_ascii=False) + "\n")
                    checkpoint_fh.flush()
            if pause_before_emit is not None and emit_line is not None:
                pause_before_emit()
            emit_output_line(out_fh, emit_line, format_collect_record(record, output_format))

            if logger is not None:
                logger.log(
                    "collect",
                    (str(record["host"]), int(record["port"])),
                    exporter=str(record["exporter"]),
                    endpoint=str(record["endpoint"]),
                    status=record["status"],
                    ok=ok,
                    error=record["error"],
                    output=output_path,
                )

        pool = build_exporter_http_pool(max_workers, pool_cls, tls_context=tls_context)
        with activate_exporter_tls_context(tls_context), activate_pool_fn(pool):
            if preflight_enabled:
                planner = BoundedScheduler[
                    tuple[str, str, int], tuple[tuple[str, ...], dict[str, tuple[dict[str, Any], bool]]]
                ](
                    max_workers=max_workers,
                    max_inflight=max_inflight,
                )

                def _plan_target(
                    target: tuple[str, str, int],
                ) -> tuple[tuple[str, ...], dict[str, tuple[dict[str, Any], bool]]]:
                    host, exporter_name, port = target
                    args = (
                        host,
                        exporter_name,
                        port,
                        endpoints,
                        timeout,
                        retries,
                        adaptive_collect,
                        completed_by_target.get((host, exporter_name, int(port))),
                    )
                    if plan_collect_fn is None:
                        return plan_collect_endpoints_for_target(*args, scheme=scheme)
                    return plan_collect(*args)

                for target, plan in planner.iter_completed(collect_targets, _plan_target):
                    target_plans[target] = plan
            else:
                for host, exporter_name, port in collect_targets:
                    target_plans[(host, exporter_name, port)] = (endpoints, {})

            jobs: list[tuple[str, str, int, str, tuple[dict[str, Any], bool] | None]] = []
            for host, exporter_name, port in collect_targets:
                planned_endpoints, prefetched = target_plans.get((host, exporter_name, port), (endpoints, {}))
                for endpoint in planned_endpoints:
                    job_key = (host, exporter_name, int(port), endpoint)
                    if job_key in completed_jobs:
                        skipped_jobs += 1
                        continue
                    jobs.append((host, exporter_name, port, endpoint, prefetched.get(endpoint)))

            if stats_sink is not None:
                stats_sink["targets"] = len(collect_targets)
                stats_sink["scheduled_jobs"] = len(jobs)
                stats_sink["skipped_jobs"] = skipped_jobs

            collect_progress = start_audit_progress("COLLECT", len(jobs), enabled=True, owner=progress_owner)
            try:
                fetch_jobs: list[tuple[str, str, int, str]] = []
                for host, exporter_name, port, endpoint, prefetched_result in jobs:
                    if prefetched_result is not None:
                        record, ok = prefetched_result
                        _process_record(record, ok, pause_before_emit=collect_progress.pause_for_output)
                        collect_progress.advance()
                        continue
                    fetch_jobs.append((host, exporter_name, port, endpoint))

                scheduler = BoundedScheduler[tuple[str, str, int, str], tuple[dict[str, Any], bool]](
                    max_workers=max_workers,
                    max_inflight=max_inflight,
                )

                def _collect_job(job: tuple[str, str, int, str]) -> tuple[dict[str, Any], bool]:
                    host, exporter_name, port, endpoint = job
                    if collect_task_fn is collect_task:
                        return collect_task(
                            host,
                            exporter_name,
                            port,
                            endpoint,
                            timeout,
                            retries,
                            scheme=scheme,
                        )
                    return collect_task_fn(host, exporter_name, port, endpoint, timeout, retries)

                for _job, (record, ok) in scheduler.iter_completed(fetch_jobs, _collect_job):
                    _process_record(record, ok, pause_before_emit=collect_progress.pause_for_output)
                    collect_progress.advance()
            finally:
                collect_progress.close()

        _finalize_postprocess()
        if emit_summary:
            summary = {
                "timestamp": utc_now_iso(),
                "type": "summary",
                "hosts": len(hosts),
                "requests": total,
                "success": success,
                "errors": transport_errors,
                "output_path": output_path,
            }
            emit_output_line(out_fh, emit_line, format_collect_record(summary, output_format))
        if stats_sink is not None:
            stats_sink["requests"] = total
            stats_sink["success"] = success
            stats_sink["errors"] = transport_errors
    finally:
        _finalize_postprocess()
        if out_fh is not None:
            out_fh.close()
        if index_fh is not None:
            index_fh.close()
        if checkpoint_fh is not None:
            checkpoint_fh.close()

    return total, success


__all__ = [
    "collect_exporter_debug_data",
    "collect_task",
    "is_pprof_endpoint",
    "plan_collect_endpoints_for_target",
]
