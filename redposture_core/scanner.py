"""Compatibility facade for exporter scan/trigger/collect workflows.

The implementation lives under :mod:`redposture_core.exporters`.  This module
keeps historical imports and monkeypatch points stable while the exporter
subsystem is split into smaller files.
"""

from __future__ import annotations

import time
import urllib.request
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any

from .exporters.collect import collect_exporter_debug_data as _collect_exporter_debug_data_impl
from .exporters.collect import collect_task as _collect_task_impl
from .exporters.collect import is_pprof_endpoint as _is_pprof_endpoint_impl
from .exporters.collect import plan_collect_endpoints_for_target as _plan_collect_endpoints_for_target_impl
from .exporters.discover import SCAN_FINGERPRINT_BODY_MAX_BYTES as _SCAN_FINGERPRINT_BODY_MAX_BYTES
from .exporters.discover import SCAN_RESPONSE_BODY_MAX_BYTES as _SCAN_RESPONSE_BODY_MAX_BYTES
from .exporters.discover import WEAK_CANDIDATE_CONFIDENCE_SCORE as _WEAK_CANDIDATE_CONFIDENCE_SCORE
from .exporters.discover import fetch_fingerprint_bodies_default as _fetch_fingerprint_bodies_default
from .exporters.discover import scan_exporter_presence as _scan_exporter_presence_impl
from .exporters.discover import scan_presence_port_task as _scan_presence_port_task_impl
from .exporters.discover import scan_presence_task as _scan_presence_task_impl
from .exporters.http_client import http_get_details as _http_get_details_impl
from .exporters.http_client import http_get_text as _http_get_text_impl
from .exporters.http_pool import (
    HTTP_POOL_MAX_IDLE_PER_HOST,
    HTTP_POOL_MAX_IDLE_TOTAL,
    HTTPConnectionPool,
    activate_http_pool,
)
from .exporters.trigger import scan_exporters_and_trigger as _scan_exporters_and_trigger_impl
from .exporters.workflows import COLLECT_PPROF_PREFLIGHT_MAX_TARGETS
from .logger import AttemptLogger

_COLLECT_PPROF_PREFLIGHT_MAX_TARGETS = COLLECT_PPROF_PREFLIGHT_MAX_TARGETS
_HTTP_POOL_MAX_IDLE_TOTAL = HTTP_POOL_MAX_IDLE_TOTAL
_HTTP_POOL_MAX_IDLE_PER_HOST = HTTP_POOL_MAX_IDLE_PER_HOST
_HTTPConnectionPool = HTTPConnectionPool
_ACTIVE_HTTP_POOL: Any = None


@contextmanager
def _activate_http_pool(pool: Any):
    """Compatibility wrapper around exporters.http_pool.activate_http_pool."""

    global _ACTIVE_HTTP_POOL
    previous = _ACTIVE_HTTP_POOL
    _ACTIVE_HTTP_POOL = pool
    try:
        with activate_http_pool(pool):
            yield
    finally:
        _ACTIVE_HTTP_POOL = previous


def http_get_text(url: str, timeout: float, retries: int = 1) -> tuple[int, str]:
    """Compatibility wrapper for tests and historical scanner monkeypatching."""

    return _http_get_text_impl(
        url,
        timeout,
        retries,
        sleep_fn=time.sleep,
        urlopen_fn=urllib.request.urlopen,
    )


def http_get_details(url: str, timeout: float, retries: int = 1, *, max_bytes: int | None = None) -> dict[str, Any]:
    """Compatibility wrapper for tests and historical scanner monkeypatching."""

    return _http_get_details_impl(
        url,
        timeout,
        retries,
        max_bytes=max_bytes,
        monotonic_fn=time.monotonic,
        sleep_fn=time.sleep,
        urlopen_fn=urllib.request.urlopen,
    )


def _scan_presence_task(
    host: str,
    exporter: dict[str, Any],
    timeout: float,
    retries: int,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    return _scan_presence_task_impl(
        host,
        exporter,
        timeout,
        retries,
        http_get_details_fn=http_get_details,
        response_body_max_bytes=_SCAN_RESPONSE_BODY_MAX_BYTES,
    )


def _fetch_fingerprint_bodies(host: str, port: int, timeout: float, retries: int) -> tuple[str, str]:
    return _fetch_fingerprint_bodies_default(
        host,
        port,
        timeout,
        retries,
        http_get_details_fn=http_get_details,
        fingerprint_body_max_bytes=_SCAN_FINGERPRINT_BODY_MAX_BYTES,
    )


def _scan_presence_port_task(
    host: str,
    port: int,
    exporters: list[dict[str, Any]],
    timeout: float,
    retries: int,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    return _scan_presence_port_task_impl(
        host,
        port,
        exporters,
        timeout,
        retries,
        http_get_details_fn=http_get_details,
        fetch_fingerprint_bodies_fn=_fetch_fingerprint_bodies,
        response_body_max_bytes=_SCAN_RESPONSE_BODY_MAX_BYTES,
        weak_candidate_confidence_score=_WEAK_CANDIDATE_CONFIDENCE_SCORE,
    )


def _collect_task(
    host: str,
    exporter_name: str,
    port: int,
    endpoint: str,
    timeout: float,
    retries: int,
) -> tuple[dict[str, Any], bool]:
    return _collect_task_impl(
        host,
        exporter_name,
        port,
        endpoint,
        timeout,
        retries,
        http_get_details_fn=http_get_details,
    )


def _is_pprof_endpoint(endpoint: str) -> bool:
    return _is_pprof_endpoint_impl(endpoint)


def _plan_collect_endpoints_for_target(
    host: str,
    exporter_name: str,
    port: int,
    endpoints: tuple[str, ...],
    timeout: float,
    retries: int,
    adaptive_collect: bool = True,
    completed_endpoints: set[str] | None = None,
) -> tuple[tuple[str, ...], dict[str, tuple[dict[str, Any], bool]]]:
    return _plan_collect_endpoints_for_target_impl(
        host,
        exporter_name,
        port,
        endpoints,
        timeout,
        retries,
        adaptive_collect,
        completed_endpoints,
        collect_task_fn=_collect_task,
    )


def scan_exporters_and_trigger(
    logger: AttemptLogger | None,
    hosts: list[str],
    callback_targets: list[str],
    timeout: float,
    workers: int = 10,
    retries: int = 3,
    trigger_exporters: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
    log_trigger_events_only: bool = False,
    emit_trigger_event: Callable[[dict[str, Any]], None] | None = None,
    emit_stage_event: Callable[[dict[str, Any]], None] | None = None,
    progress_advance: Callable[[int], None] | None = None,
    progress_add_total: Callable[[int], None] | None = None,
) -> dict[str, Any]:
    return _scan_exporters_and_trigger_impl(
        logger=logger,
        hosts=hosts,
        callback_targets=callback_targets,
        timeout=timeout,
        workers=workers,
        retries=retries,
        trigger_exporters=trigger_exporters,
        log_trigger_events_only=log_trigger_events_only,
        emit_trigger_event=emit_trigger_event,
        emit_stage_event=emit_stage_event,
        progress_advance=progress_advance,
        progress_add_total=progress_add_total,
        http_get_text_fn=http_get_text,
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
) -> tuple[int, int, dict[str, list[dict[str, Any]]]]:
    return _scan_exporter_presence_impl(
        hosts=hosts,
        timeout=timeout,
        output_path=output_path,
        output_format=output_format,
        logger=logger,
        emit_line=emit_line,
        workers=workers,
        retries=retries,
        discovery_exporters=discovery_exporters,
        custom_ports=custom_ports,
        emit_summary=emit_summary,
        show_progress=show_progress,
        progress_leave=progress_leave,
        output_mode=output_mode,
        progress_owner=progress_owner,
        scan_task_fn=_scan_presence_port_task,
        pool_cls=_HTTPConnectionPool,
        activate_pool_fn=_activate_http_pool,
    )


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
) -> tuple[int, int]:
    return _collect_exporter_debug_data_impl(
        logger=logger,
        hosts=hosts,
        timeout=timeout,
        output_path=output_path,
        output_format=output_format,
        emit_line=emit_line,
        workers=workers,
        retries=retries,
        collect_exporters=collect_exporters,
        collect_debug_endpoints=collect_debug_endpoints,
        found_by_host=found_by_host,
        save_responses_dir=save_responses_dir,
        records_sink=records_sink,
        record_callback=record_callback,
        output_mode=output_mode,
        index_mode=index_mode,
        emit_summary=emit_summary,
        adaptive_collect=adaptive_collect,
        max_inflight_requests=max_inflight_requests,
        resume_completed_jobs=resume_completed_jobs,
        checkpoint_path=checkpoint_path,
        checkpoint_mode=checkpoint_mode,
        stats_sink=stats_sink,
        progress_owner=progress_owner,
        collect_task_fn=_collect_task,
        plan_collect_fn=_plan_collect_endpoints_for_target,
        pool_cls=_HTTPConnectionPool,
        activate_pool_fn=_activate_http_pool,
        preflight_max_targets=_COLLECT_PPROF_PREFLIGHT_MAX_TARGETS,
    )


__all__ = [
    "collect_exporter_debug_data",
    "http_get_details",
    "http_get_text",
    "scan_exporter_presence",
    "scan_exporters_and_trigger",
]
