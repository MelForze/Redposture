"""Exporter trigger workflow implementation."""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.parse
from collections.abc import Callable
from typing import Any

from ..constants import SCAN_EXPORTERS
from ..logger import AttemptLogger
from ..scheduler import BoundedScheduler
from .http_client import activate_exporter_tls_context, build_http_url, format_http_host
from .output import extract_display_port

HttpGetText = Callable[[str, float, int], tuple[int, str]]

# These are bounded guesses for named profiles, not an enumeration of an
# exporter's private configuration. A configured custom name remains available
# through --profiles-file (and --postgres-auth-module for Postgres).
_COMMON_PROFILE_NAMES = (
    "default",
    "monitoring",
    "metrics",
    "prometheus",
    "exporter",
    "readonly",
    "read_only",
    "read-only",
    "ro",
    "prod",
    "production",
    "stage",
    "staging",
    "test",
    "testing",
    "dev",
    "development",
    "local",
    "main",
    "primary",
    "cluster",
    "admin",
)
_KNOWN_TRIGGER_PROFILES: dict[str, tuple[str, tuple[str, ...]]] = {
    "mysqld_exporter": (
        "auth_module",
        ("client", "client.servers", "client.mysql", "client.local") + _COMMON_PROFILE_NAMES,
    ),
    "elasticsearch_exporter": (
        "auth_module",
        ("basic", "apikey", "api_key", "bearer", "userpass", "elasticsearch", "opensearch") + _COMMON_PROFILE_NAMES,
    ),
    "postgres_exporter": ("auth_module", ("userpass", "postgresql", "postgres", "pgbouncer") + _COMMON_PROFILE_NAMES),
    "snmp_exporter": (
        "auth",
        (
            "public_v2",
            "public_v1",
            "private_v2",
            "readonly_v2c",
            "read_only_v2c",
            "network_v3_authpriv",
            "public",
            "private",
        )
        + _COMMON_PROFILE_NAMES,
    ),
    "json_exporter": ("module", ("json", "http", "basic", "bearer", "apikey") + _COMMON_PROFILE_NAMES),
    "ipmi_exporter": ("module", ("ipmi", "bmc", "lan") + _COMMON_PROFILE_NAMES),
    "blackbox_exporter": (
        "module",
        ("http_2xx", "http_post_2xx", "tcp_connect", "http_basic", "http_auth", "http_bearer") + _COMMON_PROFILE_NAMES,
    ),
    "proxmox_exporter": ("module", ("pve", "proxmox", "api") + _COMMON_PROFILE_NAMES),
}


def trigger_query_variants(exporter: dict[str, Any]) -> list[str]:
    """Return the configured query followed by bounded, deduplicated profile probes."""

    base_query = str(exporter.get("trigger_query") or "").strip().lstrip("?")
    profile_spec = _KNOWN_TRIGGER_PROFILES.get(str(exporter.get("name") or ""))
    if profile_spec is None:
        return [base_query]
    parameter, names = profile_spec
    pairs = urllib.parse.parse_qsl(base_query, keep_blank_values=True)
    selected = [value for key, value in pairs if key == parameter]
    # An explicitly configured, nonstandard name is intentional. Do not
    # replace it with guesses or multiply an explicit Postgres module list.
    if selected and selected[-1] != "default":
        return [base_query]
    variants = [base_query]
    for name in names:
        query = urllib.parse.urlencode([(key, value) for key, value in pairs if key != parameter] + [(parameter, name)])
        if query not in variants:
            variants.append(query)
    return variants


def detect_trigger_exporter_task(
    logger: AttemptLogger | None,
    host: str,
    exporter: dict[str, Any],
    timeout: float,
    retries: int,
    http_get_text_fn: HttpGetText,
    log_trigger_events_only: bool = False,
    emit_trigger_event: Callable[[dict[str, Any]], None] | None = None,
    scheme: str = "http",
) -> dict[str, Any]:
    exporter_name = str(exporter["name"])
    port = int(exporter["port"])
    detect_url = build_http_url(host, port, str(exporter["detect_path"]), scheme=scheme)

    result: dict[str, Any] = {
        "host": host,
        "exporter": exporter_name,
        "port": port,
        "detected": False,
    }

    try:
        status, body = http_get_text_fn(detect_url, timeout, retries)
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        if logger is not None and not log_trigger_events_only:
            logger.log(
                "scanner",
                (host, port),
                exporter=exporter_name,
                phase="detect_error",
                error=str(exc),
            )
        return result

    markers = tuple(str(item) for item in exporter["markers"])
    if status < 200 or status >= 300 or not any(marker in body for marker in markers):
        return result

    result["detected"] = True
    if logger is not None and not log_trigger_events_only:
        logger.log(
            "scanner",
            (host, port),
            exporter=exporter_name,
            phase="detected",
            status=status,
            detect_url=detect_url,
        )

    if emit_trigger_event is not None:
        emit_trigger_event(
            {
                "phase": "detect_hit",
                "host": host,
                "exporter": exporter_name,
                "exporter_port": port,
                "detect_url": detect_url,
                "status": status,
            }
        )

    return result


def trigger_detected_exporter_task(
    logger: AttemptLogger | None,
    host: str,
    exporter: dict[str, Any],
    callback_targets: list[str],
    timeout: float,
    retries: int,
    http_get_text_fn: HttpGetText,
    emit_trigger_event: Callable[[dict[str, Any]], None] | None = None,
    scheme: str = "http",
    profile_delay: float = 0.0,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    exporter_name = str(exporter["name"])
    port = int(exporter["port"])
    result: dict[str, Any] = {
        "host": host,
        "exporter": exporter_name,
        "port": port,
        "detected": True,
        "attempted": 0,
        "accepted": 0,
        "unconfirmed": 0,
        "success": 0,
        "by_callback": {
            target: {"attempted": 0, "accepted": 0, "unconfirmed": 0, "success": 0, "fail": 0}
            for target in callback_targets
        },
    }

    attempts = [
        (callback_target, variant_index, query)
        for callback_target in callback_targets
        for variant_index, query in enumerate(trigger_query_variants(exporter))
    ]
    consecutive_exporter_failures = 0
    for attempt_index, (callback_target, variant_index, extra_query) in enumerate(attempts):
        if attempt_index and profile_delay > 0:
            sleep_fn(profile_delay)
        target = str(exporter["target_fmt"]).format(our_host=format_http_host(callback_target))
        callback_port = extract_display_port(target)
        query_parts = [f"target={urllib.parse.quote(target, safe=':/')}"]
        if extra_query:
            query_parts.append(extra_query.lstrip("?"))
        profile_event: dict[str, str] = {}
        profile_spec = _KNOWN_TRIGGER_PROFILES.get(exporter_name)
        if profile_spec is not None:
            parameter = profile_spec[0]
            selected_profile = urllib.parse.parse_qs(extra_query).get(parameter)
            if selected_profile:
                profile_event = {"profile_parameter": parameter, "profile_name": selected_profile[-1]}
        trigger_url = build_http_url(
            host,
            port,
            f"{exporter['trigger_path']}?{'&'.join(query_parts)}",
            scheme=scheme,
        )

        if emit_trigger_event is not None:
            emit_trigger_event(
                {
                    "phase": "callback_attempt",
                    "host": host,
                    "exporter": exporter_name,
                    "exporter_port": port,
                    "callback_target": callback_target,
                    "callback_port": callback_port,
                    "target": target,
                    "trigger_url": trigger_url,
                    **profile_event,
                }
            )

        result["attempted"] += 1
        result["by_callback"][callback_target]["attempted"] += 1
        try:
            trigger_status, trigger_body = http_get_text_fn(trigger_url, timeout, retries if variant_index == 0 else 0)
            consecutive_exporter_failures = consecutive_exporter_failures + 1 if trigger_status >= 500 else 0
            probe_success: bool | None = None
            for raw_line in trigger_body.splitlines():
                line = raw_line.strip()
                if not line.startswith("probe_success"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                try:
                    probe_success = float(parts[1]) >= 1.0
                except ValueError:
                    probe_success = None
                break

            request_accepted = 200 <= trigger_status < 300
            trigger_ok = request_accepted and probe_success is True

            if request_accepted:
                result["accepted"] += 1
                result["by_callback"][callback_target]["accepted"] += 1

            if trigger_ok:
                if emit_trigger_event is not None:
                    emit_trigger_event(
                        {
                            "phase": "callback_result",
                            "host": host,
                            "exporter": exporter_name,
                            "exporter_port": port,
                            "callback_target": callback_target,
                            "callback_port": callback_port,
                            "target": target,
                            "trigger_url": trigger_url,
                            "status": trigger_status,
                            "probe_success": probe_success,
                            "accepted": request_accepted,
                            "confirmed": True,
                            "success": True,
                            **profile_event,
                        }
                    )
                result["success"] += 1
                result["by_callback"][callback_target]["success"] += 1
                if logger is not None:
                    logger.log(
                        "scanner",
                        (host, port),
                        exporter=exporter_name,
                        phase="triggered",
                        callback_target=callback_target,
                        trigger_url=trigger_url,
                        status=trigger_status,
                        probe_success=probe_success,
                    )
            else:
                error_text: str | None = f"status={trigger_status}"
                if probe_success is False:
                    error_text = "probe_success=0"
                elif request_accepted:
                    # A 2xx response only proves that the exporter accepted
                    # the request.  It does not prove that the outbound probe
                    # reached the callback target.
                    error_text = None
                if emit_trigger_event is not None:
                    emit_trigger_event(
                        {
                            "phase": "callback_result",
                            "host": host,
                            "exporter": exporter_name,
                            "exporter_port": port,
                            "callback_target": callback_target,
                            "callback_port": callback_port,
                            "target": target,
                            "trigger_url": trigger_url,
                            "status": trigger_status,
                            "probe_success": probe_success,
                            "accepted": request_accepted,
                            "confirmed": False,
                            "success": False,
                            **profile_event,
                            **({"error": error_text} if error_text is not None else {}),
                        }
                    )
                if request_accepted and probe_success is None:
                    result["unconfirmed"] += 1
                    result["by_callback"][callback_target]["unconfirmed"] += 1
                else:
                    result["by_callback"][callback_target]["fail"] += 1
                if logger is not None:
                    logger.log(
                        "scanner",
                        (host, port),
                        exporter=exporter_name,
                        phase="trigger_accepted" if request_accepted and probe_success is None else "trigger_error",
                        callback_target=callback_target,
                        trigger_url=trigger_url,
                        status=trigger_status,
                        error=error_text,
                        probe_success=probe_success,
                    )
            if consecutive_exporter_failures >= 3:
                result["profile_sweep_stopped"] = "exporter_unavailable"
                break
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            consecutive_exporter_failures += 1
            if emit_trigger_event is not None:
                emit_trigger_event(
                    {
                        "phase": "callback_result",
                        "host": host,
                        "exporter": exporter_name,
                        "exporter_port": port,
                        "callback_target": callback_target,
                        "callback_port": callback_port,
                        "target": target,
                        "trigger_url": trigger_url,
                        "success": False,
                        "error": str(exc),
                        **profile_event,
                    }
                )
            result["by_callback"][callback_target]["fail"] += 1
            if logger is not None:
                logger.log(
                    "scanner",
                    (host, port),
                    exporter=exporter_name,
                    phase="trigger_error",
                    callback_target=callback_target,
                    trigger_url=trigger_url,
                    error=str(exc),
                )
            if consecutive_exporter_failures >= 3:
                result["profile_sweep_stopped"] = "exporter_unavailable"
                break

    return result


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
    http_get_text_fn: HttpGetText | None = None,
    scheme: str = "http",
    tls_context: ssl.SSLContext | None = None,
    profile_delay: float = 0.0,
) -> dict[str, Any]:
    if http_get_text_fn is None:
        from .http_client import http_get_text

        http_get_text_fn = http_get_text
    if tls_context is not None:
        base_http_get_text_fn = http_get_text_fn

        def _tls_http_get_text(url: str, request_timeout: float, request_retries: int) -> tuple[int, str]:
            with activate_exporter_tls_context(tls_context):
                return base_http_get_text_fn(url, request_timeout, request_retries)

        http_get_text_fn = _tls_http_get_text

    exporters = list(trigger_exporters or SCAN_EXPORTERS)
    callback_list = list(dict.fromkeys(callback_targets))
    pipeline_started_at = time.monotonic()

    total_detected = 0
    total_attempted = 0
    total_accepted = 0
    total_unconfirmed = 0
    total_success = 0

    host_detected: dict[str, bool] = {host: False for host in hosts}
    by_host: dict[str, dict[str, int]] = {
        host: {"detected": 0, "attempted": 0, "accepted": 0, "unconfirmed": 0, "success": 0, "fail": 0}
        for host in hosts
    }
    by_callback: dict[str, dict[str, int]] = {
        target: {"attempted": 0, "accepted": 0, "unconfirmed": 0, "success": 0, "fail": 0} for target in callback_list
    }
    by_exporter: dict[str, dict[str, int]] = {
        str(exporter.get("name") or ""): {
            "detected": 0,
            "attempted": 0,
            "accepted": 0,
            "unconfirmed": 0,
            "success": 0,
            "fail": 0,
        }
        for exporter in exporters
    }
    attempts_by_exporter_host: dict[str, dict[str, int]] = {
        str(exporter.get("name") or ""): {} for exporter in exporters
    }

    detected_pairs: list[tuple[str, dict[str, Any]]] = []

    detect_total = len(hosts) * len(exporters)
    if emit_stage_event is not None:
        emit_stage_event({"kind": "pass", "pass": "detect", "event": "start", "total": detect_total})
    detect_started_at = time.monotonic()
    detect_jobs = [(host, exporter) for host in hosts for exporter in exporters]
    detect_scheduler = BoundedScheduler[tuple[str, dict[str, Any]], dict[str, Any]](
        max_workers=max(1, workers),
        max_inflight=max(1, workers) * 4,
    )

    def _detect_job(job: tuple[str, dict[str, Any]]) -> dict[str, Any]:
        host, exporter = job
        return detect_trigger_exporter_task(
            logger,
            host,
            exporter,
            timeout,
            retries,
            http_get_text_fn,
            log_trigger_events_only,
            emit_trigger_event,
            scheme,
        )

    for (host, exporter), result in detect_scheduler.iter_completed(detect_jobs, _detect_job):
        try:
            if result["detected"]:
                total_detected += 1
                host_detected[host] = True
                by_host[host]["detected"] += 1
                exporter_name = str(result.get("exporter") or "")
                if exporter_name in by_exporter:
                    by_exporter[exporter_name]["detected"] += 1
                detected_pairs.append((host, exporter))
                if callback_list and progress_add_total is not None:
                    progress_add_total(len(callback_list) * len(trigger_query_variants(exporter)))
        finally:
            if progress_advance is not None:
                progress_advance(1)
    detect_ms = int((time.monotonic() - detect_started_at) * 1000)
    if emit_stage_event is not None:
        emit_stage_event(
            {
                "kind": "stage_trace",
                "stage_name": "detect_protocol",
                "attempt": 1,
                "duration_ms": detect_ms,
                "result": "ok",
                "error": "-",
            }
        )
        emit_stage_event(
            {
                "kind": "pass",
                "pass": "detect",
                "event": "complete",
                "total": detect_total,
                "detected_exporters": total_detected,
                "deep_candidates": len(detected_pairs),
            }
        )
        for host in hosts:
            detected_count = int(by_host.get(host, {}).get("detected", 0))
            emit_stage_event(
                {
                    "kind": "gate",
                    "host": host,
                    "gate": "run" if detected_count > 0 else "skip",
                    "reason": f"detected={detected_count}",
                }
            )

    if emit_stage_event is not None:
        emit_stage_event({"kind": "pass", "pass": "deep", "event": "start", "total": len(detected_pairs)})
    deep_started_at = time.monotonic()
    deep_scheduler = BoundedScheduler[tuple[str, dict[str, Any]], dict[str, Any]](
        max_workers=max(1, workers),
        max_inflight=max(1, workers) * 4,
    )

    def _deep_job(job: tuple[str, dict[str, Any]]) -> dict[str, Any]:
        host, exporter = job
        return trigger_detected_exporter_task(
            logger,
            host,
            exporter,
            callback_list,
            timeout,
            retries,
            http_get_text_fn,
            emit_trigger_event,
            scheme,
            profile_delay,
        )

    for _job, result in deep_scheduler.iter_completed(detected_pairs, _deep_job):
        host = str(result["host"])

        attempted = int(result["attempted"])
        accepted = int(result.get("accepted", 0))
        unconfirmed = int(result.get("unconfirmed", 0))
        success = int(result["success"])
        fail = sum(
            int(stats.get("fail", 0)) for stats in result.get("by_callback", {}).values() if isinstance(stats, dict)
        )

        total_attempted += attempted
        total_accepted += accepted
        total_unconfirmed += unconfirmed
        total_success += success

        by_host[host]["attempted"] += attempted
        by_host[host]["accepted"] += accepted
        by_host[host]["unconfirmed"] += unconfirmed
        by_host[host]["success"] += success
        by_host[host]["fail"] += fail
        exporter_name = str(result.get("exporter") or "")
        if exporter_name in by_exporter:
            by_exporter[exporter_name]["attempted"] += attempted
            by_exporter[exporter_name]["accepted"] += accepted
            by_exporter[exporter_name]["unconfirmed"] += unconfirmed
            by_exporter[exporter_name]["success"] += success
            by_exporter[exporter_name]["fail"] += fail
            if attempted > 0:
                exporter_hosts = attempts_by_exporter_host[exporter_name]
                exporter_hosts[host] = exporter_hosts.get(host, 0) + attempted

        try:
            callback_data = result["by_callback"]
            if isinstance(callback_data, dict):
                for target, stats in callback_data.items():
                    if target not in by_callback or not isinstance(stats, dict):
                        continue
                    by_callback[target]["attempted"] += int(stats.get("attempted", 0))
                    by_callback[target]["accepted"] += int(stats.get("accepted", 0))
                    by_callback[target]["unconfirmed"] += int(stats.get("unconfirmed", 0))
                    by_callback[target]["success"] += int(stats.get("success", 0))
                    by_callback[target]["fail"] += int(stats.get("fail", 0))
        finally:
            if progress_advance is not None and attempted > 0:
                progress_advance(attempted)
    deep_ms = int((time.monotonic() - deep_started_at) * 1000)
    if emit_stage_event is not None:
        emit_stage_event(
            {
                "kind": "stage_trace",
                "stage_name": "data",
                "attempt": 1,
                "duration_ms": deep_ms,
                "result": "ok",
                "error": "-",
            }
        )
        emit_stage_event(
            {
                "kind": "pass",
                "pass": "deep",
                "event": "complete",
                "total": len(detected_pairs),
                "processed": len(detected_pairs),
            }
        )
        total_ms = int((time.monotonic() - pipeline_started_at) * 1000)
        emit_stage_event(
            {
                "kind": "timing_summary",
                "status": "ok",
                "attempts": "1/1",
                "detect_ms": detect_ms,
                "data_ms": deep_ms,
                "total_ms": total_ms,
            }
        )

    if logger is not None and not log_trigger_events_only:
        for host, detected in host_detected.items():
            if not detected:
                logger.log("scanner", (host, 0), phase="not_found")

    return {
        "hosts": len(hosts),
        "detected_exporters": total_detected,
        "attempted": total_attempted,
        "accepted": total_accepted,
        "triggered": total_success,
        "unconfirmed": total_unconfirmed,
        "failed": sum(int(stats.get("fail", 0)) for stats in by_host.values()),
        "by_host": by_host,
        "by_callback": by_callback,
        "by_exporter": by_exporter,
        "attempts_by_exporter_host": attempts_by_exporter_host,
    }


__all__ = [
    "detect_trigger_exporter_task",
    "scan_exporters_and_trigger",
    "trigger_detected_exporter_task",
]
