"""Scan/trigger and collect flows for exporter interactions."""

from __future__ import annotations

import errno
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, as_completed, wait
from typing import Any
from urllib.parse import urlparse

from .constants import COLLECT_DEBUG_ENDPOINTS, COLLECT_EXPORTERS, DISCOVERY_EXPORTERS, SCAN_EXPORTERS
from .logger import AttemptLogger
from .progress import ProgressBar, iter_completed_with_progress
from .utils import utc_now_iso

_EXPORTER_DISPLAY_NAMES = {
    "blackbox_exporter": "Blackbox Exporter",
    "kafka_exporter": "Kafka Exporter",
    "node_exporter": "Node Exporter",
    "postgres_exporter": "Postgres Exporter",
    "redis_exporter": "Redis Exporter",
    "clickhouse_exporter": "ClickHouse Exporter",
    "mongodb_exporter": "MongoDB Exporter",
    "pgbouncer_exporter": "PgBouncer Exporter",
    "gobgp_exporter": "GoBGP Exporter",
    "frr_exporter": "FRR Exporter",
    "named_process_exporter": "Named Process Exporter",
    "ping_exporter": "Ping Exporter",
    "proxmox_exporter": "Proxmox Exporter",
}

_COLLECT_PPROF_PREFLIGHT_MAX_TARGETS = 1000


def _clip(value: Any, width: int) -> str:
    text = str(value if value is not None else "-").replace("\n", "\\n")
    if width <= 3 or len(text) <= width:
        return text[:width]
    return text[: width - 3] + "..."


def _status_value(value: Any) -> str:
    if value is None:
        return "-"
    return str(value)


def _extract_display_port(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return "-"
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="")
    if parsed.port is not None:
        return str(parsed.port)
    scheme = parsed.scheme.lower()
    if scheme == "http":
        return "80"
    if scheme == "https":
        return "443"
    return "-"


def _scan_nxc_prefix(record: dict[str, Any]) -> str:
    host = _clip(record.get("host") or "-", 64)
    port = _status_value(record.get("port"))
    return f"{'SCAN':<8}\t{host}\t{port}\t"


def _exporter_display_name(value: str) -> str:
    key = (value or "").strip().lower()
    return _EXPORTER_DISPLAY_NAMES.get(key, value)


def _retry_delay(attempt_index: int) -> float:
    # 0.20, 0.40, 0.80, ... capped to 1.50 seconds.
    return min(1.50, 0.20 * (2**attempt_index))


def _unwrap_network_error(exc: BaseException) -> BaseException:
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, BaseException):
            return reason
    return exc


def _should_retry_http_exception(exc: BaseException) -> bool:
    root = _unwrap_network_error(exc)
    if isinstance(root, (TimeoutError, socket.timeout)):
        return True
    if isinstance(root, socket.gaierror):
        # Retry only temporary DNS resolution failures.
        eai_again = getattr(socket, "EAI_AGAIN", None)
        return eai_again is not None and getattr(root, "errno", None) == eai_again
    if isinstance(root, OSError):
        return getattr(root, "errno", None) in {
            errno.ETIMEDOUT,
            errno.EAGAIN,
            errno.EWOULDBLOCK,
            errno.EINTR,
        }
    return False


def _safe_fs_part(value: str, fallback: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", (value or "").strip())
    clean = clean.strip("._-")
    if not clean:
        return fallback
    return clean[:96]


def _endpoint_slug(endpoint: str) -> str:
    raw = (endpoint or "").strip()
    if not raw:
        return "root"
    raw = raw.lstrip("/")
    if not raw:
        return "root"
    raw = raw.replace("/", "__").replace("?", "__q__").replace("&", "__and__").replace("=", "__")
    return _safe_fs_part(raw, "endpoint")


def _save_collect_body(
    save_dir: str,
    record: dict[str, Any],
) -> tuple[str | None, int]:
    body = str(record.get("body") or "")
    host = _safe_fs_part(str(record.get("host") or ""), "host")
    exporter = _safe_fs_part(str(record.get("exporter") or ""), "exporter")
    port = str(record.get("port") or "-")
    endpoint = str(record.get("endpoint") or "")
    slug = _endpoint_slug(endpoint)

    rel_path = os.path.join(host, exporter, f"{port}_{slug}.txt")
    abs_path = os.path.join(save_dir, rel_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as fh:
        fh.write(body)

    return rel_path, len(body.encode("utf-8"))


def http_get_text(url: str, timeout: float, retries: int = 1) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "RedPosture/1.0"})
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status = int(response.status)
                body = response.read().decode("utf-8", errors="replace")
                return status, body
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return exc.code, body
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            if attempt >= attempts - 1 or not _should_retry_http_exception(exc):
                raise
            time.sleep(_retry_delay(attempt))
    raise RuntimeError("unreachable")


def http_get_details(url: str, timeout: float, retries: int = 1) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "RedPosture/1.0"})
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                raw = response.read()
                elapsed_ms = int((time.monotonic() - started) * 1000)
                body = raw.decode("utf-8", errors="replace")
                return {
                    "status": int(response.status),
                    "body": body,
                    "content_type": response.headers.get("Content-Type"),
                    "elapsed_ms": elapsed_ms,
                    "truncated": False,
                    "error": None,
                }
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            elapsed_ms = int((time.monotonic() - started) * 1000)
            body = raw.decode("utf-8", errors="replace")
            return {
                "status": int(exc.code),
                "body": body,
                "content_type": exc.headers.get("Content-Type") if exc.headers else None,
                "elapsed_ms": elapsed_ms,
                "truncated": False,
                "error": None,
            }
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            if attempt < attempts - 1 and _should_retry_http_exception(exc):
                time.sleep(_retry_delay(attempt))
                continue
            return {
                "status": None,
                "body": "",
                "content_type": None,
                "elapsed_ms": elapsed_ms,
                "truncated": False,
                "error": str(exc),
            }
    raise RuntimeError("unreachable")


def _format_scan_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    if record.get("type") == "summary":
        output_path = record.get("output_path")
        output_suffix = f" output={output_path}" if output_path else ""
        return (
            f"{'SCAN':<8}\tsummary\t-\t[*] "
            f"hosts={record.get('hosts')} checks={record.get('checks')} found={record.get('found')}{output_suffix}"
        )

    prefix = _scan_nxc_prefix(record)
    exporter = _clip(record.get("exporter") or "-", 24)
    method = _clip(record.get("method") or "-", 12)
    marker = _clip(record.get("marker_hit") or "-", 28)
    error = _clip(record.get("error") or "-", 64)

    if bool(record.get("detected")):
        display_name = _exporter_display_name(str(record.get("exporter") or "-"))
        return f"{prefix} [+] {display_name}"

    if error != "-":
        return f"{prefix} [!] exporter={exporter} request failed err={error}"

    return f"{prefix} [-] exporter={exporter} not detected via={method} marker={marker}"


def _format_collect_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    if record.get("type") == "summary":
        output_path = record.get("output_path")
        output_suffix = f" output={output_path}" if output_path else ""
        return (
            f"{'COLLECT':<8}\tsummary\t-\t[*] "
            f"hosts={record.get('hosts')} requests={record.get('requests')} "
            f"success={record.get('success')}{output_suffix}"
        )

    host = _clip(record.get("host") or "-", 64)
    port = _status_value(record.get("port"))
    prefix = f"{'COLLECT':<8}\t{host}\t{port}\t"
    exporter_name = _exporter_display_name(str(record.get("exporter") or "-"))
    endpoint = _clip(record.get("endpoint") or "-", 30)
    url = str(record.get("url") or "-")
    error = _clip(record.get("error") or "-", 64)

    if bool(record.get("ok")):
        return f"{prefix} [+] {exporter_name} url={url}"

    if error != "-":
        return f"{prefix} [!] {exporter_name} url={url} err={error}"

    return f"{prefix} [-] {exporter_name} url={url} endpoint={endpoint}"


def _emit_line(out_fh: Any, emit_line: Callable[[str], None] | None, line: str) -> None:
    if out_fh is not None:
        out_fh.write(line + "\n")
        out_fh.flush()
    if emit_line is not None:
        emit_line(line)


def _scan_presence_task(
    host: str,
    exporter: dict[str, Any],
    timeout: float,
    retries: int,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    exporter_name = str(exporter["name"])
    port = int(exporter["port"])
    url = f"http://{host}:{port}/metrics"
    result = http_get_details(url, timeout=timeout, retries=retries)

    status = result["status"]
    body = str(result["body"] or "")
    markers = tuple(str(item) for item in exporter["markers"])
    marker_hit = next((marker for marker in markers if marker in body), None)

    is_prometheus_like = ("# HELP " in body) or ("# TYPE " in body)
    is_http_ok = status is not None and int(status) < 400
    detected = bool(is_http_ok and (marker_hit or is_prometheus_like))
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


def _scan_presence_port_task(
    host: str,
    port: int,
    exporters: list[dict[str, Any]],
    timeout: float,
    retries: int,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    url = f"http://{host}:{port}/metrics"
    result = http_get_details(url, timeout=timeout, retries=retries)

    status = result["status"]
    body = str(result["body"] or "")
    is_http_ok = status is not None and int(status) < 400
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

    best_exporter: str | None = None
    best_marker: str | None = None
    best_score: tuple[int, int] = (0, 0)

    for exporter in exporters:
        exporter_name = str(exporter.get("name") or "")
        markers = tuple(str(item) for item in exporter.get("markers", ()))
        matched = [marker for marker in markers if marker and marker in body]
        if not matched:
            continue
        score = (len(matched), max(len(marker) for marker in matched))
        if score > best_score:
            best_score = score
            best_exporter = exporter_name
            best_marker = matched[0]

    detected = best_exporter is not None
    exporter_name = best_exporter or "unknown"
    method = "marker" if detected else "none"
    marker_hit = best_marker if detected else None

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


def _collect_task(
    host: str,
    exporter_name: str,
    port: int,
    endpoint: str,
    timeout: float,
    retries: int,
) -> tuple[dict[str, Any], bool]:
    url = f"http://{host}:{port}{endpoint}"
    result = http_get_details(url, timeout=timeout, retries=retries)
    status = result["status"]
    ok = status is not None and int(status) < 400

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
    return record, ok


def _is_pprof_endpoint(endpoint: str) -> bool:
    raw = str(endpoint or "").split("?", 1)[0]
    return raw == "/debug/pprof" or raw == "/debug/pprof/" or raw.startswith("/debug/pprof/")


def _plan_collect_endpoints_for_target(
    host: str,
    exporter_name: str,
    port: int,
    endpoints: tuple[str, ...],
    timeout: float,
    retries: int,
) -> tuple[tuple[str, ...], dict[str, tuple[dict[str, Any], bool]]]:
    # Use pprof index as a cheap capability probe:
    # if it returns HTTP >= 400, skip deeper pprof paths for this target.
    probe_endpoint = "/debug/pprof/"
    if probe_endpoint not in endpoints:
        return endpoints, {}

    probe_record, probe_ok = _collect_task(
        host,
        exporter_name,
        port,
        probe_endpoint,
        timeout,
        retries,
    )
    prefetched = {probe_endpoint: (probe_record, probe_ok)}
    status = probe_record.get("status")

    # Keep all pprof endpoints if probe is successful or inconclusive.
    if status is None or probe_ok:
        return endpoints, prefetched

    planned = tuple(
        endpoint for endpoint in endpoints if endpoint == probe_endpoint or not _is_pprof_endpoint(endpoint)
    )
    return planned, prefetched


def _detect_trigger_exporter_task(
    logger: AttemptLogger | None,
    host: str,
    exporter: dict[str, Any],
    timeout: float,
    retries: int,
    log_trigger_events_only: bool = False,
    emit_trigger_event: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    exporter_name = str(exporter["name"])
    port = int(exporter["port"])
    detect_url = f"http://{host}:{port}{exporter['detect_path']}"

    result: dict[str, Any] = {
        "host": host,
        "exporter": exporter_name,
        "port": port,
        "detected": False,
    }

    try:
        status, body = http_get_text(detect_url, timeout, retries=retries)
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
    if status >= 500 or not any(marker in body for marker in markers):
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


def _trigger_detected_exporter_task(
    logger: AttemptLogger | None,
    host: str,
    exporter: dict[str, Any],
    callback_targets: list[str],
    timeout: float,
    retries: int,
    emit_trigger_event: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    exporter_name = str(exporter["name"])
    port = int(exporter["port"])
    result: dict[str, Any] = {
        "host": host,
        "exporter": exporter_name,
        "port": port,
        "detected": True,
        "attempted": 0,
        "success": 0,
        "by_callback": {target: {"attempted": 0, "success": 0, "fail": 0} for target in callback_targets},
    }

    for callback_target in callback_targets:
        target = str(exporter["target_fmt"]).format(our_host=callback_target)
        callback_port = _extract_display_port(target)
        query_parts = [f"target={urllib.parse.quote(target, safe=':/')}"]
        extra_query = str(exporter.get("trigger_query") or "").strip()
        if extra_query:
            query_parts.append(extra_query.lstrip("?"))
        trigger_url = f"http://{host}:{port}{exporter['trigger_path']}?{'&'.join(query_parts)}"

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
                }
            )

        result["attempted"] += 1
        result["by_callback"][callback_target]["attempted"] += 1
        try:
            trigger_status, trigger_body = http_get_text(trigger_url, timeout, retries=retries)
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

            trigger_ok = trigger_status < 400
            if probe_success is not None:
                trigger_ok = trigger_ok and probe_success

            if trigger_ok:
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
                result["by_callback"][callback_target]["fail"] += 1
                if logger is not None:
                    error_text = f"status={trigger_status}"
                    if probe_success is False:
                        error_text = "probe_success=0"
                    logger.log(
                        "scanner",
                        (host, port),
                        exporter=exporter_name,
                        phase="trigger_error",
                        callback_target=callback_target,
                        trigger_url=trigger_url,
                        status=trigger_status,
                        error=error_text,
                        probe_success=probe_success,
                    )
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
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
) -> dict[str, Any]:
    exporters = list(trigger_exporters or SCAN_EXPORTERS)
    callback_list = list(dict.fromkeys(callback_targets))

    total_detected = 0
    total_attempted = 0
    total_success = 0

    host_detected: dict[str, bool] = {host: False for host in hosts}
    by_host: dict[str, dict[str, int]] = {
        host: {"detected": 0, "attempted": 0, "success": 0, "fail": 0} for host in hosts
    }
    by_callback: dict[str, dict[str, int]] = {
        target: {"attempted": 0, "success": 0, "fail": 0} for target in callback_list
    }
    by_exporter: dict[str, dict[str, int]] = {
        str(exporter.get("name") or ""): {"detected": 0, "attempted": 0, "success": 0, "fail": 0}
        for exporter in exporters
    }

    detected_pairs: list[tuple[str, dict[str, Any]]] = []

    # Phase 1: detection for all target exporters.
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        future_map = {
            executor.submit(
                _detect_trigger_exporter_task,
                logger,
                host,
                exporter,
                timeout,
                retries,
                log_trigger_events_only,
                emit_trigger_event,
            ): (host, exporter)
            for host in hosts
            for exporter in exporters
        }
        for future in iter_completed_with_progress(future_map, label="TRIGGER"):
            result = future.result()
            host, exporter = future_map[future]

            if result["detected"]:
                total_detected += 1
                host_detected[host] = True
                by_host[host]["detected"] += 1
                exporter_name = str(result.get("exporter") or "")
                if exporter_name in by_exporter:
                    by_exporter[exporter_name]["detected"] += 1
                detected_pairs.append((host, exporter))

    # Phase 2: trigger callbacks only for detected exporters.
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        future_map = {
            executor.submit(
                _trigger_detected_exporter_task,
                logger,
                host,
                exporter,
                callback_list,
                timeout,
                retries,
                emit_trigger_event,
            ): (host, exporter)
            for host, exporter in detected_pairs
        }
        for future in iter_completed_with_progress(future_map, label="TRIGGER"):
            result = future.result()
            host = str(result["host"])

            attempted = int(result["attempted"])
            success = int(result["success"])
            fail = attempted - success

            total_attempted += attempted
            total_success += success

            by_host[host]["attempted"] += attempted
            by_host[host]["success"] += success
            by_host[host]["fail"] += fail
            exporter_name = str(result.get("exporter") or "")
            if exporter_name in by_exporter:
                by_exporter[exporter_name]["attempted"] += attempted
                by_exporter[exporter_name]["success"] += success
                by_exporter[exporter_name]["fail"] += fail

            callback_data = result["by_callback"]
            if isinstance(callback_data, dict):
                for target, stats in callback_data.items():
                    if target not in by_callback or not isinstance(stats, dict):
                        continue
                    by_callback[target]["attempted"] += int(stats.get("attempted", 0))
                    by_callback[target]["success"] += int(stats.get("success", 0))
                    by_callback[target]["fail"] += int(stats.get("fail", 0))

    if logger is not None and not log_trigger_events_only:
        for host, detected in host_detected.items():
            if not detected:
                logger.log("scanner", (host, 0), phase="not_found")

    return {
        "hosts": len(hosts),
        "detected_exporters": total_detected,
        "attempted": total_attempted,
        "triggered": total_success,
        "failed": total_attempted - total_success,
        "by_host": by_host,
        "by_callback": by_callback,
        "by_exporter": by_exporter,
    }


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
    show_progress: bool = True,
    progress_leave: bool = True,
) -> tuple[int, int, dict[str, list[dict[str, Any]]]]:
    exporters = list(discovery_exporters or DISCOVERY_EXPORTERS)
    if custom_ports:
        ports = list(dict.fromkeys(int(port) for port in custom_ports))
    else:
        ports = list(
            dict.fromkeys(int(exporter.get("port")) for exporter in exporters if exporter.get("port") is not None)
        )
    total_checks = 0
    total_found = 0
    found_by_host: dict[str, list[dict[str, Any]]] = {host: [] for host in hosts}

    out_fh: Any = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, "w", encoding="utf-8")

    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            future_map = {
                executor.submit(_scan_presence_port_task, host, port, exporters, timeout, retries): (host, port)
                for host in hosts
                for port in ports
            }

            for future in iter_completed_with_progress(
                future_map,
                label="SCAN",
                enabled=show_progress,
                leave=progress_leave,
            ):
                record, hit = future.result()
                total_checks += 1
                if hit is not None:
                    total_found += 1
                    found_by_host[str(record["host"])].append(hit)

                _emit_line(out_fh, emit_line, _format_scan_record(record, output_format))

                if logger is not None:
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
            _emit_line(out_fh, emit_line, _format_scan_record(summary, output_format))
    finally:
        if out_fh is not None:
            out_fh.close()

    return total_checks, total_found, found_by_host


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
) -> tuple[int, int]:
    exporters = list(collect_exporters or COLLECT_EXPORTERS)
    endpoints = tuple(collect_debug_endpoints or COLLECT_DEBUG_ENDPOINTS)
    total = 0
    success = 0

    out_fh: Any = None
    index_fh: Any = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, output_mode, encoding="utf-8")
    if save_responses_dir:
        os.makedirs(save_responses_dir, exist_ok=True)
        index_path = os.path.join(save_responses_dir, "index.jsonl")
        index_fh = open(index_path, index_mode, encoding="utf-8")

    try:
        enabled_exporters = {str(item.get("name") or "") for item in exporters}
        host_rank = {host: idx for idx, host in enumerate(hosts)}
        if found_by_host is None:
            collect_targets: list[tuple[str, str, int]] = [
                (host, str(exporter["name"]), int(exporter["port"])) for host in hosts for exporter in exporters
            ]
        else:
            collect_targets = []
            for host in hosts:
                for hit in found_by_host.get(host, []):
                    exporter_name = str(hit.get("exporter") or "")
                    if exporter_name not in enabled_exporters:
                        continue
                    try:
                        port = int(hit.get("port"))
                    except (TypeError, ValueError):
                        continue
                    collect_targets.append((host, exporter_name, port))

        # Keep unique host/exporter/port targets while preserving first appearance.
        unique_targets: list[tuple[str, str, int]] = []
        seen_targets: set[tuple[str, str, int]] = set()
        for item in collect_targets:
            if item in seen_targets:
                continue
            seen_targets.add(item)
            unique_targets.append(item)
        collect_targets = unique_targets

        collect_targets.sort(
            key=lambda item: (
                host_rank.get(str(item[0]), 10**9),
                str(item[0]),
                int(item[2]),
                str(item[1]),
            )
        )

        max_workers = max(1, workers)
        max_inflight = max(max_workers * 4, max_workers)
        preflight_enabled = (
            len(collect_targets) <= _COLLECT_PPROF_PREFLIGHT_MAX_TARGETS and "/debug/pprof/" in endpoints
        )

        target_plans: dict[tuple[str, str, int], tuple[tuple[str, ...], dict[str, tuple[dict[str, Any], bool]]]] = {}
        if preflight_enabled:
            with ThreadPoolExecutor(max_workers=max_workers) as planner:
                plan_futures = {
                    planner.submit(
                        _plan_collect_endpoints_for_target,
                        host,
                        exporter_name,
                        port,
                        endpoints,
                        timeout,
                        retries,
                    ): (host, exporter_name, port)
                    for host, exporter_name, port in collect_targets
                }
                for future in as_completed(plan_futures):
                    target = plan_futures[future]
                    target_plans[target] = future.result()
        else:
            for host, exporter_name, port in collect_targets:
                target_plans[(host, exporter_name, port)] = (endpoints, {})

        jobs: list[tuple[str, str, int, str, tuple[dict[str, Any], bool] | None]] = []
        for host, exporter_name, port in collect_targets:
            planned_endpoints, prefetched = target_plans.get((host, exporter_name, port), (endpoints, {}))
            for endpoint in planned_endpoints:
                jobs.append((host, exporter_name, port, endpoint, prefetched.get(endpoint)))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            job_index = 0
            pending: dict[Future[tuple[dict[str, Any], bool]], int] = {}
            completed: dict[int, tuple[dict[str, Any], bool]] = {}
            next_emit_index = 0

            def _submit_next() -> bool:
                nonlocal job_index
                if job_index >= len(jobs):
                    return False
                host, exporter_name, port, endpoint, prefetched_result = jobs[job_index]
                current_index = job_index
                job_index += 1
                if prefetched_result is not None:
                    completed[current_index] = prefetched_result
                    return True
                future = executor.submit(_collect_task, host, exporter_name, port, endpoint, timeout, retries)
                pending[future] = current_index
                return True

            def _process_record(
                record: dict[str, Any],
                ok: bool,
                *,
                pause_before_emit: Callable[[], None] | None = None,
            ) -> None:
                nonlocal total, success
                response_file, response_size = (None, 0)
                total += 1
                if ok:
                    success += 1
                if save_responses_dir:
                    response_file, response_size = _save_collect_body(save_responses_dir, record)
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
                        index_fh.write(json.dumps(index_payload, ensure_ascii=False) + "\n")
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
                if record_callback is not None:
                    record_callback(record)
                if pause_before_emit is not None and emit_line is not None:
                    pause_before_emit()
                _emit_line(out_fh, emit_line, _format_collect_record(record, output_format))

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

            while len(pending) < max_inflight and _submit_next():
                pass

            collect_progress = ProgressBar("COLLECT", len(jobs))
            try:
                while pending or next_emit_index < len(jobs):
                    if pending:
                        done, _ = wait(tuple(pending), return_when=FIRST_COMPLETED)
                        for future in done:
                            emit_index = pending.pop(future)
                            completed[emit_index] = future.result()

                    while len(pending) < max_inflight and _submit_next():
                        pass

                    while next_emit_index in completed:
                        record, ok = completed.pop(next_emit_index)
                        _process_record(record, ok, pause_before_emit=collect_progress.pause_for_output)
                        collect_progress.advance()
                        next_emit_index += 1
            finally:
                collect_progress.close()

        if emit_summary:
            summary = {
                "timestamp": utc_now_iso(),
                "type": "summary",
                "hosts": len(hosts),
                "requests": total,
                "success": success,
                "output_path": output_path,
            }
            _emit_line(out_fh, emit_line, _format_collect_record(summary, output_format))
    finally:
        if out_fh is not None:
            out_fh.close()
        if index_fh is not None:
            index_fh.close()

    return total, success
