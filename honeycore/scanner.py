"""Scan/trigger and collect flows for exporter interactions."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from .constants import COLLECT_DEBUG_ENDPOINTS, COLLECT_EXPORTERS, DISCOVERY_EXPORTERS, SCAN_EXPORTERS
from .logger import AttemptLogger
from .utils import utc_now_iso


def _clip(value: Any, width: int) -> str:
    text = str(value if value is not None else "-").replace("\n", "\\n")
    if width <= 3 or len(text) <= width:
        return text[:width]
    return text[: width - 3] + "..."


def _status_value(value: Any) -> str:
    if value is None:
        return "-"
    return str(value)


def _retry_delay(attempt_index: int) -> float:
    # 0.20, 0.40, 0.80, ... capped to 1.50 seconds.
    return min(1.50, 0.20 * (2**attempt_index))


def http_get_text(url: str, timeout: float, retries: int = 1) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "RedPosture/1.0"})
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status = int(response.status)
                body = response.read(256 * 1024).decode("utf-8", errors="replace")
                return status, body
        except urllib.error.HTTPError as exc:
            body = exc.read(256 * 1024).decode("utf-8", errors="replace")
            return exc.code, body
        except (urllib.error.URLError, OSError, TimeoutError):
            if attempt >= attempts - 1:
                raise
            time.sleep(_retry_delay(attempt))
    raise RuntimeError("unreachable")


def http_get_details(url: str, timeout: float, max_bytes: int, retries: int = 1) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "RedPosture/1.0"})
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                raw = response.read(max_bytes + 1)
                elapsed_ms = int((time.monotonic() - started) * 1000)
                truncated = len(raw) > max_bytes
                body = raw[:max_bytes].decode("utf-8", errors="replace")
                return {
                    "status": int(response.status),
                    "body": body,
                    "content_type": response.headers.get("Content-Type"),
                    "elapsed_ms": elapsed_ms,
                    "truncated": truncated,
                    "error": None,
                }
        except urllib.error.HTTPError as exc:
            raw = exc.read(max_bytes + 1)
            elapsed_ms = int((time.monotonic() - started) * 1000)
            truncated = len(raw) > max_bytes
            body = raw[:max_bytes].decode("utf-8", errors="replace")
            return {
                "status": int(exc.code),
                "body": body,
                "content_type": exc.headers.get("Content-Type") if exc.headers else None,
                "elapsed_ms": elapsed_ms,
                "truncated": truncated,
                "error": None,
            }
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            if attempt < attempts - 1:
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
            f"[SUMMARY] hosts={record.get('hosts')} checks={record.get('checks')} "
            f"found={record.get('found')}{output_suffix}"
        )

    status_value = _status_value(record.get("status"))
    error = _clip(record.get("error") or "-", 44)
    marker = _clip(record.get("marker_hit") or "-", 36)
    host = _clip(record.get("host") or "-", 21)
    port = _status_value(record.get("port"))
    endpoint = f"{host}:{port}"
    exporter = _clip(record.get("exporter") or "-", 24)
    method = _clip(record.get("method") or "-", 8)
    elapsed_ms = _status_value(record.get("elapsed_ms"))
    state = "[HIT ]" if bool(record.get("detected")) else "[MISS]"
    return (
        f"{state} {endpoint:<28} {exporter:<24} "
        f"st={status_value:<4} via={method:<8} t={elapsed_ms:>4}ms "
        f"marker={marker} err={error}"
    )


def _format_collect_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(record, ensure_ascii=False)

    if record.get("type") == "summary":
        output_path = record.get("output_path")
        output_suffix = f" output={output_path}" if output_path else ""
        return (
            f"[SUMMARY] hosts={record.get('hosts')} requests={record.get('requests')} "
            f"success={record.get('success')}{output_suffix}"
        )

    status_value = _status_value(record.get("status"))
    error = _clip(record.get("error") or "-", 44)
    host = _clip(record.get("host") or "-", 21)
    port = _status_value(record.get("port"))
    endpoint = f"{host}:{port}"
    exporter = _clip(record.get("exporter") or "-", 24)
    debug_endpoint = _clip(record.get("endpoint") or "-", 26)
    elapsed_ms = _status_value(record.get("elapsed_ms"))
    state = "[OK  ]" if bool(record.get("ok")) else "[FAIL]"
    return (
        f"{state} {endpoint:<28} {exporter:<24} "
        f"ep={debug_endpoint:<26} st={status_value:<4} t={elapsed_ms:>4}ms err={error}"
    )


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
    max_bytes: int,
    retries: int,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    exporter_name = str(exporter["name"])
    port = int(exporter["port"])
    url = f"http://{host}:{port}/metrics"
    result = http_get_details(url, timeout=timeout, max_bytes=max_bytes, retries=retries)

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


def _collect_task(
    host: str,
    exporter: dict[str, Any],
    endpoint: str,
    timeout: float,
    max_bytes: int,
    retries: int,
) -> tuple[dict[str, Any], bool]:
    exporter_name = str(exporter["name"])
    port = int(exporter["port"])
    url = f"http://{host}:{port}{endpoint}"
    result = http_get_details(url, timeout=timeout, max_bytes=max_bytes, retries=retries)
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


def _trigger_task(
    logger: AttemptLogger | None,
    host: str,
    exporter: dict[str, Any],
    callback_targets: list[str],
    timeout: float,
    retries: int,
    log_success_only: bool = False,
) -> dict[str, Any]:
    exporter_name = str(exporter["name"])
    port = int(exporter["port"])
    detect_url = f"http://{host}:{port}{exporter['detect_path']}"

    result: dict[str, Any] = {
        "host": host,
        "exporter": exporter_name,
        "port": port,
        "detected": False,
        "attempted": 0,
        "success": 0,
        "by_callback": {target: {"attempted": 0, "success": 0, "fail": 0} for target in callback_targets},
    }

    try:
        status, body = http_get_text(detect_url, timeout, retries=retries)
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        if logger is not None and not log_success_only:
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
    if logger is not None and not log_success_only:
        logger.log(
            "scanner",
            (host, port),
            exporter=exporter_name,
            phase="detected",
            status=status,
            detect_url=detect_url,
        )

    for callback_target in callback_targets:
        target = str(exporter["target_fmt"]).format(our_host=callback_target)
        target_q = urllib.parse.quote(target, safe=":/")
        trigger_url = f"http://{host}:{port}{exporter['trigger_path']}?target={target_q}"

        result["attempted"] += 1
        result["by_callback"][callback_target]["attempted"] += 1
        try:
            trigger_status, _ = http_get_text(trigger_url, timeout, retries=retries)
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
                )
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            result["by_callback"][callback_target]["fail"] += 1
            if logger is not None and not log_success_only:
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
    log_success_only: bool = False,
) -> dict[str, Any]:
    exporters = list(trigger_exporters or SCAN_EXPORTERS)
    callback_list = list(dict.fromkeys(callback_targets))

    total_detected = 0
    total_attempted = 0
    total_success = 0

    host_detected: dict[str, bool] = {host: False for host in hosts}
    by_host: dict[str, dict[str, int]] = {
        host: {"detected": 0, "attempted": 0, "success": 0, "fail": 0}
        for host in hosts
    }
    by_callback: dict[str, dict[str, int]] = {
        target: {"attempted": 0, "success": 0, "fail": 0}
        for target in callback_list
    }

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        future_map = {
            executor.submit(
                _trigger_task,
                logger,
                host,
                exporter,
                callback_list,
                timeout,
                retries,
                log_success_only,
            ): (host, exporter)
            for host in hosts
            for exporter in exporters
        }
        for future in as_completed(future_map):
            result = future.result()
            host = str(result["host"])

            if result["detected"]:
                total_detected += 1
                host_detected[host] = True
                by_host[host]["detected"] += 1

            attempted = int(result["attempted"])
            success = int(result["success"])
            fail = attempted - success

            total_attempted += attempted
            total_success += success

            by_host[host]["attempted"] += attempted
            by_host[host]["success"] += success
            by_host[host]["fail"] += fail

            callback_data = result["by_callback"]
            if isinstance(callback_data, dict):
                for target, stats in callback_data.items():
                    if target not in by_callback or not isinstance(stats, dict):
                        continue
                    by_callback[target]["attempted"] += int(stats.get("attempted", 0))
                    by_callback[target]["success"] += int(stats.get("success", 0))
                    by_callback[target]["fail"] += int(stats.get("fail", 0))

    if logger is not None and not log_success_only:
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
    }


def scan_exporter_presence(
    hosts: list[str],
    timeout: float,
    output_path: str | None,
    output_format: str = "json",
    max_bytes: int = 32 * 1024,
    logger: AttemptLogger | None = None,
    emit_line: Callable[[str], None] | None = None,
    workers: int = 10,
    retries: int = 3,
    discovery_exporters: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
) -> tuple[int, int, dict[str, list[dict[str, Any]]]]:
    exporters = list(discovery_exporters or DISCOVERY_EXPORTERS)
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
                executor.submit(_scan_presence_task, host, exporter, timeout, max_bytes, retries): (host, exporter)
                for host in hosts
                for exporter in exporters
            }

            for future in as_completed(future_map):
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
    max_bytes: int = 64 * 1024,
    emit_line: Callable[[str], None] | None = None,
    workers: int = 10,
    retries: int = 3,
    collect_exporters: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
    collect_debug_endpoints: list[str] | tuple[str, ...] | None = None,
) -> tuple[int, int]:
    exporters = list(collect_exporters or COLLECT_EXPORTERS)
    endpoints = tuple(collect_debug_endpoints or COLLECT_DEBUG_ENDPOINTS)
    total = 0
    success = 0

    out_fh: Any = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, "w", encoding="utf-8")

    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            future_map = {
                executor.submit(_collect_task, host, exporter, endpoint, timeout, max_bytes, retries): (host, exporter, endpoint)
                for host in hosts
                for exporter in exporters
                for endpoint in endpoints
            }

            for future in as_completed(future_map):
                record, ok = future.result()
                total += 1
                if ok:
                    success += 1

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

    return total, success
