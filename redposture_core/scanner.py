"""Scan/trigger and collect flows for exporter interactions."""

from __future__ import annotations

import errno
import http.client
import json
import os
import queue
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, as_completed, wait
from contextlib import contextmanager
from typing import Any
from urllib.parse import urlparse

from .constants import COLLECT_DEBUG_ENDPOINTS, COLLECT_EXPORTERS, DISCOVERY_EXPORTERS, SCAN_EXPORTERS
from .logger import AttemptLogger
from .progress import ProgressBar, iter_completed_with_progress
from .utils import utc_now_iso

_EXPORTER_DISPLAY_NAMES = {
    "nats_exporter": "NATS Exporter",
    "statsd_exporter": "StatsD Exporter",
    "mysqld_exporter": "MySQLd Exporter",
    "blackbox_exporter": "Blackbox Exporter",
    "elasticsearch_exporter": "Elasticsearch Exporter",
    "nginx_exporter": "Nginx Exporter",
    "haproxy_exporter": "HAProxy Exporter",
    "kafka_exporter": "Kafka Exporter",
    "node_exporter": "Node Exporter",
    "memcached_exporter": "Memcached Exporter",
    "postgres_exporter": "Postgres Exporter",
    "redis_exporter": "Redis Exporter",
    "clickhouse_exporter": "ClickHouse Exporter",
    "snmp_exporter": "SNMP Exporter",
    "apache_exporter": "Apache Exporter",
    "bind_exporter": "BIND Exporter",
    "mongodb_exporter": "MongoDB Exporter",
    "pgbouncer_exporter": "PgBouncer Exporter",
    "ceph_exporter": "Ceph Exporter",
    "varnish_exporter": "Varnish Exporter",
    "windows_exporter": "Windows Exporter",
    "ipmi_exporter": "IPMI Exporter",
    "gobgp_exporter": "GoBGP Exporter",
    "frr_exporter": "FRR Exporter",
    "named_process_exporter": "Named Process Exporter",
    "sql_exporter": "SQL Exporter",
    "ping_exporter": "Ping Exporter",
    "rabbitmq_exporter": "RabbitMQ Exporter",
    "proxmox_exporter": "Proxmox Exporter",
}

_COLLECT_PPROF_PREFLIGHT_MAX_TARGETS = 1000
_HTTP_POOL_MAX_IDLE_TOTAL = 512
_HTTP_POOL_MAX_IDLE_PER_HOST = 4
_SCAN_MAX_INFLIGHT_FACTOR = 8
_SCAN_RESPONSE_BODY_MAX_BYTES = 256 * 1024
_SCAN_FINGERPRINT_BODY_MAX_BYTES = 128 * 1024
_WEAK_CANDIDATE_CONFIDENCE_SCORE = 50
_PROMETHEUS_METRIC_LINE_RE = re.compile(
    r"(?m)^[a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^{}\n]*\})?\s+"
    r"(?:[+-]?(?:Inf|NaN|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?))\s*$"
)


class _HTTPConnectionPool:
    def __init__(
        self,
        *,
        max_idle_total: int = _HTTP_POOL_MAX_IDLE_TOTAL,
        max_idle_per_host: int = _HTTP_POOL_MAX_IDLE_PER_HOST,
    ) -> None:
        self._max_idle_total = max(1, int(max_idle_total))
        self._max_idle_per_host = max(1, int(max_idle_per_host))
        self._idle: dict[tuple[str, int], list[http.client.HTTPConnection]] = {}
        self._idle_total = 0
        self._lock = threading.Lock()

    @staticmethod
    def _target_from_url(url: str) -> tuple[str, int, str]:
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme and scheme != "http":
            raise ValueError(f"unsupported URL scheme for pooled request: {scheme}")
        host = parsed.hostname
        if not host:
            raise ValueError("invalid URL host")
        port = int(parsed.port or 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return host, port, path

    def _acquire(self, host: str, port: int, timeout: float) -> http.client.HTTPConnection:
        key = (host, port)
        with self._lock:
            bucket = self._idle.get(key)
            if bucket:
                conn = bucket.pop()
                self._idle_total = max(0, self._idle_total - 1)
                if not bucket:
                    self._idle.pop(key, None)
                conn.timeout = timeout
                return conn
        return http.client.HTTPConnection(host, port, timeout=timeout)

    def _evict_one(self) -> None:
        for key in list(self._idle):
            bucket = self._idle.get(key)
            if not bucket:
                continue
            victim = bucket.pop(0)
            self._idle_total = max(0, self._idle_total - 1)
            if not bucket:
                self._idle.pop(key, None)
            try:
                victim.close()
            except OSError:
                pass
            return

    def _release(self, host: str, port: int, conn: http.client.HTTPConnection, reusable: bool) -> None:
        if not reusable:
            try:
                conn.close()
            except OSError:
                pass
            return

        key = (host, port)
        with self._lock:
            bucket = self._idle.setdefault(key, [])
            if len(bucket) >= self._max_idle_per_host:
                try:
                    conn.close()
                except OSError:
                    pass
                return
            while self._idle_total >= self._max_idle_total:
                self._evict_one()
                if self._idle_total < self._max_idle_total:
                    break
            if self._idle_total >= self._max_idle_total:
                try:
                    conn.close()
                except OSError:
                    pass
                return
            bucket.append(conn)
            self._idle_total += 1

    def get(
        self,
        url: str,
        timeout: float,
        *,
        max_bytes: int | None = None,
    ) -> tuple[int | None, bytes, str | None, BaseException | None, bool]:
        host, port, path = self._target_from_url(url)
        conn = self._acquire(host, port, timeout)
        reusable = False
        try:
            conn.request(
                "GET",
                path,
                headers={
                    "User-Agent": "RedPosture/1.0",
                    "Connection": "keep-alive",
                },
            )
            response = conn.getresponse()
            truncated = False
            if max_bytes is None:
                raw = response.read()
            else:
                raw = response.read(max_bytes + 1)
                truncated = len(raw) > max_bytes
                if truncated:
                    raw = raw[:max_bytes]
            reusable = not response.will_close
            return int(response.status), raw, response.getheader("Content-Type"), None, truncated
        except Exception as exc:
            return None, b"", None, exc, False
        finally:
            self._release(host, port, conn, reusable)

    def close(self) -> None:
        with self._lock:
            buckets = list(self._idle.values())
            self._idle.clear()
            self._idle_total = 0
        for bucket in buckets:
            for conn in bucket:
                try:
                    conn.close()
                except OSError:
                    pass


_ACTIVE_HTTP_POOL: _HTTPConnectionPool | None = None
_ACTIVE_HTTP_POOL_LOCK = threading.Lock()


@contextmanager
def _activate_http_pool(pool: _HTTPConnectionPool | None):
    global _ACTIVE_HTTP_POOL
    if pool is None:
        yield
        return

    with _ACTIVE_HTTP_POOL_LOCK:
        previous = _ACTIVE_HTTP_POOL
        _ACTIVE_HTTP_POOL = pool
    try:
        yield
    finally:
        with _ACTIVE_HTTP_POOL_LOCK:
            _ACTIVE_HTTP_POOL = previous
        pool.close()


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


def _looks_like_prometheus_metrics(body: str) -> bool:
    if not body:
        return False
    if "# HELP " in body or "# TYPE " in body:
        return True
    return _PROMETHEUS_METRIC_LINE_RE.search(body) is not None


def _unwrap_network_error(exc: BaseException) -> BaseException:
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, BaseException):
            return reason
    return exc


def _pool_get_compat(
    pool: Any,
    url: str,
    timeout: float,
    *,
    max_bytes: int | None = None,
) -> tuple[int | None, bytes, str | None, BaseException | None, bool]:
    try:
        result = pool.get(url, timeout, max_bytes=max_bytes)
    except TypeError:
        result = pool.get(url, timeout)

    if isinstance(result, tuple) and len(result) == 4:
        status, raw, content_type, error = result
        return status, raw, content_type, error, False
    if isinstance(result, tuple) and len(result) == 5:
        status, raw, content_type, error, truncated = result
        return status, raw, content_type, error, bool(truncated)
    raise ValueError("invalid pooled HTTP response tuple")


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
    pool = _ACTIVE_HTTP_POOL
    if pool is not None:
        attempts = max(1, retries + 1)
        for attempt in range(attempts):
            status, raw, _content_type, error, _truncated = _pool_get_compat(pool, url, timeout)
            if error is None:
                body = raw.decode("utf-8", errors="replace")
                return int(status or 0), body
            should_retry = _should_retry_http_exception(error) or isinstance(
                _unwrap_network_error(error), http.client.HTTPException
            )
            if attempt >= attempts - 1 or not should_retry:
                raise error
            time.sleep(_retry_delay(attempt))
        raise RuntimeError("unreachable")

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


def http_get_details(url: str, timeout: float, retries: int = 1, *, max_bytes: int | None = None) -> dict[str, Any]:
    pool = _ACTIVE_HTTP_POOL
    if pool is not None:
        attempts = max(1, retries + 1)
        for attempt in range(attempts):
            started = time.monotonic()
            status, raw, content_type, error, truncated = _pool_get_compat(
                pool,
                url,
                timeout,
                max_bytes=max_bytes,
            )
            elapsed_ms = int((time.monotonic() - started) * 1000)
            if error is None:
                body = raw.decode("utf-8", errors="replace")
                return {
                    "status": status,
                    "body": body,
                    "content_type": content_type,
                    "elapsed_ms": elapsed_ms,
                    "truncated": truncated,
                    "error": None,
                }
            should_retry = _should_retry_http_exception(error) or isinstance(
                _unwrap_network_error(error), http.client.HTTPException
            )
            if attempt < attempts - 1 and should_retry:
                time.sleep(_retry_delay(attempt))
                continue
            return {
                "status": None,
                "body": "",
                "content_type": None,
                "elapsed_ms": elapsed_ms,
                "truncated": False,
                "error": str(error),
            }
        raise RuntimeError("unreachable")

    req = urllib.request.Request(url, headers={"User-Agent": "RedPosture/1.0"})
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                truncated = False
                if max_bytes is None:
                    raw = response.read()
                else:
                    raw = response.read(max_bytes + 1)
                    truncated = len(raw) > max_bytes
                    if truncated:
                        raw = raw[:max_bytes]
                elapsed_ms = int((time.monotonic() - started) * 1000)
                body = raw.decode("utf-8", errors="replace")
                return {
                    "status": int(response.status),
                    "body": body,
                    "content_type": response.headers.get("Content-Type"),
                    "elapsed_ms": elapsed_ms,
                    "truncated": truncated,
                    "error": None,
                }
        except urllib.error.HTTPError as exc:
            truncated = False
            if max_bytes is None:
                raw = exc.read()
            else:
                raw = exc.read(max_bytes + 1)
                truncated = len(raw) > max_bytes
                if truncated:
                    raw = raw[:max_bytes]
            elapsed_ms = int((time.monotonic() - started) * 1000)
            body = raw.decode("utf-8", errors="replace")
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
    if emit_line is not None:
        emit_line(line)


def _build_scan_error_record(host: str, port: int, error: BaseException) -> dict[str, Any]:
    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "exporter": "unknown",
        "port": port,
        "url": f"http://{host}:{port}/metrics",
        "detected": False,
        "method": "none",
        "status": None,
        "marker_hit": None,
        "elapsed_ms": 0,
        "content_type": None,
        "error": str(error),
        "truncated": False,
        "body": "",
    }


def _scan_presence_task(
    host: str,
    exporter: dict[str, Any],
    timeout: float,
    retries: int,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    exporter_name = str(exporter["name"])
    port = int(exporter["port"])
    url = f"http://{host}:{port}/metrics"
    result = http_get_details(url, timeout=timeout, retries=retries, max_bytes=_SCAN_RESPONSE_BODY_MAX_BYTES)

    status = result["status"]
    body = str(result["body"] or "")
    markers = tuple(str(item) for item in exporter["markers"])
    marker_hit = next((marker for marker in markers if marker in body), None)

    is_prometheus_like = _looks_like_prometheus_metrics(body)
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


def _as_token_tuple(raw: Any) -> tuple[str, ...]:
    if isinstance(raw, str):
        value = raw.strip()
        return (value,) if value else ()
    if not isinstance(raw, (list, tuple)):
        return ()
    result: list[str] = []
    for item in raw:
        token = str(item or "").strip()
        if not token or token in result:
            continue
        result.append(token)
    return tuple(result)


def _score_metrics_candidate(exporter: dict[str, Any], body: str) -> dict[str, Any] | None:
    exporter_name = str(exporter.get("name") or "").strip()
    if not exporter_name:
        return None

    strong_markers = _as_token_tuple(exporter.get("strong_markers")) or _as_token_tuple(exporter.get("markers"))
    weak_markers = tuple(
        marker for marker in _as_token_tuple(exporter.get("weak_markers")) if marker not in strong_markers
    )
    negative_markers = _as_token_tuple(exporter.get("negative_markers"))

    strong_hits = [marker for marker in strong_markers if marker in body]
    weak_hits = [marker for marker in weak_markers if marker in body]
    negative_hits = [marker for marker in negative_markers if marker in body]

    score = (len(strong_hits) * 100) + (len(weak_hits) * 25) - (len(negative_hits) * 80)
    if score <= 0:
        return None

    marker_hit = strong_hits[0] if strong_hits else (weak_hits[0] if weak_hits else None)
    return {
        "name": exporter_name,
        "score": score,
        "strong_count": len(strong_hits),
        "weak_count": len(weak_hits),
        "negative_count": len(negative_hits),
        "marker_hit": marker_hit,
    }


def _needs_fingerprint_tiebreak(candidates: list[dict[str, Any]]) -> bool:
    if not candidates:
        return False

    top = candidates[0]
    top_score = int(top.get("score") or 0)
    top_strong = int(top.get("strong_count") or 0)

    if top_strong <= 0:
        if len(candidates) <= 1:
            return top_score < _WEAK_CANDIDATE_CONFIDENCE_SCORE
        return True
    if len(candidates) <= 1:
        return False

    second = candidates[1]
    second_score = int(second.get("score") or 0)
    second_strong = int(second.get("strong_count") or 0)
    if top_strong > second_strong and top_score > second_score:
        return False
    if top_score == second_score:
        return True
    if (top_score - second_score) < 35:
        return True
    return False


def _select_fingerprint_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not candidates:
        return []
    top_score = int(candidates[0].get("score") or 0)
    return [item for item in candidates if (top_score - int(item.get("score") or 0)) < 35]


def _fetch_fingerprint_bodies(host: str, port: int, timeout: float, retries: int) -> tuple[str, str]:
    vars_result = http_get_details(
        f"http://{host}:{port}/debug/vars",
        timeout=timeout,
        retries=retries,
        max_bytes=_SCAN_FINGERPRINT_BODY_MAX_BYTES,
    )
    cmdline_result = http_get_details(
        f"http://{host}:{port}/debug/pprof/cmdline?debug=1",
        timeout=timeout,
        retries=retries,
        max_bytes=_SCAN_FINGERPRINT_BODY_MAX_BYTES,
    )
    vars_body = str(vars_result.get("body") or "") if (vars_result.get("status") or 0) < 400 else ""
    cmdline_body = str(cmdline_result.get("body") or "") if (cmdline_result.get("status") or 0) < 400 else ""
    return vars_body, cmdline_body


def _score_fingerprint_candidate(exporter: dict[str, Any], vars_body: str, cmdline_body: str) -> tuple[int, int]:
    vars_tokens = _as_token_tuple(exporter.get("fingerprint_vars"))
    cmdline_tokens = _as_token_tuple(exporter.get("fingerprint_cmdline"))

    vars_hits = sum(1 for token in vars_tokens if token in vars_body)
    cmdline_hits = sum(1 for token in cmdline_tokens if token in cmdline_body)
    score = (vars_hits * 20) + (cmdline_hits * 25)
    return score, vars_hits + cmdline_hits


def _resolve_best_exporter_candidate(
    *,
    host: str,
    port: int,
    candidates: list[dict[str, Any]],
    exporters_by_name: dict[str, dict[str, Any]],
    timeout: float,
    retries: int,
) -> tuple[dict[str, Any] | None, str, str]:
    if not candidates:
        return None, "none", "no_markers"

    if not _needs_fingerprint_tiebreak(candidates):
        return candidates[0], "marker", "marker_unique"

    shortlist = _select_fingerprint_candidates(candidates)
    if not shortlist:
        return None, "ambiguous", "ambiguous_empty_shortlist"

    vars_body, cmdline_body = _fetch_fingerprint_bodies(host, port, timeout, retries)

    ranked: list[tuple[int, int, int, dict[str, Any]]] = []
    for candidate in shortlist:
        exporter_name = str(candidate.get("name") or "")
        exporter = exporters_by_name.get(exporter_name)
        if exporter is None:
            continue
        fp_score, fp_hits = _score_fingerprint_candidate(exporter, vars_body, cmdline_body)
        ranked.append((fp_score, fp_hits, int(candidate.get("score") or 0), candidate))

    if not ranked:
        return None, "ambiguous", "ambiguous_no_ranked_candidates"

    ranked.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    top_fp, _top_hits, _top_metric, top_candidate = ranked[0]
    second_fp = ranked[1][0] if len(ranked) > 1 else -1
    runner_up = candidates[1] if len(candidates) > 1 else None
    top_metric_score = int(top_candidate.get("score") or 0)
    top_metric_strong = int(top_candidate.get("strong_count") or 0)
    second_metric_score = int(runner_up.get("score") or 0) if runner_up is not None else -1
    second_metric_strong = int(runner_up.get("strong_count") or 0) if runner_up is not None else -1

    if top_fp <= 0:
        if top_metric_strong > second_metric_strong and top_metric_score > second_metric_score:
            return top_candidate, "marker", "marker_fallback_no_fingerprint"
        # Precision-first: unresolved conflict stays unknown.
        return None, "ambiguous", "ambiguous_no_fingerprint_hits"
    if top_fp == second_fp:
        if top_metric_strong > second_metric_strong and top_metric_score > second_metric_score:
            return top_candidate, "marker", "marker_fallback_fp_tie"
        return None, "ambiguous", "ambiguous_fingerprint_tie"

    return top_candidate, "fingerprint", "fingerprint_unique"


def _resolve_fingerprint_only_candidate(
    *,
    host: str,
    port: int,
    exporters: list[dict[str, Any]],
    timeout: float,
    retries: int,
) -> tuple[dict[str, Any] | None, str, str]:
    if not exporters:
        return None, "none", "no_exporters"

    vars_body, cmdline_body = _fetch_fingerprint_bodies(host, port, timeout, retries)
    ranked: list[tuple[int, int, str]] = []
    for exporter in exporters:
        exporter_name = str(exporter.get("name") or "").strip()
        if not exporter_name:
            continue
        fp_score, fp_hits = _score_fingerprint_candidate(exporter, vars_body, cmdline_body)
        if fp_score <= 0:
            continue
        ranked.append((fp_score, fp_hits, exporter_name))

    if not ranked:
        return None, "none", "no_fingerprint_hits"

    ranked.sort(reverse=True)
    top_score, top_hits, top_name = ranked[0]
    second = ranked[1] if len(ranked) > 1 else None
    if second is not None and (top_score, top_hits) == second[:2]:
        return None, "ambiguous", "ambiguous_fingerprint_only_tie"

    return (
        {
            "name": top_name,
            "score": 0,
            "strong_count": 0,
            "weak_count": 0,
            "negative_count": 0,
            "marker_hit": None,
        },
        "fingerprint",
        "fingerprint_only",
    )


def _resolve_prometheus_port_fallback(exporters: list[dict[str, Any]]) -> dict[str, Any] | None:
    unique_names: list[str] = []
    for exporter in exporters:
        exporter_name = str(exporter.get("name") or "").strip()
        if not exporter_name or exporter_name in unique_names:
            continue
        unique_names.append(exporter_name)
    if len(unique_names) != 1:
        return None
    return {
        "name": unique_names[0],
        "score": 0,
        "strong_count": 0,
        "weak_count": 0,
        "negative_count": 0,
        "marker_hit": None,
    }


def _scan_presence_port_task(
    host: str,
    port: int,
    exporters: list[dict[str, Any]],
    timeout: float,
    retries: int,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    url = f"http://{host}:{port}/metrics"
    result = http_get_details(url, timeout=timeout, retries=retries, max_bytes=_SCAN_RESPONSE_BODY_MAX_BYTES)

    status = result["status"]
    body = str(result["body"] or "")
    is_http_ok = status is not None and int(status) < 400
    is_prometheus_like = _looks_like_prometheus_metrics(body)
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
        candidate = _score_metrics_candidate(exporter, body)
        if candidate is None:
            continue
        candidates.append(candidate)

    candidates.sort(
        key=lambda item: (
            int(item.get("score") or 0),
            int(item.get("strong_count") or 0),
            int(item.get("weak_count") or 0),
        ),
        reverse=True,
    )
    if candidates:
        winner, method, resolution = _resolve_best_exporter_candidate(
            host=host,
            port=port,
            candidates=candidates,
            exporters_by_name=exporters_by_name,
            timeout=timeout,
            retries=retries,
        )
    elif is_prometheus_like:
        winner, method, resolution = _resolve_fingerprint_only_candidate(
            host=host,
            port=port,
            exporters=exporters,
            timeout=timeout,
            retries=retries,
        )
        if winner is None:
            winner = _resolve_prometheus_port_fallback(exporters)
            if winner is not None:
                method = "metrics"
                resolution = "prometheus_unique_port_fallback"
    else:
        winner, method, resolution = None, "none", "no_markers"

    detected = winner is not None
    exporter_name = str((winner or {}).get("name") or "unknown")
    if detected:
        marker_hit = str(winner.get("marker_hit") or "")
    elif candidates:
        marker_hit = str(candidates[0].get("marker_hit") or "")
    else:
        marker_hit = None

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
    adaptive_collect: bool = True,
    completed_endpoints: set[str] | None = None,
) -> tuple[tuple[str, ...], dict[str, tuple[dict[str, Any], bool]]]:
    def _is_hard_failure(result: tuple[dict[str, Any], bool]) -> bool:
        record, ok = result
        if ok:
            return False
        status = record.get("status")
        if status is None:
            return True
        try:
            return int(status) >= 400
        except (TypeError, ValueError):
            return True

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
        prefetched[endpoint] = _collect_task(
            host,
            exporter_name,
            port,
            endpoint,
            timeout,
            retries,
        )

    planned = list(endpoints)

    pprof_probe = prefetched.get("/debug/pprof/")
    if pprof_probe is not None and _is_hard_failure(pprof_probe):
        planned = [endpoint for endpoint in planned if endpoint == "/debug/pprof/" or not _is_pprof_endpoint(endpoint)]

    if adaptive_collect:
        metrics_probe = prefetched.get("/metrics")
        vars_probe = prefetched.get("/debug/vars")
        pprof_hard = pprof_probe is not None and _is_hard_failure(pprof_probe)
        metrics_hard = metrics_probe is not None and _is_hard_failure(metrics_probe)
        vars_hard = vars_probe is not None and _is_hard_failure(vars_probe)
        if metrics_hard and vars_hard and (pprof_probe is None or pprof_hard):
            planned = [endpoint for endpoint in planned if endpoint in prefetched]

    return tuple(planned), prefetched


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
    work_items = [(host, port) for host in hosts for port in ports]
    max_workers = max(1, workers)
    max_inflight = max(max_workers, max_workers * _SCAN_MAX_INFLIGHT_FACTOR)

    out_fh: Any = None
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        out_fh = open(output_path, "w", encoding="utf-8")

    try:
        progress = ProgressBar("SCAN", len(work_items), enabled=show_progress, leave=progress_leave)
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                pending: dict[Future[Any], tuple[str, int]] = {}
                work_queue: deque[tuple[str, int]] = deque(work_items)

                while work_queue or pending:
                    while work_queue and len(pending) < max_inflight:
                        host, port = work_queue.popleft()
                        future = executor.submit(_scan_presence_port_task, host, port, exporters, timeout, retries)
                        pending[future] = (host, port)

                    if not pending:
                        continue

                    done, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for future in done:
                        host, port = pending.pop(future)
                        try:
                            record, hit = future.result()
                        except Exception as exc:
                            record, hit = _build_scan_error_record(host, port, exc), None

                        total_checks += 1
                        if hit is not None:
                            total_found += 1
                            found_by_host[str(record["host"])].append(hit)

                        progress.pause_for_output()
                        _emit_line(out_fh, emit_line, _format_scan_record(record, output_format))
                        progress.advance()

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
        finally:
            progress.close()

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
    adaptive_collect: bool = True,
    max_inflight_requests: int | None = None,
    resume_completed_jobs: set[tuple[str, str, int, str]] | None = None,
    checkpoint_path: str | None = None,
    checkpoint_mode: str = "a",
    stats_sink: dict[str, int] | None = None,
) -> tuple[int, int]:
    exporters = list(collect_exporters or COLLECT_EXPORTERS)
    endpoints = tuple(collect_debug_endpoints or COLLECT_DEBUG_ENDPOINTS)
    total = 0
    success = 0

    out_fh: Any = None
    index_fh: Any = None
    checkpoint_fh: Any = None
    postprocess_queue: queue.Queue[Any] | None = None
    postprocess_thread: threading.Thread | None = None
    postprocess_stop = object()
    postprocess_errors: list[BaseException] = []
    postprocess_errors_lock = threading.Lock()

    def _record_postprocess_error(exc: BaseException) -> None:
        with postprocess_errors_lock:
            if not postprocess_errors:
                postprocess_errors.append(exc)

    def _raise_postprocess_error() -> None:
        if not postprocess_errors:
            return
        err = postprocess_errors[0]
        if isinstance(err, Exception):
            raise err
        raise RuntimeError(str(err))

    def _finalize_postprocess() -> None:
        nonlocal postprocess_queue, postprocess_thread
        if postprocess_queue is None:
            return
        postprocess_queue.join()
        _raise_postprocess_error()
        postprocess_queue.put(postprocess_stop)
        postprocess_queue.join()
        if postprocess_thread is not None:
            postprocess_thread.join()
            postprocess_thread = None
        postprocess_queue = None
        _raise_postprocess_error()

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
        postprocess_queue = queue.Queue()

        def _postprocess_worker() -> None:
            while True:
                payload = postprocess_queue.get()
                try:
                    if payload is postprocess_stop:
                        return
                    callback_record, index_payload, checkpoint_payload = payload
                    if callback_record is not None and record_callback is not None:
                        record_callback(callback_record)
                    if index_payload is not None and index_fh is not None:
                        index_fh.write(json.dumps(index_payload, ensure_ascii=False) + "\n")
                    if checkpoint_payload is not None and checkpoint_fh is not None:
                        checkpoint_fh.write(json.dumps(checkpoint_payload, ensure_ascii=False) + "\n")
                        checkpoint_fh.flush()
                except Exception as exc:
                    _record_postprocess_error(exc)
                finally:
                    postprocess_queue.task_done()

        postprocess_thread = threading.Thread(
            target=_postprocess_worker,
            name="collect-postprocess",
            daemon=True,
        )
        postprocess_thread.start()

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
        if max_inflight_requests is None:
            max_inflight = max(max_workers * 16, max_workers)
        else:
            max_inflight = max(max_workers, int(max_inflight_requests))
        completed_jobs = resume_completed_jobs or set()
        completed_by_target: dict[tuple[str, str, int], set[str]] = {}
        for host, exporter_name, port, endpoint in completed_jobs:
            completed_by_target.setdefault((host, exporter_name, int(port)), set()).add(endpoint)
        skipped_jobs = 0
        preflight_enabled = (
            adaptive_collect
            and len(collect_targets) <= _COLLECT_PPROF_PREFLIGHT_MAX_TARGETS
            and any(item in endpoints for item in ("/debug/pprof/", "/debug/vars", "/metrics"))
        )

        target_plans: dict[tuple[str, str, int], tuple[tuple[str, ...], dict[str, tuple[dict[str, Any], bool]]]] = {}

        def _process_record(
            record: dict[str, Any],
            ok: bool,
            *,
            pause_before_emit: Callable[[], None] | None = None,
        ) -> None:
            nonlocal total, success
            response_file, response_size = (None, 0)
            index_payload: dict[str, Any] | None = None
            checkpoint_payload: dict[str, Any] | None = None
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
                }
            if postprocess_queue is not None:
                postprocess_queue.put(
                    (record if record_callback is not None else None, index_payload, checkpoint_payload)
                )
                _raise_postprocess_error()
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

        pool = _HTTPConnectionPool(
            max_idle_total=max(max_workers * 16, _HTTP_POOL_MAX_IDLE_TOTAL),
            max_idle_per_host=max(_HTTP_POOL_MAX_IDLE_PER_HOST, min(max_workers, 8)),
        )
        with _activate_http_pool(pool):
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
                            adaptive_collect,
                            completed_by_target.get((host, exporter_name, int(port))),
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
                    job_key = (host, exporter_name, int(port), endpoint)
                    if job_key in completed_jobs:
                        skipped_jobs += 1
                        continue
                    jobs.append((host, exporter_name, port, endpoint, prefetched.get(endpoint)))

            if stats_sink is not None:
                stats_sink["targets"] = len(collect_targets)
                stats_sink["scheduled_jobs"] = len(jobs)
                stats_sink["skipped_jobs"] = skipped_jobs

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                job_index = 0
                pending: dict[Future[tuple[dict[str, Any], bool]], None] = {}
                prefetched_ready: deque[tuple[dict[str, Any], bool]] = deque()

                def _submit_next() -> bool:
                    nonlocal job_index
                    if job_index >= len(jobs):
                        return False
                    host, exporter_name, port, endpoint, prefetched_result = jobs[job_index]
                    job_index += 1
                    if prefetched_result is not None:
                        prefetched_ready.append(prefetched_result)
                        return True
                    future = executor.submit(_collect_task, host, exporter_name, port, endpoint, timeout, retries)
                    pending[future] = None
                    return True

                while len(pending) < max_inflight and _submit_next():
                    pass

                collect_progress = ProgressBar("COLLECT", len(jobs))
                try:
                    while pending or prefetched_ready or job_index < len(jobs):
                        while prefetched_ready:
                            record, ok = prefetched_ready.popleft()
                            _process_record(record, ok, pause_before_emit=collect_progress.pause_for_output)
                            collect_progress.advance()

                        while len(pending) < max_inflight and _submit_next():
                            pass

                        if not pending:
                            continue

                        done, _ = wait(pending, return_when=FIRST_COMPLETED)
                        for future in done:
                            pending.pop(future, None)
                            record, ok = future.result()
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
                "output_path": output_path,
            }
            _emit_line(out_fh, emit_line, _format_collect_record(summary, output_format))
    finally:
        if postprocess_queue is not None:
            postprocess_queue.put(postprocess_stop)
            postprocess_queue.join()
        if postprocess_thread is not None:
            postprocess_thread.join(timeout=1.0)
        if out_fh is not None:
            out_fh.close()
        if index_fh is not None:
            index_fh.close()
        if checkpoint_fh is not None:
            checkpoint_fh.close()

    return total, success
