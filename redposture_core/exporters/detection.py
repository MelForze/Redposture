"""Exporter discovery detection helpers."""

from __future__ import annotations

import re
from typing import Any

from ..utils import utc_now_iso
from .http_client import build_http_url

PROMETHEUS_METRIC_LINE_RE = re.compile(
    r"(?m)^[a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^{}\n]*\})?\s+"
    r"(?:[+-]?(?:Inf|NaN|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?))\s*$"
)


def looks_like_prometheus_metrics(body: str) -> bool:
    if not body:
        return False
    if "# HELP " in body or "# TYPE " in body:
        return True
    return PROMETHEUS_METRIC_LINE_RE.search(body) is not None


def build_scan_error_record(host: str, port: int, error: BaseException) -> dict[str, Any]:
    return {
        "timestamp": utc_now_iso(),
        "host": host,
        "exporter": "unknown",
        "port": port,
        "url": build_http_url(host, port, "/metrics"),
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


__all__ = [
    "PROMETHEUS_METRIC_LINE_RE",
    "build_scan_error_record",
    "looks_like_prometheus_metrics",
]
