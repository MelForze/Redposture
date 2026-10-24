"""Native first metrics request; exporter scoring stays in the existing scanner."""

from __future__ import annotations

import asyncio
import http.client
import ssl
import time
from typing import Any

from ..clients.async_http_detect import AsyncDetectionHttp
from . import discover
from .http_client import HTTPResponseDetails, build_http_url, http_get_details, retry_delay, should_retry_http_exception


async def prefetch_metrics(
    host: str,
    port: int,
    scheme: str,
    timeout: float,
    retries: int,
    tls_context: ssl.SSLContext | None = None,
    *,
    path: str = "/metrics",
) -> dict[str, Any]:
    url = build_http_url(host, port, path, scheme=scheme)
    # Match exporters' existing retry policy and constant per-attempt timeout;
    # this differs intentionally from the audit HTTP pool's escalating timeout.
    async with AsyncDetectionHttp(
        timeout=timeout,
        retries=0,
        max_bytes=discover.SCAN_RESPONSE_BODY_MAX_BYTES,
        ssl_context=tls_context,
        decode_content=False,
        escalate_timeouts=False,
    ) as client:
        for attempt in range(max(1, retries + 1)):
            started = time.monotonic()
            response = await client.get(url, headers={"User-Agent": "RedPosture/1.0"})
            elapsed = int((time.monotonic() - started) * 1000)
            error = client.last_exception
            retry = error is not None and (
                should_retry_http_exception(error) or isinstance(error, http.client.HTTPException)
            )
            if retry and attempt < retries:
                await asyncio.sleep(retry_delay(attempt))
                continue
            return HTTPResponseDetails(
                {
                    "status": response.status or None,
                    "body": response.body.decode("utf-8", errors="replace"),
                    "elapsed_ms": elapsed,
                    "content_type": next((v for k, v in response.headers.items() if k.lower() == "content-type"), ""),
                    "error": response.error,
                    "truncated": response.truncated,
                },
                raw_body=response.body,
            )
    raise AssertionError("unreachable")


def scan_with_prefetched_metrics(
    host: str,
    port: int,
    exporters: list[dict[str, Any]],
    timeout: float,
    retries: int,
    scheme: str,
    details: dict[str, Any],
) -> Any:
    metrics_url = build_http_url(host, port, "/metrics", scheme=scheme)
    consumed = False

    def get(url: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal consumed
        if not consumed and url == metrics_url:
            consumed = True
            return details
        return http_get_details(url, *args, **kwargs)

    return discover.scan_presence_port_task(
        host, port, exporters, timeout, retries, scheme=scheme, http_get_details_fn=get
    )
