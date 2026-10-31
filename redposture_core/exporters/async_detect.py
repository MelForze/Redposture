"""Native first metrics request; exporter scoring stays in the existing scanner."""

from __future__ import annotations

import asyncio
import http.client
import ssl
import time
from contextvars import ContextVar
from typing import Any

from ..clients.async_http_detect import AsyncDetectionHttp
from ..detection_io import DetectCall
from . import discover
from .http_client import HTTPResponseDetails, build_http_url, http_get_details, retry_delay, should_retry_http_exception

_PREFETCH_CLIENT: ContextVar[AsyncDetectionHttp | None] = ContextVar("exporter_prefetch_client", default=None)


class PrefetchedResponse(HTTPResponseDetails):
    exception: BaseException | None = None


async def _prefetch_response(
    client: AsyncDetectionHttp, url: str, timeout: float, retries: int, max_bytes: int
) -> dict[str, Any]:
    previous_cap = client.max_bytes
    client.max_bytes = max_bytes
    try:
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
            result = PrefetchedResponse(
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
            result.exception = error
            return result
    finally:
        client.max_bytes = previous_cap
    raise AssertionError("unreachable")


async def prefetch_metrics(
    host: str,
    port: int,
    scheme: str,
    timeout: float,
    retries: int,
    tls_context: ssl.SSLContext | None = None,
    *,
    path: str = "/metrics",
    max_bytes: int = discover.SCAN_RESPONSE_BODY_MAX_BYTES,
) -> dict[str, Any]:
    url = build_http_url(host, port, path, scheme=scheme)
    active = _PREFETCH_CLIENT.get()
    if active is not None:
        return await _prefetch_response(active, url, timeout, retries, max_bytes)
    # Constant per-attempt timeout matches the exporter transport policy.
    async with AsyncDetectionHttp(
        timeout=timeout,
        retries=0,
        max_bytes=max_bytes,
        ssl_context=tls_context,
        decode_content=False,
        escalate_timeouts=False,
    ) as client:
        return await _prefetch_response(client, url, timeout, retries, max_bytes)


class DiscoveryRecord(dict[str, Any]):
    """JSON-compatible result; response snapshots stay out of saved records."""

    def __init__(self, record: dict[str, Any], responses: dict[str, dict[str, Any]]) -> None:
        super().__init__(record)
        self.responses = responses


async def prefetch_discovery(
    host: str,
    port: int,
    scheme: str,
    timeout: float,
    retries: int,
    exporters: list[dict[str, Any]],
    tls_context: ssl.SSLContext | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Resume one shared scoring continuation across native HTTP reads."""
    responses: dict[str, dict[str, Any]] = {}

    def metrics_read(*a: Any, **kw: Any) -> Any:
        raise AssertionError("native metrics continuation was run synchronously")

    def fingerprint_read(*a: Any, **kw: Any) -> Any:
        raise AssertionError("native fingerprint continuation was run synchronously")

    steps = discover.scan_presence_port_steps(
        host,
        port,
        exporters,
        timeout,
        retries,
        scheme=scheme,
        http_get_details_fn=metrics_read,
        fetch_fingerprint_bodies_fn=fingerprint_read,
    )
    async with AsyncDetectionHttp(
        timeout=timeout,
        retries=0,
        max_bytes=discover.SCAN_RESPONSE_BODY_MAX_BYTES,
        ssl_context=tls_context,
        decode_content=False,
        escalate_timeouts=False,
    ) as client:
        token = _PREFETCH_CLIENT.set(client)
        try:
            step = next(steps)
            value: Any
            while True:
                if not isinstance(step, DetectCall):
                    raise AssertionError("unsupported exporter detection step")
                if step.function is metrics_read:
                    value = await prefetch_metrics(host, port, scheme, timeout, retries, tls_context)
                    responses[step.args[0]] = value
                elif step.function is fingerprint_read:
                    bodies = []
                    for path in ("/debug/vars", "/debug/pprof/cmdline?debug=1"):
                        url = build_http_url(host, port, path, scheme=scheme)
                        value = await _prefetch_response(
                            client, url, timeout, retries, discover.SCAN_FINGERPRINT_BODY_MAX_BYTES
                        )
                        responses[url] = value
                        bodies.append(str(value.get("body") or "") if (value.get("status") or 0) < 400 else "")
                    value = tuple(bodies)
                else:
                    raise AssertionError("unexpected exporter detection helper")
                step = steps.send(value)
        except StopIteration as result:
            record, hit = result.value
            return DiscoveryRecord(record, responses), hit
        finally:
            steps.close()
            _PREFETCH_CLIENT.reset(token)


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
