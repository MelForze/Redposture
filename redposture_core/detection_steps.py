"""Run one fingerprint decision tree with synchronous or asynchronous HTTP."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Generator
from typing import Any, TypeVar

from .clients.http_api import HttpResponse

T = TypeVar("T")
DetectionRequest = tuple[str, str] | tuple[str, str, dict[str, Any]]
DetectionRequests = Generator[DetectionRequest, HttpResponse, dict[str, Any]]
NATIVE_DETECT_BODY_MAX_BYTES = 256 * 1024


def run_requests(steps: Generator[DetectionRequest, HttpResponse, T], send: Callable[..., HttpResponse]) -> T:
    try:
        request = next(steps)
        while True:
            response = send(*request)
            request = steps.send(response)
    except StopIteration as result:
        return result.value
    finally:
        steps.close()


async def run_async_requests(
    steps: Generator[DetectionRequest, HttpResponse, T], send: Callable[..., Awaitable[HttpResponse]]
) -> T:
    try:
        request = next(steps)
        while True:
            response = await send(*request)
            request = steps.send(response)
    except StopIteration as result:
        return result.value
    finally:
        steps.close()


def with_async_http_detection(spec: Any, actions: Any, *, api_prefixes: tuple[str, ...]) -> Any:
    """Bind the opt-in coroutine to exactly this synchronous detector."""
    from dataclasses import replace

    from .audit_models import AuditRecord
    from .clients.async_http_detect import AsyncHttpFallback
    from .clients.http_api import http_target_context

    if actions.detect_record is not getattr(actions, "_SYNC_DETECT_RECORD", None):
        return spec
    original = actions.detect_record

    async def detect_async(ctx: Any, http: Any) -> AuditRecord:
        if actions.detect_record is not original:
            raise AsyncHttpFallback("detector override")
        with http_target_context(ctx.target, route_state=ctx.lifecycle_state, api_prefixes=api_prefixes):

            async def send(base: str, path: str) -> HttpResponse:
                response = await http.get(base + path, headers={"Accept": "application/json"})
                if response.truncated or (response.status > 0 and response.error):
                    # A larger/undecodable fingerprint still gets the original
                    # 4 MiB synchronous verification, never a negative verdict.
                    raise AsyncHttpFallback("native fingerprint needs full synchronous response")
                return response

            value = await run_async_requests(actions.detect_requests(ctx), send)
        return AuditRecord.from_mapping(value, module=spec.module, service=spec.module)

    return replace(spec, detect_async=detect_async, async_detect_sync_hook=spec.detect)
