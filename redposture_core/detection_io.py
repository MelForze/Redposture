"""Shared detection continuations; only their I/O interpreter differs.

Synchronous callers retain their original clients and monkeypatch points.
Native detection never invokes an unknown helper or a blocking fallback.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Generator, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from threading import local
from typing import Any, TypeVar, cast

from .clients.async_http_detect import AsyncHttpFallback
from .clients.http_api import HttpResponse
from .clients.http_session import HttpSessionPool
from .detection_steps import NATIVE_DETECT_BODY_MAX_BYTES

T = TypeVar("T")


@dataclass(frozen=True)
class DetectCall:
    function: Callable[..., Any]
    args: tuple[Any, ...]
    kwargs: dict[str, Any]


@dataclass(frozen=True)
class DetectDelay:
    seconds: float


@dataclass(frozen=True)
class HttpRead:
    pool: Any
    method: str
    url: str
    options: dict[str, Any]
    readonly_post: bool = False


Step = DetectCall | DetectDelay | HttpRead
Steps = Generator[Step, Any, T]


def detection_thread_locals(actions: Any) -> tuple[local, ...]:
    """Bindings used by legacy helpers must not escape a continuation resume."""
    return tuple(value for value in vars(actions).values() if isinstance(value, local))


def run_sync(steps: Steps[T]) -> T:
    try:
        step = next(steps)
        while True:
            try:
                if isinstance(step, DetectCall):
                    value = step.function(*step.args, **step.kwargs)
                elif isinstance(step, DetectDelay):
                    time.sleep(step.seconds)
                    value = None
                else:
                    value = step.pool.request(step.method, step.url, **step.options)
            except Exception as exc:
                step = steps.throw(exc)
            else:
                step = steps.send(value)
    except StopIteration as result:
        return result.value
    finally:
        steps.close()


async def read_http(step: HttpRead, http: Any) -> HttpResponse:
    """Preserve the originating pool's TLS, timeout, retry and body policy."""
    pool, options = step.pool, step.options
    if (
        not isinstance(pool, HttpSessionPool)
        or step.method.upper() not in {"GET", "HEAD"}
        and not (step.method.upper() == "POST" and step.readonly_post)
    ):
        raise AsyncHttpFallback("unsupported detection client or operation")
    if pool.proxy is not None:
        raise AsyncHttpFallback("proxied detection client")
    allowed = {
        "headers",
        "body",
        "timeout",
        "response_size_cap",
        "retries",
        "allow_cross_origin_redirects",
        "preserve_authorization_on_cross_origin",
        "prepare_request",
        "replay_safe",
    }
    if options.get("prepare_request") is not None or set(options) - allowed:
        raise AsyncHttpFallback("unsupported detection request options")
    tls = pool._target_context()
    saved = (http.timeout, http.retries, http.max_bytes, http.ssl_context)
    if tls is not http.ssl_context:
        await http.close()
    http.timeout = max(0.1, float(options.get("timeout") or pool.timeout))
    http.retries = max(0, int(pool.default_retries if options.get("retries") is None else options["retries"]))
    http.max_bytes = min(NATIVE_DETECT_BODY_MAX_BYTES, max(0, int(options.get("response_size_cap", 10 * 1024 * 1024))))
    http.ssl_context = tls
    try:
        if step.method.upper() == "GET" and not options.get("body"):
            response = await http.get(step.url, headers=options.get("headers"))
        else:
            response = await http.request(
                step.method,
                step.url,
                headers=options.get("headers"),
                body=options.get("body"),
                replay_safe=bool(options.get("replay_safe", False)),
            )
        if response.truncated or (response.status > 0 and response.error):
            raise AsyncHttpFallback("detection response needs the original client")
        return response
    finally:
        # All requests belonging to a target normally share this pool's TLS
        # identity. Close only when restoring a different transport policy.
        if http.ssl_context is not saved[3]:
            await http.close()
        http.timeout, http.retries, http.max_bytes, http.ssl_context = saved


async def run_async(
    steps: Steps[T],
    http: Any,
    registry: dict[Callable[..., Any], Callable[..., Steps[Any]]],
    *,
    activate: Callable[[], None] | None = None,
    thread_locals: tuple[local, ...] = (),
) -> T:
    @contextmanager
    def resume_scope() -> Iterator[None]:
        saved = [(binding, dict(binding.__dict__)) for binding in thread_locals]
        try:
            if activate is not None:
                activate()
            yield
        finally:
            for binding, values in saved:
                binding.__dict__.clear()
                binding.__dict__.update(values)

    def resume(value: Any = None, error: Exception | None = None, *, first: bool = False) -> Step:
        with resume_scope():
            return next(steps) if first else steps.throw(error) if error is not None else steps.send(value)

    try:
        step = resume(first=True)
        while True:
            try:
                if isinstance(step, DetectCall):
                    factory = registry.get(step.function)
                    call_args = step.args
                    if factory is None and getattr(step.function, "__self__", None) is not None:
                        unbound = getattr(step.function, "__func__", None)
                        factory = registry.get(unbound) if unbound is not None else None
                        call_args = (cast(Any, step.function).__self__, *step.args)
                    if factory is None:
                        raise AsyncHttpFallback("detector helper override or synchronous-only path")
                    with resume_scope():
                        child = factory(*call_args, **step.kwargs)
                    value = await run_async(child, http, registry, activate=activate, thread_locals=thread_locals)
                elif isinstance(step, DetectDelay):
                    await asyncio.sleep(step.seconds)
                    value = None
                else:
                    value = await read_http(step, http)
            except AsyncHttpFallback:
                raise
            except Exception as exc:
                step = resume(error=exc)
            else:
                step = resume(value)
    except StopIteration as result:
        return result.value
    finally:
        with resume_scope():
            steps.close()


def with_async_io_detection(
    spec: Any,
    actions: Any,
    *,
    root_name: str,
    options: Any,
    api_prefixes: tuple[str, ...],
    activate_name: str | None = None,
) -> Any:
    from dataclasses import replace

    from .audit_models import AuditRecord
    from .clients.http_api import http_target_context

    registry = actions._ASYNC_DETECT_STEPS
    original = getattr(actions, root_name)
    if spec.detect is None or original not in registry:
        return spec

    async def detect_async(ctx: Any, http: Any) -> AuditRecord:
        if getattr(actions, root_name) is not original:
            raise AsyncHttpFallback("detector override")

        def activate() -> None:
            if activate_name is not None:
                getattr(actions, activate_name)(ctx.lifecycle_state)

        with http_target_context(ctx.target, route_state=ctx.lifecycle_state, api_prefixes=api_prefixes):
            record = await run_async(
                registry[original](ctx) if options is None else registry[original](ctx, options),
                http,
                registry,
                activate=activate,
                thread_locals=detection_thread_locals(actions),
            )
        return AuditRecord.from_mapping(record, module=spec.module, service=spec.module)

    return replace(spec, detect_async=detect_async, async_detect_sync_hook=spec.detect)
