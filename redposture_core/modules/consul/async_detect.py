"""Native anonymous probes followed by the original cache-only payload builder."""

from __future__ import annotations

from typing import Any

from ...audit_models import AuditRecord
from ...clients.async_http_detect import AsyncHttpFallback
from ...detection_io import detection_thread_locals, run_async
from . import actions


class _UnexpectedIO(BaseException):
    pass


class _ReadForbidden:
    def request(self, *_args: Any, **_kwargs: Any) -> Any:
        raise _UnexpectedIO


def _cached_payload(ctx: Any, options: dict[str, Any], *, run_deep_checks: bool) -> Any:
    if False:  # This is a continuation that returns without yielding network IO.
        yield
    state = ctx.lifecycle_state
    if (
        run_deep_checks
        or state.scheme is None
        or state.anonymous_scopes is None
        or state.anonymous_self is None
        or state.http is None
    ):
        raise AsyncHttpFallback("Consul anonymous replay cache is incomplete")
    original_pool = state.http
    state.http = _ReadForbidden()
    try:
        try:
            return actions._consul_lifecycle_call(ctx, options, run_deep_checks=False)
        except _UnexpectedIO as exc:
            raise AsyncHttpFallback("Consul payload unexpectedly requested network IO") from exc
    finally:
        state.http = original_pool


def bind(spec: Any, options: dict[str, Any]) -> Any:
    from dataclasses import replace

    original = actions.detect_consul
    registry = {**actions._ASYNC_DETECT_STEPS, actions._consul_lifecycle_call: _cached_payload}
    if spec.detect is None or original not in registry:
        return spec

    async def detect(ctx: Any, http: Any) -> AuditRecord:
        if actions.detect_consul is not original:
            raise AsyncHttpFallback("Consul detector override")

        def activate() -> None:
            actions._THREAD_LOCAL_LIFECYCLE.state = ctx.lifecycle_state

        value = await run_async(
            registry[original](ctx, options),
            http,
            registry,
            activate=activate,
            thread_locals=detection_thread_locals(actions),
        )
        return AuditRecord.from_mapping(value, module="consul", service="consul")

    return replace(spec, detect_async=detect, async_detect_sync_hook=spec.detect)
