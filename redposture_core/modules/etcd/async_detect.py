"""Native detection through the same read-only etcd decision continuation."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_models import AuditRecord
from ...clients.async_http_detect import AsyncHttpFallback
from ...clients.http_session import HttpSessionPool
from ...detection_io import detection_thread_locals, run_async
from ...stage_runtime import _prepare_host_stage_call
from . import actions


def bind(spec: Any) -> Any:
    registry = actions._ASYNC_DETECT_STEPS

    async def detect(ctx: Any, http: Any) -> AuditRecord:
        function, positional, keyword = _prepare_host_stage_call(
            spec.host_stage,
            module="etcd",
            ctx=ctx,
            run_deep_checks=False,
        )
        factory = registry.get(function)
        if factory is None:
            raise AsyncHttpFallback("etcd host-stage override")
        state = actions._EtcdHttpLifecycle(
            pool=HttpSessionPool(
                timeout=float(getattr(ctx.args, "timeout", 5)), insecure=True, proxy=getattr(ctx.args, "proxy", None)
            ),
            scheme=getattr(ctx.target, "scheme", None),
            host=ctx.host,
            port=ctx.port,
        )

        def activate() -> None:
            actions._ETCD_HTTP_LOCAL.native_state = state
            actions._ETCD_HTTP_LOCAL.state = state

        try:
            result = await run_async(
                factory(*positional, **keyword),
                http,
                registry,
                activate=activate,
                thread_locals=detection_thread_locals(actions),
            )
            return AuditRecord.from_mapping(result, module="etcd", service="etcd")
        finally:
            state.pool.close()

    return replace(spec, detect_async=detect)
