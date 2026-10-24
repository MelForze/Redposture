"""Native gRPC detection preserves the original H2 and HPACK owner."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...clients import grpc as client
from ...clients.async_http_detect import AsyncHttpFallback
from ...clients.async_retained_socket import with_native_detection as _with_native_detection
from . import actions

_STATE_CLASS = actions.GrpcLifecycleState
_SESSION_CLASS = client._GrpcH2Session
_SESSION_PROVIDER = actions.GrpcLifecycleState.session_for


def with_native_detection(spec: Any, factory: Any) -> Any:
    bound = _with_native_detection(spec, factory, {**client._ASYNC_RETAINED_STEPS, **actions._ASYNC_RETAINED_STEPS})
    if bound.detect_async is None:
        return bound
    native_detect = bound.detect_async

    async def detect_async(ctx: Any, http: Any) -> Any:
        state = ctx.lifecycle_state
        provider = getattr(state, "session_for", None)
        if (
            actions.GrpcLifecycleState is not _STATE_CLASS
            or client._GrpcH2Session is not _SESSION_CLASS
            or actions._GrpcH2Session is not _SESSION_CLASS
            or not isinstance(state, _STATE_CLASS)
            or getattr(provider, "__func__", None) is not _SESSION_PROVIDER
        ):
            raise AsyncHttpFallback("custom gRPC session provider or client")
        return await native_detect(ctx, http)

    return replace(bound, detect_async=detect_async)
