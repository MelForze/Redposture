"""Redis detection uses the sync decision continuation and a retained socket."""

from __future__ import annotations

from typing import Any

from ...clients.async_http_detect import AsyncHttpFallback
from ...clients.async_retained_socket import detect_native
from . import actions

_ORIGINAL_HOOK = actions.redis_detect_hook


async def detect(ctx: Any, http: Any) -> Any:
    if actions.redis_detect_hook is not _ORIGINAL_HOOK:
        raise AsyncHttpFallback("Redis detector override")
    return await detect_native(actions._redis_detect_hook_detect_steps(ctx), http, actions._ASYNC_RETAINED_STEPS)
