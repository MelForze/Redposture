"""Native reads borrow Kube transport policy without touching its sync socket."""

from __future__ import annotations

from typing import Any

from ...clients.async_http_detect import AsyncHttpFallback
from ...clients.http_session import HttpSessionPool
from ...detection_io import HttpRead, Steps
from .http_session import KubeApiHttpSession


def http_response_steps(client: Any, method: str, url: str, **options: Any) -> Steps[Any]:
    """Leave a lifecycle's thread-confined session unclaimed for auth/data.

    The session owns its policy pool through the final handoff/close. Its
    synchronous request method is never invoked by the native interpreter.
    """
    if isinstance(client, KubeApiHttpSession):
        pool = client.detection_pool()
    elif isinstance(client, HttpSessionPool):
        pool = client
    else:
        raise AsyncHttpFallback("Kube detection transport override")
    yield_options = {**options, "retries": 0}
    return (yield HttpRead(pool, method, url, yield_options))
