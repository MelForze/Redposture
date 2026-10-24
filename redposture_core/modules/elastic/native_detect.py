"""Native anonymous Elastic reads with the original decision continuations."""

from __future__ import annotations

from typing import Any

from ...clients.async_http_detect import AsyncHttpFallback
from ...clients.http_api import HttpClientConfig, join_http_target_path
from ...clients.http_session import HttpSessionPool
from ...detection_io import HttpRead, Steps
from ...network_proxy import ProxySocketPatch


def detect_steps(ctx: Any, options: Any) -> Steps[dict[str, Any]]:
    from . import actions

    if str(getattr(ctx.args, "proxy", "") or "").strip() or ProxySocketPatch._active_proxy is not None:
        raise AsyncHttpFallback("proxied Elastic detection")
    return (yield from actions.detect_elastic_steps(ctx, options))


def no_direct_prefetch_steps(*_args: Any, **_kwargs: Any) -> Steps[None]:
    # The legacy optimization creates its own event loop. Native detection
    # already yields every normal confirmation request through the shared I/O.
    yield from ()
    return None


def session_response_steps(session: Any, scheme: str, method: str, path: str, **options: Any) -> Steps[Any]:
    pool = HttpSessionPool(
        timeout=session.timeout,
        insecure=session._insecure,
        ca_file=session._ca_file,
        retries=0,
    )
    url = f"{scheme}://{session._authority(scheme)}{join_http_target_path(path)}"
    try:
        return (
            yield HttpRead(
                pool,
                method,
                url,
                {
                    "headers": options.get("headers"),
                    "body": options.get("data"),
                    "timeout": session.timeout,
                    "response_size_cap": session.response_cap,
                    "retries": 0,
                },
            )
        )
    finally:
        pool.close()


def generic_response_steps(config: HttpClientConfig, method: str, url: str, **options: Any) -> Steps[Any]:
    if config.proxy is not None:
        raise AsyncHttpFallback("proxied Elastic detection client")
    pool = HttpSessionPool(
        timeout=config.timeout,
        insecure=config.insecure,
        ca_file=config.ca_file,
        cert_file=config.client_cert,
        key_file=config.client_key,
        retries=config.retries,
    )
    try:
        return (
            yield HttpRead(
                pool,
                method,
                url,
                {
                    **options,
                    "response_size_cap": config.response_size_cap,
                    "allow_cross_origin_redirects": config.allow_cross_origin_redirects,
                },
            )
        )
    finally:
        pool.close()
