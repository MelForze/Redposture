"""Native HTTP transport for the original Docker detection decision tree."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...audit_models import AuditRecord
from ...clients.async_http_detect import AsyncHttpFallback
from ...clients.docker_engine import DockerEngineClient, DockerEngineHTTPError, DockerHTTPResponse
from ...clients.http_session import HttpSessionPool
from ...detection_io import HttpRead, run_async
from ...stage_runtime import _prepare_host_stage_call
from . import actions


def bind(spec: Any) -> Any:
    async def detect(ctx: Any, http: Any) -> AuditRecord:
        function, positional, keyword = _prepare_host_stage_call(
            spec.host_stage, module="docker", ctx=ctx, run_deep_checks=False
        )
        registry = dict(actions._ASYNC_DETECT_STEPS)
        if function not in registry:
            raise AsyncHttpFallback("Docker host-stage override")

        def request(
            client: Any,
            method: str,
            path: str,
            *,
            json_body: Any = None,
            headers: Any = None,
            allow_statuses: set[int] | None = None,
            response_size_cap: int = 10 * 1024 * 1024,
        ) -> Any:
            if method != "GET" or json_body is not None or not isinstance(client, DockerEngineClient):
                raise AsyncHttpFallback("Docker detect operation override")
            scheme, host, port = client._connection_origin
            authority = f"[{host}]" if ":" in host else host
            endpoint = path if path.startswith("/") else "/" + path
            if client.base_path and endpoint != client.base_path and not endpoint.startswith(client.base_path + "/"):
                endpoint = client.base_path + endpoint
            url = f"{scheme}://{authority}:{port}{endpoint}"
            req_headers = {
                "Host": f"{authority}:{port}",
                "User-Agent": "redposture",
                "Accept": "application/json",
                **(headers or {}),
            }
            pool = HttpSessionPool(
                timeout=client.timeout,
                insecure=client.insecure,
                ca_file=client.ca_file,
                cert_file=client.cert_file,
                key_file=client.key_file,
            )
            try:
                response = yield HttpRead(
                    pool, "GET", url, {"headers": req_headers, "response_size_cap": response_size_cap}
                )
                if response.error:
                    raise AsyncHttpFallback("Docker transport error needs original normalization")
                reason = getattr(http, "last_reason", None)
                if reason is None:
                    raise AsyncHttpFallback("Docker response reason unavailable")
                normalized_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
                if response.status not in (allow_statuses or set(range(200, 300))):
                    raise DockerEngineHTTPError(response.status, reason, response.body, normalized_headers)
                return DockerHTTPResponse(response.status, reason, normalized_headers, response.body)
            finally:
                pool.close()

        registry[DockerEngineClient.request] = request
        result = await run_async(registry[function](*positional, **keyword), http, registry)
        return AuditRecord.from_mapping(result, module="docker", service="docker")

    return replace(spec, detect_async=detect)
