"""Read existing definitions and runtime parameters, never consume messages."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from ...discovery_http_reader import read_json
from ...storage_discovery import DiscoveryCollector

# Password hashes and user records are deliberately not plaintext credentials.
_DEFINITION_SOURCES = ("parameters", "global_parameters", "policies", "queues", "exchanges", "bindings")


def _definition_content(value: Any) -> dict[str, Any]:
    return {name: value[name] for name in _DEFINITION_SOURCES if name in value} if isinstance(value, Mapping) else {}


def discover(ctx: Any, record: dict[str, Any]) -> dict[str, Any]:
    from .actions import _can_read, _read_client

    collector = DiscoveryCollector("rabbitmq", ctx, record)
    collector.declare_sources("runtime_parameters", "definitions")
    if not _can_read(record):
        collector.partial("rabbitmq", "access_unverified")
        return collector.result()
    client = _read_client(ctx, record)
    headers = {"Accept": "application/json"}
    if client.username is not None and client.password is not None:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{client.username}:{client.password}".encode()).decode()
    vhost = getattr(ctx.args, "vhost", None)
    if vhost is None:
        read_json(
            collector,
            client.pool,
            client.base_url + "/api/parameters",
            "/api/parameters",
            source_class="rabbitmq.runtime_parameters",
            root="array",
            headers=headers,
            timeout=ctx.args.timeout,
        )
    # A vhost selector uses the scoped definitions API: other virtual hosts
    # must not be downloaded merely to filter their values on the client.
    path = "/api/definitions" + ("/" + quote(vhost, safe="") if vhost is not None else "")
    read_json(
        collector,
        client.pool,
        client.base_url + path,
        path,
        source_class="rabbitmq.definitions",
        headers=headers,
        timeout=ctx.args.timeout,
        project=_definition_content,
        exclude=lambda path: bool(path and path[0] not in _DEFINITION_SOURCES),
    )
    return collector.result()
