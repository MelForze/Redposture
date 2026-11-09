"""Inspect existing Docker configurations; never create, start or exec objects."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import closing
from typing import Any
from urllib.parse import quote

from ...clients.http_api import infer_http_base_path
from ...clients.http_session import HttpSessionPool
from ...discovery_frontier import DiscoveryFrontier
from ...discovery_http_reader import read_json
from ...storage_discovery import DiscoveryCollector


def discover(ctx: Any, record: dict[str, Any]) -> dict[str, Any]:
    collector = DiscoveryCollector("docker", ctx, record)
    collector.declare_sources("container_catalog", "container_configs", "image_catalog", "image_configs")
    if record.get("status") not in {"open_no_auth", "valid_credentials"}:
        collector.partial("docker", "access_unverified")
        return collector.result()
    args = ctx.args
    base_path = (
        infer_http_base_path(str(getattr(ctx.target, "path", "") or ""), ("/_ping", "/version", "/info", "/containers"))
        if getattr(ctx, "target", None)
        else ""
    )
    host = f"[{ctx.host}]" if ":" in ctx.host else ctx.host
    base = f"{'https' if record.get('transport_mode') == 'tls' else 'http'}://{host}:{ctx.port}{base_path}"
    selector = getattr(args, "container", None)
    headers = {"Accept": "application/json", "User-Agent": "RedPosture/1.0"}
    with (
        closing(
            HttpSessionPool(
                timeout=args.timeout,
                insecure=bool(getattr(args, "insecure", False)),
                ca_file=getattr(args, "tls_ca", None),
                cert_file=getattr(args, "tls_cert", None),
                key_file=getattr(args, "tls_key", None),
            )
        ) as pool,
        DiscoveryFrontier() as containers,
        DiscoveryFrontier() as images,
    ):

        def read(path: str, source_class: str, *, root: str = "object", scan: bool = True) -> Any:
            return read_json(
                collector,
                pool,
                base + path,
                path.split("?", 1)[0],
                source_class="docker." + source_class,
                headers=headers,
                timeout=args.timeout,
                root=root,
                scan=scan,
                required_fields=("Config",) if source_class in {"container_configs", "image_configs"} else (),
            )

        if selector:
            containers.enqueue(str(selector))
        else:
            catalog = read("/containers/json?all=1", "container_catalog", root="array")
            if catalog is not None:
                for item in catalog:
                    if isinstance(item, Mapping) and isinstance(item.get("Id"), str) and item["Id"]:
                        containers.enqueue(item["Id"])
                    else:
                        collector.partial("/containers/json", "invalid_catalog_row")
        while collector.allowed() and (container := containers.pop()) is not None:
            detail = read("/containers/" + quote(container, safe="") + "/json", "container_configs")
            if isinstance(detail, Mapping) and isinstance(detail.get("Image"), str) and detail["Image"]:
                images.enqueue(detail["Image"])
        if not selector:
            catalog = read("/images/json?all=1", "image_catalog", root="array")
            if catalog is not None:
                for item in catalog:
                    if isinstance(item, Mapping) and isinstance(item.get("Id"), str) and item["Id"]:
                        images.enqueue(item["Id"])
                    else:
                        collector.partial("/images/json", "invalid_catalog_row")
        while collector.allowed() and (image := images.pop()) is not None:
            read("/images/" + quote(image, safe="") + "/json", "image_configs")
    return collector.result()
