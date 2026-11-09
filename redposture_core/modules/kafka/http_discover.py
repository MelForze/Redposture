"""Read existing Connect configuration and retained Registry schemas by GET."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from ...discovery_frontier import DiscoveryFrontier
from ...discovery_http_reader import read_json
from ...storage_discovery import DiscoveryCollector

SUPPORTED = {"kafka_connect", "schema_registry"}


def discover(ctx: Any, record: dict[str, Any], state: Any) -> dict[str, Any]:
    collector = DiscoveryCollector("kafka", ctx, record)
    connect = record.get("ui_vendor") == "kafka_connect"
    collector.declare_sources(
        *(
            ("connect_catalog", "connect_configs")
            if connect
            else ("schema_subjects", "schema_versions", "schema_definitions")
        )
    )
    pool = getattr(state, "ui_http", None)
    base = getattr(state, "ui_base", None) or record.get("ui_base")
    if pool is None or not base:
        collector.partial("kafka/http", "http_session_unavailable")
        return collector.result()

    def read(path: str, kind: str, *, root: str = "object", scan: bool = True, required: tuple[str, ...] = ()) -> Any:
        return read_json(
            collector,
            pool,
            str(base).rstrip("/") + path,
            path,
            source_class="kafka." + kind,
            headers={"Accept": "application/json"},
            timeout=ctx.args.timeout,
            root=root,
            scan=scan,
            required_fields=required,
        )

    def invalid(path: str, kind: str) -> None:
        collector.partial(path, "invalid_catalog_identity")
        if collector.source_manifest is not None:
            collector.source_manifest.finish("kafka." + kind, complete=False)

    catalog_path = "/connectors" if connect else "/subjects?deleted=true"
    catalog_kind = "connect_catalog" if connect else "schema_subjects"
    with DiscoveryFrontier() as names, DiscoveryFrontier() as versions:
        catalog = read(catalog_path, catalog_kind, root="array", scan=False)
        if catalog is not None:
            for name in catalog:
                if isinstance(name, str) and name and len(name) <= 4096:
                    names.enqueue(name)
                else:
                    invalid(catalog_path, catalog_kind)
        while collector.allowed() and (name := names.pop()) is not None:
            encoded = quote(name, safe="")
            if connect:
                read("/connectors/" + encoded + "/config", "connect_configs", required=("connector.class",))
                continue
            path = "/subjects/" + encoded + "/versions"
            catalog = read(path + "?deleted=true", "schema_versions", root="array", scan=False)
            if catalog is None:
                continue
            for version in catalog:
                if not collector.allowed():
                    break
                if type(version) is not int or version < 1:
                    invalid(path, "schema_versions")
                    continue
                if not versions.claim(name + "/" + str(version)):
                    continue
                read(
                    path + "/" + str(version) + "?deleted=true",
                    "schema_definitions",
                    required=("subject", "version", "id", "schema"),
                )
    return collector.result()
