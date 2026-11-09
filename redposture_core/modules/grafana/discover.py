"""Read stored Grafana configuration in the current organization, never query it."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from ...clients.http_api import build_http_target_url
from ...discovery_frontier import DiscoveryFrontier
from ...discovery_http_reader import read_json
from ...storage_discovery import DiscoveryCollector

_PAGE_SIZE = 100


def discover(ctx: Any, record: dict[str, Any]) -> dict[str, Any]:
    from .actions import _grafana_request_headers

    collector = DiscoveryCollector("grafana", ctx, record)
    collector.declare_sources("dashboard_catalog", "dashboards", "datasources", "contact_points", "alert_rules")
    state = getattr(ctx, "lifecycle_state", None)
    pool = getattr(state, "http", None)
    if (
        state is None
        or pool is None
        or not (
            record.get("auth_required") is False
            or record.get("provided_credentials_ok") is True
            or record.get("default_credentials")
        )
    ):
        collector.partial("grafana", "access_unverified")
        return collector.result()
    headers = {"Accept": "application/json"}
    if state.auth_header:
        headers["Authorization"] = state.auth_header

    def read(
        path: str, source_class: str, *, root: str = "object", scan: bool = True, required: tuple[str, ...] = ()
    ) -> Any:
        url = build_http_target_url(
            state.host or ctx.host,
            state.port or ctx.port,
            path,
            default_scheme=state.scheme or ("https" if ctx.port in {443, 8443} else "http"),
            override_bound_scheme=True,
        )
        return read_json(
            collector,
            pool,
            url,
            path.split("?", 1)[0],
            source_class="grafana." + source_class,
            headers=_grafana_request_headers(headers, url),
            timeout=ctx.args.timeout,
            root=root,
            scan=scan,
            required_fields=required,
        )

    with DiscoveryFrontier() as visited:
        page = 1
        while collector.allowed():
            catalog = read(
                f"/api/search?type=dash-db&limit={_PAGE_SIZE}&page={page}",
                "dashboard_catalog",
                root="array",
                scan=False,
            )
            if catalog is None:
                break
            fresh = 0
            for item in catalog:
                uid = item.get("uid") if isinstance(item, Mapping) else None
                if not isinstance(uid, str) or not uid or len(uid) > 256:
                    collector.partial("/api/search", "invalid_dashboard_row")
                    if collector.source_manifest is not None:
                        collector.source_manifest.finish("grafana.dashboard_catalog", complete=False)
                    continue
                if visited.claim(uid):
                    fresh += 1
                    read("/api/dashboards/uid/" + quote(uid, safe=""), "dashboards", required=("dashboard",))
            if catalog and not fresh:
                collector.partial("/api/search", "repeated_page")
                if collector.source_manifest is not None:
                    collector.source_manifest.finish("grafana.dashboard_catalog", complete=False)
                break
            if len(catalog) < _PAGE_SIZE:
                break
            page += 1
    read("/api/datasources", "datasources", root="array")
    # These export stored configuration; no datasource queries or notification
    # tests are sent. A denied decrypt endpoint is an explicit coverage gap.
    read("/api/v1/provisioning/contact-points/export?format=json&decrypt=true", "contact_points")
    read("/api/v1/provisioning/alert-rules", "alert_rules", root="array")
    result = collector.result()
    result["scope"] = "current organization"
    return result
