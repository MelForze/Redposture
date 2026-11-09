"""Read current Keycloak configuration and existing credentials; never rotate."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from ...discovery_frontier import DiscoveryFrontier
from ...discovery_http_reader import read_json
from ...storage_discovery import DiscoveryCollector

_PAGE_SIZE = 100


def discover(ctx: Any, record: dict[str, Any]) -> dict[str, Any]:
    from .actions import _REALM_PATH, _realms

    collector = DiscoveryCollector("keycloak", ctx, record)
    collector.declare_sources(
        "realm_catalog", "realm_configs", "clients", "client_credentials", "identity_providers", "components"
    )
    pool = getattr(getattr(ctx, "lifecycle_state", None), "http", None)
    token = getattr(ctx.args, "_keycloak_token", None) or getattr(ctx.credential, "token", None)
    if pool is None or not token or record.get("provided_credentials_ok") is not True:
        collector.partial("keycloak", "access_unverified")
        return collector.result()
    base = str(record.get("api_endpoint") or "").rstrip("/")
    if not base:
        collector.partial("keycloak", "api_endpoint_unverified")
        return collector.result()
    headers = {"Accept": "application/json", "Authorization": "Bearer " + token}

    def read(path: str, kind: str, *, root: str = "object", scan: bool = True, required: tuple[str, ...] = ()) -> Any:
        return read_json(
            collector,
            pool,
            base + path,
            path,
            source_class="keycloak." + kind,
            headers=headers,
            timeout=ctx.args.timeout,
            root=root,
            scan=scan,
            required_fields=required,
        )

    def invalid(path: str, kind: str, reason: str) -> None:
        collector.partial(path, reason)
        if collector.source_manifest is not None:
            collector.source_manifest.finish("keycloak." + kind, complete=False)

    target_path = str(getattr(getattr(ctx, "target", None), "path", "") or "")
    selected = bool(getattr(ctx.args, "realm", None)) or bool(_REALM_PATH.match("/" + target_path.strip("/")))
    with DiscoveryFrontier() as realms, DiscoveryFrontier() as clients:
        if selected:
            for selected_realm in _realms(ctx.args, target_path):
                realms.enqueue(selected_realm)
        else:
            catalog = read("/admin/realms", "realm_catalog", root="array", scan=False)
            if catalog is not None:
                for item in catalog:
                    candidate = item.get("realm") if isinstance(item, Mapping) else None
                    if isinstance(candidate, str) and candidate and len(candidate) <= 128:
                        realms.enqueue(candidate)
                    else:
                        invalid("/admin/realms", "realm_catalog", "invalid_realm_row")
            else:
                # Preserve a known realm's readable subset despite catalog ACL.
                realms.enqueue(str(record.get("detected_realm") or "master"))
        while collector.allowed() and (realm := realms.pop()) is not None:
            prefix = "/admin/realms/" + quote(realm, safe="")
            read(prefix, "realm_configs", required=("realm",))
            read(prefix + "/identity-provider/instances", "identity_providers", root="array")
            read(prefix + "/components", "components", root="array")
            offset = 0
            while collector.allowed():
                catalog = read(prefix + f"/clients?first={offset}&max={_PAGE_SIZE}", "clients", root="array")
                if catalog is None:
                    break
                fresh = 0
                for item in catalog:
                    identifier = item.get("id") if isinstance(item, Mapping) else None
                    if not isinstance(identifier, str) or not identifier or len(identifier) > 256:
                        invalid(prefix + "/clients", "clients", "invalid_client_row")
                        continue
                    if not clients.claim(realm + "/" + identifier):
                        continue
                    fresh += 1
                    # These credential types do not apply to public, bearer-only
                    # or asymmetric clients. Their configs are still inspected.
                    if item.get("publicClient") is True or item.get("bearerOnly") is True:
                        continue
                    if item.get("clientAuthenticatorType") not in {None, "client-secret", "client-secret-jwt"}:
                        continue
                    read(
                        prefix + "/clients/" + quote(identifier, safe="") + "/client-secret",
                        "client_credentials",
                        required=("value",),
                    )
                if catalog and not fresh:
                    invalid(prefix + "/clients", "clients", "repeated_page")
                    break
                if len(catalog) < _PAGE_SIZE:
                    break
                offset += _PAGE_SIZE
    return collector.result()
