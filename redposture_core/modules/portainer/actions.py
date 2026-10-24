"""Portainer UI principal using the shared product protocol implementation."""

from __future__ import annotations

from copy import copy
from typing import Any

from ... import web_panels
from ...storage_discovery import DiscoveryCollector, _portainer_discovery_view, discover_portainer_sources
from ...utils import utc_now_iso
from .types import PortainerLifecycleState

host_stage = None

_SESSIONS = ("session_token", "session_api_key", "session_cookie", "session_authorization")
_INVENTORY = ("containers", "images", "networks", "volumes", "system")


def lifecycle_state_factory(ctx: Any) -> PortainerLifecycleState:
    return PortainerLifecycleState()


def _credential_key(credential: Any) -> tuple[Any, ...]:
    return credential.username, credential.password, credential.token


def detect_record(ctx: Any) -> dict[str, Any]:
    record = web_panels.detect_panel("portainer", ctx, report_failure=True)
    return panel_record(ctx, record)


def panel_record(ctx: Any, record: dict[str, Any] | None) -> dict[str, Any]:
    if record is not None and record.get("is_portainer") is False:
        return {**record, "timestamp": utc_now_iso()}
    if record is None:
        return {
            "timestamp": utc_now_iso(),
            "host": ctx.host,
            "port": ctx.port,
            "module": "portainer",
            "service": "portainer",
            "status": "not_service",
            "is_portainer": False,
        }
    record = {
        **record,
        "timestamp": utc_now_iso(),
        "module": "portainer",
        "service": "portainer",
        "is_portainer": True,
        "credential_verification_status": "available",
    }
    record.pop("is_docker", None)
    return record


_SYNC_DETECT_RECORD = detect_record


def auth_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    state = ctx.lifecycle_state
    if state is not None and state.blocked:
        return web_panels._auth_result(prior, "rate_limited", proof="Portainer credential attempts stopped")
    credential = ctx.credential
    token = credential.token
    if token is not None:
        result = web_panels.authenticate_portainer_token(ctx, prior, str(token))
    elif credential.username is not None and credential.password is not None:
        result = web_panels.authenticate_panel(ctx, prior)
    else:
        return prior
    result = {
        **result,
        "provided_username": credential.username,
        "provided_password": credential.password,
        "token_provided": token is not None,
    }
    ui = dict(result.get("ui") or {})
    session: dict[str, str] = {}
    for field in _SESSIONS:
        secret = ui.pop(field, None)
        if secret is not None and state is not None and field in {"session_token", "session_api_key"}:
            setattr(state, "ui_" + field, secret)
            session[field] = secret
    if session and state is not None:
        state.sessions[_credential_key(credential)] = session
    result["ui"] = ui
    if state is not None and result.get("status") == "rate_limited":
        state.blocked = True
    return result


def data_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    if prior.get("status") not in {"open_no_auth", "valid_credentials"}:
        return prior
    panel = {**prior, "ui": dict(prior.get("ui") or {})}
    state = ctx.lifecycle_state
    if state is not None:
        panel["ui"].update(state.sessions.get(_credential_key(ctx.credential), {}))
    args = copy(ctx.args)
    discover = bool(getattr(args, "discover", False))
    explicit = {key for key in _INVENTORY if getattr(args, key, False)}
    if discover:
        for key in _INVENTORY:
            setattr(args, key, True)
    args.endpoints = bool(getattr(args, "endpoints", False) or getattr(args, "endpoint", None) or discover)
    # Bounded inventory supplies the discovery scanner without creating exports.
    args._ui_standard_export = False
    data_ctx = copy(ctx)
    object.__setattr__(data_ctx, "args", args)
    collector = DiscoveryCollector("portainer", ctx, prior) if discover else None
    result = web_panels.enumerate_panel(data_ctx, panel)
    inventory_bytes_read = int(result.pop("_portainer_inventory_bytes_read", 0) or 0)
    if collector is not None and inventory_bytes_read:
        if not collector.charge(inventory_bytes_read):
            collector.partial("portainer/inventory", "discover_max_bytes")
            collector.remaining = 0
    ui = dict(result.get("ui") or {})
    for field in _SESSIONS:
        ui.pop(field, None)
    inventory = ui.get("inventory") or {}
    if discover:
        result["portainer_metadata"] = {
            name: [
                {key: field for key, field in item.items() if key != "ResourceID"}
                if name == "volumes" and isinstance(item, dict)
                else item
                for item in value.get("records", [])
            ]
            for name, value in inventory.items()
            if isinstance(value, dict) and isinstance(value.get("records"), list)
        }
        result["content_discovery_partial"] = any(
            not isinstance(value, dict) or value.get("partial") or value.get("status") for value in inventory.values()
        )
        if collector is not None:
            for name, items in result["portainer_metadata"].items():
                collector.add(f"portainer/inventory/{name}", _portainer_discovery_view(items))
            for name, items in inventory.items():
                if not isinstance(items, dict) or items.get("partial") or items.get("status"):
                    collector.partial(f"portainer/inventory/{name}", "inventory_incomplete")
            discover_portainer_sources(ctx, panel, inventory, collector)
            result["content_discovery"] = collector.result()
        ui["inventory"] = {
            name: value
            for name, value in inventory.items()
            if name in explicit or (name == "environments" and getattr(ctx.args, "endpoints", False))
        }
    result["ui"] = ui
    return result
