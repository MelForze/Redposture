"""Read-only ResourceManager inspection and explicit application-ID allocation probe."""

from __future__ import annotations

import re
from typing import Any

from ...clients.http_api import http_response_requires_https
from ...detection_steps import DetectionRequests, run_requests
from ..token_api import ReadBudget, access, bases, json_value, request
from .types import DetectionStatus

host_stage = None
_LIMIT = 5000
_APP_ID = re.compile(r"application_[0-9]{1,20}_[0-9]{1,20}\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9._-]+)?\Z")


def _get(ctx: Any, base: str, path: str, *, method: str = "GET") -> Any:
    return request(ctx, base, path, header="", method=method)


def _info(data: Any) -> dict[str, Any] | None:
    value = data.get("clusterInfo") if isinstance(data, dict) else None
    if not isinstance(value, dict):
        return None
    if value.get("state") not in ("NOTINITED", "INITED", "STARTED", "STOPPED") or value.get("haState") not in (
        "INITIALIZING",
        "ACTIVE",
        "STANDBY",
        "OBSERVER",
        "STOPPING",
    ):
        return None
    for name in ("resourceManagerVersion", "hadoopVersion"):
        if not isinstance(value.get(name), str) or not _VERSION.fullmatch(value[name]):
            return None
    return value


def _rows(data: Any, name: str) -> list[dict[str, Any]] | None:
    singular = "app" if name == "apps" else "node"
    if not isinstance(data, dict) or name not in data:
        return None
    wrapper = data[name]
    # Jersey's Hadoop 3.x JSON provider emits {} for empty collections;
    # other supported versions emit null. The outer product key is required.
    if wrapper is None or wrapper == {}:
        return []
    rows = wrapper.get(singular) if isinstance(wrapper, dict) else None
    if not isinstance(rows, list):
        return None
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
            return None
        if name == "apps" and not _APP_ID.fullmatch(row["id"]):
            return None
        if name == "nodes" and (len(row["id"]) > 4096 or any(ord(c) < 32 for c in row["id"])):
            return None
    return rows


def detect_record(ctx: Any) -> dict[str, Any]:
    return run_requests(detect_requests(ctx), lambda base, path: _get(ctx, base, path))


def detect_requests(ctx: Any) -> DetectionRequests:
    reachable = False
    probable = False
    for base in bases(ctx):
        response = yield (base, "/ws/v1/cluster/info")
        reachable |= response.status > 0
        info = _info(json_value(response))
        if response.status == 200 and info is not None:
            apps_response = yield (base, "/ws/v1/cluster/apps?limit=1")
            app_state = access(apps_response, _rows(json_value(apps_response), "apps") is not None)
            allowed = app_state == "allowed"
            required = False if allowed else True if app_state == "denied" else None
            return {
                "host": ctx.host,
                "port": ctx.port,
                "service": "yarn",
                "is_yarn": True,
                "detection_status": "confirmed",
                "detection_signals": ["yarn.cluster_info"],
                "version": info["resourceManagerVersion"],
                "hadoop_version": info["hadoopVersion"],
                "cluster_state": info["state"],
                "ha_state": info["haState"],
                "cluster_info": info,
                "api_endpoint": base,
                "anonymous_apps_access": allowed,
                "apps_access": app_state,
                "anonymous_access": allowed,
                "auth_required": required,
                "rce_potential": False,
                "submit_access": "unverified",
                "allocation_access": "unverified",
                "status": "open_no_auth" if allowed else "auth_required" if required else "detected",
            }
        if response.status > 0 and not http_response_requires_https(response.status, response.body):
            ui = yield (base, "/cluster")
            reachable |= ui.status > 0
            probable = bool(
                ui.status == 200
                and not ui.error
                and not ui.truncated
                and "ResourceManager" in ui.text
                and "Hadoop" in ui.text
                and "/ws/v1/cluster" in ui.text
            )
            break
    state: DetectionStatus = "probable" if probable else "not_service" if reachable else "transport_failure"
    return {
        "host": ctx.host,
        "port": ctx.port,
        "service": "yarn",
        "is_yarn": False,
        "status": state,
        "detection_status": state,
        "detection_signals": ["yarn.ui"] if probable else ["yarn.probe"],
    }


_SYNC_DETECT_RECORD = detect_record


def auth_record(_ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    """Simple user.name impersonation is not a password credential verifier."""
    return dict(prior)


def _probe(ctx: Any, base: str) -> dict[str, Any]:
    response = _get(ctx, base, "/ws/v1/cluster/apps/new-application", method="POST")
    data = json_value(response)
    resource = data.get("maximum-resource-capability") if isinstance(data, dict) else None
    identifier = data.get("application-id") if isinstance(data, dict) else None
    valid = bool(
        isinstance(identifier, str)
        and _APP_ID.fullmatch(identifier)
        and isinstance(resource, dict)
        and all(type(resource.get(key)) is int and resource[key] > 0 for key in ("memory", "vCores"))
    )
    state = access(response, valid)
    if state == "unknown":
        state = "unverified"
    result: dict[str, Any] = {
        "access": state,
        "http_status": response.status,
        "executed": False,
        "submitted": False,
        "reason": "application ID allocation only; application submission and execution unverified",
    }
    if state == "allowed":
        result["application_id"] = identifier
        result["maximum_resource_capability"] = resource
    return result


def data_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    result = dict(prior)
    if prior.get("is_yarn") is not True:
        return result
    base = prior["api_endpoint"]
    budget = ReadBudget(ctx.args)
    discover = bool(getattr(ctx.args, "discover", False))
    requested: list[str] = []
    states: list[str] = []
    for name, path in (
        ("apps", "/ws/v1/cluster/apps?limit=5000"),
        ("nodes", "/ws/v1/cluster/nodes"),
        ("metrics", "/ws/v1/cluster/metrics"),
    ):
        if not getattr(ctx.args, "show_" + name, False) and not (name == "apps" and discover):
            continue
        if getattr(ctx.args, "show_" + name, False):
            requested.append(name)
        state, error, partial = "unknown", None, False
        if not budget.allowed():
            error, partial = "discovery budget reached", True
        else:
            response = _get(ctx, base, path)
            if not budget.consume(response):
                error, partial = "response or byte limit", True
            else:
                data = json_value(response)
                if name == "metrics":
                    model = data.get("clusterMetrics") if isinstance(data, dict) else None
                    valid = isinstance(model, dict) and all(
                        type(model.get(k)) is int and model[k] >= 0 for k in ("totalMB", "allocatedMB", "totalNodes")
                    )
                    state = access(response, valid)
                    if state == "allowed":
                        result[name] = model
                else:
                    rows = _rows(data, name)
                    state = access(response, rows is not None)
                    if state == "allowed" and rows is not None:
                        unique = {row["id"]: row for row in rows}
                        result[name] = list(unique.values())[:_LIMIT]
                        if len(unique) != len(rows):
                            error, partial = "duplicate resource IDs", True
                        if len(rows) >= _LIMIT:
                            error, partial = "bounded snapshot item limit; collection coverage unverified", True
                if state != "allowed":
                    error, partial = "invalid collection" if response.status == 200 else f"HTTP {response.status}", True
        result[name + "_access"] = state
        result[name + "_partial"] = partial
        if error:
            result[name + "_error"] = error
        budget.partial |= partial
        states.append(state)
    if discover:
        # The list endpoint already returns complete AppInfo models, validated
        # by _rows. Reuse this bounded snapshot instead of refreshing every app.
        result["app_specs"] = [{"app": row["id"], "spec": row} for row in result.get("apps", [])]
        result["app_discovery_partial"] = budget.partial
    result["inventory_requested"] = requested
    result["inventory_status"] = (
        "complete"
        if states and all(s == "allowed" for s in states) and not budget.partial
        else "partial"
        if "allowed" in states
        else "unavailable"
        if states
        else "not_requested"
    )
    if getattr(ctx.args, "probe_submit", False):
        probe = _probe(ctx, base)
        result["submit_probe"] = probe
        result["allocation_access"] = probe["access"]
        result["rce_potential"] = probe["access"] == "allowed"
        result["operational_failure"] = probe["access"] in ("unverified", "rate_limited")
    return result
