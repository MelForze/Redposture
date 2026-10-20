"""Read-only Nomad fingerprint, ACL token proof and job inspection."""

from __future__ import annotations

import hmac
import uuid
from typing import Any
from urllib.parse import urlencode

from ...clients.http_api import http_response_requires_https
from ..token_api import ReadBudget, access, bases, json_value, path_value, request, safe_path, verdict
from .types import DetectionStatus

host_stage = None


def _get(ctx: Any, base: str, path: str, token: str | None = None) -> Any:
    return request(ctx, base, path, header="X-Nomad-Token", token=token)


def _namespace(ctx: Any) -> str:
    return str(getattr(ctx.args, "namespace", "default"))


def _job_path(ctx: Any, suffix: str = "", namespace: str | None = None) -> str:
    return (
        ("/v1/job/" + path_value(suffix) if suffix else "/v1/jobs")
        + "?"
        + urlencode({"namespace": namespace or _namespace(ctx)})
    )


def detect_record(ctx: Any) -> dict[str, Any]:
    reachable = False
    for base in bases(ctx):
        response = _get(ctx, base, "/v1/agent/self")
        reachable |= response.status > 0
        data = json_value(response)
        config = data.get("config") if isinstance(data, dict) else None
        version_data = config.get("Version") if isinstance(config, dict) else None
        version = version_data.get("Version") if isinstance(version_data, dict) else None
        acl_data = config.get("ACL") if isinstance(config, dict) else None
        acl = acl_data.get("Enabled") if isinstance(acl_data, dict) else None
        self_shape = (
            response.status == 200
            and isinstance(version, str)
            and isinstance(config, dict)
            and (isinstance(data.get("stats"), dict) or type(acl) is bool)
        )
        leader = _get(ctx, base, "/v1/status/leader")
        leader_value = json_value(leader)
        leader_shape = (
            leader.status == 200 and isinstance(leader_value, str) and (not leader_value or ":" in leader_value)
        )
        nomad_header = any(key.lower().startswith("x-nomad-") for item in (response, leader) for key in item.headers)
        ui_shape = False
        if leader_shape and not (self_shape or nomad_header):
            ui = _get(ctx, base, "/ui/")
            ui_shape = (
                ui.status == 200
                and not ui.truncated
                and "<title>Nomad</title>" in ui.text
                and "nomad-ui/config/environment" in ui.text
            )
        if leader_shape and (self_shape or nomad_header or ui_shape):
            jobs_response = _get(ctx, base, _job_path(ctx))
            jobs = json_value(jobs_response)
            allowed = jobs_response.status == 200 and _rows(jobs, "ID")
            required = False if allowed else True if jobs_response.status in {401, 403} else None
            return {
                "host": ctx.host,
                "port": ctx.port,
                "service": "nomad",
                "is_nomad": True,
                "detection_status": "confirmed",
                "detection_signals": [
                    "nomad.leader",
                    "nomad.agent_self" if self_shape else "nomad.header" if nomad_header else "nomad.ui",
                ],
                "version": version if self_shape else None,
                "enterprise": ("+ent" in str(version)) if self_shape else None,
                "api_endpoint": base,
                "acl_enabled": acl if type(acl) is bool else None,
                "anonymous_jobs_access": allowed,
                "auth_required": required,
                "anonymous_access": allowed,
                "rce_potential": acl is False,
                "submit_access": "unverified",
                "status": "open_no_auth" if allowed else "auth_required" if required else "detected",
            }
        if response.status > 0 and not http_response_requires_https(response.status, response.body):
            break
    state: DetectionStatus = "not_service" if reachable else "transport_failure"
    return {
        "host": ctx.host,
        "port": ctx.port,
        "service": "nomad",
        "status": state,
        "is_nomad": False,
        "detection_status": state,
    }


def auth_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    token = getattr(ctx.credential, "token", None)
    if not token:
        return dict(prior)
    response = _get(ctx, prior["api_endpoint"], "/v1/acl/token/self", token)
    data = json_value(response)
    valid = (
        response.status == 200
        and isinstance(data, dict)
        and isinstance(data.get("SecretID"), str)
        and hmac.compare_digest(data["SecretID"].encode(), token.encode())
        and isinstance(data.get("AccessorID"), str)
        and bool(data["AccessorID"])
        and data.get("Type") in {"client", "management"}
    )
    text = response.text.strip().lower()
    invalid = response.status in {403, 404} and any(
        marker in text for marker in ("acl token not found", "acl token expired", "invalid acl token")
    )
    try:
        uuid.UUID(token)
        is_acl_id = True
    except ValueError:
        is_acl_id = False
    # token-self has no resource ACL requirement. A UUID token rejected here
    # with Nomad's exact denial is not the ambiguous jobs/nodes ACL denial.
    invalid |= response.status in {403, 404} and is_acl_id and text == "permission denied"
    invalid |= (
        response.status == 500
        and text.startswith("failed to parse signed token:")
        and "compact jws format must have three parts" in text
    )
    result = verdict(prior, response, valid, invalid)
    if valid:
        server = json_value(_get(ctx, prior["api_endpoint"], "/v1/agent/self", token))
        config = server.get("config") if isinstance(server, dict) else None
        ver = config.get("Version") if isinstance(config, dict) else None
        if isinstance(ver, dict) and isinstance(ver.get("Version"), str):
            result["version"] = ver["Version"]
            result["enterprise"] = "+ent" in ver["Version"]
        acl = config.get("ACL") if isinstance(config, dict) else None
        if isinstance(acl, dict) and type(acl.get("Enabled")) is bool:
            result["acl_enabled"] = acl["Enabled"]
        result["token_type"] = data["Type"]
        result["token_policies"] = (
            [p for p in data.get("Policies", []) if isinstance(p, str)][:100]
            if isinstance(data.get("Policies", []), list)
            else []
        )
    return result


def _rows(data: Any, key: str) -> bool:
    return isinstance(data, list) and all(isinstance(row, dict) and isinstance(row.get(key), str) for row in data)


def data_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    result = dict(prior)
    token = getattr(ctx.credential, "token", None) if prior.get("token_valid") else None
    budget = ReadBudget(ctx.args)
    requested: list[str] = []
    states: list[str] = []
    discover = bool(getattr(ctx.args, "discover", False))
    for name, path, key in (
        ("jobs", _job_path(ctx), "ID"),
        ("nodes", "/v1/nodes", "ID"),
        ("members", "/v1/agent/members", "Name"),
    ):
        if not getattr(ctx.args, "show_" + name, False) and not (name == "jobs" and discover):
            continue
        requested.append(name)
        rows: list[dict[str, Any]] = []
        next_seen: set[str] = set()
        page_path = path
        state = "unknown"
        any_page_allowed = False
        complete = False
        error: str | None = None
        while budget.allowed():
            response = _get(ctx, prior["api_endpoint"], page_path, token)
            if not budget.consume(response):
                error = "response or byte limit"
                break
            data = json_value(response)
            if name == "members" and isinstance(data, dict):
                data = data.get("Members")
            state = access(response, _rows(data, key))
            if state != "allowed":
                error = f"HTTP {response.status}" if response.status != 200 else "invalid collection"
                break
            any_page_allowed = True
            remaining = 5000 - len(rows)
            rows.extend(data[:remaining])
            if len(data) > remaining:
                budget.partial = True
                error = "item limit"
                break
            next_token = next((value for k, value in response.headers.items() if k.lower() == "x-nomad-nexttoken"), "")
            if not next_token:
                complete = True
                break
            if next_token in next_seen or len(rows) >= 5000:
                budget.partial = True
                error = "pagination repeated a token" if next_token in next_seen else "item limit"
                break
            next_seen.add(next_token)
            page_path = path + ("&" if "?" in path else "?") + urlencode({"next_token": next_token})
        budget.partial |= not complete
        if any_page_allowed:
            state = "allowed"
        states.append(state)
        result[name + "_access"] = state
        result[name + "_partial"] = not complete
        if not complete:
            result[name + "_error"] = error or "discovery budget reached"
        if state == "allowed" or rows:
            result[name] = rows
        if name == "jobs" and discover:
            specs: list[dict[str, Any]] = []
            for row in rows:
                if not budget.allowed():
                    break
                namespace = row.get("Namespace") or _namespace(ctx)
                if not safe_path(namespace) or namespace == "*" or not safe_path(row["ID"]):
                    budget.partial = True
                    continue
                response = _get(ctx, prior["api_endpoint"], _job_path(ctx, row["ID"], namespace), token)
                if not budget.consume(response):
                    break
                spec = json_value(response)
                if response.status == 200 and isinstance(spec, dict) and spec.get("ID") == row["ID"]:
                    specs.append({"namespace": namespace, "job": row["ID"], "spec": spec})
                else:
                    budget.partial = True
            result["job_specs"] = specs
    result["inventory_requested"] = requested
    result["inventory_status"] = (
        "complete"
        if states and all(s == "allowed" for s in states) and not budget.partial
        else "partial"
        if any(s == "allowed" for s in states)
        else "unavailable"
    )
    result["job_discovery_partial"] = budget.partial or (discover and any(s != "allowed" for s in states))
    if getattr(ctx.args, "probe_submit", False):
        from .execution import probe_submit

        result["submit_probe"] = probe_submit(ctx, prior)
        result["submit_access"] = result["submit_probe"]["access"]
        if result["submit_probe"]["access"] == "unverified" or result["submit_probe"]["cleanup"] == "failed":
            result["operational_failure"] = True
    if getattr(ctx.args, "execute", None):
        from ..execution_api import finish
        from .execution import execute

        result["execution"] = finish(execute(ctx, prior), max_bytes=ctx.args.execute_max_bytes)
        result["execute_verified"] = result["execution"]["executed"]
        if result["execution"].get("status") == "partial":
            result["partial"] = True
        if not result["execute_verified"] or result["execution"].get("cleanup") == "failed":
            result["operational_failure"] = True
    return result
