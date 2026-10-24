"""Jupyter Server/Notebook read-only discovery; never create a session or kernel."""

from __future__ import annotations

from collections import deque
from typing import Any
from urllib.parse import quote

from ...clients.http_api import http_response_requires_https
from ...detection_steps import DetectionRequests, run_requests
from ..token_api import ReadBudget, access, bases, json_value, request, safe_path, verdict
from .types import DetectionStatus

host_stage = None


def _get(ctx: Any, base: str, path: str, token: str | None = None) -> Any:
    return request(ctx, base, path, header="Authorization", token=token)


def _status(data: Any) -> bool:
    return (
        isinstance(data, dict)
        and all(type(data.get(key)) is int and data[key] >= 0 for key in ("connections", "kernels"))
        and all(isinstance(data.get(key), str) for key in ("started", "last_activity"))
    )


def _contents(data: Any) -> bool:
    return (
        isinstance(data, dict)
        and data.get("type") in {"directory", "notebook", "file"}
        and isinstance(data.get("path"), str)
        and isinstance(data.get("name"), str)
    )


def detect_record(ctx: Any) -> dict[str, Any]:
    return run_requests(detect_requests(ctx), lambda base, path: _get(ctx, base, path))


def detect_requests(ctx: Any) -> DetectionRequests:
    reachable = False
    for base in bases(ctx):
        response = yield (base, "/api")
        reachable |= response.status > 0
        data = json_value(response)
        version = data.get("version") if isinstance(data, dict) and response.status == 200 else None
        status_response = yield (base, "/api/status")
        status = json_value(status_response)
        status_shape = status_response.status == 200 and _status(status)
        signals = ["jupyter.api_version"] if isinstance(version, str) and version else []
        if status_shape:
            signals.append("jupyter.status")
        else:
            login = yield (base, "/login")
            text = login.text.lower()
            if (
                login.status == 200
                and "jupyter" in text
                and any(
                    marker in text for marker in ("login_form", 'name="_xsrf"', "jupyter-config-data", "jupyterhub")
                )
            ):
                signals.append("jupyter.login")
        if len(signals) >= 2:
            required = (
                False
                if status_shape
                else True
                if status_response.status in {401, 403} or "/login" in str(status_response.final_url)
                else None
            )
            kernels_response = (yield (base, "/api/kernels")) if status_shape else None
            kernels = json_value(kernels_response) if kernels_response is not None else None
            kernels_allowed = (
                kernels_response is not None
                and kernels_response.status == 200
                and isinstance(kernels, list)
                and all(isinstance(k, dict) and "id" in k and "name" in k for k in kernels)
            )
            terminals_response = yield (base, "/api/terminals")
            terminals = json_value(terminals_response)
            terminals_allowed = (
                terminals_response.status == 200
                and isinstance(terminals, list)
                and all(isinstance(t, dict) and isinstance(t.get("name"), str) for t in terminals)
            )
            return {
                "host": ctx.host,
                "port": ctx.port,
                "service": "jupyter",
                "is_jupyter": True,
                "detection_status": "confirmed",
                "detection_signals": signals,
                "version": version,
                "api_endpoint": base,
                "auth_required": required,
                "anonymous_access": status_shape,
                "anonymous_kernels_access": kernels_allowed,
                "anonymous_terminals_access": terminals_allowed,
                "rce_surfaces": [
                    name for name, allowed in (("kernel", kernels_allowed), ("terminal", terminals_allowed)) if allowed
                ],
                "rce_potential": kernels_allowed or terminals_allowed,
                "execute_verified": False,
                "status": "open_no_auth" if status_shape else "auth_required" if required else "detected",
            }
        if response.status > 0 and not http_response_requires_https(response.status, response.body):
            break
    state: DetectionStatus = "not_service" if reachable else "transport_failure"
    return {
        "host": ctx.host,
        "port": ctx.port,
        "service": "jupyter",
        "status": state,
        "detection_status": state,
        "is_jupyter": False,
    }


def auth_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    token = getattr(ctx.credential, "token", None)
    if not token:
        return dict(prior)
    response = _get(ctx, prior["api_endpoint"], "/api/status", token)
    data = json_value(response)
    # The public /api version endpoint never verifies a token. A protected
    # status endpoint becoming readable does; an already open server does not.
    protected = prior.get("auth_required") is True
    valid = protected and response.status == 200 and _status(data)
    invalid = False
    if protected and not valid and response.status != 429:
        identity_response = _get(ctx, prior["api_endpoint"], "/api/me", token)
        identity = json_value(identity_response)
        user = identity.get("identity") if isinstance(identity, dict) else None
        valid = (
            identity_response.status == 200
            and isinstance(user, dict)
            and isinstance(user.get("username"), str)
            and bool(user["username"])
        )
        # /api/me is an authenticated identity endpoint, not a resource ACL.
        invalid = (
            identity_response.status in {401, 403}
            and isinstance(identity, dict)
            and identity.get("message") in {"Forbidden", "Unauthorized"}
            and "reason" in identity
            and identity["reason"] is None
        )

        response = identity_response

    return verdict(prior, response, valid, invalid)


def data_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    result = dict(prior)
    token = getattr(ctx.credential, "token", None) if prior.get("token_valid") else None
    base = prior["api_endpoint"]
    budget = ReadBudget(ctx.args)
    states: list[str] = []
    requested: list[str] = []
    for name in ("sessions", "kernels", "terminals"):
        if not getattr(ctx.args, "show_" + name, False):
            continue
        requested.append(name)
        response = _get(ctx, base, "/api/" + name, token)
        data = json_value(response)
        valid = isinstance(data, list) and all(
            isinstance(item, dict)
            and (isinstance(item.get("name"), str) if name == "terminals" else isinstance(item.get("id"), str))
            and (isinstance(item.get("kernel"), dict) if name == "sessions" else True)
            for item in data
        )
        state = access(response, valid)
        states.append(state)
        result[name + "_access"] = state
        if state == "allowed":
            result[name] = data[:5000]
            result[name + "_partial"] = len(data) > 5000
            if result[name + "_partial"]:
                result[name + "_error"] = "bounded snapshot item limit"
                budget.partial = True
    discover = bool(getattr(ctx.args, "discover", False))
    if getattr(ctx.args, "show_contents", False) or discover:
        if getattr(ctx.args, "show_contents", False):
            requested.append("contents")
        pending = deque([str(getattr(ctx.args, "path", "")).rstrip("/")])
        seen: set[str] = set()
        rows: list[dict[str, Any]] = []
        notebooks: list[dict[str, Any]] = []
        content_state = "unknown"
        content_partial = False
        while pending and budget.allowed():
            path = pending.popleft()
            if path in seen:
                continue
            seen.add(path)
            if len(seen) > 5000:
                content_partial = True
                break
            response = _get(
                ctx, base, "/api/contents" + ("/" + quote(path, safe="/") if path else "") + "?content=1", token
            )
            if not budget.consume(response):
                content_partial = True
                break
            data = json_value(response)
            state = access(response, _contents(data))
            if len(seen) == 1:
                content_state = state
            if state != "allowed":
                content_partial = True
                continue
            if data["type"] == "directory":
                children = data.get("content")
                if not isinstance(children, list):
                    content_partial = True
                    continue
                for item in children:
                    if (
                        not _contents(item)
                        or not safe_path(item["path"])
                        or not item["path"].startswith(path + "/" if path else "")
                    ):
                        content_partial = True
                        continue
                    if len(rows) >= 5000:
                        content_partial = True
                        break
                    rows.append({key: item.get(key) for key in ("name", "path", "type", "size", "writable")})
                    if discover and item["type"] in {"notebook", "directory"}:
                        pending.append(item["path"])
            elif data["type"] == "notebook" and discover:
                if isinstance(data.get("content"), dict):
                    notebooks.append({"path": data["path"], "notebook": data["content"]})
                else:
                    content_partial = True
            else:
                rows.append({key: data.get(key) for key in ("name", "path", "type", "size", "writable")})
        states.append(content_state)
        result["contents_access"] = content_state
        if content_state == "allowed":
            result["contents"] = rows
        content_partial |= bool(pending)
        result["contents_partial"] = content_partial
        budget.partial |= content_partial
        if content_partial:
            result["contents_error"] = "incomplete content inventory or discovery budget reached"
        if discover:
            result["notebook_contents"] = notebooks
    result["inventory_requested"] = requested
    result["content_discovery_partial"] = budget.partial
    result["inventory_status"] = (
        "complete"
        if states and all(s == "allowed" for s in states) and not budget.partial
        else "partial"
        if any(s == "allowed" for s in states)
        else "unavailable"
    )
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


# Native adapters must not bypass an explicitly replaced synchronous detector.
_SYNC_DETECT_RECORD = detect_record
