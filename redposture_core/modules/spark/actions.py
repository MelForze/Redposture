"""Read-only Spark Standalone product proof and bounded UI metadata inventory."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from ...clients.http_api import http_response_requires_https
from ...detection_steps import DetectionRequests, run_requests
from ..token_api import CAP, ReadBudget, access, bases, json_value, request

_STATUS_PATH = "/v1/submissions/status/redposture-probe"
_MAX_ITEMS = 5000
_VERSION = r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9][A-Za-z0-9.\-]*)?"
host_stage = None


def _get(ctx: Any, base: str, path: str) -> Any:
    return request(ctx, base, path, header="Authorization")


def _integer(value: Any) -> bool:
    return type(value) is int and value >= 0


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and len(value) <= 4096 and not any(ord(c) < 32 for c in value)


def _worker(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and all(_text(value.get(key)) for key in ("id", "host", "state"))
        and type(value.get("port")) is int
        and 0 < value["port"] <= 65535
        and all(_integer(value.get(key)) for key in ("cores", "coresused", "memory", "memoryused"))
    )


def _app(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and all(_text(value.get(key)) for key in ("id", "name", "user", "state"))
        and _integer(value.get("cores"))
    )


def _master(data: Any) -> bool:
    if not isinstance(data, dict) or not _text(data.get("url")):
        return False
    try:
        url = urlsplit(data["url"])
        valid_url = url.scheme == "spark" and bool(url.hostname) and url.port is not None and 0 < url.port <= 65535
    except ValueError:
        return False
    return bool(
        valid_url
        and not url.username
        and not url.password
        and not url.query
        and not url.fragment
        and url.path in {"", "/"}
        and _integer(data.get("cores"))
        and isinstance(data.get("workers"), list)
        and isinstance(data.get("activeapps"), list)
        and all(_worker(row) for row in data["workers"])
        and all(_app(row) for row in data["activeapps"])
    )


def _status(data: Any) -> bool:
    return bool(
        isinstance(data, dict)
        and data.get("action") == "SubmissionStatusResponse"
        and isinstance(data.get("serverSparkVersion"), str)
        and re.fullmatch(_VERSION, data["serverSparkVersion"])
        and data.get("submissionId") == "redposture-probe"
        and type(data.get("success")) is bool
    )


def _ui_version(response: Any) -> str | None:
    if response.status != 200 or response.error or response.truncated:
        return None
    # The title supports the JSON proof; a title alone never identifies Spark.
    if not re.search(r"<title>\s*Spark Master at spark://[^<]+</title>", response.text, re.I):
        return None
    match = re.search(r'\bclass=[\'"]version[\'"][^>]*>\s*(' + _VERSION + r")\s*<", response.text)
    return match.group(1) if match else None


def detect_record(ctx: Any) -> dict[str, Any]:
    return run_requests(detect_requests(ctx), lambda base, path: _get(ctx, base, path))


def detect_requests(ctx: Any) -> DetectionRequests:
    result: dict[str, Any] = {
        "host": ctx.host,
        "port": ctx.port,
        "service": "spark",
        "is_spark": False,
        "submit_access": "unverified",
        "submit_parser_reachable": None,
    }
    if ctx.port == 7077:
        # Spark's default cluster listener speaks RPC, not HTTP. No safe native
        # fingerprint is implemented, so never send HTTP probes to this port.
        return {
            **result,
            "status": "unsupported_protocol",
            "detection_status": "unsupported_protocol",
            "reason": "7077 is the native Spark RPC port; use the Master UI or submission REST port",
        }
    reachable = False
    for base in bases(ctx):
        response = yield (base, "/json/")
        reachable |= response.status > 0
        data = json_value(response)
        if response.status == 200 and _master(data):
            ui = yield (base, "/")
            return {
                **result,
                "is_spark": True,
                "status": "open_no_auth",
                "detection_status": "confirmed",
                "detection_signals": ["spark.master_json"],
                "surface": "master_ui",
                "api_endpoint": base,
                "version": _ui_version(ui),
                "master_url": data["url"],
                "auth_required": False,
                "anonymous_access": True,
                "master_ui_access": "allowed",
                "rce_potential": False,
            }
        status_response = yield (base, _STATUS_PATH)
        reachable |= status_response.status > 0
        status = json_value(status_response)
        if status_response.status == 200 and _status(status):
            return {
                **result,
                "is_spark": True,
                "status": "open_no_auth",
                "detection_status": "confirmed",
                "detection_signals": ["spark.submission_status"],
                "surface": "submission_rest",
                "api_endpoint": base,
                "version": status["serverSparkVersion"],
                "auth_required": False,
                "anonymous_access": True,
                "submission_status_access": "allowed",
                "rce_potential": True,
            }
        # Retry TLS only for transport failure or an explicit HTTPS requirement.
        if any(
            item.status and not http_response_requires_https(item.status, item.body)
            for item in (response, status_response)
        ):
            break
    state = "not_service" if reachable else "transport_failure"
    return {**result, "status": state, "detection_status": state, "detection_signals": ["spark.probe"]}


_SYNC_DETECT_RECORD = detect_record


def auth_record(_ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    """Standalone exposes no portable username/password verifier."""
    return dict(prior)


def _probe_submit(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    if prior.get("surface") != "submission_rest":
        return {
            "access": "unavailable",
            "parser_reachable": None,
            "execution": False,
            "reason": "submission REST endpoint not confirmed",
        }
    # Apache Spark SubmitRequestServlet validates the protocol message BEFORE
    # handleSubmit (RestSubmissionServer.scala). Omitting clientSparkVersion,
    # appResource, sparkProperties, appArgs and environmentVariables prevents
    # the driver submission handler from running. Never add launch fields here.
    response = ctx.lifecycle_state.http.request(
        "POST",
        prior["api_endpoint"] + "/v1/submissions/create",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        body=b'{"action":"CreateSubmissionRequest"}',
        response_size_cap=CAP,
        retries=0,
        replay_safe=False,
        allow_cross_origin_redirects=False,
        preserve_authorization_on_cross_origin=False,
    )
    data = json_value(response)
    parser = bool(
        response.status == 400
        and isinstance(data, dict)
        and data.get("action") == "ErrorResponse"
        and isinstance(data.get("serverSparkVersion"), str)
        and re.fullmatch(_VERSION, data["serverSparkVersion"])
        and isinstance(data.get("message"), str)
        and "Malformed request:" in data["message"]
        and "Validation of message CreateSubmissionRequest failed!" in data["message"]
    )
    denied = response.status in {401, 403}
    return {
        "access": "denied" if denied else "rate_limited" if response.status == 429 else "unverified",
        "parser_reachable": True if parser else False if denied else None,
        "execution": False,
        "http_status": response.status,
        "reason": "required-field validation reached; submission permission not verified"
        if parser
        else "submission denied"
        if denied
        else "parser reachability unverified",
    }


def data_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    result = dict(prior)
    if not prior.get("is_spark"):
        return result
    requested = [name for name in ("workers", "apps") if getattr(ctx.args, "show_" + name, False)]
    discover = bool(getattr(ctx.args, "discover", False))
    result["inventory_requested"] = requested
    if requested or discover:
        budget = ReadBudget(ctx.args)
        state = "unavailable"
        data = None
        error = "Master UI metadata unavailable on submission REST endpoint"
        if prior.get("surface") == "master_ui" and budget.allowed():
            response = _get(ctx, prior["api_endpoint"], "/json/")
            consumed = budget.consume(response)
            data = json_value(response) if consumed else None
            state = access(response, _master(data))
            if not consumed:
                state = "unknown"
            error = (
                "response or byte limit"
                if not consumed
                else "invalid Master collection"
                if response.status == 200
                else f"HTTP {response.status}"
            )
        valid = state == "allowed"
        partial = not valid or budget.partial
        metadata: dict[str, Any] = {}
        for name, key in (("workers", "workers"), ("apps", "activeapps")):
            collection = data[key] if valid and isinstance(data, dict) else []
            rows = collection[:_MAX_ITEMS] if valid else None
            limited = valid and len(collection) > _MAX_ITEMS
            partial |= limited
            if rows is not None:
                metadata[name] = rows
            if name in requested:
                result[name + "_access"] = state
                result[name + "_partial"] = not valid or limited
                if rows is not None:
                    result[name] = rows
                if not valid or limited:
                    result[name + "_error"] = "item limit" if limited else error
        result["inventory_status"] = "partial" if valid and partial else "complete" if valid else "unavailable"
        if discover:
            result["content_discovery_partial"] = partial
            if valid:
                result["spark_metadata"] = metadata
    if getattr(ctx.args, "probe_submit", False):
        probe = _probe_submit(ctx, prior)
        result["submit_probe"] = probe
        result["submit_parser_reachable"] = probe["parser_reachable"]
        result["submit_access"] = probe["access"]
        if probe["access"] == "denied":
            result["rce_potential"] = False
    return result
