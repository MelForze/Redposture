"""Bounded, read-only Vault API probes."""

from __future__ import annotations

import hmac
from collections import deque
from typing import Any
from urllib.parse import quote

from ...clients.http_api import (
    HttpResponse,
    build_http_target_url,
    current_http_target_binding,
    http_response_requires_https,
)
from ...clients.scoped_http import ScopedHttpClient
from ..token_api import ReadBudget, json_value, safe_path
from .types import DetectionStatus

host_stage = None

_CAP = 4 * 1024 * 1024
_MAX_KEYS = 5000


def _client(ctx: Any) -> ScopedHttpClient:
    pool = getattr(getattr(ctx, "lifecycle_state", None), "http", None)
    if pool is None:
        raise RuntimeError("Vault HTTP lifecycle unavailable")
    return ScopedHttpClient(pool, _CAP)


def _json(response: HttpResponse) -> dict[str, Any] | None:
    value = json_value(response)
    return value if isinstance(value, dict) else None


def _base(ctx: Any, scheme: str) -> str:
    return build_http_target_url(ctx.host, ctx.port, "/", default_scheme=scheme, override_bound_scheme=True).rstrip("/")


def _scheme_order(ctx: Any) -> tuple[str, str]:
    selected = current_http_target_binding().scheme
    first = selected or ("https" if ctx.port == 443 else "http")
    return first, "http" if first == "https" else "https"


def _request(
    client: ScopedHttpClient, base: str, path: str, *, token: str | None = None, method: str = "GET"
) -> HttpResponse:
    headers = {"Accept": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    return client.request(method, base + path, headers=headers)


def _vault_health(data: dict[str, Any] | None) -> bool:
    return bool(
        data is not None
        and type(data.get("initialized")) is bool
        and type(data.get("sealed")) is bool
        and type(data.get("standby")) is bool
    )


def _header(response: HttpResponse, name: str) -> str:
    return next((str(value) for key, value in response.headers.items() if key.lower() == name.lower()), "")


def detect_record(ctx: Any) -> dict[str, Any]:
    client = _client(ctx)
    transport_ok = False
    probable = False
    for index, scheme in enumerate(_scheme_order(ctx)):
        base = _base(ctx, scheme)
        response = _request(client, base, "/v1/sys/health")
        transport_ok |= response.status > 0
        data = _json(response)
        shape = _vault_health(data)
        probable |= shape
        signals = ["vault.health_shape"] if shape else []
        version = data.get("version") if data is not None and shape and isinstance(data.get("version"), str) else None
        cluster_name = (
            data.get("cluster_name")
            if data is not None and shape and isinstance(data.get("cluster_name"), str)
            else None
        )
        header = _header(response, "X-Vault-Cluster") or _header(response, "X-Vault-Index")
        if header and shape:
            signals.append("vault.header")
        if version:
            signals.append("vault.version")
        if cluster_name:
            signals.append("vault.cluster")
        # A generic health JSON is not a sufficient product fingerprint.
        if shape and not (version or cluster_name or header):
            seal = _request(client, base, "/v1/sys/seal-status")
            seal_data = _json(seal)
            if (
                seal.status == 200
                and seal_data is not None
                and type(seal_data.get("initialized")) is bool
                and type(seal_data.get("sealed")) is bool
                and isinstance(seal_data.get("type"), str)
            ):
                signals.append("vault.seal_status")
        if data is not None and shape and len(signals) >= 2 and response.status in {200, 429, 472, 473, 501, 503}:
            initialized = data["initialized"]
            sealed = data["sealed"]
            mounts = _request(client, base, "/v1/sys/mounts") if initialized and not sealed else None
            mounts_data = _json(mounts) if mounts is not None and mounts.status == 200 else None
            anonymous = bool(mounts_data and isinstance(mounts_data.get("data"), dict))
            auth_required = False if anonymous else True if mounts is not None and mounts.status in {401, 403} else None
            return {
                "host": ctx.host,
                "port": ctx.port,
                "service": "vault",
                "status": "open_no_auth" if anonymous else "auth_required" if auth_required else "detected",
                "is_vault": True,
                "detection_status": "confirmed",
                "detection_signals": signals,
                "initialized": initialized,
                "sealed": sealed,
                "standby": data["standby"],
                "version": version,
                "enterprise": data.get("enterprise")
                if type(data.get("enterprise")) is bool
                else True
                if version and "+ent" in version
                else None,
                "cluster_name": cluster_name,
                "init_takeover_possible": initialized is False,
                "auth_required": auth_required,
                "anonymous_access": anonymous,
                "api_endpoint": base,
            }
        if index == 0 and response.status > 0 and not http_response_requires_https(response.status, response.body):
            break
    status: DetectionStatus = "probable" if probable else "not_service" if transport_ok else "transport_failure"
    return {
        "host": ctx.host,
        "port": ctx.port,
        "service": "vault",
        "status": status,
        "is_vault": False,
        "detection_status": status,
    }


def auth_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    result = dict(prior)
    credential = getattr(ctx, "credential", None)
    token = getattr(credential, "token", None)
    if not token:
        return result
    response = _request(_client(ctx), str(prior["api_endpoint"]), "/v1/auth/token/lookup-self", token=token)
    data = _json(response)
    identity = data.get("data") if isinstance(data, dict) else None
    valid = bool(
        response.status == 200
        and isinstance(identity, dict)
        and isinstance(identity.get("id"), str)
        and hmac.compare_digest(identity["id"].encode(), token.encode())
        and isinstance(identity.get("policies"), list)
    )
    errors = data.get("errors") if isinstance(data, dict) else None
    invalid = (
        response.status in {400, 401, 403}
        and isinstance(errors, list)
        and any(isinstance(item, str) and "invalid token" in item.lower() for item in errors)
    )
    result["token_valid"] = True if valid else False if invalid else None
    result["provided_credentials_ok"] = result["token_valid"]
    result["credential_state"] = "valid" if valid else "invalid" if invalid else "unverified"
    result["credential_verification_reason"] = (
        "lookup-self returned token identity"
        if valid
        else "Vault explicitly rejected token"
        if invalid
        else "lookup-self did not verify token"
    )
    result["auth_http_status"] = response.status
    result["status"] = (
        "valid_credentials"
        if valid
        else "invalid_credentials"
        if invalid
        else "rate_limited"
        if response.status == 429
        else prior["status"]
    )
    if valid and isinstance(identity, dict):
        result["token_policies"] = [str(value) for value in identity["policies"] if isinstance(value, str)][:100]
        result["token_ttl"] = identity.get("ttl") if type(identity.get("ttl")) is int else None
        result["token_renewable"] = identity.get("renewable") if type(identity.get("renewable")) is bool else None
        result["weak_token_accepted"] = getattr(credential, "source", "") == "default"
    return result


def _inventory_section(
    client: ScopedHttpClient, base: str, path: str, token: str | None
) -> tuple[list[dict[str, Any]] | None, str]:
    response = _request(client, base, path, token=token)
    data = _json(response)
    entries = data.get("data", data) if isinstance(data, dict) else None
    if response.status == 200 and isinstance(entries, dict):
        rows: list[dict[str, Any]] = []
        for name, item in sorted(entries.items()):
            if not isinstance(name, str) or not isinstance(item, dict):
                continue
            rows.append(
                {
                    "path": name,
                    "type": item.get("type") if isinstance(item.get("type"), str) else None,
                    "description": item.get("description") if isinstance(item.get("description"), str) else None,
                    "options": item.get("options") if isinstance(item.get("options"), dict) else {},
                }
            )
        return rows, "allowed"
    return None, "denied" if response.status in {401, 403} else "rate_limited" if response.status == 429 else "unknown"


def _discover_kv(
    client: ScopedHttpClient,
    base: str,
    mounts: list[dict[str, Any]],
    token: str | None,
    selected: str | None,
    budget: ReadBudget,
) -> tuple[list[dict[str, Any]], bool, list[str]]:
    items: list[dict[str, Any]] = []
    reasons: list[str] = []
    partial = False
    for mount in mounts:
        name = str(mount["path"])
        if (selected and name != selected) or mount.get("type") != "kv":
            continue
        if not safe_path(name) or name.startswith("/"):
            partial = True
            continue
        version = str(mount.get("options", {}).get("version") or "1")
        listing = "metadata" if version == "2" else ""
        content = "data" if version == "2" else ""
        pending = deque([""])
        seen: set[str] = set()
        read_keys: set[str] = set()
        while pending:
            if len(items) >= _MAX_KEYS or not budget.allowed():
                partial = True
                reasons.append("safety limit reached")
                return items, partial, reasons
            prefix = pending.popleft()
            if prefix in seen:
                continue
            seen.add(prefix)
            list_path = f"/v1/{quote(name, safe='/')}{listing + '/' if listing else ''}{quote(prefix, safe='/')}"
            response = _request(client, base, list_path, token=token, method="LIST")
            if not budget.consume(response):
                return items, True, ["response or byte limit"]
            if response.status == 405 and budget.allowed():
                response = _request(client, base, list_path + "?list=true", token=token)
                if not budget.consume(response):
                    return items, True, ["response or byte limit"]
            data = _json(response)
            keys = (
                data.get("data", {}).get("keys")
                if isinstance(data, dict) and isinstance(data.get("data"), dict)
                else None
            )
            if response.status != 200 or not isinstance(keys, list):
                partial = True
                reasons.append(f"{name}{prefix}: list {response.status or 'error'}")
                continue
            for key in keys:
                if not isinstance(key, str) or not key or not safe_path(key) or key.startswith("/"):
                    partial = True
                    continue
                full = prefix + key
                if not safe_path(name + full):
                    partial = True
                    continue
                if key.endswith("/"):
                    if len(seen) + len(pending) < _MAX_KEYS:
                        pending.append(full)
                    else:
                        partial = True
                    continue
                if full in read_keys:
                    continue
                read_keys.add(full)
                read_path = f"/v1/{quote(name, safe='/')}{content + '/' if content else ''}{quote(full, safe='/')}"
                if not budget.allowed():
                    return items, True, ["safety limit reached"]
                read = _request(client, base, read_path, token=token)
                if not budget.consume(read):
                    return items, True, ["response or byte limit"]
                body = _json(read)
                value = body.get("data") if isinstance(body, dict) else None
                if version == "2" and isinstance(value, dict):
                    value = value.get("data")
                if read.status != 200 or value is None:
                    partial = True
                    reasons.append(f"{name}{full}: read {read.status or 'error'}")
                    continue
                if len(items) >= _MAX_KEYS:
                    partial = True
                    reasons.append("safety limit reached")
                    return items, partial, reasons
                items.append({"key": name + full, "value": value})
    return items, partial, reasons[:20]


def data_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    result = dict(prior)
    show_mounts = bool(getattr(ctx.args, "show_mounts", False))
    show_auth = bool(getattr(ctx.args, "show_auth", False))
    discover = bool(getattr(ctx.args, "discover", False))
    if not (show_mounts or show_auth or discover):
        return result
    client = _client(ctx)
    base = str(prior["api_endpoint"])
    credential = getattr(ctx, "credential", None)
    token = getattr(credential, "token", None) if prior.get("token_valid") is True else None
    requested: list[str] = []
    access: list[str] = []
    if show_mounts or discover:
        requested.append("mounts")
        mounts, status = _inventory_section(client, base, "/v1/sys/mounts", token)
        access.append(status)
        result["mounts_access"] = status
        if mounts is not None:
            result["mounts"] = mounts if show_mounts else None
            if discover:
                items, partial, reasons = _discover_kv(
                    client, base, mounts, token, getattr(ctx.args, "mount", None), ReadBudget(ctx.args)
                )
                result["kv_dump_items"] = items
                result["kv_discovery_partial"] = partial
                result["kv_discovery_reasons"] = reasons
                result["kv_secrets_read"] = len(items)
                if getattr(ctx.args, "mount", None) and not any(
                    item["path"] == ctx.args.mount and item.get("type") == "kv" for item in mounts
                ):
                    result["kv_discovery_partial"] = True
                    result["kv_discovery_reasons"] = ["selected KV mount unavailable"]
        elif discover:
            result["kv_discovery_partial"] = True
            result["kv_discovery_reasons"] = [f"mount listing {status}"]
    if show_auth:
        requested.append("auth")
        methods, status = _inventory_section(client, base, "/v1/sys/auth", token)
        access.append(status)
        result["auth_methods_access"] = status
        if methods is not None:
            result["auth_methods"] = methods
    result["inventory_status"] = (
        "complete"
        if all(item == "allowed" for item in access) and not result.get("kv_discovery_partial")
        else "partial"
        if "allowed" in access
        else "unavailable"
    )
    result["inventory_requested"] = requested
    return result


__all__ = ["detect_record", "auth_record", "data_record"]
