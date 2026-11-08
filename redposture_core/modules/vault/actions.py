"""Bounded, read-only Vault API probes."""

from __future__ import annotations

import hmac
import re
from contextlib import nullcontext
from typing import Any
from urllib.parse import quote

from ...clients.http_api import (
    HttpResponse,
    build_http_target_url,
    current_http_target_binding,
    http_response_requires_https,
)
from ...clients.scoped_http import ScopedHttpClient
from ...detection_steps import DetectionRequests, run_requests
from ...discovery_frontier import DiscoveryFrontier
from ...discovery_sources import SourceManifest
from ...discovery_spool import SpoolingRecords
from ...discovery_values import DiskBackedText
from ...json_stream import JSONPath, JSONScalarStream
from ...storage_discovery import DiscoveryCollector
from ..token_api import ReadBudget, json_value
from .policy import safe_vault_path
from .types import DetectionStatus

host_stage = None

_CAP = 4 * 1024 * 1024
_MAX_KEYS = 5000


def _enqueue_kv_key(frontier: DiscoveryFrontier, mount: str, prefix: str, key: Any) -> bool:
    if not isinstance(key, str) or not key or not safe_vault_path(key) or key.startswith("/"):
        return False
    full = prefix + key
    if not safe_vault_path(mount + full):
        return False
    frontier.enqueue(("d:" if key.endswith("/") else "k:") + full)
    return True


def _stream_kv_keys(
    client: ScopedHttpClient,
    base: str,
    list_path: str,
    token: str | None,
    mount: str,
    prefix: str,
    budget: ReadBudget,
    frontier: DiscoveryFrontier,
) -> bool:
    stream = getattr(client.pool, "request_stream", None)
    if not callable(stream) or not budget.allowed():
        return False
    fragments: list[str] = []
    array_seen = False
    invalid_key = False
    status_ok = False

    def on_string(path: JSONPath, value: str, complete: bool) -> None:
        nonlocal invalid_key
        if len(path) != 3 or path[:2] != ("data", "keys") or not isinstance(path[2], int):
            return
        fragments.append(value)
        if complete:
            if not _enqueue_kv_key(frontier, mount, prefix, "".join(fragments)):
                invalid_key = True
            fragments.clear()

    def on_container(path: JSONPath, kind: str) -> None:
        nonlocal array_seen, invalid_key
        if path == ("data", "keys"):
            array_seen = kind == "array"
        elif len(path) == 3 and path[:2] == ("data", "keys"):
            invalid_key = True

    def on_primitive(item: tuple[JSONPath, Any]) -> None:
        nonlocal invalid_key
        if len(item[0]) == 3 and item[0][:2] == ("data", "keys"):
            invalid_key = True

    parser = JSONScalarStream(on_string, on_primitive=on_primitive, on_container=on_container)

    def on_response(status: int, headers: Any) -> None:
        nonlocal status_ok
        content_type = next((str(v).lower() for k, v in headers.items() if str(k).lower() == "content-type"), "")
        status_ok = status == 200 and "json" in content_type
        if not status_ok:
            raise ValueError("unexpected KV listing response")

    def on_chunk(chunk: bytes) -> None:
        if not budget.allowed():
            raise TimeoutError("KV listing deadline reached")
        parser.feed(chunk)

    headers = {"Accept": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    try:
        response = stream(
            "GET",
            base + list_path + "?list=true",
            on_chunk=on_chunk,
            on_response=on_response,
            chunk_size=max(1, min(budget.remaining, 64 * 1024)),
            headers=headers,
            timeout=budget.timeout(),
            deadline=budget.deadline,
            allow_cross_origin_redirects=False,
        )
        budget.calls += 1
        parser.finish()
    except (ValueError, UnicodeError, TimeoutError):
        return False
    finally:
        parser.close()
    return status_ok and response.status == 200 and not response.error and array_seen and not invalid_key


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
    client: ScopedHttpClient,
    base: str,
    path: str,
    *,
    token: str | None = None,
    method: str = "GET",
    timeout: float | None = None,
) -> HttpResponse:
    headers = {"Accept": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    return client.request(method, base + path, headers=headers, timeout=timeout)


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
    return run_requests(detect_requests(ctx), lambda base, path: _request(client, base, path))


def detect_requests(ctx: Any) -> DetectionRequests:
    transport_ok = False
    probable = False
    for index, scheme in enumerate(_scheme_order(ctx)):
        base = _base(ctx, scheme)
        response = yield (base, "/v1/sys/health")
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
        if shape and not version:
            seal = yield (base, "/v1/sys/seal-status")
            seal_data = _json(seal)
            if (
                seal.status == 200
                and seal_data is not None
                and type(seal_data.get("initialized")) is bool
                and type(seal_data.get("sealed")) is bool
                and isinstance(seal_data.get("type"), str)
            ):
                signals.append("vault.seal_status")
                if isinstance(seal_data.get("version"), str) and re.fullmatch(
                    r"v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?", seal_data["version"]
                ):
                    version = seal_data["version"]
        if data is not None and shape and len(signals) >= 2 and response.status in {200, 429, 472, 473, 501, 503}:
            initialized = data["initialized"]
            sealed = data["sealed"]
            mounts = (yield (base, "/v1/sys/mounts")) if initialized and not sealed else None
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
    client: ScopedHttpClient,
    base: str,
    path: str,
    token: str | None,
    budget: ReadBudget | None = None,
    *,
    stream_large_mounts: bool = False,
) -> tuple[list[dict[str, Any]] | None, str]:
    if budget is not None and not budget.allowed():
        return None, "unknown"
    scoped = client if budget is None else budget.scoped(client)
    response = _request(scoped, base, path, token=token, timeout=budget.timeout() if budget is not None else None)
    if (
        stream_large_mounts
        and budget is not None
        and response.status == 200
        and response.truncated
        and response.error is None
    ):
        budget.calls += 1
        streamed = _stream_mounts(client, base, token, budget)
        if streamed is not None:
            return streamed, "allowed"
        # Preserve the previous partial verdict if the attempted continuation
        # is unavailable or malformed after the capped first response.
        budget.reason = budget.reason or "byte_budget"
        budget.partial = True
        return None, "unknown"
    if budget is not None and not budget.consume(response):
        return None, "unknown"
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


def _stream_mounts(
    client: ScopedHttpClient, base: str, token: str | None, budget: ReadBudget
) -> SpoolingRecords | None:
    stream = getattr(client.pool, "request_stream", None)
    if not callable(stream) or not budget.allowed():
        return None
    root_rows = SpoolingRecords()
    data_rows = SpoolingRecords()
    root_seen = DiscoveryFrontier()
    data_seen = DiscoveryFrontier()
    active: dict[JSONPath, dict[str, Any]] = {}
    fragments: dict[JSONPath, list[str]] = {}
    skipped_descriptions: set[JSONPath] = set()
    catalog_seen = False
    invalid = False
    status_ok = False

    def mount_name(path: JSONPath) -> str | None:
        if not ((len(path) == 2 and path[0] == "data") or len(path) == 1):
            return None
        value = path[-1]
        # HTTP routing requires a string identifier. Decode its complete name
        # once per active mount instead of formatting a disk-owner repr.
        if isinstance(value, DiskBackedText):
            value = "".join(value.iter_text_chunks())
        return value if isinstance(value, str) and value.endswith("/") else None

    def on_container(path: JSONPath, kind: str) -> None:
        nonlocal catalog_seen, invalid
        if path == ("data",):
            catalog_seen = kind == "object"
            invalid |= kind != "object"
        elif (name := mount_name(path)) is not None:
            if kind != "object" or path in active:
                invalid = True
            else:
                active[path] = {"path": name, "type": None, "description": None, "options": {}}

    def on_string(path: JSONPath, value: str, final: bool) -> None:
        nonlocal invalid
        parent = path[:-1]
        if parent in active and path[-1] in {"type", "description"}:
            field = str(path[-1])
            row = active[parent]
        elif path[-2:] == ("options", "version") and path[:-2] in active:
            field = "version"
            row = active[path[:-2]]
        else:
            return
        if path in skipped_descriptions:
            if final:
                skipped_descriptions.remove(path)
            return
        parts = fragments.setdefault(path, [])
        if sum(map(len, parts)) + len(value) > 4096:
            if field != "description":
                invalid = True
            else:
                skipped_descriptions.add(path)
            fragments.pop(path, None)
            return
        parts.append(value)
        if final:
            full = "".join(fragments.pop(path, []))
            if field == "version":
                row["options"]["version"] = full
            else:
                row[field] = full

    def on_container_end(path: JSONPath, kind: str) -> None:
        nonlocal invalid
        if kind != "object" or path not in active:
            return
        row = active.pop(path)
        name = row["path"]
        rows = data_rows if len(path) == 2 else root_rows
        seen = data_seen if len(path) == 2 else root_seen
        if (
            not isinstance(name, str)
            or not safe_vault_path(name)
            or not isinstance(row["type"], str)
            or not seen.claim(name)
        ):
            invalid = True
            return
        rows.append(row, sort_key=name)

    parser = JSONScalarStream(on_string, on_container=on_container, on_container_end=on_container_end)

    def on_response(status: int, headers: Any) -> None:
        nonlocal status_ok
        content_type = next((str(v).lower() for k, v in headers.items() if str(k).lower() == "content-type"), "")
        status_ok = status == 200 and "json" in content_type
        if not status_ok:
            raise ValueError("unexpected mount listing response")

    def on_chunk(chunk: bytes) -> None:
        if not budget.allowed():
            raise TimeoutError("mount listing deadline reached")
        parser.feed(chunk)

    headers = {"Accept": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    try:
        response = stream(
            "GET",
            base + "/v1/sys/mounts",
            on_chunk=on_chunk,
            on_response=on_response,
            chunk_size=max(1, min(budget.remaining, 64 * 1024)),
            headers=headers,
            timeout=budget.timeout(),
            deadline=budget.deadline,
            allow_cross_origin_redirects=False,
        )
        budget.calls += 1
        parser.finish()
    except (ValueError, UnicodeError, TimeoutError):
        return None
    finally:
        parser.close()
        root_seen.close()
        data_seen.close()
    if not (status_ok and response.status == 200 and not response.error and not invalid and not active):
        return None
    if not catalog_seen and not root_rows:
        return None
    rows = data_rows if catalog_seen else root_rows
    rows.finish()
    return rows


def _discover_kv(
    client: ScopedHttpClient,
    base: str,
    mounts: list[dict[str, Any]],
    token: str | None,
    selected: str | None,
    budget: ReadBudget,
    collector: DiscoveryCollector,
) -> tuple[list[dict[str, Any]], int, bool, bool, list[str]]:
    items: list[dict[str, Any]] = []
    snapshot_bytes = 0
    snapshot_partial = False
    read_count = 0
    reasons: list[str] = []
    partial = False
    for mount in mounts:
        name = mount["path"]
        if isinstance(name, DiskBackedText):
            name = "".join(name.iter_text_chunks())
        if not isinstance(name, str):
            partial = True
            continue
        mount_type = mount.get("type")
        if (selected and name != selected) or mount_type not in {"kv", "cubbyhole", "generic"}:
            continue
        if not safe_vault_path(name) or name.startswith("/"):
            partial = True
            continue
        source_kind = "vault.cubbyhole" if mount_type == "cubbyhole" else "vault.kv"
        manifest = collector.source_manifest
        if manifest is not None:
            manifest.request(source_kind)
        before_errors = collector.partial_events
        before_reasons = len(reasons)
        version = str(mount.get("options", {}).get("version") or "1") if mount_type == "kv" else "1"
        listing = "metadata" if version == "2" else ""
        content = "data" if version == "2" else ""
        with collector.source_guard(manifest, source_kind) if manifest is not None else nullcontext():
            with DiscoveryFrontier() as frontier:
                frontier.enqueue("d:")
                while (queued := frontier.pop()) is not None:
                    if not budget.allowed():
                        partial = True
                        reasons.append("discover_time")
                        if manifest is not None:
                            manifest.finish(source_kind, complete=False)
                        return items, read_count, snapshot_partial, partial, reasons
                    full = queued[2:]
                    if queued.startswith("d:"):
                        list_path = (
                            f"/v1/{quote(name, safe='/')}{listing + '/' if listing else ''}{quote(full, safe='/')}"
                        )
                        response = _request(
                            budget.scoped(client), base, list_path, token=token, method="LIST", timeout=budget.timeout()
                        )
                        if response.status == 200 and response.truncated and not response.error:
                            streamed = _stream_kv_keys(client, base, list_path, token, name, full, budget, frontier)
                            if not streamed:
                                partial = True
                                if manifest is not None:
                                    manifest.finish(source_kind, complete=False)
                                reasons.append("incomplete KV key listing")
                            collector.mark_accessible_source()
                            continue
                        if not budget.consume(response):
                            if manifest is not None:
                                manifest.finish(source_kind, complete=False)
                            return items, read_count, snapshot_partial, True, ["response or byte limit"]
                        if response.status == 405 and budget.allowed():
                            response = _request(
                                budget.scoped(client),
                                base,
                                list_path + "?list=true",
                                token=token,
                                timeout=budget.timeout(),
                            )
                            if response.status == 200 and response.truncated and not response.error:
                                streamed = _stream_kv_keys(client, base, list_path, token, name, full, budget, frontier)
                                if not streamed:
                                    partial = True
                                    if manifest is not None:
                                        manifest.finish(source_kind, complete=False)
                                    reasons.append("incomplete KV key listing")
                                collector.mark_accessible_source()
                                continue
                            if not budget.consume(response):
                                if manifest is not None:
                                    manifest.finish(source_kind, complete=False)
                                return items, read_count, snapshot_partial, True, ["response or byte limit"]
                        data = _json(response)
                        if (
                            mount_type == "cubbyhole"
                            and response.status == 404
                            and not full
                            and isinstance(data, dict)
                            and data.get("errors") == []
                        ):
                            collector.mark_accessible_source()
                            continue
                        keys = (
                            data.get("data", {}).get("keys")
                            if isinstance(data, dict) and isinstance(data.get("data"), dict)
                            else None
                        )
                        if response.status != 200 or not isinstance(keys, list):
                            partial = True
                            if manifest is not None:
                                manifest.finish(source_kind, complete=False, denied=response.status in {401, 403})
                            denied = " access_denied" if response.status in {401, 403} else ""
                            reasons.append(f"{name}{full}: list {response.status or 'error'}{denied}")
                            continue
                        collector.mark_accessible_source()
                        for key in keys:
                            if not _enqueue_kv_key(frontier, name, full, key):
                                partial = True
                                if manifest is not None:
                                    manifest.finish(source_kind, complete=False)
                        continue
                    read_path = f"/v1/{quote(name, safe='/')}{content + '/' if content else ''}{quote(full, safe='/')}"
                    read = _request(budget.scoped(client), base, read_path, token=token, timeout=budget.timeout())
                    if read.status == 200 and read.truncated and not read.error:
                        if not callable(getattr(client.pool, "request_stream", None)):
                            if manifest is not None:
                                manifest.finish(source_kind, complete=False)
                            return items, read_count, snapshot_partial, True, ["incomplete KV value"]
                        headers = {"Accept": "application/json"}
                        if token:
                            headers["X-Vault-Token"] = token
                        value_path: JSONPath = ("data", "data") if version == "2" else ("data",)

                        def outside_value(path: JSONPath, prefix: JSONPath = value_path) -> bool:
                            return path[: len(prefix)] != prefix

                        source = f"kv_dump_items.{name}{full}"
                        if not collector.stream_json_scalars(
                            client.pool,
                            base + read_path,
                            source,
                            headers=headers,
                            timeout=budget.timeout(),
                            root_kind="object",
                            exclude=outside_value,
                            required_prefix=value_path,
                        ):
                            if manifest is not None:
                                manifest.finish(source_kind, complete=False)
                            return items, read_count, snapshot_partial, True, ["incomplete KV value"]
                        read_count += 1
                        if manifest is not None:
                            manifest.read(source_kind)
                        snapshot_partial = True
                        continue
                    if not budget.consume(read):
                        if manifest is not None:
                            manifest.finish(source_kind, complete=False)
                        return items, read_count, snapshot_partial, True, ["response or byte limit"]
                    body = _json(read)
                    value = body.get("data") if isinstance(body, dict) else None
                    if version == "2" and isinstance(value, dict):
                        value = value.get("data")
                    if read.status != 200 or value is None:
                        partial = True
                        if manifest is not None:
                            manifest.finish(source_kind, complete=False, denied=read.status in {401, 403})
                        denied = " access_denied" if read.status in {401, 403} else ""
                        reasons.append(f"{name}{full}: read {read.status or 'error'}{denied}")
                        continue
                    if not collector.charge(len(read.body)) or not collector.add(
                        f"kv_dump_items.{name}{full}", {full.rsplit("/", 1)[-1]: value}, charge=False
                    ):
                        if manifest is not None:
                            manifest.finish(source_kind, complete=False)
                        return items, read_count, snapshot_partial, True, ["discover_time"]
                    read_count += 1
                    if manifest is not None:
                        manifest.read(source_kind)
                    if len(items) < _MAX_KEYS and snapshot_bytes + len(read.body) <= 1024 * 1024:
                        items.append({"key": name + full, "value": value})
                        snapshot_bytes += len(read.body)
                    else:
                        snapshot_partial = True
        if manifest is not None:
            manifest.finish(
                source_kind, complete=collector.partial_events == before_errors and len(reasons) == before_reasons
            )
    return items, read_count, snapshot_partial, partial, reasons[:20]


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
    budget = ReadBudget(ctx.args, started_at=getattr(ctx, "discovery_started_at", None)) if discover else None
    collector = DiscoveryCollector("vault", ctx, prior) if discover else None
    if collector is not None:
        collector.source_manifest = SourceManifest()
        collector.source_manifest.request("vault.mounts", scope="metadata_catalog_only")
    requested: list[str] = []
    access: list[str] = []
    if show_mounts or discover:
        requested.append("mounts")
        mounts, status = _inventory_section(client, base, "/v1/sys/mounts", token, budget, stream_large_mounts=discover)
        access.append(status)
        result["mounts_access"] = status
        if collector is not None:
            assert collector.source_manifest is not None
            collector.source_manifest.finish(
                "vault.mounts", complete=mounts is not None and status == "allowed", denied=status == "denied"
            )
            if mounts is not None:
                collector.source_manifest.read("vault.mounts", len(mounts))
        if mounts is not None:
            result["mounts_count"] = len(mounts)
            result["mounts"] = mounts if show_mounts else None
            if show_mounts and isinstance(mounts, SpoolingRecords):
                result["mounts_snapshot_partial"] = True
            if discover:
                assert budget is not None
                assert collector is not None and collector.source_manifest is not None
                items, read_count, snapshot_partial, partial, reasons = _discover_kv(
                    client,
                    base,
                    mounts,
                    token,
                    getattr(ctx.args, "mount", None),
                    budget,
                    collector,
                )
                result["kv_dump_items"] = items
                result["kv_snapshot_partial"] = snapshot_partial
                result["kv_discovery_partial"] = partial
                result["kv_discovery_reasons"] = reasons
                result["kv_secrets_read"] = read_count
                if getattr(ctx.args, "mount", None) and not any(
                    item["path"] == ctx.args.mount and item.get("type") in {"kv", "generic", "cubbyhole", "transit"}
                    for item in mounts
                ):
                    result["kv_discovery_partial"] = True
                    result["kv_discovery_reasons"] = ["selected discovery mount unavailable"]
                for reason in result["kv_discovery_reasons"]:
                    collector.partial("vault/kv", reason)
                if result["kv_discovery_partial"] and not result["kv_discovery_reasons"]:
                    collector.partial("vault/kv", "incomplete")
                from .discover import discover_transit_mount

                selected = getattr(ctx.args, "mount", None)
                for mount in mounts:
                    if selected and mount.get("path") != selected:
                        continue
                    if mount.get("type") == "transit":
                        discover_transit_mount(
                            client, base, str(mount["path"]), token, budget, collector, collector.source_manifest
                        )
                    elif mount.get("type") not in {"kv", "generic", "cubbyhole", "system"}:
                        collector.source_manifest.request("vault.unsupported_engines", implemented=False)
                        collector.source_manifest.finish("vault.unsupported_engines", complete=False, unsupported=True)
                        collector.partial(
                            "vault/" + str(mount.get("path")), "unsupported_readonly_engine:" + str(mount.get("type"))
                        )
                result["content_discovery"] = collector.result()
        elif discover:
            result["kv_discovery_partial"] = True
            result["kv_discovery_reasons"] = [f"mount listing {status}"]
            assert collector is not None
            collector.partial("vault/mounts", "access_denied" if status == "denied" else "mount_catalog_unavailable")
            result["content_discovery"] = collector.result()
    if show_auth:
        requested.append("auth")
        methods, status = _inventory_section(client, base, "/v1/sys/auth", token, budget)
        access.append(status)
        result["auth_methods_access"] = status
        if methods is not None:
            result["auth_methods"] = methods
    result["inventory_status"] = (
        "complete"
        if all(item == "allowed" for item in access)
        and not result.get("kv_discovery_partial")
        and not result.get("mounts_snapshot_partial")
        else "partial"
        if "allowed" in access
        else "unavailable"
    )
    result["inventory_requested"] = requested
    if budget is not None and budget.reason is not None:
        result["discovery_budget_reason"] = budget.reason
    return result


__all__ = ["detect_record", "auth_record", "data_record"]

# Native adapters must not bypass an explicitly replaced synchronous detector.
_SYNC_DETECT_RECORD = detect_record
