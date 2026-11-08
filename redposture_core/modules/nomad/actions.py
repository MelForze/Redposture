"""Read-only Nomad fingerprint, ACL token proof and job inspection."""

from __future__ import annotations

import hmac
import json
import re
import uuid
from collections.abc import Mapping
from contextlib import nullcontext
from typing import Any
from urllib.parse import urlencode

from ...clients.http_api import HttpResponse, http_response_requires_https
from ...detection_steps import DetectionRequests, run_requests
from ...discovery_frontier import DiscoveryFrontier
from ...discovery_spool import SpoolingRecords
from ...html_fingerprint import markup_evidence
from ...json_stream import JSONPath
from ...storage_discovery import DiscoveryCollector
from ..token_api import ReadBudget, access, bases, json_value, path_value, request, safe_path, verdict
from .types import DetectionStatus

host_stage = None

_VERSION = re.compile(r"v?\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9._-]+)?\Z")


def _config_version(config: Any) -> str | None:
    value = config.get("Version") if isinstance(config, dict) else None
    if isinstance(value, dict):
        value = value.get("Version")
    elif isinstance(value, str) and isinstance(config, dict):
        prerelease = config.get("VersionPrerelease")
        if isinstance(prerelease, str) and prerelease and "-" not in value and "+" not in value:
            value += "-" + prerelease
    return value if isinstance(value, str) and _VERSION.fullmatch(value) else None


def _get(ctx: Any, base: str, path: str, token: str | None = None, *, budget: ReadBudget | None = None) -> Any:
    return request(ctx, base, path, header="X-Nomad-Token", token=token, budget=budget)


def _namespace(ctx: Any) -> str:
    return str(getattr(ctx.args, "namespace", "default"))


def _job_path(ctx: Any, suffix: str = "", namespace: str | None = None) -> str:
    return (
        ("/v1/job/" + path_value(suffix) if suffix else "/v1/jobs")
        + "?"
        + urlencode({"namespace": namespace or _namespace(ctx)})
    )


def detect_record(ctx: Any) -> dict[str, Any]:
    return run_requests(detect_requests(ctx), lambda base, path: _get(ctx, base, path))


def detect_requests(ctx: Any) -> DetectionRequests:
    reachable = False
    for base in bases(ctx):
        response = yield (base, "/v1/agent/self")
        reachable |= response.status > 0
        data = json_value(response)
        config = data.get("config") if isinstance(data, dict) else None
        version = _config_version(config)
        acl_data = config.get("ACL") if isinstance(config, dict) else None
        acl = acl_data.get("Enabled") if isinstance(acl_data, dict) else None
        self_shape = (
            response.status == 200
            and isinstance(version, str)
            and isinstance(config, dict)
            and (isinstance(data.get("stats"), dict) or type(acl) is bool)
        )
        leader = yield (base, "/v1/status/leader")
        leader_value = json_value(leader)
        leader_shape = (
            leader.status == 200 and isinstance(leader_value, str) and (not leader_value or ":" in leader_value)
        )
        nomad_header = any(key.lower().startswith("x-nomad-") for item in (response, leader) for key in item.headers)
        ui_shape = False
        if leader_shape and not (self_shape or nomad_header):
            ui = yield (base, "/ui/")
            page = markup_evidence(ui.text)
            ui_shape = (
                ui.status == 200
                and not ui.error
                and not ui.truncated
                and page is not None
                and page.title == "Nomad"
                and any(meta.get("name") == "nomad-ui/config/environment" for meta in page.attributes.get("meta", ()))
            )
        if leader_shape and (self_shape or nomad_header or ui_shape):
            jobs_response = yield (base, _job_path(ctx))
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
                "submit_probe_requested": bool(getattr(ctx.args, "probe_submit", False)),
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
        ver = _config_version(config)
        if ver:
            result["version"] = ver
            result["enterprise"] = "+ent" in ver
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
    budget = ReadBudget(ctx.args, started_at=getattr(ctx, "discovery_started_at", None))
    requested: list[str] = []
    states: list[str] = []
    discover = bool(getattr(ctx.args, "discover", False))
    collector = DiscoveryCollector("nomad", ctx, prior) if discover else None
    if collector is not None:
        collector.declare_sources("job_catalog_pages", "job_specs")
    job_frontier = DiscoveryFrontier() if discover else None
    job_specs: list[dict[str, Any]] = []
    job_snapshot_bytes = 0
    for name, path, key in (
        ("jobs", _job_path(ctx), "ID"),
        ("nodes", "/v1/nodes", "ID"),
        ("members", "/v1/agent/members", "Name"),
    ):
        if not getattr(ctx.args, "show_" + name, False) and not (name == "jobs" and discover):
            continue
        if getattr(ctx.args, "show_" + name, False):
            requested.append(name)
        rows: list[Mapping[str, Any]] = []
        snapshot_bytes = 0
        next_seen: set[str] = set()
        page_size = 100
        page_cursor = ""
        page_path = path + f"&per_page={page_size}" if name == "jobs" and discover else path
        page_base = page_path
        state = "unknown"
        any_page_allowed = False
        complete = False
        error: str | None = None
        snapshot_limited = False
        catalog_denied = False
        if name == "jobs" and collector is not None:
            assert collector.source_manifest is not None
            collector.source_manifest.request("nomad.job_catalog_pages", scope="selected_namespace_validated_pages")

        def observe_catalog_status(status: int) -> None:
            nonlocal catalog_denied
            catalog_denied |= status in {401, 403}

        with (
            collector.source_guard(collector.source_manifest, "nomad.job_catalog_pages")
            if name == "jobs" and collector is not None and collector.source_manifest is not None
            else nullcontext()
        ):
            while budget.allowed():
                response = _get(ctx, prior["api_endpoint"], page_path, token, budget=budget)
                catalog_denied |= response.status in {401, 403}
                if (
                    name == "jobs"
                    and discover
                    and response.status == 200
                    and response.truncated
                    and not response.error
                    and page_size > 1
                ):
                    page_size = max(1, page_size // 2)
                    page_base = path + f"&per_page={page_size}"
                    page_path = page_base + ("&" + urlencode({"next_token": page_cursor}) if page_cursor else "")
                    continue
                streamed_rows = None
                streamed_page_complete = True
                if (
                    name == "jobs"
                    and collector is not None
                    and response.status == 200
                    and response.truncated
                    and not response.error
                ):
                    pool = getattr(ctx.lifecycle_state, "http", None)
                    if callable(getattr(pool, "request_stream", None)):
                        streamed_rows = SpoolingRecords()
                        response_headers: dict[str, str] = {}
                        headers = {"Accept": "application/json"}
                        if token:
                            headers["X-Nomad-Token"] = token

                        def append_catalog_row(
                            _path: JSONPath,
                            row: Mapping[str, Any],
                            rows: SpoolingRecords | None = streamed_rows,
                        ) -> None:
                            assert rows is not None
                            rows.append(dict(row))

                        streamed_page_complete = collector.stream_json_scalars(
                            pool,
                            prior["api_endpoint"] + page_path,
                            "nomad/jobs/catalog",
                            headers=headers,
                            timeout=budget.timeout(),
                            root_kind="array",
                            exclude=lambda _path: True,
                            row_validators={
                                (): (
                                    frozenset({"ID", "Namespace", "Name", "Status", "Type"}),
                                    lambda row: (
                                        isinstance(row.get("ID"), str)
                                        and safe_path(row["ID"])
                                        and safe_path(row.get("Namespace") or _namespace(ctx))
                                    ),
                                )
                            },
                            on_row=append_catalog_row,
                            on_response_headers=response_headers.update,
                            on_status=observe_catalog_status,
                        )
                        streamed_rows.finish()
                        response = HttpResponse(200, b"[]", response_headers)
                if not budget.consume(response):
                    error = "response or byte limit"
                    break
                data = streamed_rows if streamed_rows is not None else json_value(response)
                if name == "members" and isinstance(data, dict):
                    data = data.get("Members")
                state = access(response, _rows(data, key))
                if state != "allowed":
                    error = f"HTTP {response.status}" if response.status != 200 else "invalid collection"
                    break
                next_token = next(
                    (value for k, value in response.headers.items() if k.lower() == "x-nomad-nexttoken"), ""
                )
                any_page_allowed = True
                if name == "jobs" and collector is not None:
                    assert collector.source_manifest is not None
                    collector.source_manifest.read("nomad.job_catalog_pages")
                if name == "jobs" and collector is not None:
                    collector.mark_accessible_source()
                if discover:
                    for row in data:
                        row_size = len(json.dumps(row, ensure_ascii=False).encode("utf-8"))
                        if len(rows) < 5000 and snapshot_bytes + row_size <= 1024 * 1024:
                            rows.append(row)
                            snapshot_bytes += row_size
                        else:
                            snapshot_limited = True
                else:
                    remaining = max(0, 5000 - len(rows))
                    rows.extend(data[:remaining])
                    snapshot_limited |= len(data) > remaining
                if name == "jobs" and collector is not None and job_frontier is not None:
                    for row in data:
                        if not budget.allowed():
                            budget.partial = True
                            error = "discovery budget reached"
                            break
                        namespace = row.get("Namespace") or _namespace(ctx)
                        identifier = row["ID"]
                        if not safe_path(namespace) or namespace == "*" or not safe_path(identifier):
                            budget.partial = True
                            collector.partial("nomad/jobs", "invalid job identifier or namespace")
                            continue
                        if not job_frontier.claim("k:" + namespace + "\0" + identifier):
                            continue
                        with collector.source_attempt(
                            "nomad.job_specs", scope="selected_namespace_job_specifications"
                        ) as evidence:
                            detail_path = _job_path(ctx, identifier, namespace)
                            response = _get(ctx, prior["api_endpoint"], detail_path, token, budget=budget)
                            evidence.status = response.status
                            evidence.unsupported = response.status in {404, 405, 501}
                            if response.status == 200 and response.truncated and not response.error:
                                pool = getattr(ctx.lifecycle_state, "http", None)
                                if callable(getattr(pool, "request_stream", None)):
                                    headers = {"Accept": "application/json"}
                                    if token:
                                        headers["X-Nomad-Token"] = token
                                    source = f"job_specs.{namespace}.{identifier}"
                                    streamed = collector.stream_json_scalars(
                                        pool,
                                        prior["api_endpoint"] + detail_path,
                                        source,
                                        headers=headers,
                                        timeout=budget.timeout(),
                                        root_kind="object",
                                        on_status=lambda status: setattr(evidence, "status", status),
                                        required_prefix=("ID",),
                                        expected_string=(("ID",), identifier),
                                        path_style="dot",
                                    )
                                    if streamed:
                                        evidence.accept()
                                        continue
                                    budget.partial = True
                                    collector.partial("nomad/jobs", "incomplete job specification")
                                    continue
                            if not budget.consume(response):
                                budget.partial = True
                                collector.partial("nomad/jobs", "incomplete job specification")
                                continue
                            spec = json_value(response)
                            if response.status != 200 or not isinstance(spec, dict) or spec.get("ID") != identifier:
                                budget.partial = True
                                collector.partial("nomad/jobs", f"{identifier}: HTTP {response.status or 'error'}")
                                continue
                            source = f"job_specs.{namespace}.{identifier}"
                            if not collector.add(source, spec):
                                budget.partial = True
                                error = "discovery budget reached"
                                break
                            evidence.accept()
                            if len(job_specs) < 5000 and job_snapshot_bytes + len(response.body) <= 1024 * 1024:
                                job_specs.append({"namespace": namespace, "job": identifier, "spec": spec})
                                job_snapshot_bytes += len(response.body)
                    if error:
                        break
                elif snapshot_limited:
                    budget.partial = True
                    error = "item limit"
                    break
                if not streamed_page_complete:
                    error = "incomplete streamed collection"
                    budget.partial = True
                    break
                if not next_token:
                    complete = True
                    break
                repeated = (
                    not job_frontier.claim("p:" + next_token) if job_frontier is not None else next_token in next_seen
                )
                if repeated or (len(rows) >= 5000 and not discover):
                    budget.partial = True
                    error = "pagination repeated a token" if repeated else "item limit"
                    break
                if job_frontier is None:
                    next_seen.add(next_token)
                page_cursor = next_token
                page_path = page_base + ("&" if "?" in page_base else "?") + urlencode({"next_token": next_token})
        if name == "jobs" and collector is not None:
            assert collector.source_manifest is not None
            collector.source_manifest.finish("nomad.job_catalog_pages", complete=complete, denied=catalog_denied)
        budget.partial |= not complete
        if any_page_allowed:
            state = "allowed"
        states.append(state)
        result[name + "_access"] = state
        result[name + "_partial"] = not complete or snapshot_limited
        if not complete:
            result[name + "_error"] = error or "discovery budget reached"
        elif snapshot_limited:
            result[name + "_error"] = "inventory snapshot limited to 5000 items or 1 MiB"
        if state == "allowed" or rows:
            result[name] = rows
        if name == "jobs" and discover:
            result["job_specs"] = job_specs
    result["inventory_requested"] = requested
    result["inventory_status"] = (
        "complete"
        if states
        and all(s == "allowed" for s in states)
        and not budget.partial
        and not any(result.get(name + "_partial") for name in requested)
        else "partial"
        if any(s == "allowed" for s in states)
        else "unavailable"
    )
    result["job_discovery_partial"] = budget.partial or (discover and any(s != "allowed" for s in states))
    if collector is not None:
        if job_frontier is not None:
            job_frontier.close()
        if result["job_discovery_partial"]:
            collector.partial("nomad/jobs", budget.reason or "incomplete")
        result["content_discovery"] = collector.result()
    if discover and budget.reason is not None:
        result["discovery_budget_reason"] = budget.reason
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


# Native adapters must not bypass an explicitly replaced synchronous detector.
_SYNC_DETECT_RECORD = detect_record
