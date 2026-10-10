"""Bounded, read-only Jenkins fingerprint, identity and inventory probes."""

from __future__ import annotations

import base64
import re
from typing import Any
from urllib.parse import quote, urlsplit

from ...clients.http_api import (
    HttpApiClient,
    HttpClientConfig,
    HttpResponse,
    build_http_target_url,
    current_http_target_binding,
    http_response_requires_https,
)
from ...clients.http_session import HttpSessionPool
from ...clients.scoped_http import ScopedHttpClient

_VERSION = re.compile(r"^\d+\.\d+(?:\.\d+)?$")
_MAX_JOBS = 200
_MAX_BUILDS = 5
_MAX_PLUGINS = 500
_MAX_NODES = 200
_MAX_QUEUE = 200
_MAX_ARTIFACTS = 100
_JSON_CAP = 1024 * 1024
host_stage = None  # This module uses the phase-aware audit hooks.


def _client(ctx: Any, *, allow_cross_origin_redirects: bool = False) -> HttpApiClient | ScopedHttpClient:
    pool = getattr(getattr(ctx, "lifecycle_state", None), "http", None)
    if isinstance(pool, HttpSessionPool):
        return ScopedHttpClient(pool, _JSON_CAP, allow_cross_origin_redirects)
    return HttpApiClient(
        HttpClientConfig(
            timeout=float(getattr(ctx.args, "timeout", 5.0) or 5.0),
            retries=int(getattr(ctx.args, "retries", 0) or 0),
            proxy=getattr(ctx.args, "proxy", None),
            insecure=True,
            response_size_cap=_JSON_CAP,
            allow_cross_origin_redirects=allow_cross_origin_redirects,
        )
    )


def _header(response: HttpResponse, name: str) -> str:
    return next((str(value) for key, value in response.headers.items() if key.lower() == name.lower()), "")


def _json_object(response: HttpResponse) -> dict[str, Any] | None:
    if response.status != 200 or response.error or response.truncated:
        return None
    try:
        value = response.json()
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _jenkins_api(value: dict[str, Any] | None) -> bool:
    if value is None:
        return False
    klass = value.get("_class")
    jobs = value.get("jobs")
    return (
        isinstance(klass, str) and klass in {"hudson.model.Hudson", "jenkins.model.Jenkins"} and isinstance(jobs, list)
    )


def _whoami(value: dict[str, Any] | None) -> bool:
    return (
        value is not None
        and type(value.get("authenticated")) is bool
        and isinstance(value.get("name"), str)
        and isinstance(value.get("authorities"), list)
    )


def _login(response: HttpResponse) -> bool:
    if response.status != 200 or response.truncated:
        return False
    body = response.text[:128_000].lower()
    return all(marker in body for marker in ("<form", "j_username", "j_password", "jenkins"))


def _get(client: HttpApiClient | ScopedHttpClient, base: str, path: str, basic: str | None = None) -> HttpResponse:
    headers = {"Accept": "application/json"}
    if basic:
        headers["Authorization"] = basic
    return client.get(base + path, headers=headers)


def _basic(username: str, secret: str) -> str:
    encoded = base64.b64encode(f"{username}:{secret}".encode()).decode("ascii")
    return f"Basic {encoded}"


def _base(ctx: Any, scheme: str) -> str:
    return build_http_target_url(ctx.host, ctx.port, "/", default_scheme=scheme, override_bound_scheme=True).rstrip("/")


def _scheme_order(ctx: Any) -> tuple[str, str]:
    selected = current_http_target_binding().scheme
    first = selected or ("https" if ctx.port in {443, 8443} else "http")
    return first, "http" if first == "https" else "https"


def _confirmed_base(
    base: str,
    api: HttpResponse,
    who: HttpResponse | None,
    login: HttpResponse | None,
    *,
    api_ok: bool,
    who_ok: bool,
    login_ok: bool,
) -> str:
    """Carry a confirmed safe redirect into auth/inventory, never an IdP redirect."""
    for response, suffix, confirmed in (
        (api, "/api/json", api_ok),
        (who, "/whoAmI/api/json", who_ok),
        (login, "/login", login_ok),
    ):
        if not confirmed or response is None or not response.final_url:
            continue
        parsed = urlsplit(response.final_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.path.endswith(suffix):
            continue
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path.removesuffix(suffix)}".rstrip("/")
    return base


def detect_record(ctx: Any) -> dict[str, Any]:
    client = _client(ctx, allow_cross_origin_redirects=True)
    probable = False
    transport_ok = False
    signals: list[str] = []
    for index, scheme in enumerate(_scheme_order(ctx)):
        base = _base(ctx, scheme)
        root = _get(client, base, "/")
        api = _get(client, base, "/api/json?tree=_class,jobs[name],mode,nodeDescription")
        api_data = _json_object(api)
        api_ok = _jenkins_api(api_data)
        version = next((text for item in (root, api) if _VERSION.fullmatch(text := _header(item, "X-Jenkins"))), None)
        # The API shape and version header already satisfy the existing
        # independent-signal rule. Only fetch further evidence when needed.
        who = None if api_ok and version else _get(client, base, "/whoAmI/api/json")
        who_data = _json_object(who) if who is not None else None
        who_ok = _whoami(who_data)
        login = None if api_ok and version else _get(client, base, "/login")
        responses = tuple(item for item in (root, api, who, login) if item is not None)
        transport_ok |= any(item.status > 0 for item in responses)
        version = next((text for item in responses if _VERSION.fullmatch(text := _header(item, "X-Jenkins"))), None)
        login_ok = _login(login) if login is not None else False
        current = [
            name
            for present, name in (
                (version is not None, "jenkins.version_header"),
                (api_ok, "jenkins.root_api"),
                (who_ok, "jenkins.whoami"),
                (login_ok, "jenkins.login_form"),
            )
            if present
        ]
        signals.extend(current)
        probable |= bool(current)
        if (api_ok and (version or who_ok or login_ok)) or (who_ok and login_ok) or (version and login_ok):
            anonymous_access = api_ok
            auth_required = False if anonymous_access else True if api.status in {401, 403} else None
            return {
                "host": ctx.host,
                "port": ctx.port,
                "service": "jenkins",
                "status": "open_no_auth" if anonymous_access else "auth_required" if auth_required else "detected",
                "is_jenkins": True,
                "detection_status": "confirmed",
                "detection_signals": list(dict.fromkeys(signals)),
                "auth_required": auth_required,
                "anonymous_jobs_access": False if api.status in {401, 403} else True if anonymous_access else None,
                "version": version,
                "api_endpoint": _confirmed_base(base, api, who, login, api_ok=api_ok, who_ok=who_ok, login_ok=login_ok),
            }
        # A successful unrelated HTTP response is not a reason to probe a
        # second scheme. Only transport failures or canonical HTTPS errors are.
        if (
            index == 0
            and not all(item.status == 0 for item in responses)
            and not any(http_response_requires_https(item.status, item.body) for item in responses)
        ):
            break
    status = "probable" if probable else "not_service" if transport_ok else "transport_failure"
    return {
        "host": ctx.host,
        "port": ctx.port,
        "service": "jenkins",
        "status": status,
        "is_jenkins": False,
        "detection_status": status,
        "detection_signals": list(dict.fromkeys(signals)),
    }


def auth_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    result = dict(prior)
    credential = getattr(ctx, "credential", None)
    username = getattr(credential, "username", None)
    secret = getattr(credential, "password", None)
    if not username or secret is None:
        return result
    base = str(prior.get("api_endpoint") or "")
    client = _client(ctx)
    identity = _get(client, base, "/whoAmI/api/json", _basic(username, secret))
    data = _json_object(identity)
    verified = (
        _whoami(data) and data is not None and data.get("authenticated") is True and data.get("name") != "anonymous"
    )
    result["provided_credentials_ok"] = verified
    result["credential_state"] = "valid" if verified else "invalid" if identity.status == 401 else "unknown"
    result["status"] = (
        "valid_credentials"
        if verified
        else "invalid_credentials"
        if identity.status == 401
        else "rate_limited"
        if identity.status == 429
        else "auth_required"
    )
    result["auth_http_status"] = identity.status
    result["credential_results"] = [{"username": username}]
    result["credential_password"] = "API token" if getattr(credential, "source", "") == "api_token" else secret
    if verified and data is not None:
        result["authenticated_identity"] = data["name"]
    result["credential_verification_reason"] = (
        "Jenkins whoAmI authenticated identity"
        if verified
        else "Jenkins rejected Basic credentials"
        if identity.status == 401
        else "identity unavailable or Basic authentication not supported"
    )
    if verified:
        jobs_response = _get(client, base, "/api/json?tree=jobs[name]", _basic(username, secret))
        jobs = _entries(_json_object(jobs_response), "jobs")
        result["credential_jobs_access"] = (
            "allowed" if jobs is not None else "denied" if jobs_response.status in {401, 403} else "unknown"
        )
        if jobs is not None:
            result["credential_jobs_count"] = len(jobs)
    return result


def _limit(value: Any, default: int, cap: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return min(max(value, 0), cap)
    return min(default, cap)


def _entries(data: dict[str, Any] | None, key: str) -> list[dict[str, Any]] | None:
    items = data.get(key) if data is not None else None
    if not isinstance(items, list):
        return None
    return [item for item in items if isinstance(item, dict)]


def _artifact_url(base: str, job_path: str, number: int, relative_path: str) -> str | None:
    parts = relative_path.split("/")
    if not parts or any(
        part in {"", ".", ".."} or "\\" in part or any(ord(char) < 32 for char in part) for part in parts
    ):
        return None
    return f"{base}{job_path}/{number}/artifact/" + "/".join(quote(part, safe="") for part in parts)


def _artifact_size(client: HttpApiClient | ScopedHttpClient, url: str, basic: str | None) -> int | None:
    headers = {"Authorization": basic} if basic else None
    response = client.request("HEAD", url, headers=headers)
    size = _header(response, "Content-Length")
    return int(size) if response.status == 200 and size.isdecimal() else None


def _busy_executors(node: dict[str, Any]) -> int | None:
    regular = node.get("executors")
    one_off = node.get("oneOffExecutors", [])
    if not isinstance(regular, list) or not isinstance(one_off, list):
        return None
    executors = regular + one_off
    if any(not isinstance(item, dict) or "currentExecutable" not in item for item in executors):
        return None
    return sum(item["currentExecutable"] is not None for item in executors)


def data_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    result = dict(prior)
    args = ctx.args
    show_artifacts = bool(getattr(args, "show_artifacts", False))
    show_builds = bool(getattr(args, "show_builds", False) or show_artifacts)
    show_jobs = bool(getattr(args, "show_jobs", False) or show_builds)
    show_plugins = bool(getattr(args, "show_plugins", False) or getattr(args, "enum_cve", False))
    show_nodes = bool(getattr(args, "show_nodes", False))
    show_queue = bool(getattr(args, "show_queue", False))
    if not (show_jobs or show_plugins or show_nodes or show_queue):
        return result
    base = str(prior.get("api_endpoint") or "")
    client = _client(ctx)
    credential = getattr(ctx, "credential", None)
    authenticated = prior.get("provided_credentials_ok") is True
    basic = (
        _basic(credential.username, credential.password)
        if authenticated and credential is not None and credential.username and credential.password is not None
        else None
    )
    if show_jobs:
        result["jobs_requested"] = show_jobs
        result["builds_requested"] = show_builds
        response = _get(client, base, "/api/json?tree=jobs[name,url,color,lastBuild[number,result]]", basic)
        jobs = _entries(_json_object(response), "jobs")
        if jobs is None:
            result["jobs_access"] = "denied" if response.status in {401, 403} else "unknown"
        else:
            selected = sorted(
                {
                    str(item["name"]): item for item in jobs if isinstance(item.get("name"), str) and item["name"]
                }.values(),
                key=lambda item: str(item["name"]),
            )[: _limit(getattr(args, "show_jobs", None), _MAX_JOBS, _MAX_JOBS)]
            result["jobs"] = [{"name": item["name"], "color": item.get("color")} for item in selected]
            result["jobs_access"] = "allowed"
            result["jobs_count"] = len(jobs)
            if show_builds:
                builds: list[dict[str, Any]] = []
                artifacts: list[dict[str, Any]] = []
                artifact_limit = _limit(getattr(args, "show_artifacts", None), _MAX_ARTIFACTS, _MAX_ARTIFACTS)
                per_job = _limit(getattr(args, "show_builds", None), _MAX_BUILDS, _MAX_BUILDS)
                for item in selected:
                    path = "/job/" + quote(str(item["name"]), safe="")
                    build_fields = (
                        "number,result,artifacts[fileName,relativePath]" if show_artifacts else "number,result"
                    )
                    detail = _get(client, base, path + f"/api/json?tree=builds[{build_fields}]{{0,{per_job}}}", basic)
                    for build in _entries(_json_object(detail), "builds") or []:
                        if isinstance(build.get("number"), int) and not isinstance(build.get("number"), bool):
                            builds.append(
                                {"job": item["name"], "number": build["number"], "result": build.get("result")}
                            )
                            if show_artifacts:
                                for artifact in _entries(build, "artifacts") or []:
                                    if len(artifacts) >= artifact_limit:
                                        break
                                    name = artifact.get("fileName")
                                    relative_path = artifact.get("relativePath")
                                    if not isinstance(name, str) or not name or not isinstance(relative_path, str):
                                        continue
                                    url = _artifact_url(base, path, build["number"], relative_path)
                                    if url is None:
                                        continue
                                    artifacts.append(
                                        {
                                            "job": item["name"],
                                            "build": build["number"],
                                            "name": name,
                                            "path": relative_path,
                                            "size_bytes": _artifact_size(client, url, basic),
                                        }
                                    )
                result["builds"] = builds
                result["builds_count"] = len(builds)
                if show_artifacts:
                    result["artifacts_requested"] = True
                    result["artifacts"] = artifacts
                    result["artifacts_count"] = len(artifacts)
        if jobs is None and show_artifacts:
            result["artifacts_requested"] = True
            result["artifacts_access"] = result["jobs_access"]
        if jobs is None and show_builds:
            result["builds_access"] = result["jobs_access"]
    if show_plugins:
        result["plugins_requested"] = bool(getattr(args, "show_plugins", False))
        response = _get(client, base, "/pluginManager/api/json?tree=plugins[shortName,version,active]", basic)
        plugins = _entries(_json_object(response), "plugins")
        if plugins is None:
            result["plugins_access"] = "denied" if response.status in {401, 403} else "unknown"
        else:
            valid = [
                {"short_name": item["shortName"], "version": item["version"], "active": item.get("active")}
                for item in plugins
                if isinstance(item.get("shortName"), str) and isinstance(item.get("version"), str)
            ]
            valid.sort(key=lambda item: item["short_name"])
            result["plugins"] = valid[: _limit(getattr(args, "show_plugins", None), _MAX_PLUGINS, _MAX_PLUGINS)]
            result["plugins_access"] = "allowed"
            result["plugins_count"] = len(valid)
    if show_nodes:
        result["nodes_requested"] = True
        response = _get(
            client,
            base,
            "/computer/api/json?tree=computer[displayName,offline,temporarilyOffline,numExecutors,executors[currentExecutable[url]],oneOffExecutors[currentExecutable[url]]]",
            basic,
        )
        nodes = _entries(_json_object(response), "computer")
        if nodes is None:
            result["nodes_access"] = "denied" if response.status in {401, 403} else "unknown"
        else:
            selected_nodes = nodes[: _limit(getattr(args, "show_nodes", None), _MAX_NODES, _MAX_NODES)]
            result["nodes"] = [
                {
                    "name": item.get("displayName"),
                    "offline": item.get("offline") if type(item.get("offline")) is bool else None,
                    "executors": item.get("numExecutors") if type(item.get("numExecutors")) is int else None,
                    "busy": _busy_executors(item),
                }
                for item in selected_nodes
                if isinstance(item.get("displayName"), str)
            ]
            result["nodes_count"] = len(nodes)
            result["nodes_access"] = "allowed"
    if show_queue:
        result["queue_requested"] = True
        response = _get(client, base, "/queue/api/json?tree=items[id,task[name,url],why,inQueueSince]", basic)
        queue = _entries(_json_object(response), "items")
        if queue is None:
            result["queue_access"] = "denied" if response.status in {401, 403} else "unknown"
        else:
            result["queue"] = [
                {
                    "id": item.get("id") if type(item.get("id")) is int else None,
                    "task": task.get("name"),
                    "why": reason[:300] if isinstance(reason := item.get("why"), str) else None,
                }
                for item in queue[: _limit(getattr(args, "show_queue", None), _MAX_QUEUE, _MAX_QUEUE)]
                if isinstance(task := item.get("task"), dict) and isinstance(task.get("name"), str)
            ]
            result["queue_count"] = len(queue)
            result["queue_access"] = "allowed"
    return result


__all__ = ["detect_record", "auth_record", "data_record"]
