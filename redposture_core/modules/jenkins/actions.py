"""Bounded, read-only Jenkins fingerprint, identity and inventory probes."""

from __future__ import annotations

import base64
import json
import re
import threading
import time
from collections.abc import Iterable, Iterator, Mapping
from contextlib import closing
from dataclasses import replace
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
from ...clients.scoped_http import HttpLifecycleState, ScopedHttpClient
from ...detection_steps import DetectionRequests, run_requests
from ...discovery_frontier import DiscoveryFrontier
from ...discovery_spool import SpoolingFindings, SpoolingRecords
from ...html_fingerprint import markup_evidence
from ...storage_discovery import DiscoveryCollector

_VERSION = re.compile(r"^\d+\.\d+(?:\.\d+)?$")
_MAX_JOBS = 200
_MAX_BUILDS = 5
_MAX_PLUGINS = 500
_MAX_NODES = 200
_MAX_QUEUE = 200
_MAX_ARTIFACTS = 100
_JSON_CAP = 1024 * 1024
host_stage = None  # This module uses the phase-aware audit hooks.


class JenkinsLifecycleState(HttpLifecycleState):
    """One small anonymous proof, scoped to the endpoint and live transport."""

    def __init__(self, http: HttpSessionPool | None) -> None:
        super().__init__(http)
        self._anonymous_lock = threading.Lock()
        self._anonymous_closed = False
        self._anonymous_control: tuple[tuple[Any, ...], HttpResponse] | None = None

    def _control_key(self, base: str) -> tuple[Any, ...]:
        pool = self.http
        return (
            base,
            pool,
            *(
                (getattr(pool, key, None))
                for key in ("insecure", "ca_file", "cert_file", "key_file", "proxy", "timeout")
            ),
        )

    def remember_anonymous(self, base: str, response: HttpResponse) -> None:
        # These are memo limits, never response-reading limits. A larger or
        # ambiguous control is fetched normally during credential verification.
        usable = (
            not response.error
            and not response.truncated
            and len(response.body) <= 16_384
            and sum(len(key) + len(value) for key, value in response.headers.items()) <= 8192
            and response.request_url == base + "/whoAmI/api/json"
            and response.final_url == base + "/whoAmI/api/json"
            and (response.status in {401, 403} or _whoami(_json_object(response)))
            and not _auth_stop_reason(response)
        )
        with self._anonymous_lock:
            if self._anonymous_closed:
                return
            self._anonymous_control = (
                (self._control_key(base), replace(response, headers=dict(response.headers))) if usable else None
            )

    def anonymous_control(self, base: str) -> HttpResponse | None:
        with self._anonymous_lock:
            if not self._anonymous_closed and self._anonymous_control is not None:
                key, response = self._anonymous_control
                if key == self._control_key(base):
                    return response
            return None

    def discard_anonymous(self) -> None:
        with self._anonymous_lock:
            self._anonymous_control = None

    def close(self) -> None:
        with self._anonymous_lock:
            self._anonymous_closed = True
            self._anonymous_control = None
        super().close()


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
    if response.status != 200 or response.error or response.truncated:
        return False
    page = markup_evidence(response.text[:128_000])
    return bool(
        page is not None
        and re.search(r"\bjenkins\b", " ".join(page.visible), re.I)
        and any({"j_username", "j_password"}.issubset(form.inputs) for form in page.forms)
    )


def _get(client: HttpApiClient | ScopedHttpClient, base: str, path: str, basic: str | None = None) -> HttpResponse:
    headers = {"Accept": "application/json"}
    if basic:
        headers["Authorization"] = basic
    return client.get(base + path, headers=headers)


def _get_discovery(
    client: HttpApiClient | ScopedHttpClient,
    base: str,
    path: str,
    basic: str | None,
    collector: DiscoveryCollector,
    *,
    allow_truncated: bool = False,
) -> HttpResponse | None:
    cap = collector.cap(_JSON_CAP)
    if not cap:
        return None
    if isinstance(client, ScopedHttpClient):
        bounded: HttpApiClient | ScopedHttpClient = ScopedHttpClient(
            client.pool, cap, client.allow_cross_origin_redirects
        )
    elif isinstance(client, HttpApiClient):
        bounded = HttpApiClient(replace(client.config, response_size_cap=cap))
    else:
        bounded = client
    if isinstance(bounded, (ScopedHttpClient, HttpApiClient)):
        headers = {"Accept": "application/json"}
        if basic:
            headers["Authorization"] = basic
        timeout = max(0.001, collector.deadline - time.monotonic())
        response = bounded.get(base + path, headers=headers, timeout=timeout)
    else:
        response = _get(bounded, base, path, basic)
    if response.truncated or len(response.body) > cap:
        if not collector.charge(min(len(response.body), cap)):
            return None
        if not allow_truncated:
            collector.partial(path, "byte_budget")
            return None
        return response
    if not collector.charge(len(response.body)):
        return None
    return response


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
    return run_requests(detect_requests(ctx), lambda base, path: _get(client, base, path))


def detect_requests(ctx: Any) -> DetectionRequests:
    state = getattr(ctx, "lifecycle_state", None)
    if isinstance(state, JenkinsLifecycleState):
        state.discard_anonymous()
    probable = False
    transport_ok = False
    signals: list[str] = []
    for index, scheme in enumerate(_scheme_order(ctx)):
        base = _base(ctx, scheme)
        root = yield (base, "/")
        api = yield (base, "/api/json?tree=_class,jobs[name],mode,nodeDescription")
        api_data = _json_object(api)
        api_ok = _jenkins_api(api_data)
        version = next((text for item in (root, api) if _VERSION.fullmatch(text := _header(item, "X-Jenkins"))), None)
        # The API shape and version header already satisfy the existing
        # independent-signal rule. Only fetch further evidence when needed.
        who = None if api_ok and version else (yield (base, "/whoAmI/api/json"))
        who_data = _json_object(who) if who is not None else None
        who_ok = _whoami(who_data)
        login = None if api_ok and version else (yield (base, "/login"))
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
            confirmed_base = _confirmed_base(base, api, who, login, api_ok=api_ok, who_ok=who_ok, login_ok=login_ok)
            state = getattr(ctx, "lifecycle_state", None)
            if isinstance(state, JenkinsLifecycleState) and who is not None:
                state.remember_anonymous(confirmed_base, who)
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
                "api_endpoint": confirmed_base,
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


_SYNC_DETECT_RECORD = detect_record


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
    evidence = identity
    safety_reason = _auth_stop_reason(identity)
    data = _json_object(identity)
    identity_observed = (
        _whoami(data) and data is not None and data.get("authenticated") is True and data.get("name") != "anonymous"
    )
    verified = False
    if identity_observed and data is not None and not safety_reason:
        state = getattr(ctx, "lifecycle_state", None)
        anonymous = state.anonymous_control(base) if isinstance(state, JenkinsLifecycleState) else None
        if anonymous is None:
            anonymous = _get(client, base, "/whoAmI/api/json")
            if isinstance(state, JenkinsLifecycleState):
                state.remember_anonymous(base, anonymous)
        if _auth_stop_reason(anonymous):
            evidence = anonymous
            safety_reason = _auth_stop_reason(anonymous)
        anonymous_data = _json_object(anonymous)
        verified = anonymous.status in {401, 403} or (
            _whoami(anonymous_data)
            and anonymous_data is not None
            and (anonymous_data.get("authenticated") is False or anonymous_data.get("name") != data.get("name"))
        )
    rejected = identity.status == 401 and not safety_reason and not identity.error
    verified = verified and not safety_reason
    result["credential_state"] = "valid" if verified else "invalid" if rejected else "unknown"
    result["provided_credentials_ok"] = True if verified else False if rejected else None
    result["status"] = (
        "valid_credentials"
        if verified
        else "invalid_credentials"
        if rejected
        else safety_reason
        if safety_reason
        else "auth_required"
    )
    result["auth_http_status"] = evidence.status
    result["auth_error_detail"] = evidence.error
    result["auth_response_body"] = evidence.text
    result["auth_retry_after"] = _header(evidence, "Retry-After") or None
    if safety_reason:
        result["credential_stop_reason"] = safety_reason
    result["credential_results"] = [{"username": username}]
    result["credential_password"] = secret
    result["credential_source"] = getattr(credential, "source", "provided")
    if identity_observed and data is not None:
        result["authenticated_identity"] = data["name"]
    result["credential_verification_reason"] = (
        "Jenkins whoAmI authenticated identity"
        if verified
        else "Jenkins rejected Basic credentials"
        if rejected
        else f"{safety_reason}: HTTP {evidence.status}"
        + (f"; Retry-After={result['auth_retry_after']}" if result["auth_retry_after"] else "")
        if safety_reason
        else evidence.error
        if evidence.error
        else "observed identity does not establish credential-specific access"
        if identity_observed
        else "identity unavailable or Basic authentication not supported"
    )
    if verified:
        if not result.get("version") and _VERSION.fullmatch(version := _header(identity, "X-Jenkins")):
            result["version"] = version
        jobs_response = _get(client, base, "/api/json?tree=jobs[name]", _basic(username, secret))
        jobs_stop = _auth_stop_reason(jobs_response)
        if jobs_stop:
            result["credential_stop_reason"] = jobs_stop
            result["auth_retry_after"] = _header(jobs_response, "Retry-After") or None
            result["auth_error_detail"] = jobs_response.error
            result["auth_response_body"] = jobs_response.text
        jobs = _entries(_json_object(jobs_response), "jobs")
        result["credential_jobs_access"] = (
            "allowed" if jobs is not None else "denied" if jobs_response.status in {401, 403} else "unknown"
        )
        if jobs is not None:
            result["credential_jobs_count"] = len(jobs)
    return result


def _auth_stop_reason(response: HttpResponse) -> str | None:
    """Recognize explicit throttling/lockout evidence before judging a pair."""
    if response.status == 429:
        return "rate_limited"
    message = (str(response.error or "") + " " + response.text).lower()
    if any(
        marker in message
        for marker in (
            "account locked",
            "account has been locked",
            "account is locked",
            "locked out",
            "too many login attempts",
        )
    ):
        return "account_locked"
    if any(marker in message for marker in ("too many requests", "rate limit exceeded", "rate limited")):
        return "rate_limited"
    return None


def _limit(value: Any, default: int, cap: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return min(max(value, 0), cap)
    return min(default, cap)


def _entries(data: dict[str, Any] | None, key: str) -> list[dict[str, Any]] | None:
    items = data.get(key) if data is not None else None
    if not isinstance(items, list):
        return None
    return [item for item in items if isinstance(item, dict)]


def _discovery_jobs(
    client: HttpApiClient | ScopedHttpClient,
    base: str,
    path: str,
    basic: str | None,
    collector: DiscoveryCollector,
) -> tuple[list[dict[str, Any]] | None, HttpResponse | None]:
    """Retry an oversized Jenkins tree response in verified index ranges."""
    response = _get_discovery(client, base, path, basic, collector, allow_truncated=True)
    jobs = _entries(_json_object(response) if response is not None else None, "jobs")
    if jobs is not None or response is None or response.status != 200 or response.error or not response.truncated:
        return _job_catalog(jobs) if jobs is not None else None, response
    page_size = 100
    offset = 0
    collected = SpoolingRecords()

    def retained_jobs() -> SpoolingRecords | None:
        collected.finish()
        return collected if collected else None

    with DiscoveryFrontier() as seen_pages:
        while collector.allowed():
            page_path = f"{path}{{{offset},{offset + page_size}}}"
            response = _get_discovery(client, base, page_path, basic, collector, allow_truncated=True)
            if response is None:
                return retained_jobs(), response
            if response.truncated:
                if page_size == 1:
                    collector.partial(page_path, "oversized_single_job")
                    return retained_jobs(), response
                page_size = max(1, page_size // 2)
                continue
            page = _entries(_json_object(response), "jobs")
            if page is None:
                collector.partial(page_path, "invalid_job_page")
                return retained_jobs(), response
            signature = json.dumps([str(item.get("name") or "") for item in page])
            if page and not seen_pages.claim(signature):
                collector.partial(page_path, "repeated_job_page")
                return retained_jobs(), response
            for item in page:
                collected.append(item, sort_key=str(item.get("name") or ""))
            if len(page) < page_size:
                collected.finish()
                return collected, response
            offset += len(page)
    collector.partial(path, "discover_time")
    return retained_jobs(), response


def _job_catalog(jobs: Iterable[dict[str, Any]]) -> SpoolingRecords:
    catalog = SpoolingRecords()
    for item in jobs:
        catalog.append(item, sort_key=str(item.get("name") or ""))
    catalog.finish()
    return catalog


def _select_discovery_jobs(jobs: Iterable[dict[str, Any]], limit: int) -> SpoolingRecords:
    """Keep last duplicate and name order without a second full in-memory catalog."""
    selected = SpoolingRecords()
    previous: dict[str, Any] | None = None
    for item in jobs:
        name = item.get("name")
        if not isinstance(name, str) or not name:
            continue
        if previous is not None and previous["name"] != name:
            selected.append(previous)
            if len(selected) >= limit:
                previous = None
                break
        previous = item
    if previous is not None and len(selected) < limit:
        selected.append(previous)
    selected.finish()
    return selected


def _iter_discovery_queue(pending: SpoolingRecords) -> Iterator[Mapping[str, Any]]:
    """Read one queued job while permitting nested folders to append more jobs."""
    ordinal = 0
    while True:
        with closing(pending.iter_appended(ordinal)) as records:
            item = next(records, None)
        if item is None:
            return
        ordinal += 1
        yield item


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
    discover = bool(getattr(args, "discover", False))
    collector = DiscoveryCollector("jenkins", ctx, prior) if discover else None

    def incomplete(reason: str, resource: str = "jobs", *, collector_reason: str | None = None) -> None:
        result[resource + "_partial"] = True
        result.setdefault(resource + "_errors", []).append(reason)
        if discover:
            result["job_discovery_partial"] = True
            result.setdefault("discovery_errors", []).append(reason)
            if collector is not None:
                collector.partial(resource, collector_reason or reason)

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

    def stream_discovery_text(path: str, source: str) -> bool | None:
        if collector is None or not isinstance(client, ScopedHttpClient):
            return None
        pool = client.pool
        if not callable(getattr(pool, "request_stream", None)):
            return None
        headers = {"Accept": "text/plain, application/xml"}
        if basic:
            headers["Authorization"] = basic
        return collector.stream_http_content(
            pool,
            base + path,
            source,
            headers=headers,
            timeout=float(getattr(args, "timeout", 5.0) or 5.0),
            allow_cross_origin_redirects=False,
            prefer_specific=True,
        )

    if show_jobs:
        result["jobs_requested"] = show_jobs
        result["builds_requested"] = show_builds
        job_tree = (
            "jobs[name,url,color,_class,firstBuild[number],lastBuild[number,result]]"
            if discover
            else "jobs[name,url,color,lastBuild[number,result]]"
        )
        if collector is not None:
            jobs, response = _discovery_jobs(client, base, "/api/json?tree=" + job_tree, basic, collector)
        else:
            response = _get(client, base, "/api/json?tree=" + job_tree, basic)
            jobs = _entries(_json_object(response), "jobs")
        if jobs is None:
            result["jobs_access"] = "denied" if response is not None and response.status in {401, 403} else "unknown"
            incomplete(
                "jobs list unavailable",
                collector_reason="access_denied" if response is not None and response.status in {401, 403} else None,
            )
        else:
            discovery_job_limit = (
                len(jobs)
                if discover and type(getattr(args, "show_jobs", None)) is not int
                else _limit(getattr(args, "show_jobs", None), _MAX_JOBS, _MAX_JOBS)
            )
            selected = (
                _select_discovery_jobs(jobs, discovery_job_limit)
                if discover
                else sorted(
                    {
                        str(item["name"]): item for item in jobs if isinstance(item.get("name"), str) and item["name"]
                    }.values(),
                    key=lambda item: str(item["name"]),
                )[:discovery_job_limit]
            )
            result["jobs"] = SpoolingRecords() if discover else []
            for item in selected:
                result["jobs"].append({"name": item["name"], "color": item.get("color")})
            result["jobs_access"] = "allowed"
            result["jobs_count"] = len(jobs)
            if discover:
                assert collector is not None
                collector.mark_accessible_source()
                if len(jobs) > len(selected):
                    incomplete("job discovery item limit reached")
                job_configs = SpoolingRecords()
                build_logs = SpoolingRecords()
                build_envs = SpoolingRecords()
                pending = SpoolingRecords()
                for item in selected:
                    pending.append(
                        {"name": str(item["name"]), "path": "/job/" + quote(str(item["name"]), safe=""), "item": item}
                    )
                visited = SpoolingFindings()
                for queued in _iter_discovery_queue(pending):
                    job_name, path, item = queued["name"], queued["path"], queued["item"]
                    if not visited.add({"path": path}, identity=("job", path)):
                        incomplete(f"{job_name}: duplicate job path")
                        continue
                    if not collector.allowed():
                        incomplete("discover budget exhausted")
                        break
                    config_source = f"job.{job_name}.config"
                    config_streamed = stream_discovery_text(path + "/config.xml", config_source)
                    config_response = (
                        _get_discovery(client, base, path + "/config.xml", basic, collector)
                        if config_streamed is None
                        else None
                    )
                    if config_streamed is True:
                        pass
                    elif config_response is not None and config_response.status == 200 and not config_response.error:
                        job_configs.append({"job": job_name, "config": config_response.text})
                        collector.add(config_source, config_response.text, charge=False, prefer_specific=True)
                    else:
                        incomplete(
                            f"{job_name}: config unavailable (HTTP {config_response.status if config_response else 'budget'})"
                        )
                    if not collector.allowed():
                        break
                    job_class = str(item.get("_class") or "").lower()
                    if "folder" in job_class or "multibranch" in job_class:
                        children, children_response = _discovery_jobs(
                            client, base, path + "/api/json?tree=" + job_tree, basic, collector
                        )
                        if children is None:
                            incomplete(f"{job_name}: nested jobs unavailable")
                        else:
                            for child in children:
                                child_name = child.get("name")
                                if not isinstance(child_name, str) or not child_name:
                                    incomplete(f"{job_name}: invalid nested job")
                                    continue
                                full_name = job_name + "/" + child_name
                                pending.append(
                                    {
                                        "name": full_name,
                                        "path": path + "/job/" + quote(child_name, safe=""),
                                        "item": child,
                                    }
                                )
                                result["jobs"].append({"name": full_name, "color": child.get("color")})
                        continue
                    last = item.get("lastBuild")
                    last_number = last.get("number") if isinstance(last, dict) else None
                    first = item.get("firstBuild")
                    first_number = first.get("number") if isinstance(first, dict) else None
                    if not isinstance(last_number, int) or isinstance(last_number, bool):
                        continue
                    if not isinstance(first_number, int) or isinstance(first_number, bool):
                        incomplete(f"{job_name}: first build unavailable; older logs unverified")
                        first_number = last_number
                    if first_number < 1 or last_number < first_number:
                        incomplete(f"{job_name}: invalid build range")
                        continue
                    raw_build_limit = getattr(args, "show_builds", None)
                    explicit_build_limit = (
                        raw_build_limit
                        if type(raw_build_limit) is int and not bool(getattr(args, "_discover_implicit_builds", False))
                        else None
                    )
                    for build_index, number in enumerate(range(last_number, first_number - 1, -1)):
                        if explicit_build_limit is not None and build_index >= explicit_build_limit:
                            incomplete(f"{job_name}: build discovery item limit reached")
                            break
                        if not collector.allowed():
                            incomplete("discover budget exhausted")
                            break
                        log_source = f"job.{job_name}.build.{number}.log"
                        log_streamed = stream_discovery_text(path + f"/{number}/consoleText", log_source)
                        log_response = (
                            _get_discovery(client, base, path + f"/{number}/consoleText", basic, collector)
                            if log_streamed is None
                            else None
                        )
                        if log_streamed is True:
                            pass
                        elif log_response is not None and log_response.status == 200 and not log_response.error:
                            build_logs.append({"job": job_name, "build": number, "log": log_response.text})
                            collector.add(log_source, log_response.text, charge=False, prefer_specific=True)
                        else:
                            incomplete(
                                f"{job_name}/{number}: console unavailable (HTTP {log_response.status if log_response else 'budget'})"
                            )
                        if not collector.allowed():
                            break
                        env_path = path + f"/{number}/injectedEnvVars/api/json"
                        env_response = _get_discovery(client, base, env_path, basic, collector, allow_truncated=True)
                        if env_response is not None and env_response.truncated:
                            if isinstance(client, ScopedHttpClient) and collector.stream_json_scalars(
                                client.pool,
                                base + env_path,
                                f"job.{job_name}.build.{number}.env",
                                headers={"Accept": "application/json", **({"Authorization": basic} if basic else {})},
                                timeout=float(getattr(args, "timeout", 5.0) or 5.0),
                                root_kind="object",
                                exclude=lambda source_path: not source_path or source_path[0] != "envMap",
                                required_containers={(): "object", ("envMap",): "object"},
                                prefer_specific=True,
                            ):
                                continue
                            incomplete(f"{job_name}/{number}: environment stream unavailable")
                            continue
                        env_data = _json_object(env_response) if env_response is not None else None
                        if env_data is not None:
                            env_map = env_data.get("envMap")
                            if isinstance(env_map, dict):
                                build_envs.append({"job": job_name, "build": number, "env": env_map})
                                collector.add(
                                    f"job.{job_name}.build.{number}.env", env_map, charge=False, prefer_specific=True
                                )
                            else:
                                incomplete(f"{job_name}/{number}: invalid environment map")
                        elif env_response is None or env_response.status != 404:
                            incomplete(
                                f"{job_name}/{number}: environment unavailable (HTTP {env_response.status if env_response else 'budget'})"
                            )
                result["jobs_count"] = len(result["jobs"])
                for spool in (result["jobs"], job_configs, build_logs, build_envs, pending, visited):
                    spool.finish()
                result["job_configs"] = job_configs
                result["build_logs"] = build_logs
                result["build_envs"] = build_envs
            if show_builds:
                builds: list[dict[str, Any]] = []
                artifacts: list[dict[str, Any]] = []
                artifact_limit = _limit(getattr(args, "show_artifacts", None), _MAX_ARTIFACTS, _MAX_ARTIFACTS)
                per_job = _limit(getattr(args, "show_builds", None), _MAX_BUILDS, _MAX_BUILDS)
                for item in selected:
                    path = "/job/" + quote(str(item["name"]), safe="")
                    build_fields = (
                        "number,result,building,artifacts[fileName,relativePath]"
                        if show_artifacts
                        else "number,result,building"
                    )
                    detail = _get(client, base, path + f"/api/json?tree=builds[{build_fields}]{{0,{per_job}}}", basic)
                    child_builds = _entries(_json_object(detail), "builds")
                    if child_builds is None:
                        incomplete(f"{item['name']}: build list unavailable (HTTP {detail.status})", "builds")
                        if show_artifacts:
                            incomplete(f"{item['name']}: artifact build list unavailable", "artifacts")
                    for build in child_builds or []:
                        if isinstance(build.get("number"), int) and not isinstance(build.get("number"), bool):
                            builds.append(
                                {
                                    "job": item["name"],
                                    "number": build["number"],
                                    "result": build.get("result"),
                                    **({"building": build["building"]} if type(build.get("building")) is bool else {}),
                                }
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
    if collector is not None:
        result["content_discovery"] = collector.result()
    return result


__all__ = ["detect_record", "auth_record", "data_record"]
