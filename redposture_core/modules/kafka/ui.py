"""Read-only Provectus/Kafbat Kafka UI probes on a Kafka audit target."""

from __future__ import annotations

import hashlib
import html
import json
import re
import sqlite3
import tempfile
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from itertools import islice
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from ...clients.http_api import HttpResponse, format_http_authority, infer_http_base_path
from ...clients.http_session import HttpSessionPool
from ...detection_io import DetectCall as _DetectCall
from ...detection_io import HttpRead as _HttpRead
from ...detection_io import run_sync as _run_detect_sync
from ...discovery_frontier import DiscoveryFrontier
from ...discovery_json import DiskJSONDocument
from ...discovery_options import DEFAULT_DISCOVER_TIME, UNLIMITED_DISCOVER_BYTES
from ...discovery_sources import SourceManifest, SourceRead
from ...discovery_spool import SpoolingRecords, SpoolingStrings, SpoolingValues
from ...discovery_values import iter_json_chunks
from ...html_fingerprint import markup_evidence
from ...storage_discovery import DiscoveryCollector
from ...ui_export import UIExport
from ...utils import utc_now_iso
from . import http_surfaces
from .discovery import read_events

_AUTH_TYPES = {"DISABLED", "LOGIN_FORM", "LDAP", "OAUTH2"}
_VERSION = re.compile(r"^v?[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?$")
_CSRF = re.compile(r'name=["\']_csrf["\'][^>]*value=["\']([^"\']+)', re.I)
_MAX_CLUSTERS = 20
_MAX_TOPICS = 200
_MAX_DUMP_TOPICS = 2_000
_MAX_DUMP_MESSAGES = 10_000
_MAX_DUMP_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_DUMP_BYTES = 64 * 1024 * 1024
_MAX_DUMP_SECONDS = 300.0


@dataclass
class _UiDiscoveryBudget:
    remaining: int
    deadline: float
    reason: str | None = None


class _FullIncomplete(Exception):
    """A full Kafka UI export cannot prove that it reached the topic end."""


def _json(response: HttpResponse) -> Any:
    if response.error or response.truncated or response.status != 200:
        return None
    try:
        return response.json()
    except (ValueError, UnicodeError):
        return None


def _header(response: HttpResponse, name: str) -> str:
    return next((str(value) for key, value in response.headers.items() if key.lower() == name.lower()), "")


def _cookie(response: HttpResponse) -> str:
    value = _header(response, "set-cookie")
    return value.split(";", 1)[0] if "=" in value else ""


def _info(value: Any) -> tuple[bool, str | None, str | None]:
    if not isinstance(value, dict) or not isinstance(value.get("build"), dict):
        return False, None, None
    build = value["build"]
    version = build.get("version")
    commit = build.get("commitId") or build.get("commit")
    if not isinstance(commit, str) or not commit.strip():
        # A version field alone is generic and cannot identify Kafka UI.
        return False, None, None
    if not isinstance(version, str) and not isinstance(build.get("buildTime"), str):
        return False, None, None
    brand = "kafbat" if "kafbat" in str(value).lower() else "provectus" if "provectus" in str(value).lower() else None
    return True, version if isinstance(version, str) and _VERSION.fullmatch(version) else None, brand


def _auth_type(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    mode = value.get("authType")
    return mode if isinstance(mode, str) and mode in _AUTH_TYPES else None


def _authorization(value: Any) -> bool:
    if not isinstance(value, dict) or not isinstance(value.get("rbacEnabled"), bool):
        return False
    user = value.get("userInfo")
    return user is None or isinstance(user, dict)


def _clusters(value: Any, *, limit: int | None = _MAX_CLUSTERS) -> list[Mapping[str, Any]] | None:
    if not isinstance(value, list):
        return None
    selected: list[Mapping[str, Any]] = SpoolingRecords() if isinstance(value, SpoolingValues) else []
    for item in islice(value, limit) if limit is not None else value:
        if not isinstance(item, Mapping) or not isinstance(item.get("name"), str) or not item["name"]:
            return None
        status = item.get("status")
        if (not isinstance(status, str) or status not in {"online", "offline", "initializing"}) and not any(
            key in item for key in ("brokerCount", "topicCount", "readOnly")
        ):
            return None
        selected.append(item)
    return selected if selected else None


def _base(ctx: Any, scheme: str) -> str:
    target = getattr(ctx, "target", None)
    path = str(getattr(target, "path", "") or "")
    prefix = infer_http_base_path(
        path,
        (
            "/api/info",
            "/api/config/authentication",
            "/api/clusters",
            "/actuator/info",
            "/auth",
            "/login",
            "/topics",
            "/v3/clusters",
            "/connectors",
            "/subjects",
            "/info",
            "/ui",
        ),
    )
    return f"{scheme}://{format_http_authority(ctx.host, ctx.port)}{prefix.rstrip('/')}"


def _get(
    pool: HttpSessionPool,
    base: str,
    path: str,
    *,
    cookie: str = "",
    basic: str = "",
    budget: _UiDiscoveryBudget | None = None,
) -> HttpResponse:
    if budget is not None:
        if time.monotonic() >= budget.deadline:
            budget.reason = "discover_time"
        if budget.reason:
            return HttpResponse(status=0, body=b"", headers={}, error=budget.reason)
    response = _run_detect_sync(_get_detect_steps(pool, base, path, cookie=cookie, basic=basic, budget=budget))
    if budget is not None:
        cap = min(128 * 1024, budget.remaining)
        if (
            response.truncated or len(response.body) > cap or (response.error and "exceeds limit" in response.error)
        ) and cap < 128 * 1024:
            budget.reason = "byte_budget"
            return HttpResponse(status=response.status, body=b"", headers=response.headers, error=budget.reason)
    return response


def _full_json(
    pool: Any, base: str, path: str, *, cookie: str = "", budget: _UiDiscoveryBudget | None = None
) -> tuple[HttpResponse, Any]:
    if budget is None or not callable(getattr(pool, "request_stream", None)):
        options: dict[str, Any] = {"budget": budget} if budget is not None else {}
        response = _get(pool, base, path, cookie=cookie, **options)
        return response, _json(response)
    decoder = DiskJSONDocument(deadline=budget.deadline)
    status = 0
    response_headers: dict[str, str] = {}

    def on_response(code: int, headers: Mapping[str, str]) -> None:
        nonlocal status
        status = code
        response_headers.update(headers)

    def retained() -> Any:
        if status != 200:
            return None
        if decoder.parser.root_kind == "array":
            return decoder.completed_array()
        return decoder.partial_value(completed_arrays_only=True)

    try:
        response = pool.request_stream(
            "GET",
            base + path,
            on_chunk=decoder.feed,
            on_response=on_response,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                **({"Cookie": cookie} if cookie else {}),
            },
            deadline=budget.deadline,
            timeout=max(0.001, budget.deadline - time.monotonic()),
            allow_cross_origin_redirects=False,
            preserve_authorization_on_cross_origin=False,
        )
        status = response.status
        response_headers.update(response.headers)
        if response.error or response.truncated or response.status != 200:
            return response, retained()
        return response, decoder.finish()
    except (ValueError, UnicodeError, OSError) as exc:
        return HttpResponse(status, b"", response_headers, error=str(exc), truncated=True), retained()
    finally:
        decoder.close()


def _get_detect_steps(
    pool: HttpSessionPool,
    base: str,
    path: str,
    *,
    cookie: str = "",
    basic: str = "",
    budget: _UiDiscoveryBudget | None = None,
):
    headers = {"Accept": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    if basic:
        headers["Authorization"] = basic
    request_options: dict[str, Any] = {
        "headers": headers,
        "response_size_cap": min(128 * 1024, budget.remaining) if budget is not None else 128 * 1024,
        "allow_cross_origin_redirects": False,
        "preserve_authorization_on_cross_origin": False,
    }
    if budget is not None:
        request_options.update({"timeout": max(0.001, budget.deadline - time.monotonic()), "retries": 0})
    return (
        yield _HttpRead(
            pool,
            "GET",
            base + path,
            request_options,
        )
    )


def _parse_message_events_page(
    response: HttpResponse, *, limit: int
) -> tuple[list[dict[str, Any]], bool, str | None, str | None]:
    content_type = _header(response, "content-type").lower()
    if response.error and (response.status != 200 or not response.body):
        return [], False, response.error, None
    if response.status != 200:
        return [], False, f"HTTP {response.status} from Kafka UI message API", None
    if "text/event-stream" not in content_type:
        return [], False, "Kafka UI message API did not return an event stream", None
    messages: list[dict[str, Any]] = []
    done = False
    cursor: str | None = None
    for line in response.text.splitlines():
        if not line.startswith("data:"):
            continue
        try:
            event = json.loads(line[5:].strip())
        except (ValueError, UnicodeError):
            return messages, False, "invalid Kafka UI message event", None
        if not isinstance(event, dict):
            return messages, False, "invalid Kafka UI message event", None
        event_type = event.get("type")
        if event_type == "DONE":
            done = True
            cursor_data = event.get("cursor")
            if isinstance(cursor_data, dict) and isinstance(cursor_data.get("id"), str):
                cursor = cursor_data["id"] or None
            break
        if event_type == "ERROR":
            return messages, False, "Kafka UI message stream reported an error", None
        if event_type != "MESSAGE":
            continue
        message = event.get("message")
        if not isinstance(message, dict):
            return messages, False, "invalid Kafka UI message payload", None
        value = message.get("value", message.get("content"))
        if not isinstance(value, str) and value is not None:
            return messages, False, "invalid Kafka UI message value", None
        partition, offset = message.get("partition"), message.get("offset")
        if (
            not isinstance(partition, int)
            or isinstance(partition, bool)
            or partition < 0
            or not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset < 0
        ):
            return messages, False, "invalid Kafka UI message position", None
        messages.append(
            {
                "partition": partition,
                "offset": offset,
                "timestamp": message.get("timestamp"),
                "key": message.get("key"),
                "value": value,
                "headers": message.get("headers"),
            }
        )
        if len(messages) > limit:
            return messages[:limit], False, "Kafka UI returned more messages than requested", None
    if response.error:
        return messages, False, response.error, None
    if response.truncated:
        return messages, False, "Kafka UI message response exceeded 8 MiB", None
    if not done:
        return messages, False, "Kafka UI message stream ended without completion", None
    return messages, True, None, cursor


def _parse_message_events(response: HttpResponse, *, limit: int) -> tuple[list[dict[str, Any]], bool, str | None]:
    messages, done, error, _cursor = _parse_message_events_page(response, limit=limit)
    return messages, done, error


def _read_ui_messages(
    pool: HttpSessionPool,
    base: str,
    cluster: str,
    topic: str,
    *,
    vendor: str | None,
    cookie: str,
    limit: int,
    cursor: str | None = None,
    offsets: dict[int, int] | None = None,
    budget: _UiDiscoveryBudget | None = None,
    on_message: Any = None,
) -> tuple[list[dict[str, Any]], bool, str | None, str | None, bool]:
    prefix = f"/api/clusters/{quote(cluster, safe='')}/topics/{quote(topic, safe='')}/messages"
    legacy_query: dict[str, Any] = {"limit": min(limit, 500)}
    if offsets is not None:
        legacy_query.update(
            {"seekType": "OFFSET", "seekTo": [f"{part}::{offset}" for part, offset in sorted(offsets.items())]}
        )
    paths = (
        [prefix + "/v2?" + urlencode({"cursor": cursor})]
        if cursor
        else [prefix + "?" + urlencode(legacy_query, doseq=True)]
        if offsets is not None
        else [prefix + f"/v2?mode=EARLIEST&limit={limit}", prefix + "?" + urlencode(legacy_query)]
    )
    for index, path in enumerate(paths):
        if budget is not None:
            if time.monotonic() >= budget.deadline:
                budget.reason = "discover_time"
            if budget.reason:
                return [], False, budget.reason, None, "/v2?" in path
        if budget is not None and callable(getattr(pool, "request_stream", None)):
            response, messages, done, error, next_cursor = read_events(
                pool, base + path, cookie=cookie, deadline=budget.deadline, limit=limit, on_message=on_message
            )
            if index + 1 < len(paths) and response.status in {400, 404}:
                continue
            return messages, done, error, next_cursor, "/v2?" in path
        cap = min(_MAX_DUMP_RESPONSE_BYTES, budget.remaining) if budget is not None else _MAX_DUMP_RESPONSE_BYTES
        request_kwargs: dict[str, Any] = {}
        if budget is not None:
            request_kwargs["timeout"] = max(0.001, budget.deadline - time.monotonic())
            request_kwargs["retries"] = 0
        response = pool.request(
            "GET",
            base + path,
            headers={"Accept": "text/event-stream", **({"Cookie": cookie} if cookie else {})},
            response_size_cap=cap,
            preserve_partial_body=True,
            allow_cross_origin_redirects=False,
            preserve_authorization_on_cross_origin=False,
            **request_kwargs,
        )
        if budget is not None:
            if (
                response.truncated or (response.error and "exceeds limit" in response.error)
            ) and cap < _MAX_DUMP_RESPONSE_BYTES:
                budget.reason = "byte_budget"
                return [], False, budget.reason, None, "/v2?" in path
        if index + 1 < len(paths) and response.status in {400, 404}:
            continue
        messages, done, error, next_cursor = _parse_message_events_page(response, limit=limit)
        return messages, done, error, next_cursor, "/v2?" in path
    return [], False, "Kafka UI message API unavailable", None, False


def _legacy_topic_offsets(
    pool: HttpSessionPool,
    base: str,
    cluster: str,
    topic: str,
    *,
    cookie: str,
    budget: _UiDiscoveryBudget | None = None,
) -> tuple[dict[int, int], dict[int, int]] | None:
    """Read a fixed partition end-offset snapshot for cursorless Provectus UI."""
    path = f"/api/clusters/{quote(cluster, safe='')}/topics/{quote(topic, safe='')}"
    request_kwargs: dict[str, Any] = {"budget": budget} if budget is not None else {}
    response, value = _full_json(pool, base, path, cookie=cookie, **request_kwargs)
    if response.error or response.truncated or response.status != 200:
        return None
    partitions = value.get("partitions") if isinstance(value, Mapping) else None
    if not isinstance(partitions, list) or not partitions:
        return None
    start: dict[int, int] = {}
    end: dict[int, int] = {}
    for item in partitions:
        if not isinstance(item, Mapping):
            return None
        number, low, high = item.get("partition"), item.get("offsetMin"), item.get("offsetMax")
        if not all(
            isinstance(position, int) and not isinstance(position, bool) and position >= 0
            for position in (number, low, high)
        ):
            return None
        assert isinstance(number, int) and isinstance(low, int) and isinstance(high, int)
        if number in start or low > high:
            return None
        start[number], end[number] = low, high
    return start, end


def detect_ui(ctx: Any, state: Any) -> dict[str, Any]:
    return _run_detect_sync(_detect_ui_detect_steps(ctx, state))


def _provectus_form_detect_steps(pool: Any, base: str, responses: tuple[HttpResponse, ...]):
    """Confirm the legacy protected API using its public release identity.

    Only an observed same-origin /auth form redirect enables the extra probe;
    generic foreign HTTP responses incur no additional actuator request.
    """
    origin = urlsplit(base)
    login_path = origin.path.rstrip("/") + "/auth"
    form_seen = False
    for response in responses:
        if response.error or response.truncated or response.status not in {200, 406} or not response.redirected:
            continue
        try:
            final = urlsplit(response.final_url or "")
            if (
                final.scheme != origin.scheme
                or final.hostname != origin.hostname
                or (final.port or (443 if final.scheme == "https" else 80))
                != (origin.port or (443 if origin.scheme == "https" else 80))
                or final.username is not None
                or final.password is not None
                or final.path != login_path
            ):
                continue
        except ValueError:
            continue
        if response.status == 406:
            # Spring's generated login form rejects the API reader's JSON
            # Accept header. Negotiate HTML only on the observed /auth route.
            response = yield _HttpRead(
                pool,
                "GET",
                base.rstrip("/") + "/auth",
                {
                    "headers": {"Accept": "text/html"},
                    "response_size_cap": 64 * 1024,
                    "allow_cross_origin_redirects": False,
                    "preserve_authorization_on_cross_origin": False,
                },
            )
            if response.error or response.truncated or response.status != 200:
                return None
        page = markup_evidence(response.text[:8192])
        allowed_actions = {login_path, base.rstrip("/") + "/auth", "auth", "./auth", ""}
        if page is not None and any(
            {"username", "password"}.issubset(form.inputs) and (form.action or "") in allowed_actions
            for form in page.forms
        ):
            form_seen = True
            break
    if not form_seen:
        return None
    response = yield _DetectCall(_get, (pool, base, "/actuator/info"), {})
    data = _json(response)
    build = data.get("build") if isinstance(data, dict) else None
    git = data.get("git") if isinstance(data, dict) else None
    commit = git.get("commit") if isinstance(git, dict) else None
    revision = commit.get("id") if isinstance(commit, dict) else None
    if isinstance(revision, dict):
        revision = revision.get("full") or revision.get("abbrev")
    version = build.get("version") if isinstance(build, dict) else None
    if (
        not isinstance(build, dict)
        or build.get("artifact") != "kafka-ui-api"
        or build.get("name") != "kafka-ui-api"
        or build.get("group") != "com.provectus"
        or not isinstance(version, str)
        or not _VERSION.fullmatch(version)
        or not isinstance(revision, str)
        or not re.fullmatch(r"[0-9a-fA-F]{7,64}", revision)
    ):
        return None
    return version


def _detect_ui_detect_steps(ctx: Any, state: Any):
    """Confirm UI only after two independent product-specific API responses."""
    target_scheme = str(getattr(getattr(ctx, "target", None), "scheme", "") or "").lower()
    schemes = (
        (target_scheme,)
        if target_scheme in {"http", "https"}
        else ("https", "http")
        if ctx.port in {443, 8443}
        else ("http", "https")
    )
    pool = state.ui_http
    if pool is None:
        pool = HttpSessionPool(
            timeout=float(getattr(ctx.args, "timeout", 5.0) or 5.0),
            insecure=True,
            proxy=getattr(ctx.args, "_proxy_config", None),
            retries=0,
        )
        state.ui_http = pool
    signals: list[str] = []
    last_error: str | None = None
    for scheme in schemes:
        base = _base(ctx, scheme)
        other = yield _DetectCall(http_surfaces.detect, (pool, base, ctx), {})
        if other is not None:
            state.ui_base = base
            state.ui_vendor = str(other["ui_vendor"])
            state.ui_auth_type = None
            return other
        info_response = yield _DetectCall(_get, (pool, base, "/api/info"), {})
        if info_response.error:
            last_error = info_response.error
            continue
        info_ok, version, brand = _info(_json(info_response))
        if info_ok and info_response.final_url:
            final = urlsplit(info_response.final_url)
            if (
                final.scheme in {"http", "https"}
                and final.hostname == str(ctx.host).lower()
                and final.path.endswith("/api/info")
            ):
                base = info_response.final_url[: -len("/api/info")]
        if info_ok:
            signals.append("ui_info_build")
        auth_response = yield _DetectCall(_get, (pool, base, "/api/config/authentication"), {})
        mode = _auth_type(_json(auth_response))
        api_mode = mode
        if mode:
            signals.append("ui_auth_config")
        authorization_response = yield _DetectCall(_get, (pool, base, "/api/authorization"), {})
        authorization_ok = _authorization(_json(authorization_response))
        if authorization_ok:
            signals.append("ui_authorization")
        cluster_response = yield _DetectCall(_get, (pool, base, "/api/clusters"), {})
        cluster_payload = _json(cluster_response)
        clusters = _clusters(cluster_payload)
        if clusters is not None:
            signals.append("ui_cluster_schema")
        login_form = False
        branded_login = False
        if clusters is None and (info_ok or (mode == "LOGIN_FORM" and authorization_ok)):
            login_probe = yield _DetectCall(_get, (pool, base, "/login"), {})
            page = markup_evidence(login_probe.text[:8192])
            complete_login = login_probe.status == 200 and not login_probe.error and not login_probe.truncated
            branded_login = bool(complete_login and page is not None and page.title.casefold() == "kafbat ui")
            login_form = bool(
                complete_login
                and page is not None
                and any({"username", "password"}.issubset(form.inputs) for form in page.forms)
            )
            if branded_login:
                brand = "kafbat"
                signals.append("ui_kafbat_login_title")
            if login_form:
                if mode is None:
                    mode = "LOGIN_FORM"
                signals.append("ui_login_form")
        confirmed = (
            info_ok
            and (authorization_ok or clusters is not None or (api_mode is not None and login_form))
            or (clusters is not None and api_mode is not None and authorization_ok)
            or (api_mode == "LOGIN_FORM" and authorization_ok and branded_login)
        )
        if not confirmed and mode in {None, "LOGIN_FORM"}:
            legacy_version = yield from _provectus_form_detect_steps(
                pool, base, (info_response, auth_response, authorization_response, cluster_response)
            )
            if legacy_version is not None:
                state.ui_base = base
                state.ui_vendor = "provectus"
                state.ui_auth_type = "LOGIN_FORM"
                state.ui_login_path = "/auth"
                state.ui_anonymous_clusters = None
                return {
                    "timestamp": utc_now_iso(),
                    "host": str(ctx.host),
                    "port": int(ctx.port),
                    "is_kafka": True,
                    "is_kafka_ui": True,
                    "kafka_interface": "ui",
                    "ui_vendor": "provectus",
                    "ui_base": base,
                    "ui_auth_type": "LOGIN_FORM",
                    "ui_auth_type_source": "observed_login_form",
                    "ui_login_path": "/auth",
                    "version": legacy_version,
                    "auth_required": True,
                    "status": "auth_required",
                    "detection_status": "confirmed",
                    "detection_signals": ["ui_actuator_release_identity", "ui_same_origin_auth_form_redirect"],
                    "cluster_count": None,
                    "credential_verification_status": "available",
                    "error": None,
                }
        if confirmed:
            if clusters is None and cluster_payload == []:
                clusters = []
            state.ui_base = base
            state.ui_auth_type = mode
            state.ui_anonymous_clusters = clusters
            auth_required = mode != "DISABLED" if mode is not None else False if clusters is not None else None
            if brand is None:
                home = yield _DetectCall(_get, (pool, base, "/"), {})
                page = (
                    markup_evidence(home.text[:8192])
                    if home.status == 200 and not home.error and not home.truncated
                    else None
                )
                visible = " ".join(page.visible).casefold() if page is not None else ""
                brand = (
                    "kafbat"
                    if re.search(r"\bkafbat\b", visible)
                    else "provectus"
                    if re.search(r"\bprovectus\b", visible)
                    else None
                )
            state.ui_vendor = brand
            return {
                "timestamp": utc_now_iso(),
                "host": str(ctx.host),
                "port": int(ctx.port),
                "is_kafka": True,
                "is_kafka_ui": True,
                "kafka_interface": "ui",
                "ui_vendor": brand,
                "ui_base": base,
                "ui_auth_type": mode,
                "version": version,
                "auth_required": auth_required,
                "status": "open_no_auth"
                if auth_required is False
                else "auth_required"
                if auth_required
                else "unknown_auth",
                "detection_status": "confirmed",
                "detection_signals": sorted(set(signals)),
                "cluster_count": len(clusters) if clusters is not None else None,
                "credential_verification_status": "available" if mode == "LOGIN_FORM" else "unavailable",
                "error": None,
            }
        last_error = info_response.error or auth_response.error or cluster_response.error
    return {
        "timestamp": utc_now_iso(),
        "host": str(ctx.host),
        "port": int(ctx.port),
        "is_kafka": False,
        "is_kafka_ui": False,
        "status": "fail",
        "auth_required": None,
        "detection_status": "probable" if signals else "transport_failure" if last_error else "not_service",
        "detection_signals": sorted(set(signals)),
        "error": last_error,
    }


def authenticate_ui(ctx: Any, record: dict[str, Any], state: Any) -> dict[str, Any]:
    """Verify a login-form identity; redirects and public 200s are never success."""
    payload = dict(record)
    user = str(ctx.credential.username or "")
    password = str(ctx.credential.password or "")
    if not user and not password:
        return payload
    base = state.ui_base
    pool = state.ui_http
    if not base or pool is None or state.ui_auth_type != "LOGIN_FORM":
        return payload
    login_path = payload.get("ui_login_path") or getattr(state, "ui_login_path", "/login")
    if not isinstance(login_path, str) or login_path not in {"/login", "/auth"}:
        payload.update(status="unknown_auth", provided_credentials_ok=None, error="unsupported UI login endpoint")
        return payload
    login = pool.request_once("GET", base + login_path, response_size_cap=64 * 1024)
    cookie = _cookie(login)
    csrf_match = _CSRF.search(login.text)
    fields = {"username": user, "password": password}
    if csrf_match:
        fields["_csrf"] = html.unescape(csrf_match.group(1))
    body = urlencode(fields).encode("utf-8")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookie:
        headers["Cookie"] = cookie
    response = pool.request_once("POST", base + login_path, headers=headers, body=body, response_size_cap=64 * 1024)
    updated_cookie = _cookie(response) or cookie
    location = _header(response, "location").lower()
    limited = response.status == 429
    captcha = "captcha" in response.text[:4096].lower()
    rejected = response.status == 401 or "error" in location or "login" in location
    verified = False
    if not limited and not captcha and not rejected and response.status in {200, 302, 303}:
        identity = _json(_get(pool, base, "/api/authorization", cookie=updated_cookie))
        user_info = identity.get("userInfo") if isinstance(identity, dict) else None
        verified = isinstance(user_info, dict) and user_info.get("username") == user
    if verified:
        state.ui_cookie = updated_cookie
        state.ui_csrf = html.unescape(csrf_match.group(1)) if csrf_match else ""
        info_ok, version, brand = _info(_json(_get(pool, base, "/api/info", cookie=updated_cookie)))
        if info_ok:
            payload["version"] = version
            if brand:
                payload["ui_vendor"] = brand
    status = (
        "weak_default_creds"
        if verified and ctx.credential.source == "default"
        else "valid_credentials"
        if verified
        else "rate_limited"
        if limited or captcha
        else "invalid_credentials"
        if rejected
        else "unknown_auth"
    )
    payload.update(
        {
            "timestamp": utc_now_iso(),
            "status": status,
            "provided_username": user,
            "provided_password": password,
            "provided_credentials": ctx.credential.source != "default",
            "provided_credentials_ok": (True if verified else False if rejected else None)
            if ctx.credential.source != "default"
            else None,
            "defcreds_enabled": ctx.credential.source == "default",
            "effective_username": user if verified else None,
            "credential_attempts": [
                {
                    "username": user,
                    "password": password,
                    "default": ctx.credential.source == "default",
                    "ok": True if verified else False if rejected else None,
                    "error": "rate limited" if limited else "CAPTCHA" if captcha else None,
                }
            ],
            "error": "rate limited" if limited else "CAPTCHA" if captcha else None,
        }
    )
    return payload


def _collect_cluster_inventory(
    payload: dict[str, Any], pool: Any, base: str, cluster_path: str, name: str, cookie: str, options: dict[str, Any]
) -> None:
    if options.get("show_brokers"):
        response = _get(pool, base, cluster_path + "/brokers", cookie=cookie)
        items = _json(response)
        if isinstance(items, list):
            payload["ui_brokers"].extend(
                {"cluster": name, "id": item.get("id"), "host": item.get("host")}
                for item in items
                if isinstance(item, dict)
            )
        else:
            payload["ui_brokers_partial"] = True
            payload["ui_brokers_error"] = response.error or f"brokers unavailable: HTTP {response.status}"
    if options.get("show_consumer_groups"):
        page = 1
        seen_groups: set[str] = set()
        while True:
            value = _json(
                _get(pool, base, cluster_path + f"/consumer-groups/paged?page={page}&perPage=100", cookie=cookie)
            )
            items = value.get("consumerGroups") if isinstance(value, dict) else value
            if not isinstance(items, list):
                payload["ui_consumer_groups_partial"] = True
                break
            new_groups = 0
            for item in items:
                group = item.get("groupId") or item.get("name") if isinstance(item, dict) else None
                if isinstance(group, str) and group not in seen_groups:
                    seen_groups.add(group)
                    payload["ui_consumer_groups"].append({"cluster": name, "name": group})
                    new_groups += 1
            if len(items) < 100:
                break
            if not new_groups:
                payload["ui_consumer_groups_partial"] = True
                break
            page += 1


@contextmanager
def _source_attempt(options: dict[str, Any], kind: str) -> Iterator[SourceRead]:
    manifest = options.get("_source_manifest")
    source = "kafka." + kind
    evidence, finished = SourceRead(), False
    if manifest is not None:
        manifest.request(source, scope="selected_ui_collections_and_topic_walks")
    try:
        with manifest.guard(source) if manifest is not None else nullcontext():
            yield evidence
            finished = True
    finally:
        if manifest is not None:
            manifest.read(source, evidence.count)
            manifest.finish(source, complete=finished and evidence.complete, denied=evidence.status in {401, 403})


def _message_error_status(error: str | None) -> int | None:
    match = re.search(r"\bHTTP (401|403)\b", error or "")
    return int(match[1]) if match else None


def _collect_ui_full(ctx: Any, record: dict[str, Any], state: Any, options: dict[str, Any]) -> dict[str, Any]:
    """Checkpoint every completed message page, keeping messages off the result object."""
    payload = dict(record)
    base, pool = state.ui_base, state.ui_http
    if not base or pool is None:
        return payload
    args = getattr(ctx, "args", None)
    collector = DiscoveryCollector("kafka", ctx, payload) if getattr(args, "discover", False) else None
    if collector is not None and options.get("_source_manifest") is not None:
        collector.source_manifest = options["_source_manifest"]
    budget = _UiDiscoveryBudget(2**63 - 1, collector.deadline) if collector is not None else None
    discovery_kwargs: dict[str, Any] = {"budget": budget} if budget is not None else {}
    temporary = (
        tempfile.TemporaryDirectory(prefix="redposture-kafka-discover-")
        if collector is not None and getattr(args, "_discover_implicit_dump", False)
        else None
    )

    def check_deadline() -> None:
        if collector is not None and not collector.allowed():
            raise _FullIncomplete("discover_time")

    def response_problem(response: HttpResponse) -> str | None:
        return (
            str(response.error)
            if response.error
            else "response_truncated"
            if response.truncated
            else f"HTTP {response.status}"
            if response.status != 200
            else None
        )

    cookie = state.ui_cookie if payload.get("status") in {"valid_credentials", "weak_default_creds"} else ""
    topic_filter = str(options.get("query_topic") or "")
    payload["ui_dump_records"] = []
    payload["dump"] = False
    for flag in ("show_clusters", "show_topics", "show_brokers", "show_consumer_groups"):
        payload[flag] = bool(options.get(flag))
    payload.update(
        ui_clusters_partial=False,
        ui_topics=[],
        ui_topics_partial=False,
        ui_brokers=[],
        ui_consumer_groups=[],
        ui_consumer_groups_partial=False,
    )
    topic_limit = options.get("show_topics_limit")
    max_topics = int(topic_limit) if isinstance(topic_limit, int) and topic_limit > 0 else 2**63 - 1
    frontier = DiscoveryFrontier() if collector is not None else None
    try:
        with UIExport(
            temporary.name if temporary is not None else ".redposture/ui-exports",
            base,
            "kafka_ui",
            resume=None,
            scope={
                "username": str(getattr(ctx.args, "username", None) or ""),
                "credential": hashlib.sha256(str(getattr(ctx.args, "password", None) or "").encode()).hexdigest()[:16],
                "topic": topic_filter,
            },
        ) as writer:
            try:
                with _source_attempt(options, "ui_cluster_catalog") as evidence:
                    check_deadline()
                    cluster_response, cluster_data = _full_json(
                        pool, base, "/api/clusters", cookie=cookie, **discovery_kwargs
                    )
                    evidence.status = cluster_response.status
                    clusters = _clusters(cluster_data, limit=None)
                    cluster_problem = response_problem(cluster_response)
                    if clusters is None:
                        payload["ui_clusters_partial"] = True
                        payload["ui_topics_partial"] = True
                        payload["cluster_count"] = None
                        raise _FullIncomplete(f"Kafka UI clusters unavailable: {cluster_problem or 'invalid JSON'}")
                    if collector is not None:
                        collector.mark_accessible_source()
                    payload["ui_clusters"] = clusters
                    payload["cluster_count"] = len(clusters)
                    if cluster_problem:
                        payload["ui_clusters_partial"] = True
                        payload["ui_topics_partial"] = True
                        payload["cluster_count"] = None
                        if collector is not None:
                            collector.add("ui.clusters", clusters, charge=False)
                        raise _FullIncomplete(f"Kafka UI clusters: {cluster_problem}")
                    evidence.accept()
                for cluster in clusters:
                    check_deadline()
                    cluster_name = str(cluster["name"])
                    cluster_path = "/api/clusters/" + quote(cluster_name, safe="")
                    _collect_cluster_inventory(payload, pool, base, cluster_path, cluster_name, cookie, options)
                    topics: list[str] = SpoolingStrings() if collector is not None else []
                    topic_problem: str | None = None
                    if not topic_filter or options.get("show_topics"):
                        with _source_attempt(options, "ui_topic_catalog") as evidence:
                            page_number = 1
                            seen_pages: set[tuple[str, ...]] = set()
                            while True:
                                check_deadline()
                                page_response, value = _full_json(
                                    pool,
                                    base,
                                    cluster_path + f"/topics?page={page_number}&perPage=200",
                                    cookie=cookie,
                                    **discovery_kwargs,
                                )
                                evidence.status = page_response.status
                                items = value.get("topics") if isinstance(value, Mapping) else value
                                page_problem = response_problem(page_response)
                                if not isinstance(items, list):
                                    payload["ui_topics_partial"] = True
                                    raise _FullIncomplete(
                                        f"Kafka UI {cluster_name} topics unavailable: {page_problem or 'invalid JSON'}"
                                    )
                                names = tuple(
                                    item["name"]
                                    for item in items
                                    if isinstance(item, Mapping) and isinstance(item.get("name"), str)
                                )
                                digest = hashlib.sha256(json.dumps(names).encode()).hexdigest()
                                if frontier is not None:
                                    fresh_page = frontier.claim(f"page:{cluster_name}:{digest}")
                                else:
                                    fresh_page = names not in seen_pages
                                    seen_pages.add(names)
                                if not fresh_page:
                                    raise _FullIncomplete(f"Kafka UI {cluster_name}: repeated topic page")
                                for name in names:
                                    if frontier is None or frontier.claim(f"topic:{cluster_name}:{name}"):
                                        topics.append(name)
                                if page_problem:
                                    payload["ui_topics_partial"] = True
                                    if collector is not None:
                                        collector.add(f"ui.cluster.{cluster_name}.topics", items, charge=False)
                                    topic_problem = page_problem
                                    break
                                evidence.count += 1
                                if len(items) < 200:
                                    evidence.complete = True
                                    break
                                page_number += 1
                    if options.get("show_topics"):
                        if collector is not None:
                            if not isinstance(payload["ui_topics"], SpoolingRecords):
                                payload["ui_topics"] = SpoolingRecords()
                            for topic in topics:
                                if len(payload["ui_topics"]) >= max_topics:
                                    break
                                payload["ui_topics"].append({"cluster": cluster_name, "name": topic})
                        else:
                            payload["ui_topics"].extend(
                                {"cluster": cluster_name, "name": topic}
                                for topic in sorted(set(topics))[: max(0, max_topics - len(payload["ui_topics"]))]
                            )
                    if topic_problem:
                        raise _FullIncomplete(f"Kafka UI {cluster_name} topics: {topic_problem}")
                    for topic in [topic_filter] if topic_filter else topics:
                        with _source_attempt(options, "ui_message_walks") as evidence:
                            checkpoint_key = f"topic:{cluster_name}:{topic}"
                            checkpoint = writer.get_meta(checkpoint_key) or {}
                            if checkpoint.get("complete"):
                                continue
                            cursor = checkpoint.get("cursor")
                            legacy = checkpoint.get("legacy")
                            offsets: dict[int, int] | None = None
                            end: dict[int, int] | None = None
                            if isinstance(legacy, dict):
                                offsets = {int(k): int(v) for k, v in legacy.get("offsets", {}).items()}
                                end = {int(k): int(v) for k, v in legacy.get("end", {}).items()}
                            elif state.ui_vendor == "provectus":
                                snapshot = _legacy_topic_offsets(
                                    pool, base, cluster_name, topic, cookie=cookie, **discovery_kwargs
                                )
                                if snapshot is None:
                                    raise _FullIncomplete(
                                        f"legacy Kafka UI {cluster_name}/{topic}: end offsets unavailable"
                                    )
                                offsets, end = snapshot
                                writer.set_meta(checkpoint_key, {"legacy": {"offsets": offsets, "end": end}})
                            seen_cursors: set[str] = set()
                            while True:
                                check_deadline()
                                scanned: set[tuple[int, int]] = set()

                                def scan_message(
                                    message: dict[str, Any],
                                    *,
                                    scanned: set[tuple[int, int]] = scanned,
                                    offsets: dict[int, int] | None = offsets,
                                    end: dict[int, int] | None = end,
                                    cluster_name: str = cluster_name,
                                    topic: str = topic,
                                ) -> None:
                                    position_key = (message["partition"], message["offset"])
                                    if collector is None or position_key in scanned:
                                        return
                                    if offsets is not None:
                                        assert end is not None
                                        part, position = position_key
                                        if part not in offsets or not offsets[part] <= position < end[part]:
                                            return
                                    scanned.add(position_key)
                                    source = f"ui.cluster.{cluster_name}.topic.{topic}.partition.{position_key[0]}.offset.{position_key[1]}"
                                    collector.scan_json_chunks(
                                        source, (chunk.encode("utf-8") for chunk in iter_json_chunks(message))
                                    )

                                message_kwargs = (
                                    {**discovery_kwargs, "on_message": scan_message} if collector is not None else {}
                                )
                                page, done, error, next_cursor, cursor_supported = _read_ui_messages(
                                    pool,
                                    base,
                                    cluster_name,
                                    topic,
                                    vendor=state.ui_vendor,
                                    cookie=cookie,
                                    limit=500,
                                    cursor=cursor,
                                    offsets=offsets,
                                    **message_kwargs,
                                )
                                evidence.status = _message_error_status(error)
                                if done and not error and not cursor_supported and offsets is None:
                                    snapshot = _legacy_topic_offsets(
                                        pool, base, cluster_name, topic, cookie=cookie, **discovery_kwargs
                                    )
                                    if snapshot is None:
                                        raise _FullIncomplete(
                                            f"legacy Kafka UI {cluster_name}/{topic}: end offsets unavailable"
                                        )
                                    offsets, end = snapshot
                                advanced = 0
                                next_offsets = dict(offsets) if offsets is not None else None
                                for message in page:
                                    part, position = message["partition"], message["offset"]
                                    if offsets is not None:
                                        assert end is not None
                                        if part not in offsets or not offsets[part] <= position < end[part]:
                                            continue
                                        assert next_offsets is not None
                                        next_offsets[part] = max(next_offsets[part], position + 1)
                                        advanced += 1
                                    key = f"message:{cluster_name}:{topic}:{part}:{position}"
                                    if writer.add(
                                        key, "messages", {"cluster": cluster_name, "topic": topic, **message}
                                    ):
                                        if collector is not None:
                                            scan_message(message)
                                        emit = getattr(ctx, "live_emit", None)
                                        if collector is None and callable(emit) and writer.new_count % 100 == 0:
                                            emit(
                                                [
                                                    f"KAFKA\t{ctx.host}\t{ctx.port}\t [*] UI Export (messages:{writer.count})"
                                                ]
                                            )
                                if not done or error:
                                    raise _FullIncomplete(
                                        f"Kafka UI {cluster_name}/{topic}: {error or 'incomplete message page'}"
                                    )
                                if next_offsets is not None:
                                    offsets = next_offsets
                                    assert end is not None
                                    complete = all(offsets[part] >= high for part, high in end.items())
                                    writer.set_meta(
                                        checkpoint_key,
                                        {"legacy": {"offsets": offsets, "end": end}, "complete": complete},
                                    )
                                    if complete:
                                        break
                                    if not advanced:
                                        raise _FullIncomplete(
                                            f"legacy Kafka UI {cluster_name}/{topic}: no offset progress"
                                        )
                                    continue
                                if next_cursor:
                                    fresh_cursor = (
                                        frontier.claim(f"cursor:{cluster_name}:{topic}:{next_cursor}")
                                        if frontier is not None
                                        else next_cursor not in seen_cursors
                                    )
                                    if not fresh_cursor or next_cursor == cursor:
                                        raise _FullIncomplete(f"Kafka UI {cluster_name}/{topic}: repeated cursor")
                                    if frontier is None:
                                        seen_cursors.add(next_cursor)
                                    cursor = next_cursor
                                    writer.set_meta(checkpoint_key, {"cursor": cursor})
                                    continue
                                writer.set_meta(checkpoint_key, {"complete": True})
                                break
                            evidence.accept()
            except (KeyboardInterrupt, _FullIncomplete) as exc:
                result = writer.finish(complete=False, reason=str(exc) or "interrupted")
            else:
                result = writer.finish(complete=True)
    except (OSError, ValueError, sqlite3.Error) as exc:
        result = {"status": "unavailable", "partial": True, "reason": str(exc)}
    finally:
        if frontier is not None:
            frontier.close()
        if temporary is not None:
            temporary.cleanup()
    if collector is not None:
        if result.get("partial"):
            collector.partial("ui", str(result.get("reason") or "incomplete export"))
        payload["content_discovery"] = collector.result()
    if collector is None or not getattr(args, "_discover_implicit_dump", False):
        payload["ui_export"] = result
    payload["topic_count"] = (
        len(payload["ui_topics"]) if options.get("show_topics") and not payload["ui_topics_partial"] else None
    )
    return payload


def collect_ui(ctx: Any, record: dict[str, Any], state: Any, options: dict[str, Any]) -> dict[str, Any]:
    if not bool(getattr(getattr(ctx, "args", None), "discover", False)):
        return _collect_ui(ctx, record, state, options)
    from .http_discover import SUPPORTED, discover

    if record.get("kafka_interface") == "http_surface" and record.get("ui_vendor") in SUPPORTED:
        inventory_options = dict(options)
        if getattr(ctx.args, "_discover_implicit_dump", False):
            inventory_options["dump"] = False
        payload = http_surfaces.collect(record, inventory_options)
        payload["content_discovery"] = discover(ctx, record, state)
        payload["discover_sources"] = payload["content_discovery"].get("sources", [])
        return payload
    manifest = SourceManifest()
    if record.get("kafka_interface") == "http_surface":
        source = "kafka.http_surface_messages"
        manifest.request(source, implemented=False, scope=str(record.get("ui_vendor") or "http_surface"))
        manifest.finish(source, complete=False, unsupported=True)
    else:
        for kind in ("ui_cluster_catalog", "ui_topic_catalog", "ui_message_walks"):
            manifest.declare("kafka." + kind)
    result = _collect_ui(ctx, record, state, {**options, "_source_manifest": manifest})
    result["discover_sources"] = manifest.result()
    return result


def _collect_ui(ctx: Any, record: dict[str, Any], state: Any, options: dict[str, Any]) -> dict[str, Any]:
    if record.get("kafka_interface") == "http_surface":
        return http_surfaces.collect(record, options)
    if options.get("ui_dump_all"):
        return _collect_ui_full(ctx, record, state, options)
    payload = dict(record)
    base, pool = state.ui_base, state.ui_http
    if not base or pool is None:
        return payload
    args = getattr(ctx, "args", None)
    discovery_budget = (
        _UiDiscoveryBudget(
            remaining=int(getattr(args, "discover_max_bytes", None) or UNLIMITED_DISCOVER_BYTES),
            deadline=(getattr(ctx, "discovery_started_at", None) or time.monotonic())
            + float(getattr(args, "discover_time", None) or DEFAULT_DISCOVER_TIME),
        )
        if bool(getattr(args, "discover", False))
        else None
    )
    cookie = state.ui_cookie if payload.get("status") in {"valid_credentials", "weak_default_creds"} else ""
    discovery_kwargs: dict[str, Any] = {"budget": discovery_budget} if discovery_budget is not None else {}
    with _source_attempt(options, "ui_cluster_catalog") as evidence:
        cluster_response = _get(
            pool,
            base,
            "/api/clusters",
            cookie=cookie,
            **discovery_kwargs,
        )
        cluster_data = _json(cluster_response)
        clusters = _clusters(cluster_data, limit=None) or []
        evidence.status = cluster_response.status
        if (
            cluster_response.status == 200
            and not cluster_response.error
            and not cluster_response.truncated
            and _clusters(cluster_data, limit=None) is not None
        ):
            evidence.accept()
    payload["ui_clusters"] = [
        {
            "name": c["name"],
            "broker_count": c.get("brokerCount"),
            "topic_count": c.get("topicCount"),
            "read_only": c.get("readOnly"),
        }
        for c in clusters
    ]
    payload["cluster_count"] = len(clusters) if cluster_response.status == 200 else None
    payload["show_clusters"] = bool(options.get("show_clusters"))
    payload["show_topics"] = bool(options.get("show_topics"))
    payload["show_brokers"] = bool(options.get("show_brokers"))
    payload["show_consumer_groups"] = bool(options.get("show_consumer_groups"))
    payload["ui_topics"] = []
    payload["ui_topics_partial"] = False
    payload["ui_brokers"] = []
    payload["ui_brokers_partial"] = False
    payload["ui_consumer_groups"] = []
    payload["ui_consumer_groups_partial"] = False
    dump_enabled = bool(options.get("dump"))
    query_topic = str(options.get("query_topic") or "").strip()
    requested_limit = (
        int(options.get("max_messages") or 10) if options.get("max_messages_explicit") else _MAX_DUMP_MESSAGES
    )
    dump_limit = max(1, min(_MAX_DUMP_MESSAGES, requested_limit))
    payload["dump"] = dump_enabled
    payload["query_topic"] = query_topic or None
    payload["max_messages"] = dump_limit if dump_enabled else None
    payload["ui_dump_limit_reduced"] = dump_enabled and requested_limit > dump_limit
    payload["ui_dump_records"] = []
    payload["ui_dump_skipped_topics"] = 0
    payload["ui_dump_partial"] = dump_enabled and isinstance(cluster_data, list) and len(cluster_data) > len(clusters)
    if _clusters(cluster_data, limit=None) is None:
        reason = cluster_response.error or f"clusters unavailable: HTTP {cluster_response.status}"
        payload["ui_clusters_partial"] = True
        if discovery_budget is not None and discovery_budget.reason:
            payload["ui_discovery_budget_reason"] = discovery_budget.reason
        else:
            payload["error"] = reason
        payload["ui_topics_partial"] = bool(options.get("show_topics"))
        payload["ui_brokers_partial"] = bool(options.get("show_brokers"))
        payload["ui_brokers_error"] = reason if options.get("show_brokers") else None
        payload["ui_consumer_groups_partial"] = bool(options.get("show_consumer_groups"))
        payload["ui_dump_partial"] = dump_enabled
        return payload
    dump_deadline = discovery_budget.deadline if discovery_budget else time.monotonic() + _MAX_DUMP_SECONDS
    dump_byte_limit = (
        int(getattr(args, "discover_max_bytes", None) or UNLIMITED_DISCOVER_BYTES)
        if discovery_budget
        else _MAX_DUMP_BYTES
    )
    dump_bytes = 0
    topic_limit = options.get("show_topics_limit")
    max_topics = int(topic_limit) if isinstance(topic_limit, int) and topic_limit > 0 else 2**63 - 1
    topic_pages_remaining = (_MAX_DUMP_TOPICS + 199) // 200
    for cluster in clusters:
        name = str(cluster["name"])
        cluster_path = "/api/clusters/" + quote(name, safe="")
        cluster_topics: list[str] = []
        if options.get("show_topics") or (dump_enabled and not query_topic):
            with _source_attempt(options, "ui_topic_catalog") as evidence:
                page = 1
                seen_names: set[str] = set()
                while True:
                    if dump_enabled and (topic_pages_remaining <= 0 or time.monotonic() >= dump_deadline):
                        payload["ui_dump_partial"] = True
                        break
                    response = _get(
                        pool,
                        base,
                        cluster_path + f"/topics?page={page}&perPage=200",
                        cookie=cookie,
                        **discovery_kwargs,
                    )
                    if dump_enabled:
                        topic_pages_remaining -= 1
                    evidence.status = response.status
                    value = _json(response)
                    items = value.get("topics") if isinstance(value, dict) else value
                    if not isinstance(items, list):
                        payload["ui_dump_partial"] = dump_enabled
                        payload["ui_topics_partial"] = bool(options.get("show_topics"))
                        break
                    new_topics = 0
                    for item in items:
                        topic = item.get("name") if isinstance(item, dict) else None
                        if isinstance(topic, str) and topic not in seen_names:
                            seen_names.add(topic)
                            cluster_topics.append(topic)
                            new_topics += 1
                    if not response.error and not response.truncated and response.status == 200:
                        evidence.count += 1
                    if len(items) < 200:
                        evidence.complete = not response.error and not response.truncated and response.status == 200
                        break
                    if not new_topics:
                        payload["ui_dump_partial"] = dump_enabled
                        payload["ui_topics_partial"] = bool(options.get("show_topics"))
                        break
                    if not dump_enabled and len(cluster_topics) >= max_topics:
                        break
                    page += 1
            cluster_topics.sort()
            if options.get("show_topics"):
                payload["ui_topics"].extend(
                    {"cluster": name, "name": topic}
                    for topic in cluster_topics[: max(0, max_topics - len(payload["ui_topics"]))]
                )
        if dump_enabled:
            dump_topics = [query_topic] if query_topic else cluster_topics
            remaining = max(0, _MAX_DUMP_TOPICS - len(payload["ui_dump_records"]))
            payload["ui_dump_skipped_topics"] += max(0, len(dump_topics) - remaining)
            selected_topics = dump_topics[:remaining]
            for index, topic in enumerate(selected_topics):
                with _source_attempt(options, "ui_message_walks") as evidence:
                    if (
                        discovery_budget is None and dump_bytes >= dump_byte_limit
                    ) or time.monotonic() >= dump_deadline:
                        payload["ui_dump_partial"] = True
                        payload["ui_dump_skipped_topics"] += len(selected_topics) - index
                        break
                    messages: list[dict[str, Any]] = []
                    error: str | None = None
                    complete = False
                    cursor: str | None = None
                    seen_cursors: set[str] = set()
                    legacy_offsets: dict[int, int] | None = None
                    legacy_end: dict[int, int] | None = None
                    seen_positions: set[tuple[int, int]] = set()
                    while (
                        len(messages) < dump_limit
                        and (discovery_budget is not None or dump_bytes < dump_byte_limit)
                        and time.monotonic() < dump_deadline
                    ):
                        message_page, done, error, next_cursor, cursor_supported = _read_ui_messages(
                            pool,
                            base,
                            name,
                            topic,
                            vendor=state.ui_vendor,
                            cookie=cookie,
                            limit=min(500, dump_limit - len(messages)),
                            cursor=cursor,
                            offsets=legacy_offsets,
                            **({"budget": discovery_budget} if discovery_budget is not None else {}),
                        )
                        page_positions: set[tuple[int, int]] = set()
                        unique_page = []
                        for message in message_page:
                            position = (message["partition"], message["offset"])
                            if position not in seen_positions and position not in page_positions:
                                unique_page.append(message)
                                page_positions.add(position)
                        duplicate_only = bool(message_page) and not unique_page
                        message_page = unique_page
                        message_bytes = (
                            sum(len(chunk.encode("utf-8")) for chunk in iter_json_chunks(message_page))
                            if discovery_budget is not None
                            else len(json.dumps(message_page, ensure_ascii=False).encode())
                        )
                        if next_cursor and next_cursor in seen_cursors:
                            error = error or "Kafka UI repeated a message cursor"
                        if duplicate_only and next_cursor:
                            error = error or "Kafka UI made no unique message progress"
                        if (discovery_budget is not None and message_bytes > dump_byte_limit) or (
                            discovery_budget is None and dump_bytes + message_bytes > dump_byte_limit
                        ):
                            error = "Kafka UI dump byte budget reached"
                            break
                        if not done or error:
                            dump_bytes += message_bytes
                            messages.extend(message_page)
                            break
                        if not cursor_supported:
                            if legacy_offsets is None:
                                snapshot = _legacy_topic_offsets(
                                    pool,
                                    base,
                                    name,
                                    topic,
                                    cookie=cookie,
                                    **({"budget": discovery_budget} if discovery_budget is not None else {}),
                                )
                                if snapshot is None:
                                    error = "legacy Kafka UI topic end offsets unavailable"
                                    dump_bytes += message_bytes
                                    messages.extend(message_page)
                                    break
                                legacy_offsets, legacy_end = snapshot
                            assert legacy_end is not None
                            new_positions = 0
                            for message in message_page:
                                position = (message["partition"], message["offset"])
                                if position[0] not in legacy_offsets or position in seen_positions:
                                    continue
                                if not (legacy_offsets[position[0]] <= position[1] < legacy_end[position[0]]):
                                    continue
                                seen_positions.add(position)
                                legacy_offsets[position[0]] = position[1] + 1
                                messages.append(message)
                                new_positions += 1
                            dump_bytes += message_bytes
                            if all(legacy_offsets[part] >= high for part, high in legacy_end.items()):
                                complete = True
                                break
                            if not new_positions:
                                error = "legacy Kafka UI made no offset progress before topic end"
                                break
                            continue
                        dump_bytes += message_bytes
                        messages.extend(message_page)
                        seen_positions.update(page_positions)
                        if next_cursor:
                            seen_cursors.add(next_cursor)
                            cursor = next_cursor
                            continue
                        # The v2 cursor contract defines an absent next cursor as
                        # the end of polling, regardless of the page size.
                        complete = True
                        break
                    if len(messages) >= dump_limit and not complete:
                        error = error or "Kafka UI message limit reached"
                    payload["ui_dump_partial"] = payload["ui_dump_partial"] or not complete
                    payload["ui_dump_records"].append(
                        {"cluster": name, "topic": topic, "messages": messages, "complete": complete, "error": error}
                    )
                    evidence.status = _message_error_status(error)
                    if complete and not error:
                        evidence.accept()
        _collect_cluster_inventory(payload, pool, base, cluster_path, name, cookie, options)
    payload["topic_count"] = len(payload["ui_topics"]) if options.get("show_topics") else None
    payload["ui_dump_partial"] = payload["ui_dump_partial"] or payload["ui_dump_skipped_topics"] > 0
    if discovery_budget is not None and time.monotonic() >= discovery_budget.deadline:
        discovery_budget.reason = discovery_budget.reason or "discover_time"
    if discovery_budget is not None and discovery_budget.reason:
        payload["ui_discovery_budget_reason"] = discovery_budget.reason
        payload["ui_dump_partial"] = True
    if any(options.get(key) for key in ("probe_write", "write_payload")):
        payload["ui_unsupported_actions"] = "topic writes are unavailable through Kafka UI"
    return payload


# Exact synchronous wrappers are the compatibility/override identities.
_ASYNC_RETAINED_STEPS = {
    _get: _get_detect_steps,
    detect_ui: _detect_ui_detect_steps,
}
