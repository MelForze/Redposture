"""Read-only Provectus/Kafbat Kafka UI probes on a Kafka audit target."""

from __future__ import annotations

import html
import json
import re
import time
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from ...clients.http_api import HttpResponse, infer_http_base_path
from ...clients.http_session import HttpSessionPool
from ...utils import utc_now_iso

_AUTH_TYPES = {"DISABLED", "LOGIN_FORM", "LDAP", "OAUTH2"}
_VERSION = re.compile(r"^v?[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?$")
_CSRF = re.compile(r'name=["\']_csrf["\'][^>]*value=["\']([^"\']+)', re.I)
_LOGIN_USER = re.compile(r'name=["\']username["\']', re.I)
_LOGIN_PASSWORD = re.compile(r'name=["\']password["\']', re.I)
_KAFBAT_TITLE = re.compile(r"<title>\s*Kafbat UI\s*</title>", re.I)
_MAX_CLUSTERS = 20
_MAX_TOPICS = 200
_MAX_DUMP_TOPICS = 2_000
_MAX_DUMP_MESSAGES = 10_000
_MAX_DUMP_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_DUMP_BYTES = 64 * 1024 * 1024
_MAX_DUMP_SECONDS = 300.0


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


def _clusters(value: Any) -> list[dict[str, Any]] | None:
    if not isinstance(value, list):
        return None
    selected: list[dict[str, Any]] = []
    for item in value[:_MAX_CLUSTERS]:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"]:
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
    prefix = infer_http_base_path(path, ("/api/info", "/api/config/authentication", "/api/clusters", "/login"))
    return f"{scheme}://{ctx.host}:{ctx.port}{prefix.rstrip('/')}"


def _get(pool: HttpSessionPool, base: str, path: str, *, cookie: str = "", basic: str = "") -> HttpResponse:
    headers = {"Accept": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    if basic:
        headers["Authorization"] = basic
    return pool.request(
        "GET",
        base + path,
        headers=headers,
        response_size_cap=128 * 1024,
        allow_cross_origin_redirects=False,
        preserve_authorization_on_cross_origin=False,
    )


def _parse_message_events_page(
    response: HttpResponse, *, limit: int
) -> tuple[list[dict[str, Any]], bool, str | None, str | None]:
    content_type = _header(response, "content-type").lower()
    if response.error:
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
        if not isinstance(partition, int) or not isinstance(offset, int):
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
) -> tuple[list[dict[str, Any]], bool, str | None, str | None, bool]:
    prefix = f"/api/clusters/{quote(cluster, safe='')}/topics/{quote(topic, safe='')}/messages"
    paths = (
        [prefix + "/v2?" + urlencode({"cursor": cursor})]
        if cursor
        else [prefix + f"/v2?mode=EARLIEST&limit={limit}", prefix + f"?limit={limit}"]
    )
    for index, path in enumerate(paths):
        response = pool.request(
            "GET",
            base + path,
            headers={"Accept": "text/event-stream", **({"Cookie": cookie} if cookie else {})},
            response_size_cap=_MAX_DUMP_RESPONSE_BYTES,
            allow_cross_origin_redirects=False,
            preserve_authorization_on_cross_origin=False,
        )
        if index + 1 < len(paths) and response.status in {400, 404}:
            continue
        messages, done, error, next_cursor = _parse_message_events_page(response, limit=limit)
        return messages, done, error, next_cursor, "/v2?" in path
    return [], False, "Kafka UI message API unavailable", None, False


def detect_ui(ctx: Any, state: Any) -> dict[str, Any]:
    """Confirm UI only after two independent product-specific API responses."""
    target_scheme = str(getattr(getattr(ctx, "target", None), "scheme", "") or "").lower()
    schemes = (
        (target_scheme,)
        if target_scheme in {"http", "https"}
        else (("https", "http") if ctx.port in {443, 8443} else ("http", "https"))
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
        info_response = _get(pool, base, "/api/info")
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
        auth_response = _get(pool, base, "/api/config/authentication")
        mode = _auth_type(_json(auth_response))
        api_mode = mode
        if mode:
            signals.append("ui_auth_config")
        authorization_response = _get(pool, base, "/api/authorization")
        authorization_ok = _authorization(_json(authorization_response))
        if authorization_ok:
            signals.append("ui_authorization")
        cluster_response = _get(pool, base, "/api/clusters")
        clusters = _clusters(_json(cluster_response))
        if clusters is not None:
            signals.append("ui_cluster_schema")
        login_form = False
        branded_login = False
        if clusters is None and (info_ok or (mode == "LOGIN_FORM" and authorization_ok)):
            login_probe = _get(pool, base, "/login")
            branded_login = bool(login_probe.status == 200 and _KAFBAT_TITLE.search(login_probe.text[:8192]))
            login_form = bool(
                login_probe.status == 200
                and _LOGIN_USER.search(login_probe.text)
                and _LOGIN_PASSWORD.search(login_probe.text)
            )
            if branded_login:
                brand = "kafbat"
                signals.append("ui_kafbat_login_title")
            if login_form:
                if mode is None:
                    mode = "LOGIN_FORM"
                signals.append("ui_login_form")
        confirmed = (
            (info_ok and (authorization_ok or clusters is not None or (api_mode is not None and login_form)))
            or (clusters is not None and api_mode is not None and authorization_ok)
            or (api_mode == "LOGIN_FORM" and authorization_ok and branded_login)
        )
        if confirmed:
            state.ui_base = base
            state.ui_auth_type = mode
            state.ui_anonymous_clusters = clusters
            auth_required = mode != "DISABLED" if mode is not None else False if clusters is not None else None
            # The two projects use a shared API. Name a vendor only on an explicit signal.
            if brand is None:
                home = _get(pool, base, "/")
                page = home.text[:8192].lower() if home.status == 200 else ""
                brand = "kafbat" if "kafbat" in page else "provectus" if "provectus" in page else None
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
    login = pool.request_once("GET", base + "/login", response_size_cap=64 * 1024)
    cookie = _cookie(login)
    csrf_match = _CSRF.search(login.text)
    fields = {"username": user, "password": password}
    if csrf_match:
        fields["_csrf"] = html.unescape(csrf_match.group(1))
    body = urlencode(fields).encode("utf-8")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookie:
        headers["Cookie"] = cookie
    response = pool.request_once("POST", base + "/login", headers=headers, body=body, response_size_cap=64 * 1024)
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


def collect_ui(ctx: Any, record: dict[str, Any], state: Any, options: dict[str, Any]) -> dict[str, Any]:
    payload = dict(record)
    base, pool = state.ui_base, state.ui_http
    if not base or pool is None:
        return payload
    cookie = state.ui_cookie if payload.get("status") in {"valid_credentials", "weak_default_creds"} else ""
    cluster_response = _get(pool, base, "/api/clusters", cookie=cookie)
    cluster_data = _json(cluster_response)
    clusters = _clusters(cluster_data) or []
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
    payload["ui_brokers"] = []
    payload["ui_consumer_groups"] = []
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
    dump_deadline = time.monotonic() + _MAX_DUMP_SECONDS
    dump_bytes = 0
    topic_limit = options.get("show_topics_limit")
    max_topics = min(_MAX_TOPICS, int(topic_limit)) if isinstance(topic_limit, int) and topic_limit > 0 else _MAX_TOPICS
    topic_pages_remaining = (_MAX_DUMP_TOPICS + 199) // 200
    for cluster in clusters:
        name = str(cluster["name"])
        cluster_path = "/api/clusters/" + quote(name, safe="")
        cluster_topics: list[str] = []
        if options.get("show_topics") or (dump_enabled and not query_topic):
            page = 1
            seen_names: set[str] = set()
            while True:
                if dump_enabled and (topic_pages_remaining <= 0 or time.monotonic() >= dump_deadline):
                    payload["ui_dump_partial"] = True
                    break
                response = _get(pool, base, cluster_path + f"/topics?page={page}&perPage=200", cookie=cookie)
                if dump_enabled:
                    topic_pages_remaining -= 1
                value = _json(response)
                items = value.get("topics") if isinstance(value, dict) else value
                if not isinstance(items, list):
                    payload["ui_dump_partial"] = dump_enabled
                    break
                for item in items:
                    topic = item.get("name") if isinstance(item, dict) else None
                    if isinstance(topic, str) and topic not in seen_names:
                        seen_names.add(topic)
                        cluster_topics.append(topic)
                if len(items) < 200:
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
                if dump_bytes >= _MAX_DUMP_BYTES or time.monotonic() >= dump_deadline:
                    payload["ui_dump_partial"] = True
                    payload["ui_dump_skipped_topics"] += len(selected_topics) - index
                    break
                messages: list[dict[str, Any]] = []
                error: str | None = None
                complete = False
                cursor: str | None = None
                seen_cursors: set[str] = set()
                while len(messages) < dump_limit and dump_bytes < _MAX_DUMP_BYTES and time.monotonic() < dump_deadline:
                    message_page, done, error, next_cursor, cursor_supported = _read_ui_messages(
                        pool,
                        base,
                        name,
                        topic,
                        vendor=state.ui_vendor,
                        cookie=cookie,
                        limit=min(1_000, dump_limit - len(messages)),
                        cursor=cursor,
                    )
                    message_bytes = len(json.dumps(message_page, ensure_ascii=False).encode())
                    if next_cursor and next_cursor in seen_cursors:
                        error = "Kafka UI repeated a message cursor"
                        break
                    if dump_bytes + message_bytes > _MAX_DUMP_BYTES:
                        error = "Kafka UI dump byte budget reached"
                        break
                    dump_bytes += message_bytes
                    messages.extend(message_page)
                    if not done or error:
                        break
                    if next_cursor:
                        seen_cursors.add(next_cursor)
                        cursor = next_cursor
                        continue
                    complete = cursor_supported or len(message_page) < min(
                        1_000, dump_limit - len(messages) + len(message_page)
                    )
                    break
                if cursor and len(messages) >= dump_limit:
                    complete = False
                if len(messages) >= dump_limit and not complete:
                    error = error or "Kafka UI message limit reached"
                payload["ui_dump_partial"] = payload["ui_dump_partial"] or not complete
                payload["ui_dump_records"].append(
                    {"cluster": name, "topic": topic, "messages": messages, "complete": complete, "error": error}
                )
        if options.get("show_brokers"):
            items = _json(_get(pool, base, cluster_path + "/brokers", cookie=cookie))
            if isinstance(items, list):
                payload["ui_brokers"].extend(
                    {"cluster": name, "id": item.get("id"), "host": item.get("host")}
                    for item in items[:100]
                    if isinstance(item, dict)
                )
        if options.get("show_consumer_groups"):
            value = _json(_get(pool, base, cluster_path + "/consumer-groups/paged?page=1&perPage=100", cookie=cookie))
            items = value.get("consumerGroups") if isinstance(value, dict) else value
            if isinstance(items, list):
                payload["ui_consumer_groups"].extend(
                    {"cluster": name, "name": item.get("groupId") or item.get("name")}
                    for item in items[:100]
                    if isinstance(item, dict)
                )
    payload["topic_count"] = len(payload["ui_topics"]) if options.get("show_topics") else None
    payload["ui_dump_partial"] = payload["ui_dump_partial"] or payload["ui_dump_skipped_topics"] > 0
    if any(options.get(key) for key in ("probe_write", "write_payload")):
        payload["ui_unsupported_actions"] = "topic writes are unavailable through Kafka UI"
    return payload
