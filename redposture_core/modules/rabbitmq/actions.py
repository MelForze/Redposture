"""RabbitMQ detection, identity verification, permissions, and enumeration.

Only metadata GET endpoints are used. No message consumption, declarations,
publishing, or definitions import occurs in this module.
"""

from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any
from urllib.parse import quote

from ...clients.http_session import HttpSessionPool
from ...clients.rabbitmq_api import RabbitMQClient, RabbitMQResponse

# guest:guest is the vendor default; the remaining pairs are common weak
# deployment credentials, not additional RabbitMQ factory defaults.
DEFAULT_CREDENTIALS = (
    ("admin", "admin"),
    ("admin", "changeme"),
    ("admin", "password"),
    ("admin", "rabbitmq"),
    ("guest", "guest"),
    ("guest", "password"),
    ("rabbitmq", "admin"),
    ("rabbitmq", "password"),
    ("rabbitmq", "rabbitmq"),
    ("root", "password"),
    ("root", "root"),
    ("service", "password"),
    ("service", "service"),
    ("test", "test"),
    ("user", "password"),
    ("user", "user"),
)
host_stage = None


class RabbitMQLifecycleState:
    def __init__(self, ctx: Any) -> None:
        self.host = str(ctx.host)
        self.port = int(ctx.port)
        target = getattr(ctx, "target", None)
        self.scheme = getattr(target, "scheme", None)
        if self.scheme not in {None, "http", "https"}:
            raise ValueError("rabbitmq supports HTTP/HTTPS Management targets only")
        self.base_path = getattr(target, "path", "") or ""
        # Targets copied from an API or UI page still refer to the same mount.
        self.base_path = re.sub(r"/api(?:/.*)?$|/index\.html$", "", self.base_path.rstrip("/"))
        self.pool = HttpSessionPool(
            timeout=float(getattr(ctx.args, "timeout", 5.0)),
            insecure=True,
            retries=int(getattr(ctx.args, "retries", 0)),
            proxy=getattr(ctx.args, "_proxy_config", None),
        )
        self.overview: RabbitMQResponse | None = None
        self.anonymous_identity: str | None = None

    def client(self, credential: Any = None) -> RabbitMQClient:
        return RabbitMQClient(
            self.pool,
            host=self.host,
            port=self.port,
            scheme=self.scheme or ("https" if self.port in {443, 15671} else "http"),
            base_path=self.base_path,
            username=getattr(credential, "username", None),
            password=getattr(credential, "password", None),
        )

    def resolve(self) -> RabbitMQResponse:
        if self.overview is not None:
            return self.overview
        explicit_scheme = self.scheme is not None
        self.scheme = self.scheme or ("https" if self.port in {443, 15671} else "http")
        response = self.client().get("/api/overview")
        detail = (response.error or "").lower()
        mismatch = any(
            word in detail
            for word in (
                "wrong_version_number",
                "unknown_protocol",
                "remote end closed",
                "remotedisconnected",
                "badstatusline",
                "connection reset",
                "connectionreset",
                "reset by peer",
                "unknown protocol",
                "record layer failure",
            )
        )
        tls_required = self.scheme == "http" and response.status == 400 and b"https" in response.body.lower()
        if not explicit_scheme and (mismatch or tls_required):
            self.scheme = "http" if self.scheme == "https" else "https"
            response = self.client().get("/api/overview")
        self.overview = response
        return response

    def close(self) -> None:
        self.pool.close()


def _state(ctx: Any) -> RabbitMQLifecycleState:
    state = ctx.lifecycle_state
    if not isinstance(state, RabbitMQLifecycleState):
        raise TypeError("RabbitMQ hooks require a RabbitMQLifecycleState")
    return state


def _overview(response: RabbitMQResponse) -> dict[str, Any] | None:
    data = response.data
    if response.outcome == "ok" and isinstance(data, dict):
        if isinstance(data.get("rabbitmq_version"), str) and any(
            key in data for key in ("management_version", "erlang_version", "cluster_name")
        ):
            return data
    return None


def _identity(response: RabbitMQResponse) -> dict[str, Any] | None:
    data = response.data
    if response.outcome == "ok" and isinstance(data, dict) and isinstance(data.get("name"), str):
        if data["name"] and isinstance(data.get("tags"), (list, str)):
            return data
    return None


def _tags(identity: dict[str, Any]) -> list[str]:
    value = identity.get("tags", [])
    return [
        tag.strip()
        for tag in (value.split(",") if isinstance(value, str) else value)
        if isinstance(tag, str) and tag.strip()
    ]


def detect_record(ctx: Any) -> dict[str, Any]:
    state = _state(ctx)
    response = state.resolve()
    client = state.client()
    overview = _overview(response)
    challenge = next((v for k, v in response.headers.items() if k.lower() == "www-authenticate"), "")
    realm = "rabbitmq" in challenge.lower()
    evidence: dict[str, Any] = {"overview_status": response.status, "rabbitmq_realm": realm}
    confirmed = overview is not None or (realm and response.status in {401, 403})
    ui = False
    if not confirmed and not response.error:
        root = client.get("/")
        ui = not root.error and bool(
            re.search(rb"<title\b[^>]*>\s*RabbitMQ\s+Management\b[^<]*</title\s*>", root.body, re.I)
        )
        evidence["management_ui"] = ui
        # A generic HTML login page is not an API verifier.
        confirmed = (
            ui and response.status in {401, 403} and isinstance(response.data, dict) and "error" in response.data
        )
    detection = (
        "confirmed" if confirmed else "probable" if ui else "transport_failure" if response.error else "not_rabbitmq"
    )
    record: dict[str, Any] = {
        "host": ctx.host,
        "port": ctx.port,
        "service": "rabbitmq",
        "status": "detected" if confirmed else "probable" if ui else "fail" if response.error else "not_service",
        "detection_status": detection,
        "detection": evidence,
        "api_endpoint": client.base_url,
        "auth_required": None,
        "credential_verification_status": "available" if confirmed else "unavailable",
    }
    if response.error:
        record["error"] = response.error
    if not confirmed:
        return record
    anonymous_endpoints = []
    if overview is not None:
        record["version"] = overview["rabbitmq_version"]
        anonymous_endpoints.append("/api/overview")
    whoami = client.get("/api/whoami")
    identity = _identity(whoami)
    if identity:
        state.anonymous_identity = identity["name"]
        record["anonymous_username"] = identity["name"]
        record["anonymous_tags"] = _tags(identity)
        anonymous_endpoints.append("/api/whoami")
        # A proxy-authenticated identity cannot verify the submitted password.
        record["credential_verification_status"] = "unavailable"
    vhosts = client.collection("/api/vhosts", limit=1, columns="name", paginated=False)
    if vhosts.status == "ok" and all(isinstance(row.get("name"), str) for row in vhosts.items):
        anonymous_endpoints.append("/api/vhosts")
    record["anonymous_endpoints"] = anonymous_endpoints
    record["anonymous"] = (
        "accessible" if anonymous_endpoints else "denied" if response.status in {401, 403} else "unknown"
    )
    if anonymous_endpoints:
        record["auth_required"] = False
        record["status"] = "open_no_auth"
    elif response.status == 401 and whoami.status == 401 and vhosts.http_status == 401:
        record["auth_required"] = True
    return record


def check_admin(client: RabbitMQClient) -> dict[str, Any]:
    """Verify access to the admin-only users API without modifying the broker.

    RabbitMQ's rabbit_mgmt_wm_users calls is_authorized_admin for this route.
    Request only one name; never retain user records or password hashes.
    """
    result = client.collection("/api/users", limit=1, page_size=1, columns="name")
    status = result.status
    if status == "ok" and any(not isinstance(row.get("name"), str) for row in result.items):
        status = "unexpected_response"
    admin = True if status == "ok" else False if status == "denied" else None
    return {
        "admin": admin,
        "admin_status": "confirmed" if admin is True else "denied" if admin is False else "unknown",
        "admin_evidence": {"endpoint": "/api/users", "http_status": result.http_status, "outcome": status},
    }


def auth_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    record = dict(prior)
    credential = ctx.credential
    if credential.username is None or credential.password is None:
        return record
    client = _state(ctx).client(credential)
    response = client.get("/api/whoami")
    identity = _identity(response)
    valid = identity is not None and identity["name"] == credential.username
    # 401/403 can also mean loopback-only guest or no management tag. Neither
    # proves the password itself is wrong; report API rejection/denial precisely.
    result = (
        "valid"
        if valid
        else "rejected"
        if response.status == 401
        else "denied"
        if response.status == 403
        else "unverified"
    )
    record.update(
        credential_state=result,
        provided_credentials_ok=valid,
        credential_username=credential.username,
        credential_http_status=response.status,
        credential_error=response.error,
        credential_type="basic",
        default_credentials=valid and (credential.username, credential.password) in DEFAULT_CREDENTIALS,
    )
    if identity:
        record["effective_username"] = identity["name"]
    if valid:
        record["tags"] = _tags(identity or {})
        # Probe every accepted candidate, not only the identity later selected
        # for enumeration: --defcreds can find users with different privileges.
        record.update(check_admin(client))
    return record


def _can_read(prior: dict[str, Any]) -> bool:
    return prior.get("provided_credentials_ok") is True or prior.get("auth_required") is False


def _read_client(ctx: Any, prior: dict[str, Any]) -> RabbitMQClient:
    return _state(ctx).client(ctx.credential if prior.get("provided_credentials_ok") is True else None)


def capabilities_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    record = dict(prior)
    if not _can_read(prior):
        return record
    client = _read_client(ctx, prior)
    if prior.get("provided_credentials_ok") is not True:
        record.update(check_admin(client))
        record["anonymous_admin"] = record["admin"]
    response = client.get("/api/overview")
    overview = _overview(response)
    if overview:
        record["version"] = overview["rabbitmq_version"]
        record["cluster_name"] = overview.get("cluster_name")
    user = prior.get("effective_username") if prior.get("provided_credentials_ok") else prior.get("anonymous_username")
    if not user:
        record["permissions_status"] = "identity_unknown"
        return record
    if prior.get("provided_credentials_ok") is not True:
        record["tags"] = prior.get("anonymous_tags", [])
    vhost = getattr(ctx.args, "vhost", None)
    for name, suffix in (("permissions", "permissions"), ("topic_permissions", "topic-permissions")):
        result = client.collection(
            f"/api/users/{quote(str(user), safe='')}/{suffix}",
            limit=ctx.args.limit,
            page_size=ctx.args.page_size,
            paginated=False,
        )
        record[name] = [row for row in result.items if vhost is None or row.get("vhost") == vhost]
        record[f"{name}_status"] = result.status
        record[f"{name}_truncated"] = result.truncated
    return record


def data_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    record = dict(prior)
    collections = {
        "vhosts": "name",
        "queues": "name,vhost,type,durable,auto_delete,messages,messages_ready,messages_unacknowledged,consumers",
        "exchanges": "name,vhost,type,durable,auto_delete,internal",
        "bindings": "vhost,source,destination,destination_type,routing_key",
        "nodes": "name,type,running,mem_alarm,disk_free_alarm,partitions",
    }
    show_all = bool(getattr(ctx.args, "enum", False))
    selected = [name for name in collections if show_all or getattr(ctx.args, f"show_{name}", False)]
    show_permissions = show_all or bool(getattr(ctx.args, "show_permissions", False))
    if not (selected or show_permissions) or not _can_read(prior):
        return record
    record["show_permissions"] = show_permissions
    client = _read_client(ctx, prior)
    vhost = getattr(ctx.args, "vhost", None)
    identity = client.get("/api/global-parameters/internal_cluster_id")
    if (
        identity.outcome == "ok"
        and isinstance(identity.data, dict)
        and identity.data.get("name") == "internal_cluster_id"
        and isinstance(identity.data.get("value"), str)
        and identity.data["value"]
    ):
        record["cluster_id"] = identity.data["value"]
    suffix = "/" + quote(vhost, safe="") if vhost is not None else ""
    enumeration: dict[str, Any] = {}
    for name in selected:
        columns = collections[name]
        if name == "vhosts" and vhost is not None:
            response = client.get("/api/vhosts" + suffix)
            if response.outcome == "denied":
                # Management-only users can list visible vhosts while the
                # single-vhost metrics endpoint requires a stronger tag.
                visible = client.collection("/api/vhosts", limit=ctx.args.limit, columns="name", paginated=False)
                enumeration[name] = {
                    **asdict(visible),
                    "items": [{"name": vhost} for row in visible.items if row.get("name") == vhost],
                }
                continue
            good = response.outcome == "ok" and isinstance(response.data, dict) and response.data.get("name") == vhost
            enumeration[name] = {
                "items": [{"name": vhost}] if good else [],
                "status": "ok" if good else response.outcome if response.outcome != "ok" else "unexpected_response",
                "truncated": response.truncated,
                "http_status": response.status,
            }
        else:
            result = client.collection(
                f"/api/{name}" + (suffix if name not in {"vhosts", "nodes"} else ""),
                limit=ctx.args.limit,
                page_size=ctx.args.page_size,
                columns=columns,
                paginated=name not in {"vhosts", "nodes"},
            )
            # Project locally too: servers and reverse proxies may ignore columns.
            projected = [{key: row[key] for key in columns.split(",") if key in row} for row in result.items]
            enumeration[name] = {**asdict(result), "items": projected}
    record["enumeration"] = enumeration
    return record
