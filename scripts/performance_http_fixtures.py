"""Explicit identity/data fixtures for end-to-end performance scenarios.

These are controlled protocol emulations, never real product evidence. Unknown
routes stay unknown instead of returning a product-shaped success everywhere.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlsplit

GRAFANA_AUTH_SURFACES = {
    "user": "/api/user",
    "org": "/api/org",
    "ping": "/api/login/ping",
    "user-orgs": "/api/user/orgs",
    "preferences": "/api/user/preferences",
    "permissions": "/api/access-control/user/permissions",
    "teams": "/api/user/teams",
    "org-users": "/api/org/users",
}

PLATFORM_TOKEN_PRODUCTS = frozenset({"consul", "kubeapi", "qdrant", "gitlab"})
TOKEN_PRODUCTS = frozenset({"vault", "nomad", "jupyter", "keycloak"}) | PLATFORM_TOKEN_PRODUCTS


def profile_pair(module: str, mode: str, auth_case: str) -> tuple[str, str]:
    """Explicit seeded accounts, independent of the product's credential list."""
    if module == "proxmox":
        if mode == "defcreds":
            return "root@pam", "root"
        return (
            ("profile-invalid-user@pve", "profile-invalid-password")
            if auth_case == "invalid"
            else ("profile-reader@pve", "profile-password")
        )
    if mode == "defcreds":
        return "admin", "admin"
    return (
        ("profile-invalid-user", "profile-invalid-password")
        if auth_case == "invalid"
        else ("profile-user", "profile-password")
    )


def profile_token(module: str, auth_case: str) -> str:
    if module in {"nomad", "consul"}:
        return (
            "00000000-0000-4000-8000-000000000001" if auth_case == "invalid" else "11111111-1111-4111-8111-111111111111"
        )
    return "profile-invalid-token" if auth_case == "invalid" else "profile-valid-token"


def rabbitmq_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    valid_pair: tuple[str, str] | None,
    limited: bool,
) -> bytes:
    """Read-only management identity and vhost ACL model, never an AMQP broker.

    Shapes and tag boundaries follow the RabbitMQ management/HTTP reference.
    A management-only identity still verifies; denial of /api/users is separate.
    """
    route = urlsplit(path).path
    challenge = {"WWW-Authenticate": 'Basic realm="RabbitMQ Management"'}
    if method != "GET":
        return response(405, {"error": "method_not_allowed"})
    if body:
        return response(400, {"error": "unexpected_body"})
    pair = _pair(headers)
    if valid_pair is None or pair != valid_pair:
        return response(401, {"error": "not_authorized", "reason": "Not_Authorized"}, headers=challenge)
    user = valid_pair[0]
    if route == "/api/whoami":
        return response(200, {"name": user, "tags": ["management" if limited else "administrator"]})
    if route == "/api/overview":
        return response(
            200,
            {"rabbitmq_version": "4.1.4", "management_version": "4.1.4", "cluster_name": "qa-billing"},
        )
    if route == "/api/global-parameters/internal_cluster_id":
        if limited:
            return response(401, {"error": "not_authorised", "reason": "User not authorised to access object"})
        return response(200, {"name": "internal_cluster_id", "value": "rabbitmq-cluster-id-qa-billing"})
    vhosts = ["billing"] if limited else ["billing", "events"]
    if route in {"/api/users", "/api/nodes"}:
        if limited:
            return response(401, {"error": "not_authorised", "reason": "Not administrator user"})
        return response(200, [{"name": user}] if route.endswith("users") else [{"name": "rabbit@qa", "running": True}])
    if route == "/api/vhosts":
        return response(200, [{"name": name} for name in vhosts])
    if route.startswith("/api/vhosts/"):
        selected: str | None = unquote(route.removeprefix("/api/vhosts/"))
        if selected not in {"billing", "events"}:
            return response(404, {"error": "not_found"})
        return response(200, {"name": selected}) if selected in vhosts else response(401, {"error": "not_authorised"})
    if route == "/api/users/" + quote(user, safe="") + "/permissions":
        if limited:
            return response(401, {"error": "not_authorised", "reason": "Not administrator user"})
        return response(
            200,
            [{"user": user, "vhost": name, "configure": "^$", "write": "^$", "read": ".*"} for name in vhosts],
        )
    if route == "/api/users/" + quote(user, safe="") + "/topic-permissions":
        if limited:
            return response(401, {"error": "not_authorised", "reason": "Not administrator user"})
        return response(200, [])
    if route == "/api/queues" or route.startswith("/api/queues/"):
        selected = unquote(route.removeprefix("/api/queues/")) if route.startswith("/api/queues/") else None
        if selected is not None and selected not in {"billing", "events"}:
            return response(404, {"error": "not_found"})
        if selected is not None and selected not in vhosts:
            return response(401, {"error": "not_authorised"})
        rows = [
            {
                "vhost": vhost,
                "name": name,
                "messages": messages,
                "consumers": consumers,
                "type": "classic",
                "durable": True,
            }
            for vhost, name, messages, consumers in (
                ("billing", "billing.invoices", 12, 2),
                ("billing", "billing.retry", 3, 0),
                ("events", "events.audit", 7, 1),
            )
            if vhost in vhosts and (selected is None or vhost == selected)
        ]
        try:
            fields = parse_qs(urlsplit(path).query, max_num_fields=16)
            page, size = int(fields.get("page", ["1"])[0]), int(fields.get("page_size", ["100"])[0])
            if page < 1 or not 1 <= size <= 500:
                raise ValueError("unsupported page")
        except ValueError:
            return response(400, {"error": "invalid_page"})
        if "page" not in fields and fields.get("pagination") != ["true"]:
            return response(200, rows)
        return response(
            200,
            {
                "page": page,
                "page_size": size,
                "page_count": max(1, (len(rows) + size - 1) // size),
                "total_count": len(rows),
                "filtered_count": len(rows),
                "item_count": len(rows[(page - 1) * size : page * size]),
                "items": rows[(page - 1) * size : page * size],
            },
        )
    return response(404, {"error": "not_found"})


def gitlab_web_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    valid_pair: tuple[str, str] | None,
    limited: bool,
    origin: str,
) -> bytes:
    """CSRF/session-aware web peer; independent of PAT and OCI surfaces."""
    route = urlsplit(path).path
    csrf = hmac.new(b"redposture-qa-only-csrf", origin.encode(), "sha256").hexdigest()
    anonymous = "profile-anon-" + csrf[:24]
    session = (
        "profile-auth-"
        + hmac.new(
            b"redposture-qa-only-session", (origin + "\0" + "\0".join(valid_pair)).encode(), "sha256"
        ).hexdigest()
        if valid_pair is not None
        else None
    )
    cookie = headers.get(b"cookie", b"").decode("ascii", errors="replace").split(";", 1)[0]
    if method == "GET" and route in {"/", "/users/sign_in"}:
        return response(
            200,
            '<html><head><title>GitLab</title></head><body><form method="post" action="/users/sign_in">'
            f'<input type="hidden" name="authenticity_token" value="{csrf}">'
            '<input name="user[login]"><input type="password" name="user[password]"></form></body></html>',
            headers={"Content-Type": "text/html", "Set-Cookie": f"_gitlab_session={anonymous}; Path=/; HttpOnly"},
        )
    if method == "POST" and route == "/users/sign_in":
        try:
            fields = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=True, max_num_fields=16)
        except (ValueError, UnicodeError):
            return response(400, "Invalid form", headers={"Content-Type": "text/plain"})
        if (
            cookie != "_gitlab_session=" + anonymous
            or fields.get("authenticity_token") != [csrf]
            or not headers.get(b"content-type", b"").startswith(b"application/x-www-form-urlencoded")
        ):
            return response(422, "Can't verify CSRF token authenticity", headers={"Content-Type": "text/html"})
        if any(
            not isinstance(fields.get(key), list) or len(fields[key]) != 1 for key in ("user[login]", "user[password]")
        ):
            return response(400, "Invalid form", headers={"Content-Type": "text/plain"})
        pair = fields["user[login]"][0], fields["user[password]"][0]
        if pair != valid_pair:
            return response(
                422,
                "<html><head><title>GitLab</title></head><body>"
                '<div class="flash-alert">Invalid Login or password.</div></body></html>',
                headers={"Content-Type": "text/html"},
            )
        return response(
            302, "", headers={"Location": "/", "Set-Cookie": f"_gitlab_session={session}; Path=/; HttpOnly"}
        )
    if method == "GET" and route == "/api/v4/user":
        if session is not None and cookie == "_gitlab_session=" + session:
            assert valid_pair is not None
            return response(200, {"id": 7, "username": valid_pair[0], "name": "QA User", "state": "active"})
        return response(401, {"message": "401 Unauthorized"})
    return platform_token_reply(
        method, path, headers, body, module="gitlab", valid_token=None, limited=limited, origin=origin
    )


def kube_basic_proxy_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    valid_pair: tuple[str, str] | None,
    limited: bool,
) -> bytes:
    """Explicit HTTP Basic terminating proxy before a modern Kubernetes API."""
    route = urlsplit(path).path
    supplied: tuple[str, str] | None = None
    raw = headers.get(b"authorization", b"")
    if raw[:6].lower() == b"basic ":
        try:
            user, separator, password = base64.b64decode(raw[6:], validate=True).decode("utf-8").partition(":")
            if separator:
                supplied = user, password
        except (UnicodeError, ValueError):
            pass
    allowed = supplied is not None and valid_pair is not None and supplied == valid_pair
    review = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
    if route in {"/api/v1/namespaces", "/api/v1/pods", review} and not allowed:
        return response(
            401,
            {"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": 401, "reason": "Unauthorized"},
            headers={"WWW-Authenticate": 'Basic realm="Kubernetes QA proxy"'},
        )
    if route == review and method == "POST" and allowed:
        try:
            submitted = json.loads(body)
        except ValueError:
            submitted = None
        if (
            not isinstance(submitted, dict)
            or submitted.get("kind") != "SelfSubjectReview"
            or submitted.get("apiVersion") != "authentication.k8s.io/v1"
        ):
            return response(
                400, {"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": 400, "reason": "BadRequest"}
            )
        assert supplied is not None
        return response(
            201,
            {
                "kind": "SelfSubjectReview",
                "apiVersion": "authentication.k8s.io/v1",
                "status": {"userInfo": {"username": supplied[0], "groups": ["system:authenticated"]}},
            },
        )
    # Internal fixture delegation after verification, not a changed client header.
    return platform_token_reply(
        method,
        path,
        {b"authorization": b"Bearer qa-verified-proxy"} if allowed else {},
        body,
        module="kubeapi",
        valid_token="qa-verified-proxy",
        limited=limited,
    )


def response(status: int, payload: Any, *, headers: dict[str, str] | None = None) -> bytes:
    body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
    fields = {"Content-Type": "application/json", "Connection": "close", **(headers or {})}
    fields["Content-Length"] = str(len(body))
    return (
        f"HTTP/1.1 {status} Result\r\n" + "".join(f"{k}: {v}\r\n" for k, v in fields.items()) + "\r\n"
    ).encode() + body


def verified_s3_access_key(
    method: str, path: str, headers: dict[bytes, bytes], body: bytes, *, secret_key: str
) -> str | None:
    """Independent QA SigV4 verifier; never imports the product's signer.

    Header-signed requests only, with a hashed body. Timestamp freshness, STS,
    presigned URLs and streaming/chunk signatures are not emulated here.
    """
    try:
        auth = headers[b"authorization"].decode("ascii")
        if len(auth) > 4096 or not auth.startswith("AWS4-HMAC-SHA256 "):
            return None
        parts = [item.strip().split("=", 1) for item in auth.split(" ", 1)[1].split(",")]
        if len(parts) != 3 or any(len(item) != 2 for item in parts):
            return None
        fields = dict(parts)
        if set(fields) != {"Credential", "SignedHeaders", "Signature"}:
            return None
        scope = fields["Credential"].split("/")
        if len(scope) != 5 or scope[3:] != ["s3", "aws4_request"] or not scope[0] or not scope[2]:
            return None
        date = headers[b"x-amz-date"].decode("ascii")
        if re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", date) is None or scope[1] != date[:8]:
            return None
        names = fields["SignedHeaders"].split(";")
        if (
            not 1 <= len(names) <= 32
            or names != sorted(set(names))
            or not {"host", "x-amz-date"}.issubset(names)
            or any(re.fullmatch(r"[a-z0-9-]+", name) is None for name in names)
        ):
            return None
        payload_hash = headers[b"x-amz-content-sha256"].decode("ascii")
        if payload_hash != hashlib.sha256(body).hexdigest():
            return None
        canonical_headers = "".join(
            name + ":" + " ".join(headers[name.encode()].decode("ascii").split()) + "\n" for name in names
        )
        parsed = urlsplit(path)
        query = []
        for part in parsed.query.split("&") if parsed.query else ():
            if part:
                name, _, value = part.partition("=")
                query.append((quote(unquote(name), safe="-_.~"), quote(unquote(value), safe="-_.~")))
        canonical = "\n".join(
            [
                method.upper(),
                parsed.path or "/",
                "&".join(name + "=" + value for name, value in sorted(query)),
                canonical_headers,
                fields["SignedHeaders"],
                payload_hash,
            ]
        )
        signing_key = ("AWS4" + secret_key).encode()
        for part in scope[1:]:
            signing_key = hmac.digest(signing_key, part.encode(), "sha256")
        to_sign = "\n".join(
            ["AWS4-HMAC-SHA256", date, "/".join(scope[1:]), hashlib.sha256(canonical.encode()).hexdigest()]
        )
        expected = hmac.new(signing_key, to_sign.encode(), hashlib.sha256).hexdigest()
        return scope[0] if hmac.compare_digest(expected, fields["Signature"]) else None
    except (KeyError, UnicodeError, ValueError):
        return None


def minio_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    valid_pair: tuple[str, str] | None,
    limited: bool,
) -> bytes:
    """Read-only S3/Admin peer: signature proof precedes the ACL decision."""
    wire_headers = {"Server": "MinIO", "Content-Type": "application/xml"}

    def deny(code: str, status: int = 403) -> bytes:
        return response(status, f"<Error><Code>{code}</Code><Message>{code}</Message></Error>", headers=wire_headers)

    route = urlsplit(path).path
    if method != "GET":
        return deny("AccessDenied")
    if route in {"/minio/health/live", "/minio/health/ready"}:
        return response(200, "", headers=wire_headers)
    authorization = headers.get(b"authorization", b"")
    if not authorization:
        return deny("AccessDenied")
    match = re.search(rb"\bCredential=([^/ ,]+)(?:/)", authorization)
    if match is None:
        return deny("SignatureDoesNotMatch")
    if valid_pair is None or match[1] != valid_pair[0].encode():
        return deny("InvalidAccessKeyId")
    if verified_s3_access_key(method, path, headers, body, secret_key=valid_pair[1]) != valid_pair[0]:
        return deny("SignatureDoesNotMatch")
    if headers.get(b"x-amz-security-token"):
        return deny("InvalidToken")
    if limited:
        return deny("AccessDenied")
    if route == "/":
        buckets = "".join(
            f"<Bucket><Name>{name}</Name><CreationDate>2026-01-01T00:00:00Z</CreationDate></Bucket>"
            for name in ("analytics-reports", "pipeline-artifacts", "audit-backups")
        )
        return response(
            200,
            '<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            f"<Buckets>{buckets}</Buckets></ListAllMyBucketsResult>",
            headers=wire_headers,
        )
    admin = {
        "/minio/admin/v3/accountinfo": {"accountName": valid_pair[0], "buckets": [], "policy": {}},
        "/minio/admin/v3/list-users": {"pipeline-reader": {"status": "enabled"}},
        "/minio/admin/v3/list-canned-policies": {"readonly": {"Version": "2012-10-17", "Statement": []}},
    }
    if route in admin:
        return response(200, admin[route], headers={"Server": "MinIO"})
    return deny("NoSuchKey", 404)


def token_from_headers(module: str, headers: dict[bytes, bytes]) -> str | None:
    name = {
        "vault": b"x-vault-token",
        "nomad": b"x-nomad-token",
        "jupyter": b"authorization",
        "consul": b"x-consul-token",
        "kubeapi": b"authorization",
        "qdrant": b"api-key",
        "gitlab": b"private-token",
        "keycloak": b"authorization",
    }[module]
    value = headers.get(name)
    if value is None:
        return None
    if module in {"jupyter", "kubeapi", "keycloak"}:
        prefix = b"token " if module == "jupyter" else b"Bearer "
        if not value.startswith(prefix):
            return None
        value = value[len(prefix) :]
    try:
        return value.decode("utf-8")
    except UnicodeError:
        return None


def keycloak_token_reply(
    method: str, path: str, headers: dict[bytes, bytes], *, valid_token: str | None, limited: bool, origin: str
) -> bytes:
    """Read-only realm discovery and independent bearer identity/admin ACLs."""
    from scripts.performance_keycloak import REALMS, client_page, realm_representation

    parsed = urlsplit(path)
    route = parsed.path
    if method != "GET":
        return response(403, {"error": "read-only performance fixture"})
    public_realm = next(
        (realm for realm in REALMS if route == f"/realms/{realm}" or route.startswith(f"/realms/{realm}/")), None
    )
    issuer = origin + "/realms/" + (public_realm or "master")
    if public_realm is not None and route == f"/realms/{public_realm}":
        return response(
            200,
            {
                "realm": public_realm,
                "public_key": "A" * 128,
                "token-service": issuer + "/protocol/openid-connect",
                "account-service": issuer + "/account",
            },
        )
    if public_realm is not None and route == f"/realms/{public_realm}/.well-known/openid-configuration":
        return response(
            200,
            {
                "issuer": issuer,
                "jwks_uri": issuer + "/protocol/openid-connect/certs",
                "token_endpoint": issuer + "/protocol/openid-connect/token",
                "authorization_endpoint": issuer + "/protocol/openid-connect/auth",
            },
        )
    if public_realm is not None and route == f"/realms/{public_realm}/protocol/openid-connect/certs":
        return response(200, {"keys": []})
    protected = {
        "/admin/serverinfo",
        "/admin/realms",
        "/realms/master/protocol/openid-connect/userinfo",
        "/admin/master/console/whoami",
    }
    protected.update(f"/admin/realms/{realm}" for realm in REALMS)
    protected.update(f"/admin/realms/{realm}/clients" for realm in REALMS)
    protected.update(f"/admin/{realm}/console/whoami" for realm in REALMS)
    protected.update(f"/realms/{realm}/protocol/openid-connect/userinfo" for realm in REALMS)
    if route not in protected:
        return response(404, {"error": "not a supported route"})
    supplied = token_from_headers("keycloak", headers)
    if supplied is None or valid_token is None or supplied != valid_token:
        return response(
            401, {"error": "unauthorized"}, headers={"WWW-Authenticate": 'Bearer realm="master", error="invalid_token"'}
        )
    if route == "/realms/master/protocol/openid-connect/userinfo":
        return response(200, {"sub": "profile-subject", "preferred_username": "profile-reader"})
    if route.endswith("/protocol/openid-connect/userinfo"):
        return response(401, {"error": "wrong token realm"})
    if limited:
        return response(403, {"error": "Forbidden"})
    if route == "/admin/serverinfo":
        return response(200, {"systemInfo": {"version": "26.6.3"}})
    if route == "/admin/realms":
        return response(200, [{"realm": realm, "enabled": True} for realm in REALMS])
    for realm in REALMS:
        if route == f"/admin/realms/{realm}":
            return response(200, realm_representation(realm))
        if route == f"/admin/realms/{realm}/clients":
            query = parse_qs(parsed.query, keep_blank_values=True)
            if set(query) - {"first", "max"} or any(len(values) != 1 for values in query.values()):
                return response(400, {"error": "unsupported or ambiguous fixture query"})
            try:
                values = client_page(realm, int(query.get("first", ["0"])[0]), int(query.get("max", ["100"])[0]))
            except ValueError:
                return response(400, {"error": "invalid pagination"})
            return response(200, values)
    return response(200, {"username": "profile-reader"})


def token_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    module: str,
    valid_token: str | None,
    limited: bool = False,
    origin: str = "http://profile.invalid",
) -> bytes:
    """Product-shaped identities; ACL denial does not revoke a valid token.

    Vault and Nomad error distinctions follow their official token API docs;
    Jupyter shapes match the existing token API integration corpus. This is an
    emulation, never evidence of testing a real product or executing a task.
    """
    if module not in TOKEN_PRODUCTS:
        raise ValueError("unsupported token product")
    if module in PLATFORM_TOKEN_PRODUCTS:
        return platform_token_reply(
            method, path, headers, body, module=module, valid_token=valid_token, limited=limited, origin=origin
        )
    if module == "keycloak":
        return keycloak_token_reply(method, path, headers, valid_token=valid_token, limited=limited, origin=origin)
    route = urlsplit(path).path
    if method != "GET":
        return response(403, {"message": "read-only profile; writes and execution denied"})
    supplied = token_from_headers(module, headers)
    allowed = supplied is not None and valid_token is not None and supplied == valid_token
    if module == "vault":
        if route == "/v1/sys/health":
            return response(
                200, {"initialized": True, "sealed": False, "standby": False, "version": "1.17.5", "enterprise": False}
            )
        if route == "/v1/auth/token/lookup-self":
            return (
                response(
                    200,
                    {
                        "data": {
                            "id": supplied,
                            "policies": ["default", "identity" if limited else "reader"],
                            "ttl": 900,
                            "renewable": False,
                        }
                    },
                )
                if allowed
                else response(403, {"errors": ["permission denied", "invalid token"]})
            )
        if route not in {"/v1/sys/mounts", "/v1/sys/auth"}:
            return response(404, {"errors": ["unsupported path"]})
        if not allowed or limited:
            return response(403, {"errors": ["permission denied"]})
        return (
            response(
                200,
                {
                    "data": {
                        "secret/": {"type": "kv", "description": "Platform configuration", "options": {"version": "2"}},
                        "database/": {"type": "database", "description": "Database roles"},
                        "transit/": {"type": "transit", "description": "Application signing"},
                    }
                },
            )
            if route == "/v1/sys/mounts"
            else response(200, {"data": {"token/": {"type": "token"}}})
        )
    if module == "nomad":
        common = {"X-Nomad-Index": "42"}
        if route == "/v1/agent/self":
            return response(
                200, {"config": {"Version": "1.10.1", "ACL": {"Enabled": True}}, "stats": {}}, headers=common
            )
        if route == "/v1/status/leader":
            return response(200, json.dumps("127.0.0.1:4647"), headers=common)
        if route == "/ui/":
            return response(
                200,
                '<title>Nomad</title><meta name="nomad-ui/config/environment">',
                headers={**common, "Content-Type": "text/html"},
            )
        if route == "/v1/acl/token/self":
            return (
                response(
                    200,
                    {
                        "SecretID": supplied,
                        "AccessorID": "profile-accessor",
                        "Type": "client",
                        "Policies": ["identity" if limited else "read"],
                    },
                    headers=common,
                )
                if allowed
                else response(403, "ACL token not found", headers={**common, "Content-Type": "text/plain"})
            )
        if route not in {"/v1/jobs", "/v1/nodes", "/v1/agent/members"}:
            return response(404, "not found", headers=common)
        if not allowed or limited:
            return response(403, "Permission denied", headers={**common, "Content-Type": "text/plain"})
        if route == "/v1/jobs":
            return response(
                200,
                [
                    {"ID": name, "Name": name, "Namespace": "default", "Status": "running"}
                    for name in ("platform-api", "billing-batch", "nightly-backup")
                ],
                headers=common,
            )
        return (
            response(200, [{"ID": "client-1", "Name": "worker-1", "Status": "ready"}])
            if route == "/v1/nodes"
            else response(200, {"Members": [{"Name": "server-1"}]})
        )
    if route == "/api":
        return response(200, {"version": "2.17.0"})
    if route == "/login":
        return response(
            200,
            '<title>Jupyter Server</title><form id="login_form"><input name="_xsrf"></form>',
            headers={"Content-Type": "text/html"},
        )
    if route not in {"/api/status", "/api/me", "/api/kernels", "/api/sessions", "/api/terminals", "/api/contents"}:
        return response(404, {"message": "Not Found", "reason": None})
    if not allowed or (limited and route != "/api/me"):
        return response(403, {"message": "Forbidden", "reason": None})
    if route == "/api/me":
        return response(200, {"identity": {"username": "profile-reader", "name": "Profile reader"}})
    if route == "/api/status":
        return response(
            200,
            {
                "connections": 2,
                "kernels": 2,
                "started": "2026-11-07T00:00:00Z",
                "last_activity": "2026-11-07T00:01:00Z",
            },
        )
    if route == "/api/kernels":
        return response(
            200,
            [
                {"id": "analysis", "name": "python3", "execution_state": "idle"},
                {"id": "reporting", "name": "python3", "execution_state": "busy"},
            ],
        )
    if route == "/api/contents":
        return response(
            200,
            {
                "name": "",
                "path": "",
                "type": "directory",
                "content": [{"name": "analysis.ipynb", "path": "analysis.ipynb", "type": "notebook"}],
            },
        )
    return response(200, [])


def _pair(headers: dict[bytes, bytes]) -> tuple[str, str] | None:
    value = headers.get(b"authorization", b"")
    if not value.startswith(b"Basic "):
        return None
    try:
        user, separator, password = base64.b64decode(value[6:], validate=True).decode().partition(":")
    except (ValueError, UnicodeError, binascii.Error):
        return None
    return (user, password) if separator else None


def airflow_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    valid_pair: tuple[str, str] | None,
    limited: bool = False,
) -> bytes:
    """Airflow2 Basic API, with typed refusal and independent collection ACLs."""
    route = urlsplit(path).path

    def problem(code: int, title: str) -> bytes:
        return response(
            code,
            {
                "status": code,
                "title": title,
                "detail": title,
                "type": "https://airflow.apache.org/docs/apache-airflow/2.9.2/stable-rest-api-ref.html#section/Errors/"
                + title,
            },
            headers={"Content-Type": "application/problem+json"},
        )

    if method != "GET":
        return problem(403, "PermissionDenied")
    if route == "/api/v1/version":
        return response(200, {"version": "2.9.2", "git_version": "profile-build"})
    if route in {"/api/v1/health", "/health"}:
        return response(200, {"metadatabase": {"status": "healthy"}, "scheduler": {"status": "healthy"}})
    collection = {"/api/v1/dags": "dags", "/api/v1/variables": "variables", "/api/v1/connections": "connections"}.get(
        route
    )
    if collection is None:
        return problem(404, "NotFound")
    if valid_pair is None or _pair(headers) != valid_pair:
        return problem(401, "Unauthorized")
    if limited and collection in {"dags", "connections"}:
        return problem(403, "PermissionDenied")
    collections: dict[str, list[dict[str, Any]]] = {
        "dags": [
            {
                "dag_id": name,
                "is_active": True,
                "is_paused": False,
                "tags": [],
                "owners": ["data-platform"],
                "fileloc": "/opt/airflow/dags/" + name + ".py",
            }
            for name in ("finance_daily", "events_ingest", "warehouse_rollup")
        ],
        "variables": [{"key": "deployment_region", "value": "qa-east"}, {"key": "pipeline_pool", "value": "batch"}],
        "connections": [
            {
                "connection_id": name,
                "conn_type": "postgres",
                "host": "database.internal",
                "port": 5432,
                "login": "reader",
                "schema": "analytics",
            }
            for name in ("warehouse_reporting", "events_archive")
        ],
    }
    records = collections[collection]
    query = parse_qs(urlsplit(path).query)
    try:
        offset, limit = int(query.get("offset", ["0"])[0]), int(query.get("limit", ["100"])[0])
    except ValueError:
        return problem(400, "BadRequest")
    if not 0 <= offset <= 100000 or not 1 <= limit <= 1000:
        return problem(400, "BadRequest")
    return response(200, {collection: records[offset : offset + limit], "total_entries": len(records)})


def grafana_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    valid_pair: tuple[str, str] | None,
    limited: bool = False,
    auth_surface: str = "user",
) -> bytes | None:
    """Return None only for public detection routes supplied by the wire corpus."""
    path = urlsplit(path).path
    if auth_surface not in GRAFANA_AUTH_SURFACES:
        raise ValueError("undefined Grafana authentication surface")
    selected = list(GRAFANA_AUTH_SURFACES).index(auth_surface)
    unavailable = set(list(GRAFANA_AUTH_SURFACES.values())[:selected])
    if selected:
        unavailable.add("/api/datasources")
    if path in unavailable:
        return response(404, {"message": "Not found"})
    pair = _pair(headers)
    if method == "POST" and path == "/login":
        try:
            login = json.loads(body)
        except (ValueError, UnicodeError):
            return response(400, {"message": "bad login request"})
        if not isinstance(login, dict):
            return response(400, {"message": "bad login request"})
        pair = (str(login.get("user", "")), str(login.get("password", "")))
        if valid_pair is None or pair != valid_pair:
            return response(401, {"message": "Invalid username or password"})
        # Basic-identity proof is the primary path; cookie login remains a
        # distinct explicit surface, not a generic success for every POST.
        return response(200, {"message": "Logged in"}, headers={"Set-Cookie": "grafana_session=qa-profile; Path=/"})
    if path in {"/", "/login", "/api/health"}:
        return None
    if not path.startswith("/api/"):
        return response(404, {"message": "Not found"})
    if valid_pair is None or pair != valid_pair:
        return response(401, {"message": "Unauthorized"})
    if path == "/api/user":
        return response(200, {"id": 1, "login": valid_pair[0], "email": "profile@example.invalid", "orgId": 1})
    if path == "/api/org":
        return response(200, {"id": 1, "name": "Profile operations", "address": {}})
    if path == "/api/login/ping":
        return response(200, {"message": "Logged in"})
    if path == "/api/user/orgs":
        return response(200, [{"orgId": 1, "name": "Profile operations", "role": "Admin"}])
    if path == "/api/user/preferences":
        return response(200, {"theme": "dark", "timezone": "utc"})
    if path == "/api/access-control/user/permissions":
        return response(200, {"datasources:read": ["datasources:*"]})
    if path == "/api/user/teams":
        return response(200, [{"id": 1, "orgId": 1, "name": "Operations", "email": "ops@example.invalid"}])
    if path == "/api/org/users":
        return response(200, [{"orgId": 1, "userId": 1, "login": valid_pair[0], "role": "Editor"}])
    if path == "/api/datasources":
        if limited:
            return response(403, {"message": "Access denied"})
        return response(
            200,
            [
                {
                    "id": 1,
                    "uid": "metrics",
                    "name": "Platform metrics",
                    "type": "prometheus",
                    "url": "http://metrics:9090",
                    "access": "proxy",
                    "isDefault": True,
                },
                {
                    "id": 2,
                    "uid": "logs",
                    "name": "Application logs",
                    "type": "loki",
                    "url": "http://logs:3100",
                    "access": "proxy",
                    "isDefault": False,
                },
            ],
        )
    return response(404, {"message": "Not found"})


def jenkins_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    valid_pair: tuple[str, str] | None,
    limited: bool = False,
    origin: str = "http://127.0.0.1",
) -> bytes:
    """A protected API, independent whoAmI and three realistic job identities."""
    parsed = urlsplit(path)
    route = parsed.path
    common = {"X-Jenkins": "2.541.3"}
    if method == "GET" and route in {"/", "/login"}:
        return response(
            200,
            '<html><title>Jenkins</title><h1>Jenkins</h1><form action="j_spring_security_check"><input name="j_username"><input name="j_password"></form></html>',
            headers={**common, "Content-Type": "text/html"},
        )
    pair = _pair(headers)
    authenticated = valid_pair is not None and pair == valid_pair
    if route == "/whoAmI/api/json":
        if pair is not None and not authenticated:
            return response(401, {"message": "Invalid credentials"}, headers=common)
        return response(
            200,
            {
                "authenticated": authenticated,
                "name": valid_pair[0] if authenticated and valid_pair else "anonymous",
                "authorities": ["authenticated"] if authenticated else ["anonymous"],
            },
            headers=common,
        )
    if not authenticated:
        return response(401, {"message": "Authentication required"}, headers=common)
    if route == "/api/json" and method == "GET":
        if limited:
            return response(403, {"message": "Access denied"}, headers=common)
        jobs = [
            {
                "name": "platform-deploy",
                "url": origin + "/job/platform-deploy/",
                "color": "blue",
                "lastBuild": {"number": 42, "result": "SUCCESS"},
            },
            {
                "name": "billing-tests",
                "url": origin + "/job/billing-tests/",
                "color": "red",
                "lastBuild": {"number": 117, "result": "FAILURE"},
            },
            {
                "name": "nightly-backup",
                "url": origin + "/job/nightly-backup/",
                "color": "blue",
                "lastBuild": {"number": 28, "result": "SUCCESS"},
            },
        ]
        tree = parse_qs(parsed.query).get("tree", [""])[0]
        if tree:
            jobs = [{key: value for key, value in job.items() if key in tree} for job in jobs]
        result: dict[str, Any] = {"jobs": jobs}
        if not tree or "_class" in tree:
            result["_class"] = "hudson.model.Hudson"
        return response(200, result, headers=common)
    if route == "/crumbIssuer/api/json":
        return response(200, {"crumbRequestField": "Jenkins-Crumb", "crumb": "profile-crumb"}, headers=common)
    if route == "/scriptText" and method == "POST":
        # The execution probe is a real public-stage request, but this read-only
        # profile identity cannot execute anything; no script body is evaluated.
        return response(403, "Permission denied: Overall/RunScripts", headers=common)
    return response(404, {"message": "Not found"}, headers=common)


def proxmox_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    valid_pair: tuple[str, str] | None,
    limited: bool = False,
) -> bytes:
    """Non-persistent ticket emulation; read-only cluster, never a hypervisor."""
    route = urlsplit(path).path
    common = {"Server": "pve-api-daemon/3.0"}

    def reply(status: int, data: Any = None, message: str | None = None) -> bytes:
        return response(status, {"data": data, **({"message": message} if message else {})}, headers=common)

    if not route.startswith("/api2/json/"):
        return response(404, {"message": "not a supported route"})
    if route == "/api2/json/access/ticket" and method == "POST":
        try:
            fields = parse_qs(body.decode("utf-8"), strict_parsing=True, keep_blank_values=True)
        except (ValueError, UnicodeError):
            return reply(400, message="parameter verification failed")
        if set(fields) != {"username", "password"} or any(len(v) != 1 for v in fields.values()):
            return reply(400, message="parameter verification failed")
        pair = fields["username"][0], fields["password"][0]
        if valid_pair is None or pair != valid_pair:
            return reply(401, message="authentication failure")
        return reply(200, {"username": pair[0], "ticket": "profile-ticket", "CSRFPreventionToken": "profile-csrf"})
    if method != "GET":
        return reply(403, message="Permission check failed (read-only profile)")
    if route == "/api2/json/version":
        return reply(200, {"version": "8.3.0", "release": "1", "repoid": "abcdefabcdef"})
    if valid_pair is None or headers.get(b"cookie") != b"PVEAuthCookie=profile-ticket":
        return reply(401, message="invalid PVE ticket")
    if route == "/api2/json/access":
        return reply(200, [{"subdir": "users"}, {"subdir": "permissions"}])
    if route == "/api2/json/access/permissions":
        return reply(200, {"/": {} if limited else {"Sys.Audit": 1, "VM.Audit": 1}})
    if limited and route in {"/api2/json/nodes", "/api2/json/access/users"}:
        return reply(403, message="Permission check failed (Sys.Audit)")
    if route == "/api2/json/nodes":
        return reply(
            200,
            [
                {"node": name, "status": "online", "cpu": 0.1, "maxmem": 17179869184}
                for name in ("pve-app", "pve-data", "pve-edge")
            ],
        )
    if route == "/api2/json/access/users":
        return reply(200, [{"userid": name, "enable": 1} for name in ("root@pam", "monitor@pve", "backup@pve")])
    return reply(404, message="no such API path")


def registry_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    valid_pair: tuple[str, str] | None,
    limited: bool = False,
) -> bytes:
    """Protected V2 Basic identity plus independent read ACLs, never a product.

    Distribution permits authentication/authorization middleware. The limited
    case emulates such a gateway, not native htpasswd role support. No writes,
    uploads, manifest evaluation or execution are implemented by this peer.
    """
    parsed = urlsplit(path)
    route = parsed.path
    common = {"Docker-Distribution-API-Version": "registry/2.0"}

    def failure(status: int, code: str, message: str, *, challenge: bool = False) -> bytes:
        return response(
            status,
            {"errors": [{"code": code, "message": message}]},
            headers={**common, **({"WWW-Authenticate": 'Basic realm="profile-registry"'} if challenge else {})},
        )

    if not route.startswith("/v2/"):
        return response(404, {"errors": [{"code": "NOT_FOUND", "message": "not a supported route"}]})
    if method not in {"GET", "HEAD"}:
        return failure(403, "DENIED", "read-only profile; writes denied")
    if valid_pair is None or _pair(headers) != valid_pair:
        return failure(401, "UNAUTHORIZED", "authentication required", challenge=True)
    if route == "/v2/":
        return response(200, {}, headers=common)
    if limited:
        return failure(403, "DENIED", "requested access to the resource is denied")
    if route == "/v2/_catalog":
        query = parse_qs(parsed.query)
        cursor = query.get("last", [""])[0]
        if cursor not in {"", "observability/collector"}:
            return failure(400, "PAGINATION_NUMBER_INVALID", "invalid cursor")
        return response(
            200,
            {"repositories": ["platform/api"] if cursor else ["billing/worker", "observability/collector"]},
            headers={
                **common,
                **({"Link": '</v2/_catalog?n=2&last=observability%2Fcollector>; rel="next"'} if not cursor else {}),
            },
        )
    if route.startswith("/v2/") and route.endswith("/tags/list"):
        name = route[len("/v2/") : -len("/tags/list")]
        if name not in {"billing/worker", "observability/collector", "platform/api"}:
            return failure(404, "NAME_UNKNOWN", "repository name not known to registry")
        return response(200, {"name": name, "tags": ["2026.11", "stable", "rollback"]}, headers=common)
    return failure(404, "NOT_FOUND", "not a supported route")


def harbor_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    valid_pair: tuple[str, str] | None,
    limited: bool,
) -> bytes:
    """Harbor v2 local Basic identity and read ACLs, not OIDC/robot/Bearer.

    API and V2 registry are separate surfaces. This peer deliberately uses a
    Basic-protected V2 gateway; it does not pretend to implement Harbor tokens.
    """
    parsed = urlsplit(path)
    route = parsed.path
    if route.startswith("/v2/"):
        return registry_reply(method, path, headers, body, valid_pair=valid_pair, limited=limited)
    if method != "GET" or body:
        return response(405, {"errors": [{"code": "METHOD_NOT_ALLOWED"}]})
    if route == "/api/v2.0/systeminfo":
        return response(200, {"harbor_version": "v2.14.0", "auth_mode": "db_auth", "registry_url": "registry.qa"})
    if not route.startswith("/api/v2.0/"):
        return response(404, {"errors": [{"code": "NOT_FOUND"}]})
    if valid_pair is None or _pair(headers) != valid_pair:
        return response(401, {"errors": [{"code": "UNAUTHORIZED"}]})
    if route == "/api/v2.0/users/current":
        return response(200, {"username": valid_pair[0], "user_id": 42, "sysadmin_flag": not limited})
    if limited:
        return response(403, {"errors": [{"code": "FORBIDDEN"}]})
    query = parse_qs(parsed.query, keep_blank_values=True)
    try:
        page = int(query.get("page", ["1"])[0])
        size = int(query.get("page_size", ["100"])[0])
        if page < 1 or not 1 <= size <= 100:
            raise ValueError("invalid pagination")
    except ValueError:
        return response(400, {"errors": [{"code": "BAD_REQUEST"}]})
    repos = {"billing": "worker", "observability": "collector", "platform": "api"}
    items: list[dict[str, Any]]
    if route == "/api/v2.0/projects":
        items = [{"project_id": i, "name": name} for i, name in enumerate(repos, 1)]
    else:
        match = re.fullmatch(r"/api/v2.0/projects/([^/]+)/repositories(?:/([^/]+)/artifacts)?", route)
        if match is None or match[1] not in repos:
            return response(404, {"errors": [{"code": "NOT_FOUND"}]})
        project, artifact_repo = match.groups()
        name = project + "/" + repos[project]
        if artifact_repo is None:
            items = [{"id": 1, "name": name, "artifact_count": 3, "pull_count": 12}]
        elif unquote(unquote(artifact_repo)) == repos[project]:
            items = [
                {"digest": "sha256:" + hashlib.sha256((name + ":" + tag).encode()).hexdigest(), "tags": [{"name": tag}]}
                for tag in ["2026.11", "stable", "rollback"]
            ]
        else:
            return response(404, {"errors": [{"code": "NOT_FOUND"}]})
    return response(200, items[(page - 1) * size : page * size], headers={"X-Total-Count": str(len(items))})


def nexus_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    valid_pair: tuple[str, str] | None,
    limited: bool,
    origin: str,
) -> bytes:
    """Nexus 3 Basic REST identity/ACL and cursor pages, not a real server.

    This deployment protects status via an HTTP Basic gateway. A repository
    connector on a separate port is absent. Writes and script execution fail.
    """
    parsed = urlsplit(path)
    route = parsed.path
    common = {"Server": "Nexus/3.72.0-04 (OSS)"}
    if method != "GET" or body:
        return response(405, {"error": "read-only profile"}, headers=common)
    if route in {"/v2/", "/api/v2.0/systeminfo", "/api/systeminfo", "/jwt/auth"}:
        return response(404, {"error": "not found"})
    if not route.startswith("/service/rest/v1/"):
        return response(404, {"error": "not found"})
    if valid_pair is None or _pair(headers) != valid_pair:
        return response(
            401,
            {"error": "unauthorized"},
            headers={**common, "WWW-Authenticate": 'Basic realm="Sonatype Nexus Repository Manager"'},
        )
    if route == "/service/rest/v1/status":
        return response(200, {}, headers=common)
    if route == "/service/rest/v1/security/users":
        return (
            response(403, {"error": "forbidden"}, headers=common)
            if limited
            else response(
                200,
                [{"userId": valid_pair[0], "status": "active", "source": "default", "roles": ["nx-admin"]}],
                headers=common,
            )
        )
    repos: list[dict[str, Any]] = [
        {"name": "billing-images", "format": "docker", "type": "hosted", "online": True},
        {"name": "platform-maven", "format": "maven2", "type": "hosted", "online": True},
        {"name": "release-assets", "format": "raw", "type": "hosted", "online": True},
    ]
    if route not in {"/service/rest/v1/repositories", "/service/rest/v1/components"}:
        return response(404, {"error": "not found"}, headers=common)
    if limited:
        return response(403, {"error": "forbidden"}, headers=common)
    if route.endswith("/repositories"):
        return response(200, [{**r, "url": origin + "/repository/" + r["name"]} for r in repos], headers=common)
    query = parse_qs(parsed.query, keep_blank_values=True)
    selected = query.get("repository", [])
    if len(selected) != 1 or selected[0] not in {r["name"] for r in repos}:
        return response(404, {"error": "unknown repository"}, headers=common)
    repo = selected[0]
    cursor = query.get("continuationToken", [""])
    if len(cursor) != 1 or cursor[0] not in {"", "page-two"}:
        return response(400, {"error": "invalid continuation token"}, headers=common)
    items = []
    for index, version in enumerate(["2026.11", "stable", "rollback"], 1):
        name = (
            "billing/worker"
            if repo == "billing-images"
            else "platform-api"
            if repo == "platform-maven"
            else "release-notes"
        )
        asset_path = name + "/" + version + ("/manifest.json" if repo == "billing-images" else "/artifact.bin")
        items.append(
            {
                "id": repo + "-" + str(index),
                "repository": repo,
                "name": name,
                "version": version,
                "assets": [
                    {
                        "path": asset_path,
                        "downloadUrl": origin + "/repository/" + repo + "/" + asset_path,
                        "checksum": {"sha256": hashlib.sha256((repo + ":" + asset_path).encode()).hexdigest()},
                    }
                ],
            }
        )
    return response(
        200,
        {"items": items[2:] if cursor[0] else items[:2], "continuationToken": None if cursor[0] else "page-two"},
        headers=common,
    )


def platform_token_reply(
    method: str,
    path: str,
    headers: dict[bytes, bytes],
    body: bytes,
    *,
    module: str,
    valid_token: str | None,
    limited: bool = False,
    origin: str = "http://profile.invalid",
) -> bytes:
    """Seeded identity and independent object ACLs; no persistent writes.

    Kubernetes SelfSubjectReview is a non-persistent identity lookup using POST.
    All other mutating requests are denied, including execution and clone flows.
    These protocol peers are not evidence of running a real product/version.
    """
    if module not in PLATFORM_TOKEN_PRODUCTS:
        raise ValueError("unsupported platform token product")
    route = urlsplit(path).path
    query = parse_qs(urlsplit(path).query)
    token = token_from_headers(module, headers)
    allowed = token is not None and valid_token is not None and token == valid_token

    def kube_status(code: int, reason: str) -> bytes:
        return response(
            code,
            {
                "kind": "Status",
                "apiVersion": "v1",
                "status": "Failure",
                "reason": reason,
                "code": code,
                "message": reason,
            },
        )

    review = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
    if module == "kubeapi" and route == review and method == "POST":
        if not allowed:
            return kube_status(401, "Unauthorized")
        try:
            submitted = json.loads(body)
        except ValueError:
            return kube_status(400, "BadRequest")
        if (
            not isinstance(submitted, dict)
            or submitted.get("kind") != "SelfSubjectReview"
            or submitted.get("apiVersion") != "authentication.k8s.io/v1"
        ):
            return kube_status(400, "BadRequest")
        return response(
            201,
            {
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "SelfSubjectReview",
                "status": {"userInfo": {"username": "profile-reader", "groups": ["system:authenticated"]}},
            },
        )
    if method != "GET":
        return response(403, {"message": "read-only performance fixture; writes/execution denied"})

    if module == "consul":
        consul_headers = {"X-Consul-Index": "42"}
        if route == "/v1/status/leader":
            return response(200, json.dumps("127.0.0.1:8300"), headers=consul_headers)
        if route == "/v1/status/peers":
            return response(200, ["127.0.0.1:8300"], headers=consul_headers)
        if route == "/v1/acl/token/self":
            return (
                response(
                    200,
                    {
                        "AccessorID": "11111111-1111-4111-8111-111111111111",
                        "SecretID": token,
                        "Description": "Inventory reader",
                        "Local": False,
                        "Policies": [{"ID": "profile-policy", "Name": "identity-only" if limited else "reader"}],
                    },
                )
                if allowed
                else response(403, "token does not exist: ACL not found", headers={"Content-Type": "text/plain"})
            )
        if route not in {"/v1/agent/self", "/v1/agent/members", "/v1/catalog/services", "/v1/kv/"}:
            return response(404, "Not found", headers={"Content-Type": "text/plain"})
        if not allowed or limited:
            return response(403, "Permission denied", headers={"Content-Type": "text/plain"})
        if route == "/v1/agent/self":
            return response(
                200,
                {
                    "Config": {
                        "Version": "1.19.2",
                        "NodeName": "server-1",
                        "Datacenter": "dc1",
                        "EnableLocalScriptChecks": False,
                        "EnableRemoteScriptChecks": False,
                    },
                    "Member": {"Name": "server-1"},
                    "Stats": {},
                },
                headers=consul_headers,
            )
        if route == "/v1/catalog/services":
            return response(
                200,
                {"platform-api": ["prod", "http"], "billing-worker": ["prod", "batch"], "metrics": ["infra"]},
                headers=consul_headers,
            )
        if route == "/v1/agent/members":
            return response(
                200,
                [
                    {
                        "Name": "server-1",
                        "Addr": "10.0.0.10",
                        "Port": 8301,
                        "Status": 1,
                        "Tags": {"dc": "dc1", "role": "consul"},
                    }
                ],
                headers=consul_headers,
            )
        return response(200, ["platform/api/config", "billing/config", "monitoring/config"], headers=consul_headers)

    if module == "kubeapi":
        if route == "/version":
            return response(200, {"major": "1", "minor": "31", "gitVersion": "v1.31.5", "gitCommit": "abcdef"})
        if route == "/api":
            return response(200, {"kind": "APIVersions", "apiVersion": "v1", "versions": ["v1"]})
        if route == "/apis":
            return response(200, {"kind": "APIGroupList", "apiVersion": "v1", "groups": []})
        if route not in {"/api/v1/namespaces", "/api/v1/pods"}:
            return kube_status(404, "NotFound")
        if not allowed:
            return kube_status(401, "Unauthorized")
        if limited:
            return kube_status(403, "Forbidden")
        items = (
            [
                {"metadata": {"name": name}, "status": {"phase": "Active"}}
                for name in ("platform", "billing", "observability")
            ]
            if route.endswith("/namespaces")
            else [
                {
                    "metadata": {"name": "api-0", "namespace": "platform"},
                    "spec": {"containers": [{"name": "api", "image": "example.invalid/platform/api:v3"}]},
                    "status": {"phase": "Running"},
                }
            ]
        )
        try:
            limit = max(1, int(query.get("limit", ["500"])[0]))
            cursor = query.get("continue", ["c0"])[0]
            if not cursor.startswith("c"):
                raise ValueError("invalid cursor")
            start = int(cursor[1:])
            if start < 0:
                raise ValueError("negative cursor")
        except ValueError:
            return kube_status(400, "BadRequest")
        page = items[start : start + limit]
        next_cursor = "c" + str(start + limit) if start + limit < len(items) else ""
        return response(
            200,
            {
                "kind": "NamespaceList" if route.endswith("/namespaces") else "PodList",
                "apiVersion": "v1",
                "metadata": {"continue": next_cursor, "resourceVersion": "42"},
                "items": page,
            },
        )

    if module == "qdrant":
        if route == "/":
            return response(200, {"title": "qdrant - vector search engine", "version": "1.15.5"})
        if route != "/collections" and not route.startswith("/collections/"):
            return response(404, {"status": {"error": "Not found"}, "time": 0.001})
        if not allowed:
            return response(401, {"status": {"error": "Invalid API key or JWT"}, "time": 0.001})
        if route == "/collections":
            names = ["platform-events", "billing-events"] + ([] if limited else ["restricted-ml"])
            return response(
                200, {"result": {"collections": [{"name": name} for name in names]}, "status": "ok", "time": 0.001}
            )
        name = route.removeprefix("/collections/")
        if name not in {"platform-events", "billing-events", "restricted-ml"}:
            return response(404, {"status": {"error": "Not found"}, "time": 0.001})
        if limited and name == "restricted-ml":
            return response(403, {"status": {"error": "Access denied for collection restricted-ml"}, "time": 0.001})
        return response(
            200,
            {
                "result": {
                    "status": "green",
                    "points_count": 128,
                    "indexed_vectors_count": 128,
                    "config": {"params": {"vectors": {"size": 8, "distance": "Cosine"}}},
                },
                "status": "ok",
                "time": 0.001,
            },
        )

    # GitLab web API and repository metadata; registry stays independently 404.
    if route in {"/", "/users/sign_in"}:
        return response(
            200,
            '<title>GitLab</title><form action="/users/sign_in">Sign in</form>',
            headers={"Content-Type": "text/html"},
        )
    if route == "/api/v4/version":
        return response(200, {"version": "17.4.2", "revision": "abcdef"})
    if route == "/api/v4/user":
        return (
            response(
                200,
                {
                    "id": 7,
                    "username": "profile-reader",
                    "name": "Platform Reader",
                    "state": "active",
                    "is_admin": False,
                },
            )
            if allowed
            else response(401, {"message": "401 Unauthorized"})
        )
    projects = [
        {
            "id": 101 + i,
            "name": name,
            "path": name,
            "path_with_namespace": "platform/" + name,
            "visibility": "private",
            "http_url_to_repo": origin + "/platform/" + name + ".git",
            "web_url": origin + "/platform/" + name,
            "permissions": {"project_access": {"access_level": 40}},
            "issues_enabled": True,
            "merge_requests_enabled": True,
        }
        for i, name in enumerate(("api", "billing", "reporting"))
    ]
    if route == "/api/v4/projects":
        if query.get("visibility") == ["public"]:
            return response(200, [], headers={"X-Next-Page": ""})
        if not allowed:
            return response(401, {"message": "401 Unauthorized"})
        if limited:
            return response(403, {"message": "403 Forbidden"})
        try:
            project_page = int(query.get("page", ["1"])[0])
        except ValueError:
            return response(400, {"message": "invalid page"})
        if project_page < 1:
            return response(400, {"message": "invalid page"})
        return response(
            200,
            projects[(project_page - 1) * 2 : project_page * 2],
            # This deliberately small server page exercises continuation and
            # exact-count summaries independently of requested per_page=100.
            headers={
                "X-Next-Page": "2" if project_page == 1 else "",
                "X-Total": "3",
                "X-Total-Pages": "2",
                "X-Per-Page": "2",
                "X-Page": str(project_page),
            },
        )
    for project in projects:
        prefix = "/api/v4/projects/" + str(project["id"])
        if route in {prefix, prefix + "/repository/tree", prefix + "/issues", prefix + "/members/all"}:
            if not allowed or limited:
                return response(403, {"message": "403 Forbidden"})
            if route == prefix:
                return response(200, project)
            if route.endswith("/repository/tree"):
                return response(
                    200,
                    [
                        {
                            "id": "profile-blob",
                            "name": "README.md",
                            "type": "blob",
                            "path": "README.md",
                            "mode": "100644",
                        }
                    ],
                )
            if route.endswith("/issues"):
                return response(200, [{"id": 1, "iid": 1, "title": "Release checklist", "state": "opened"}])
            return response(200, [{"id": 7, "username": "profile-reader", "access_level": 40}])
    return response(404, {"message": "404 Not Found"})
