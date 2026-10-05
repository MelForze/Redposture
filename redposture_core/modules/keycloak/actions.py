"""Read-only Keycloak fingerprint and Admin API probes."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

from ...clients.http_api import HttpApiClient, HttpClientConfig, HttpResponse, http_response_requires_https

host_stage = None  # The module uses phase-aware audit hooks.

_REALM_PATH = re.compile(r"^(?P<base>.*?)/realms/(?P<realm>[^/]+)(?:/.*)?$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_COMMON_REALMS = ("master", "test", "dev", "staging", "prod", "production")
_MAX_REALMS = 12


def _json_object(response: HttpResponse) -> dict[str, Any] | None:
    if response.error or response.status != 200 or response.truncated:
        return None
    try:
        value = response.json()
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _realm_response(value: dict[str, Any] | None, realm: str) -> bool:
    """Reject generic realm/name/version JSON and foreign OIDC providers."""
    if value is None or value.get("realm") != realm:
        return False
    public_key = value.get("public_key")
    token_service = value.get("token-service")
    account_service = value.get("account-service")
    return (
        isinstance(public_key, str)
        and len(public_key) >= 32
        and isinstance(token_service, str)
        and f"/realms/{quote(realm, safe='')}/protocol/openid-connect" in token_service
        and isinstance(account_service, str)
        and f"/realms/{quote(realm, safe='')}/account" in account_service
    )


def _oidc_response(value: dict[str, Any] | None, realm: str) -> bool:
    if value is None:
        return False
    issuer = value.get("issuer")
    jwks = value.get("jwks_uri")
    token = value.get("token_endpoint")
    authorization = value.get("authorization_endpoint")
    if not all(isinstance(item, str) for item in (issuer, jwks, token, authorization)):
        return False
    try:
        issuer_url = urlsplit(str(issuer))
    except ValueError:
        return False
    if issuer_url.scheme not in {"http", "https"} or not issuer_url.hostname:
        return False
    if not issuer_url.path.endswith(f"/realms/{quote(realm, safe='')}"):
        return False
    for url, suffix in (
        (jwks, "/protocol/openid-connect/certs"),
        (token, "/protocol/openid-connect/token"),
        (authorization, "/protocol/openid-connect/auth"),
    ):
        try:
            parsed = urlsplit(str(url))
        except ValueError:
            return False
        if (parsed.scheme, parsed.netloc) != (issuer_url.scheme, issuer_url.netloc):
            return False
        if parsed.path != issuer_url.path + suffix:
            return False
    return True


def _mount_candidates(path: str) -> tuple[str, ...]:
    normalized = "/" + str(path or "").strip("/") if path and path != "/" else ""
    match = _REALM_PATH.match(normalized)
    if match is not None:
        return (match.group("base"),)
    if normalized.endswith("/admin"):
        normalized = normalized[:-6]
    candidates = [normalized]
    if not normalized.endswith("/auth"):
        candidates.append(normalized + "/auth")
    return tuple(dict.fromkeys(candidates))


def _realms(args: Any, target_path: str) -> tuple[str, ...]:
    selected = list(getattr(args, "realm", None) or [])
    match = _REALM_PATH.match("/" + target_path.strip("/")) if target_path else None
    if match is not None and not selected:
        selected.append(unquote(match.group("realm")))
    if not selected:
        selected.append("master")
    if getattr(args, "enum_realms", False):
        selected.extend(_COMMON_REALMS)
    return tuple(dict.fromkeys(selected))[:_MAX_REALMS]


def _origin(ctx: Any, scheme: str) -> str:
    host = str(ctx.host)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{scheme}://{host}:{ctx.port}"


def _client(ctx: Any) -> HttpApiClient:
    return HttpApiClient(
        HttpClientConfig(
            timeout=float(getattr(ctx.args, "timeout", 5.0) or 5.0),
            retries=int(getattr(ctx.args, "retries", 0) or 0),
            proxy=getattr(ctx.args, "proxy", None),
            insecure=True,
            response_size_cap=512 * 1024,
            allow_cross_origin_redirects=False,
        )
    )


def _get(client: HttpApiClient, url: str, token: str | None = None) -> HttpResponse:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return client.get(url, headers=headers)


def _get_public(client: HttpApiClient, url: str) -> HttpResponse:
    """Follow one same-host GET redirect only when the realm endpoint is preserved."""
    response = _get(client, url)
    if response.status not in {301, 302, 307, 308}:
        return response
    location = next((value for key, value in response.headers.items() if key.lower() == "location"), "")
    if not location:
        return response
    target = urljoin(url, location)
    original_url, target_url = urlsplit(url), urlsplit(target)
    index = original_url.path.find("/realms/")
    endpoint_suffix = original_url.path[index:] if index >= 0 else original_url.path
    if (
        original_url.scheme in {"http", "https"}
        and target_url.scheme in {"http", "https"}
        and original_url.hostname == target_url.hostname
        and target_url.path.endswith(endpoint_suffix)
        and not target_url.query
    ):
        return _get(client, target)
    return response


def detect_record(ctx: Any) -> dict[str, Any]:
    target_path = str(getattr(ctx.target, "path", "") or "")
    target_scheme = str(getattr(ctx.target, "scheme", "") or "").lower()
    schemes = (
        ("https",)
        if target_scheme == "https"
        else ("http", "https")
        if target_scheme == "http"
        else ("https", "http")
        if ctx.port in {443, 8443}
        else ("http", "https")
    )
    client = _client(ctx)
    signals: list[str] = []
    transport_ok = False
    probable = False
    for scheme in schemes:
        retry_alternate_scheme = False
        for mount in _mount_candidates(target_path):
            base = _origin(ctx, scheme) + mount
            for realm in _realms(ctx.args, target_path):
                quoted = quote(realm, safe="")
                realm_url = f"{base}/realms/{quoted}"
                realm_result = _get_public(client, realm_url)
                retry_alternate_scheme |= realm_result.status == 0 or http_response_requires_https(
                    realm_result.status, realm_result.body
                )
                realm_data = _json_object(realm_result)
                transport_ok |= realm_result.status > 0
                has_realm = _realm_response(realm_data, realm)
                if has_realm:
                    signals.append("keycloak.realm_resource")
                realm_final_url = str(realm_result.final_url or realm_url)
                oidc_result = _get_public(client, f"{realm_final_url}/.well-known/openid-configuration")
                oidc_data = _json_object(oidc_result)
                transport_ok |= oidc_result.status > 0
                has_oidc = _oidc_response(oidc_data, realm)
                if has_realm and has_oidc and realm_data is not None and oidc_data is not None:
                    issuer = str(oidc_data["issuer"])
                    has_oidc = (
                        realm_data.get("token-service") == issuer + "/protocol/openid-connect"
                        and realm_data.get("account-service") == issuer + "/account"
                    )
                if has_oidc:
                    signals.append("oidc.consistent_discovery")
                probable |= has_realm or has_oidc
                if not (has_realm and has_oidc):
                    continue
                # A valid public JWKS corroborates the two independent endpoint
                # shapes; an inaccessible JWKS does not discard their evidence.
                jwks_uri = str(oidc_data["jwks_uri"]) if oidc_data else ""
                # Never turn a target-controlled OIDC document into an
                # unrelated outbound request. Only probe this target's origin.
                jwks_url = urlsplit(jwks_uri)
                realm_final = urlsplit(realm_final_url)
                if (jwks_url.scheme, jwks_url.netloc) == (realm_final.scheme, realm_final.netloc):
                    jwks_result = _get(client, jwks_uri)
                    jwks = _json_object(jwks_result)
                    if jwks is not None and isinstance(jwks.get("keys"), list):
                        signals.append("oidc.jwks")
                # Follow only a same-endpoint redirect. A redirect to an IdP or
                # generic login page cannot rebase subsequent token requests.
                final = realm_final
                if not final.path.endswith(f"/realms/{quoted}"):
                    continue
                resolved_base = urlunsplit(
                    (final.scheme, final.netloc, final.path[: -len(f"/realms/{quoted}")], "", "")
                )
                admin = _get(client, f"{resolved_base}/admin/serverinfo")
                admin_data = _json_object(admin)
                version = _server_version(admin_data)
                admin_access = admin_data is not None and isinstance(admin_data.get("systemInfo"), dict)
                return {
                    "host": ctx.host,
                    "port": ctx.port,
                    "service": "keycloak",
                    "status": "auth_required"
                    if admin.status in {401, 403}
                    else "open_no_auth"
                    if admin_access
                    else "detected",
                    "is_keycloak": True,
                    "detection_status": "confirmed",
                    "detection_signals": list(dict.fromkeys(signals)),
                    "auth_required": True if admin.status in {401, 403} else False if admin_access else None,
                    "version": version,
                    "api_endpoint": resolved_base,
                    "detected_realm": realm,
                }
        if scheme != schemes[-1] and not retry_alternate_scheme:
            break
    return {
        "host": ctx.host,
        "port": ctx.port,
        "service": "keycloak",
        "status": "probable" if probable else "not_service" if transport_ok else "transport_failure",
        "is_keycloak": False,
        "detection_status": "probable" if probable else "not_service" if transport_ok else "transport_failure",
        "detection_signals": list(dict.fromkeys(signals)),
    }


def _server_version(data: dict[str, Any] | None) -> str | None:
    system = data.get("systemInfo") if data else None
    value = system.get("version") if isinstance(system, dict) else None
    return value if isinstance(value, str) and _VERSION.fullmatch(value) else None


def auth_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    result = dict(prior)
    token = getattr(ctx.args, "_keycloak_token", None)
    if not token:
        return result
    base = str(prior.get("api_endpoint") or "")
    client = _client(ctx)
    server = _get(client, f"{base}/admin/serverinfo", token)
    server_data = _json_object(server)
    version = _server_version(server_data)
    if version:
        result["version"] = version
    realms = _get(client, f"{base}/admin/realms", token)
    try:
        realm_items = realms.json() if realms.status == 200 and not realms.error else None
    except ValueError:
        realm_items = None
    protected_access = prior.get("auth_required") is True and (
        bool(version) or (isinstance(realm_items, list) and all(isinstance(item, dict) for item in realm_items))
    )
    realm = str(prior.get("detected_realm") or "master")
    identity_response = _get(client, f"{base}/realms/{quote(realm, safe='')}/protocol/openid-connect/userinfo", token)
    identity = _json_object(identity_response)
    subject = identity.get("sub") if identity else None
    identity_verified = isinstance(subject, str) and bool(subject)
    confirmed = protected_access or identity_verified
    if identity_verified:
        result["token_subject"] = subject
    whoami_response = _get(client, f"{base}/admin/{quote(realm, safe='')}/console/whoami", token)
    whoami = _json_object(whoami_response)
    if whoami is not None:
        username = whoami.get("username")
        if isinstance(username, str) and username:
            result["whoami_username"] = username
    result["provided_credentials_ok"] = confirmed
    if confirmed:
        result["status"] = "valid_credentials"
    result["credential_state"] = (
        "valid"
        if confirmed
        else "invalid"
        if server.status == realms.status == identity_response.status == 401
        else "unknown"
    )
    result["token_access"] = (
        "allowed" if confirmed else "denied" if result["credential_state"] == "invalid" else "unknown"
    )
    return result


def data_record(ctx: Any, prior: dict[str, Any]) -> dict[str, Any]:
    result = dict(prior)
    show_realms = bool(getattr(ctx.args, "show_realms", False))
    show_clients = bool(getattr(ctx.args, "show_clients", False))
    if not (show_realms or show_clients):
        return result
    base = str(prior.get("api_endpoint") or "")
    token = getattr(ctx.args, "_keycloak_token", None)
    client = _client(ctx)
    if show_realms:
        response = _get(client, f"{base}/admin/realms", token)
        data = None
        if response.status == 200 and not response.error:
            try:
                data = response.json()
            except ValueError:
                pass
        if isinstance(data, list):
            realm_names = sorted(
                {str(item["realm"]) for item in data if isinstance(item, dict) and isinstance(item.get("realm"), str)}
            )
            result["visible_realms"] = realm_names[:1000]
            result["realms_truncated"] = len(realm_names) > 1000
        else:
            result["realms_access"] = "denied" if response.status in {401, 403} else "unknown"
    if show_clients:
        names: list[str] = []
        limit = getattr(ctx.args, "show_clients", None)
        max_count = int(limit) if isinstance(limit, int) and not isinstance(limit, bool) else 10_000
        any_access = False
        for realm in _realms(ctx.args, str(getattr(ctx.target, "path", "") or "")):
            offset = 0
            seen_pages: set[tuple[str, ...]] = set()
            while offset < max_count:
                page_size = min(100, max_count - offset)
                response = _get(
                    client,
                    f"{base}/admin/realms/{quote(realm, safe='')}/clients?first={offset}&max={page_size}",
                    token,
                )
                if response.status != 200 or response.error:
                    break
                try:
                    data = response.json()
                except ValueError:
                    break
                if not isinstance(data, list):
                    break
                any_access = True
                page_names = tuple(
                    str(item["clientId"])
                    for item in data
                    if isinstance(item, dict) and isinstance(item.get("clientId"), str)
                )
                if page_names in seen_pages:
                    break
                seen_pages.add(page_names)
                names.extend(f"{realm}/{name}" for name in page_names)
                if len(data) < page_size:
                    break
                offset += page_size
        if any_access:
            result["visible_clients"] = sorted(set(names))[:max_count]
    return result
