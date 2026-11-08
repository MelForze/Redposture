"""Known Keycloak Admin REST inventory; protocol fixture, not a product stand."""

from __future__ import annotations

from typing import Any

REALMS = ("master", "corp", "partners")
CLIENT_COUNT = 201


def realm_representation(realm: str) -> dict[str, Any]:
    if realm not in REALMS:
        raise ValueError("unknown fixture realm")
    return {
        "id": realm,
        "realm": realm,
        "enabled": True,
        "bruteForceProtected": realm != "partners",
        "registrationAllowed": realm == "partners",
        "sslRequired": "all" if realm == "master" else "external",
        "passwordPolicy": "length(12) and digits(1)",
    }


def client_representation(realm: str, index: int) -> dict[str, Any]:
    if realm not in REALMS or not 0 <= index < CLIENT_COUNT:
        raise ValueError("unknown fixture client")
    origin = f"https://{realm}-app-{index:03d}.example.invalid"
    return {
        "id": f"qa-{realm}-{index:08d}",
        "clientId": f"app-{index:03d}",
        "enabled": True,
        "publicClient": index % 3 == 0,
        "bearerOnly": index % 3 == 2,
        "directAccessGrantsEnabled": index % 5 == 0,
        "implicitFlowEnabled": False,
        "redirectUris": [origin + "/oauth/callback", origin + "/signed-out"],
        "webOrigins": [origin],
    }


def client_page(realm: str, first: int, maximum: int) -> list[dict[str, Any]]:
    if not 0 <= first <= 100000 or not 1 <= maximum <= 1000:
        raise ValueError("invalid fixture pagination")
    return [client_representation(realm, index) for index in range(first, min(CLIENT_COUNT, first + maximum))]


def keycloak_inventory_errors(
    record: dict[str, Any],
    *,
    limited: bool,
    realms: list[str],
    limit: int | None,
    show_realms: bool,
    show_clients: bool,
) -> list[str]:
    """Exact values, scope, ordering and denials; a count-only PASS is invalid."""
    errors = []
    if record.get("provided_credentials_ok") is not True or record.get("credential_state") != "valid":
        errors.append("unverified inventory identity")
    if limited:
        if show_realms and (record.get("realms_access") != "denied" or record.get("visible_realms")):
            errors.append("realm denial missing or contains data")
        if show_clients:
            expected = dict.fromkeys(realms, "denied")
            if record.get("clients_access") != expected or record.get("visible_clients"):
                errors.append("client denial missing or contains data")
            if (
                record.get("clients_errors") != dict.fromkeys(realms, "HTTP 403")
                or record.get("clients_partial") is not True
            ):
                errors.append("client denied coverage is not explicit")
        return errors
    if show_realms:
        if record.get("visible_realms") != sorted(REALMS) or record.get("realms_truncated") is not False:
            errors.append("realm catalogue mismatch")
        expected_settings = [
            {
                "realm": realm,
                "brute_force_protected": realm != "partners",
                "registration_allowed": realm == "partners",
                "ssl_required": "all" if realm == "master" else "external",
                "password_policy": "length(12) and digits(1)",
            }
            for realm in sorted(REALMS)
        ]
        if record.get("realm_settings") != expected_settings or record.get("realm_settings_access"):
            errors.append("realm values incomplete or changed")
    if show_clients:
        maximum = limit if limit is not None else 10000
        names = sorted(f"{realm}/app-{index:03d}" for realm in realms for index in range(CLIENT_COUNT))[:maximum]
        if record.get("visible_clients") != names:
            errors.append("client catalogue/selector/limit mismatch")
        expected_clients = []
        for name in names:
            realm, client = name.split("/", 1)
            index = int(client.removeprefix("app-"))
            origin = f"https://{realm}-app-{index:03d}.example.invalid"
            expected_clients.append(
                {
                    "realm": realm,
                    "client_id": client,
                    "type": "bearer-only" if index % 3 == 2 else "public" if index % 3 == 0 else "confidential",
                    "direct_access_grants": index % 5 == 0,
                    "implicit_flow": False,
                    "redirect_uris": [origin + "/oauth/callback", origin + "/signed-out"],
                    "redirect_uri_count": 2,
                    "redirects_truncated": False,
                    "web_origins": [origin],
                    "web_origin_count": 1,
                    "origins_truncated": False,
                }
            )
        if record.get("client_settings") != expected_clients:
            errors.append("client flow/endpoint values incomplete or changed")
        if record.get("clients_partial") is not False or record.get("clients_errors") or record.get("clients_access"):
            errors.append("unexpected partial client inventory")
    return errors
