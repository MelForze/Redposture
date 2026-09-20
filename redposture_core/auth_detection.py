"""Conservative browser SSO detection shared by HTTP audit modules.

The classifier intentionally ignores a plain ``WWW-Authenticate: Bearer``
challenge.  Registry, Kubernetes and many APIs use Bearer authentication
without redirecting a browser to an identity provider.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SsoDetection:
    provider: str
    protocol: str
    evidence: tuple[str, ...]


_PROVIDER_URL_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("auth0", (".auth0.com/",)),
    ("okta", (".okta.com/",)),
    ("entra", ("login.microsoftonline.com/", "login.microsoft.com/")),
    ("google", ("accounts.google.com/",)),
    ("dex", ("/dex/auth", "/dex/approval")),
    ("zitadel", ("/oauth/v2/authorize", "/ui/login")),
    ("ory", ("/self-service/login",)),
    ("onelogin", (".onelogin.com/",)),
    ("ping", ("/as/authorization.oauth2",)),
    ("oauth2-proxy", ("/oauth2/start", "/oauth2/sign_in")),
)


def _header(headers: Mapping[str, Any] | None, name: str) -> str:
    if not headers:
        return ""
    wanted = name.casefold()
    for key, value in headers.items():
        if str(key).casefold() == wanted:
            return str(value or "")
    return ""


def _urls(
    final_url: str | None,
    redirect_history: Iterable[str] | None,
    headers: Mapping[str, Any] | None,
) -> tuple[str, ...]:
    values = [str(value).strip() for value in (redirect_history or ()) if str(value).strip()]
    if final_url and str(final_url).strip():
        values.append(str(final_url).strip())
    location = _header(headers, "location").strip()
    if location:
        values.append(location)
    return tuple(values)


def _provider_from_urls(urls: Iterable[str]) -> tuple[str, str] | None:
    for raw_url in urls:
        value = raw_url.casefold()
        try:
            parsed = urllib.parse.urlsplit(raw_url)
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except ValueError:
            query = {}
        if "/realms/" in value and "/protocol/openid-connect/" in value:
            return "keycloak", "oidc"
        if "/auth/realms/" in value and "/login-actions/" in value:
            return "keycloak", "oidc"
        for provider, markers in _PROVIDER_URL_MARKERS:
            if any(marker in value for marker in markers):
                if provider in {
                    "auth0",
                    "okta",
                    "entra",
                    "google",
                    "dex",
                    "zitadel",
                    "ory",
                    "onelogin",
                    "ping",
                    "oauth2-proxy",
                }:
                    return provider, "oidc"
        # A provider-neutral OIDC authorize URL needs the complete parameter
        # combination.  A path containing only ``oauth`` is not enough.
        if (
            {"client_id", "redirect_uri"}.issubset(query)
            and ("response_type" in query or "scope" in query)
            and ("authorize" in value or "/auth" in value)
        ):
            return "oidc", "oidc"
        if ("samlrequest" in query or "samlresponse" in query) and "relaystate" in query:
            return "saml", "saml"
    return None


def _provider_from_body(body: bytes | str | None) -> tuple[str, str] | None:
    if isinstance(body, bytes):
        text = body.decode("utf-8", errors="replace")
    else:
        text = str(body or "")
    value = text.casefold()
    if not value:
        return None
    keycloak_signals = (
        'id="kc-form-login"',
        "id='kc-form-login'",
        'id="kc-login"',
        "id='kc-login'",
        "keycloakify",
        "/protocol/openid-connect/authenticate",
    )
    if any(signal in value for signal in keycloak_signals):
        return "keycloak", "oidc"
    body_markers: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("auth0", ("cdn.auth0.com", "auth0-lock")),
        ("okta", ("okta-sign-in", "okta-signin-widget")),
        ("entra", ("login.microsoftonline.com", "aadcdn.msftauth.net")),
        ("google", ("accounts.google.com", "google-signin")),
        ("dex", ("dex-login", "dex-logo")),
        ("zitadel", ("zitadel login", "zitadel-login")),
        ("ory", ("ory kratos", "ory-elements")),
        ("oauth2-proxy", ("oauth2 proxy", "oauth2-proxy")),
    )
    for provider, markers in body_markers:
        if any(marker in value for marker in markers):
            return provider, "oidc"
    if re.search(r"name\s*=\s*['\"]saml(?:request|response)['\"]", value) and "relaystate" in value:
        return "saml", "saml"
    return None


def detect_browser_sso(
    *,
    final_url: str | None = None,
    redirect_history: Iterable[str] | None = None,
    headers: Mapping[str, Any] | None = None,
    body: bytes | str | None = None,
) -> SsoDetection | None:
    """Return an SSO identity only for strong browser-login evidence."""

    urls = _urls(final_url, redirect_history, headers)
    detected = _provider_from_urls(urls)
    evidence: list[str] = []
    if detected is not None:
        evidence.append("identity_provider_url")
    body_detected = _provider_from_body(body)
    if body_detected is not None:
        if detected is None or detected[0] == "oidc":
            detected = body_detected
        evidence.append("identity_provider_page")
    if detected is None:
        return None
    return SsoDetection(provider=detected[0], protocol=detected[1], evidence=tuple(evidence))


def auth_required_text(auth_required: Any, auth_method: Any = None) -> str:
    if auth_required is True and str(auth_method or "").casefold() == "sso":
        return "sso"
    if auth_required is True:
        return "True"
    if auth_required is False:
        return "False"
    return "unknown"


__all__ = ["SsoDetection", "auth_required_text", "detect_browser_sso"]
