"""Conservative browser SSO detection shared by HTTP audit modules.

The classifier intentionally ignores a plain ``WWW-Authenticate: Bearer``
challenge.  Registry, Kubernetes and many APIs use Bearer authentication
without redirecting a browser to an identity provider.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .html_fingerprint import markup_evidence


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
    ("zitadel", ("/oauth/v2/authorize",)),
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
        try:
            parsed = urllib.parse.urlsplit(raw_url)
            host = (parsed.hostname or "").casefold()
            value = parsed.path.casefold()
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except ValueError:
            continue
        if "/realms/" in value and "/protocol/openid-connect/" in value:
            return "keycloak", "oidc"
        if "/auth/realms/" in value and "/login-actions/" in value:
            return "keycloak", "oidc"
        for provider, markers in _PROVIDER_URL_MARKERS:
            if any(
                (host.endswith(marker.rstrip("/")) if marker.startswith(".") else host == marker.rstrip("/"))
                if not marker.startswith("/")
                else marker in value
                for marker in markers
            ):
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
        saml_keys = {key.casefold() for key in query}
        if ("samlrequest" in saml_keys or "samlresponse" in saml_keys) and "relaystate" in saml_keys:
            return "saml", "saml"
    return None


def _provider_from_body(body: bytes | str | None) -> tuple[str, str] | None:
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body or "")
    page = markup_evidence(text)
    if page is None:
        return None
    selectors = {value.casefold() for value in page.identifiers}
    selectors.update(page.elements)
    for attributes in page.attributes.values():
        for values in attributes:
            selectors.update(values.get("class", "").casefold().split())
    selectors.update(meta.get("name", "").casefold() for meta in page.attributes.get("meta", ()))
    if selectors.intersection({"kc-form-login", "kc-login", "keycloakify"}):
        return "keycloak", "oidc"
    for form in page.forms:
        fields = {name.casefold() for name in form.inputs}
        if fields.intersection({"samlrequest", "samlresponse"}) and "relaystate" in fields:
            return "saml", "saml"
        detected = _provider_from_urls((form.action,))
        if detected is not None:
            return detected
    for script in page.attributes.get("script", ()):
        source = script.get("src", "")
        try:
            resource = urllib.parse.urlsplit(source)
            if resource.scheme not in {"", "http", "https"}:
                continue
            # Preserve the existing Entra CDN signal only when it is an
            # actual external script, not an inert example or query string.
            if (resource.hostname or "").casefold() == "aadcdn.msftauth.net":
                return "entra", "oidc"
        except ValueError:
            continue
        detected = _provider_from_urls((source,))
        if detected is not None:
            return detected
    markers = (
        ("auth0", ("auth0-lock",)),
        ("okta", ("okta-sign-in", "okta-signin-widget")),
        ("google", ("google-signin",)),
        ("dex", ("dex-login", "dex-logo")),
        ("zitadel", ("zitadel-login",)),
        ("ory", ("ory-elements",)),
        ("oauth2-proxy", ("oauth2-proxy",)),
    )
    for provider, names in markers:
        if any(token == name or token.startswith(name + "-") for name in names for token in selectors):
            return provider, "oidc"
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
