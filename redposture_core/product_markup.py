"""Application DOM corroboration for HTML-only discovery fallbacks.

These are product-reported page signatures, not proof against a full replica.
Actual API/protocol evidence remains the preferred detection path.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .html_fingerprint import HtmlEvidence, markup_evidence


def _asset(page: HtmlEvidence, tag: str, attribute: str, pattern: str) -> bool:
    for attrs in page.attributes.get(tag, ()):
        if tag == "link" and "stylesheet" not in attrs.get("rel", "").lower().split():
            continue
        try:
            url = urlsplit(attrs.get(attribute, ""))
        except ValueError:
            continue
        if url.scheme not in {"", "http", "https"}:
            continue
        if re.search(pattern, url.path, re.I):
            return True
    return False


def grafana_application(body: str, *, session_cookie: bool = False) -> bool:
    page = markup_evidence(body)
    if page is None or not (session_cookie or re.search(r"\bgrafana\b", page.title, re.I)):
        return False
    branded_body = any("app-grafana" in item.get("class", "").split() for item in page.attributes.get("body", ()))
    root = (
        "reactRoot" in page.identifiers
        or "grafana-app" in page.elements
        or any(attrs.get("ng-app") == "grafana" for tag in ("html", "body") for attrs in page.attributes.get(tag, ()))
    )
    return bool(
        branded_body
        and root
        and _asset(page, "link", "href", r"(?:^|/)public/(?:build|css)/grafana[./][^/]*\.css$")
        and _asset(page, "script", "src", r"(?:^|/)public/(?:build|app)/(?:app|grafana)[./][^/]*\.js$")
    )


def minio_console_application(body: str) -> bool:
    page = markup_evidence(body)
    return bool(
        page is not None
        and re.fullmatch(r"MinIO\s+Console", page.title, re.I)
        and "root" in page.identifiers
        and _asset(page, "link", "href", r"(?:^|/)static/css/main\.[^/]+\.css$")
        and _asset(page, "script", "src", r"(?:^|/)static/js/main\.[^/]+\.js$")
    )
