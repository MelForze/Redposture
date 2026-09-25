"""Shared TXT formatting and coloring for secret-discovery findings."""

from __future__ import annotations

import json
import re
from typing import Any

_TYPE_ALIASES = {
    "access_token": "Token",
    "api_key": "ApiKey",
    "aws_access_key": "ApiKey",
    "aws_access_key_id": "ApiKey",
    "aws_secret_access_key": "Key",
    "azure_storage_key": "Key",
    "basic_auth": "Credentials",
    "bearer_token": "Token",
    "certificate": "Certificate",
    "client_secret": "Secret",
    "connection_string": "Connection",
    "credential_pair": "Credentials",
    "encoded_credentials": "Credentials",
    "generic_secret": "Secret",
    "github_token": "Token",
    "gitlab_token": "Token",
    "high_entropy": "Secret",
    "jwt": "JWT",
    "password": "Pass",
    "password_hash": "Hash",
    "private_key": "Key",
    "secret": "Secret",
    "secret_indicator": "Secret",
    "session_cookie": "Cookie",
    "slack_token": "Token",
    "stripe_key": "ApiKey",
    "url_credentials": "Credentials",
    "webhook": "Webhook",
}

_FINDING_RE = re.compile(r"^\S+\s+Value=.+\s+Place=.+$")


def normalize_discovery_type(value: Any) -> str:
    """Collapse detector names into a short, single-word display label."""

    normalized = re.sub(r"[^a-z0-9]+", "_", str(value or "secret").strip().lower()).strip("_")
    if normalized in _TYPE_ALIASES:
        return _TYPE_ALIASES[normalized]
    compact = "".join(part.capitalize() for part in normalized.split("_") if part)
    return compact or "Secret"


def format_discovery_finding_line(
    module: str,
    host: Any,
    port: Any,
    *,
    severity: Any,
    finding_type: Any,
    value: Any,
    place: Any,
    score: Any = None,
) -> str:
    """Format one common discovery line for every supporting module."""

    # Severity remains in the structured finding, but is intentionally omitted
    # from the compact TXT line shared by every discovery module.
    _ = (severity, score)
    kind = normalize_discovery_type(finding_type)
    encoded_value = json.dumps(str(value if value is not None else ""), ensure_ascii=False, separators=(",", ":"))
    encoded_place = json.dumps(str(place if place is not None else ""), ensure_ascii=False, separators=(",", ":"))
    return f"{module}\t{host or '?'}\t{int(port or 0)}\t [!] {kind} Value={encoded_value} Place={encoded_place}"


def discovery_color_spans(_marker: str, payload: str) -> list[tuple[int, int, str]]:
    """Color discovery values while keeping section titles neutral white."""

    if payload.startswith(("Discovered Secrets", "Discovered Credentials")) or re.match(
        r"^\d+ Secret Findings", payload
    ):
        return [(0, len(payload), "orange")]
    if payload.startswith(("Discover Secrets", "Discover Complete")):
        spans: list[tuple[int, int, str]] = []
        status_match = re.search(r"\(status:([^)]+)\)", payload)
        if status_match is not None:
            status = status_match.group(1).strip().lower()
            status_color = {
                "complete": "bright_green",
                "partial": "orange",
                "running": "cyan",
            }.get(status, "true_red")
            spans.append((status_match.start(), status_match.end(), status_color))
        findings_match = re.search(r"\(findings:(\d+)\)", payload)
        if findings_match is not None:
            findings_color = "true_red" if int(findings_match.group(1)) > 0 else "bright_green"
            spans.append((findings_match.start(), findings_match.end(), findings_color))
        return spans
    if _FINDING_RE.match(payload) is None:
        return []
    return [(0, len(payload), "orange")]


__all__ = [
    "discovery_color_spans",
    "format_discovery_finding_line",
    "normalize_discovery_type",
]
