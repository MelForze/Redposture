"""Shared TXT formatting and coloring for secret-discovery findings."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping
from typing import Any

from .discovery_values import DiskBackedText, iter_json_chunks

_TYPE_ALIASES = {
    "access_token": "Token",
    "api_key": "ApiKey",
    "api_token": "Token",
    "aws_access_key": "ApiKey",
    "aws_access_key_id": "ApiKey",
    "aws_secret_access_key": "Key",
    "aws_credentials": "Credentials",
    "oauth_credentials": "Credentials",
    "azure_storage_key": "Key",
    "basic_auth": "Credentials",
    "bearer_token": "Token",
    "certificate": "Certificate",
    "client_secret": "Secret",
    "connection_string": "Connection",
    "signed_url": "SignedURL",
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
    encoded_value = "".join(iter_json_chunks(value if value is not None else ""))
    encoded_place = json.dumps(str(place if place is not None else ""), ensure_ascii=False, separators=(",", ":"))
    return f"{module}\t{host or '?'}\t{int(port or 0)}\t [!] {kind} Value={encoded_value} Place={encoded_place}"


def iter_disk_discovery_finding_line_chunks(
    module: str,
    host: Any,
    port: Any,
    *,
    finding_type: Any,
    value: DiskBackedText,
    place: Any,
) -> Iterator[str]:
    """Yield the same TXT line as the short-value formatter without loading the value."""
    kind = normalize_discovery_type(finding_type)
    yield f"{module}\t{host or '?'}\t{int(port or 0)}\t [!] {kind} Value="
    yield from value.iter_json_chunks()
    yield " Place="
    if isinstance(place, DiskBackedText):
        yield from place.iter_json_chunks()
    else:
        yield json.dumps(str(place if place is not None else ""), ensure_ascii=False, separators=(",", ":"))


def iter_discovery_finding_line_chunks(
    module: str, host: Any, port: Any, *, finding_type: Any, value: Any, place: Any
) -> Iterator[str]:
    """Stream a finding with a structured source locator and exact value."""
    yield f"{module}\t{host or '?'}\t{int(port or 0)}\t [!] {normalize_discovery_type(finding_type)} Value="
    yield from iter_json_chunks(value if value is not None else "")
    yield " Place="
    yield from iter_json_chunks(place if place is not None else "")


def iter_discovery_location_lines(
    module: str, host: Any, port: Any, record: Mapping[str, Any]
) -> Iterator[Iterator[str]]:
    """Append every structured locator for a repeated value, without repeating its value.

    Final output owns these lines: early publication happens before later places
    exist. Iterating disk catalogs here keeps both many places and long keys
    bounded. A singleton keeps its compact line unless a row/document ordinal
    is needed to disambiguate the source beyond its field path.
    """
    reports = (record.get("content_discovery"), record.get("discover_report"))
    catalogs = [report.get("findings") for report in reports if isinstance(report, Mapping)]
    catalogs.extend((record.get("discover_findings"), record.get("secret_findings")))
    if module.lower() == "proxmox":
        catalogs.append(record.get("findings"))
    if record.get("surface") == "ui":
        ui = record.get("ui")
        inventory = ui.get("inventory") if isinstance(ui, Mapping) else None
        panel_discovery = inventory.get("discover") if isinstance(inventory, Mapping) else None
        if isinstance(panel_discovery, Mapping):
            catalogs.append(panel_discovery.get("records"))
    for findings in catalogs:
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, Mapping):
                continue
            locations = finding.get("locations")
            if not isinstance(locations, list) or not locations:
                continue
            if len(locations) == 1:
                first = locations[0]
                if not isinstance(first, Mapping) or not {"row_ordinal", "document_ordinal"}.intersection(first):
                    continue
            for index, location in enumerate(locations, start=1):
                if isinstance(location, Mapping):
                    yield _location_chunks(module, host, port, finding, index, location)


def iter_discovery_source_lines(module: str, host: Any, port: Any, record: Mapping[str, Any]) -> Iterator[str]:
    """Render aggregate reader evidence only when the runtime requests debug."""
    reports = (record.get("content_discovery"), record.get("discover_report"), record.get("discover_coverage"))
    catalogs = [report.get("sources") for report in reports if isinstance(report, Mapping)]
    catalogs.append(record.get("discover_sources"))
    ui = record.get("ui")
    inventory = ui.get("inventory") if isinstance(ui, Mapping) else None
    panel = inventory.get("discover") if isinstance(inventory, Mapping) else None
    if isinstance(panel, Mapping):
        catalogs.append(panel.get("sources"))
    seen = set()
    for rows in catalogs:
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, Mapping) or not isinstance(row.get("id"), str):
                continue
            fields = ["(source:" + json.dumps(row["id"], ensure_ascii=False) + ")"]
            for name in ("implemented", "requested", "read", "denied", "unsupported", "complete"):
                value = row.get(name)
                valid = (
                    type(value) is bool
                    if name in {"implemented", "unsupported", "complete"}
                    else type(value) is int and value >= 0
                )
                fields.append(f"({name}:{value if valid else 'unknown'})")
            if isinstance(row.get("scope"), str):
                fields.append("(scope:" + json.dumps(row["scope"], ensure_ascii=False) + ")")
            payload = " ".join(fields)
            if payload in seen:
                continue
            seen.add(payload)
            yield f"{module.upper()}\t{host or '?'}\t{int(port or 0)}\t [*] [debug] Discover Source " + payload


def _location_chunks(
    module: str, host: Any, port: Any, finding: Mapping[str, Any], index: int, location: Mapping[str, Any]
) -> Iterator[str]:
    kind = normalize_discovery_type(finding.get("type") or finding.get("secret_type"))
    yield f"{module.upper()}\t{host or '?'}\t{int(port or 0)}\t [!] {kind} ValueSHA256="
    yield from iter_json_chunks(str(finding.get("fingerprint") or ""))
    yield f" Location={index} Place="
    yield from iter_json_chunks(location)


def discovery_color_spans(_marker: str, payload: str) -> list[tuple[int, int, str]]:
    """Color discovery values while keeping section titles neutral white."""

    if payload.startswith("[debug] Discover Source "):
        source_spans = [(0, len("[debug] Discover Source"), "white")]
        for match in re.finditer(r"\((implemented|requested|read|denied|unsupported|complete):([^)]*)\)", payload):
            name, value = match.groups()
            color = "orange"
            if name in {"requested", "read"} and value.isdecimal():
                color = "true_red" if int(value) else "bright_green"
            elif name == "denied" and value.isdecimal():
                color = "bright_green"
            elif name == "complete" and value == "True":
                color = "bright_green"
            source_spans.append((match.start(), match.end(), color))
        return source_spans
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
    if _FINDING_RE.match(payload) is None and not re.match(r"^\S+ ValueSHA256=.+ Location=\d+ Place=", payload):
        return []
    return [(0, len(payload), "orange")]


__all__ = [
    "discovery_color_spans",
    "format_discovery_finding_line",
    "iter_discovery_location_lines",
    "iter_discovery_source_lines",
    "normalize_discovery_type",
]
