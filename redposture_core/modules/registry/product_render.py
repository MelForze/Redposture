"""Consistent TXT presentation for the public registry product commands.

The legacy OCI renderer remains available internally. This layer only changes
the presentation of confirmed products; collection and JSON stay unchanged.
"""

from __future__ import annotations

from typing import Any

from ...auth_detection import auth_required_text
from ...console import Console
from ...rendering import (
    BooleanColorRule,
    CountColorRule,
    render_colored_marker_line,
    render_tagged_detail_line,
)
from . import actions

_NAMES = {
    "docker-registry": "Docker Registry",
    "harbor": "Harbor",
    "nexus": "Nexus Repository",
    "gitlab": "GitLab Container Registry",
}


def _prefix(record: dict[str, Any]) -> str:
    tag = str(record.get("module") or record.get("service") or "docker-registry").upper()
    return f"{tag}\t{record.get('host') or '?'}\t{record.get('port') or 0}\t"


def _product(record: dict[str, Any]) -> str:
    explicit = str(record.get("module") or record.get("service") or "")
    if explicit in _NAMES:
        return explicit
    for vendor in ("harbor", "nexus", "gitlab"):
        if record.get(f"is_{vendor}") is True:
            return vendor
    return "docker-registry"


def _version(record: dict[str, Any], product: str) -> str:
    field = {"harbor": "harbor_info", "nexus": "nexus_info", "gitlab": "gitlab_info"}.get(product)
    info = record.get(field) if field else None
    if isinstance(info, dict):
        keys = ("harbor_version", "version") if product == "harbor" else ("version", "release")
        for key in keys:
            value = info.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    if output_format != "txt":
        return actions._format_detect_record(record, output_format)
    product = _product(record)
    auth = auth_required_text(record.get("auth_required"), record.get("auth_method"))
    line = f"{_prefix(record)} [*] {_NAMES[product]} (auth required:{auth})"
    version = _version(record, product)
    if version:
        line += f" (version:{version})"
    return line


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format != "txt":
        return actions._format_record(record, output_format)
    status = str(record.get("status") or "")
    if status not in {"valid_credentials", "auth_required"}:
        return actions._format_record(record, output_format) if status in {"fail", "not_registry"} else ""
    if record.get("token_provided"):
        return f"{_prefix(record)} {'[+]' if status == 'valid_credentials' else '[-]'} token auth"
    username = record.get("provided_username")
    if not record.get("provided_credentials") and username is None:
        return ""
    user = str(username or "user")
    password = record.get("provided_password")
    pair = f"{user}:{'<empty>' if password == '' else str(password or '')}"
    return f"{_prefix(record)} {'[+]' if status == 'valid_credentials' else '[-]'} {pair}"


_COUNTED_SECTIONS = {
    "Images Enumeration": ("images", "images"),
    "Harbor Projects Enumeration": ("harbor_projects", "projects"),
    "Harbor Repositories Enumeration": ("harbor_repositories", "repositories"),
    "Harbor Artifacts Enumeration": ("harbor_artifacts", "artifacts"),
    "GitLab Repositories Enumeration": ("gitlab_repositories", "repositories"),
    "Nexus Repositories Enumeration": ("nexus_repositories", "repositories"),
    "Nexus Assets Enumeration": ("nexus_assets", "assets"),
}


def _format_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return actions._format_detail_records(record, output_format)
    if record.get("status") == "auth_required":
        # The detector's authentication result is already in the service line.
        # No inventory operation has run at this point.
        return []
    product = _product(record)
    display_record = dict(record)
    if display_record.get("images") is None and not display_record.get("images_error"):
        display_record["show_images"] = False
    if display_record.get("selected_repository_tags") is None and not display_record.get("images_error"):
        display_record["show_tags"] = False
    if display_record.get("nexus_assets") is None and "data_transport_attempts" not in display_record:
        display_record["assets"] = False
    if product == "gitlab" and "data_transport_attempts" not in display_record:
        if not display_record.get("gitlab_repository_details") and not display_record.get("gitlab_repositories"):
            display_record["gitlab"] = False
    if display_record.get("metadata_result") is None and "data_transport_attempts" not in display_record:
        display_record["metadata"] = False
    legacy = actions._format_detail_records(display_record, output_format)
    prefix = _prefix(record)
    lines: list[str] = []
    for line in legacy:
        parts = line.split("\t", 3)
        if len(parts) != 4:
            continue
        payload = parts[3]
        # Detection already names the product and its version. A second
        # "detected" line obscures the first inventory section.
        if payload.startswith(
            (
                " [*] Harbor detected",
                " [*] Nexus Repository detected",
                " [*] GitLab Container Registry detected",
            )
        ):
            continue
        if product != "harbor" and payload.startswith(" [*] Harbor "):
            continue
        if product != "harbor" and payload.startswith(" [!] Harbor presence unknown: not harbor"):
            continue
        if product != "nexus" and payload.startswith(" [*] Nexus "):
            continue
        if product != "nexus" and payload.startswith(" [!] Nexus presence unknown: not nexus"):
            continue
        if product != "gitlab" and payload.startswith(" [*] GitLab "):
            continue
        if product != "gitlab" and payload.startswith(" [!] GitLab presence unknown: not gitlab"):
            continue
        for old, (field, label) in _COUNTED_SECTIONS.items():
            if payload == f" [*] {old}":
                values = record.get(field)
                count = len(values) if isinstance(values, list) else 0
                payload = f" [*] {old} ({label}:{count})"
                break
        if payload.startswith(" [*] Tags Enumeration "):
            tags = record.get("selected_repository_tags")
            count = len(tags) if isinstance(tags, list) else 0
            payload += f" (tags:{count})"
        lines.append(f"{prefix}{payload}")
    return lines


def _render_colored_registry_line(console: Console, line: str) -> bool:
    tag = line.split(None, 1)[0].strip() if line.strip() else ""
    if tag not in {"DOCKER-REGISTRY", "HARBOR", "NEXUS", "GITLAB"}:
        return False
    if render_colored_marker_line(
        console,
        line,
        tag=tag,
        include_auth_required=False,
        booleans=(BooleanColorRule("auth required", true_color="bright_green", false_color="true_red"),),
        counts=tuple(
            CountColorRule(name, "true_red", unknown_color="orange", zero_color="bright_green")
            for name in ("images", "projects", "repositories", "artifacts", "assets", "tags", "layers", "components")
        ),
        extra_spans=lambda marker, payload: (
            [(0, len(payload), "orange")] if marker == "[!]" and not payload.startswith("CVE's Enumeration") else []
        ),
    ):
        return True
    if line.startswith(tag) and "\t" in line:
        return render_tagged_detail_line(
            console,
            line,
            tag=tag,
            default_color="white",
            resource_counts=(
                "images",
                "projects",
                "repositories",
                "artifacts",
                "assets",
                "tags",
                "layers",
                "components",
            ),
        )
    return False


__all__ = ["_format_detect_record", "_format_record", "_format_detail_records", "_render_colored_registry_line"]
