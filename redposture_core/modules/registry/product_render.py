"""Consistent TXT presentation for the public registry product commands.

The legacy OCI renderer remains available internally. This layer only changes
the presentation of confirmed products; collection and JSON stay unchanged.
"""

from __future__ import annotations

import re
from typing import Any

from ...auth_detection import auth_required_text
from ...console import Console
from ...discovery_rendering import discovery_color_spans
from ...rendering import (
    BooleanColorRule,
    CountColorRule,
    render_colored_marker_line,
    render_tagged_detail_line,
)
from ..execution_api import render as render_execution
from . import actions

_NAMES = {
    "docker-registry": "Docker Registry",
    "harbor": "Harbor",
    "nexus": "Nexus Repository",
    "gitlab": "GitLab Container Registry",
}

_DATE_TAG = re.compile(
    r"(?:^|[^0-9])(?P<year>20\d{2})[-._]?(?P<month>0[1-9]|1[0-2])[-._]?"
    r"(?P<day>0[1-9]|[12]\d|3[01])(?:[Tt._-](?P<hour>[01]\d|2[0-3])[:._-]?"
    r"(?P<minute>[0-5]\d))?"
)
_VERSION_TAG = re.compile(
    r"^[vV]?(?P<number>\d+(?:\.\d+){1,3})(?:[-._]?(?P<stage>alpha|beta|rc|pre)(?P<stage_num>\d*))?$",
    re.IGNORECASE,
)


def _ordered_tags(tags: list[str]) -> list[str]:
    """Put latest first, then dated/versioned tags newest-first, then names.

    OCI tags have no creation timestamp in the tag-list response; unknown
    names are alphabetical, never presented as a claimed chronological order.
    """

    def key(tag: str) -> tuple[Any, ...]:
        name = str(tag)
        if name.casefold() == "latest":
            return (0,)
        dated = _DATE_TAG.search(name)
        if dated:
            parts = tuple(-int(dated.group(part) or 0) for part in ("year", "month", "day", "hour", "minute"))
            return (1, *parts, name.casefold(), name)
        version = _VERSION_TAG.fullmatch(name)
        if version:
            numbers = [int(part) for part in version.group("number").split(".")]
            numbers = (numbers + [0] * 4)[:4]
            stage = (version.group("stage") or "").lower()
            stage_rank = {"": 0, "rc": 1, "beta": 2, "pre": 3, "alpha": 4}[stage]
            return (2, *(-part for part in numbers), stage_rank, -int(version.group("stage_num") or 0), name)
        return (3, name.casefold(), name)

    return sorted(tags, key=key)


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
    # The OCI /v2/ response identifies the protocol, not the server build.
    # Keep the version in this service line, and be explicit when the vendor
    # does not expose a product version through a read-only endpoint.
    line += f" (version:{_version(record, product) or 'unknown'})"
    count_field = {
        "nexus": ("nexus_repository_count", "repositories"),
        "harbor": ("harbor_project_count", "projects"),
        "gitlab": ("gitlab_repository_count", "repositories"),
    }.get(product)
    if count_field is not None:
        count = record.get(count_field[0])
        if isinstance(count, int) and not isinstance(count, bool):
            line += f" ({count_field[1]}:{count})"
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
    if password == "":
        password_text = "<empty>"
    elif password is None and record.get("provided_credentials") is True:
        password_text = "<redacted>"
    else:
        password_text = str(password or "")
    pair = f"{user}:{password_text}"
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


def _registry_marker_value_spans(marker: str, payload: str) -> list[tuple[int, int, str]]:
    if marker not in {"[*]", "[+]"}:
        return []
    pattern = r"^(?:Tags Enumeration|Metadata|Inspect) (\S+)" if marker == "[*]" else r"^Download complete path=(\S+)"
    match = re.match(pattern, payload)
    return [(match.start(1), match.end(1), "orange")] if match else []


def _inventory_section_rank(payload: str, inspection_error: str) -> int | None:
    """Keep related detail lines together in the same order as the CLI actions."""
    if payload.startswith(
        (
            "[*] Nexus Repositories Enumeration",
            "[*] Harbor Projects Enumeration",
            "[*] Harbor Repositories Enumeration",
            "[*] GitLab Repositories Enumeration",
        )
    ):
        return 0
    if payload.startswith(("[*] Images Enumeration", "[*] Harbor Artifacts Enumeration")):
        return 1
    if payload.startswith(("[*] Tags Enumeration", "[-] Tags enumeration partial")):
        return 2
    if payload.startswith(("[*] Inspect ", "[-] Inspect ")) or (
        inspection_error and payload == f"[-] {inspection_error}"
    ):
        return 3
    if payload.startswith(("[*] Metadata ", "[-] Metadata ")):
        return 4
    if payload.startswith("[*] Nexus Assets Enumeration"):
        return 5
    if payload.startswith(("[+] Download ", "[-] Download ", "[!] Download ")):
        return 6
    return None


def _order_inventory_sections(lines: list[str], *, inspection_error: str) -> list[str]:
    sections: list[tuple[int, int, list[str]]] = []
    for line in lines:
        payload = line.split("\t", 3)[-1].strip()
        rank = _inventory_section_rank(payload, inspection_error)
        if rank is not None or not sections:
            sections.append((rank if rank is not None else -1, len(sections), [line]))
        else:
            sections[-1][2].append(line)
    return [line for _rank, _index, block in sorted(sections) for line in block]


def _format_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return actions._format_detail_records(record, output_format)
    if record.get("status") == "auth_required":
        # The detector's authentication result is already in the service line.
        # No inventory operation has run at this point.
        return []
    product = _product(record)
    display_record = dict(record)
    if product == "docker-registry":
        selected = display_record.get("selected_repository_tags")
        if isinstance(selected, list):
            display_record["selected_repository_tags"] = _ordered_tags(selected)
        all_tags = display_record.get("repository_tags")
        if isinstance(all_tags, dict):
            display_record["repository_tags"] = {
                name: _ordered_tags(tags) if isinstance(tags, list) else tags for name, tags in all_tags.items()
            }
    if display_record.get("images") is None and not display_record.get("images_error"):
        display_record["show_images"] = False
    if (
        display_record.get("selected_repository_tags") is None
        and display_record.get("repository_tags") is None
        and not display_record.get("images_error")
    ):
        display_record["show_tags"] = False
    if display_record.get("nexus_assets") is None and "data_transport_attempts" not in display_record:
        display_record["assets"] = False
    if not display_record.get("show_images"):
        if not display_record.get("show_repositories"):
            display_record["nexus_repositories"] = None
            display_record["nexus_repository_details"] = None
        display_record["harbor_projects"] = None
        display_record["harbor_repositories"] = None
        display_record["harbor_artifacts"] = None
        display_record["gitlab_repositories"] = None
        display_record["gitlab_repository_details"] = None
        if not display_record.get("assets") and not display_record.get("show_repositories") and product == "nexus":
            display_record["nexus"] = False
        if product == "harbor":
            display_record["harbor"] = False
        if product == "gitlab":
            display_record["gitlab"] = False
    if product == "gitlab" and "data_transport_attempts" not in display_record:
        if not display_record.get("gitlab_repository_details") and not display_record.get("gitlab_repositories"):
            display_record["gitlab"] = False
    if product == "harbor":
        # Harbor's repository list is an intermediate API collection for
        # artifacts/images. Keep it in JSON and for tag lookups, but avoid
        # repeating the same names as a separate TXT inventory section.
        display_record["harbor_repositories"] = None
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
            if not re.search(r"\(repositories:\d+\)$", payload):
                repo = payload.removeprefix(" [*] Tags Enumeration ")
                all_tags = record.get("repository_tags")
                if isinstance(all_tags, dict) and not record.get("repository"):
                    tags = all_tags.get(repo)
                else:
                    tags = record.get("selected_repository_tags")
                errors = record.get("repository_tag_errors")
                if isinstance(errors, dict) and repo in errors and not tags:
                    tag_count_text = "unknown"
                else:
                    tag_count_text = str(len(tags) if isinstance(tags, list) else 0)
                payload += f" (tags:{tag_count_text})"
        lines.append(f"{prefix}{payload}")
    return _order_inventory_sections(lines, inspection_error=str(record.get("inspection_error") or "").strip())


def _format_execution_records(record: dict[str, Any], output_format: str) -> list[str]:
    if _product(record) != "nexus" or output_format != "txt":
        return []
    return render_execution("nexus", record)


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
            ([(0, len(payload), "orange")] if marker == "[!]" and not payload.startswith("CVE's Enumeration") else [])
            + discovery_color_spans(marker, payload)
            + _registry_marker_value_spans(marker, payload)
        ),
    ):
        return True
    if line.startswith(tag) and "\t" in line:
        return render_tagged_detail_line(
            console,
            line,
            tag=tag,
            default_color="orange",
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


__all__ = [
    "_format_detect_record",
    "_format_record",
    "_format_detail_records",
    "_format_execution_records",
    "_render_colored_registry_line",
]
