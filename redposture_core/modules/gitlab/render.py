"""TXT/JSON rendering and terminal colors for GitLab's web and OCI surfaces."""

from __future__ import annotations

from typing import Any

from ...auth_detection import auth_required_text
from ...console import Console
from ...rendering import BooleanColorRule, CountColorRule, render_colored_marker_line, render_tagged_detail_line
from ..registry import product_render as oci_render
from .actions import _format_detail_records as _format_web_details
from .actions import _format_gitlab_text
from .actions import _format_record as _format_web_record


def _nxc_prefix(record: dict[str, Any]) -> str:
    return f"GITLAB\t{record.get('host') or '?'}\t{record.get('port') or 0}\t"


def _registry_payload(record: dict[str, Any]) -> dict[str, Any] | None:
    nested = record.get("container_registry")
    if not isinstance(nested, dict):
        return None
    return {**nested, "module": "gitlab", "service": "gitlab"}


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    if output_format != "txt":
        return ""
    surface = str(record.get("gitlab_surface") or "web")
    if surface == "container_registry":
        nested = _registry_payload(record)
        return oci_render._format_detect_record(nested, output_format) if nested is not None else ""
    auth = auth_required_text(record.get("auth_required"), record.get("auth_method"))
    line = f"{_nxc_prefix(record)} [*] GitLab (auth required:{auth})"
    if auth == "sso" and record.get("sso_provider"):
        line += f" (provider:{record['sso_provider']})"
    if record.get("version"):
        line += f" (version:{record['version']})"
    return line


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format != "txt":
        return _format_web_record(record, output_format)
    if str(record.get("status") or "") in {"fail", "not_gitlab"}:
        return _format_web_record(record, output_format)
    verified = record.get("provided_credentials_ok")
    if not isinstance(verified, bool):
        return ""
    username = record.get("provided_username")
    if username is not None:
        password = record.get("provided_password")
        pair = f"{username}:{'<empty>' if password == '' else str(password or '')}"
        return f"{_nxc_prefix(record)} {'[+]' if verified else '[-]'} {pair}"
    if record.get("token_valid") is True or (_registry_payload(record) or {}).get("token_provided"):
        return f"{_nxc_prefix(record)} {'[+]' if verified else '[-]'} token auth"
    return ""


def _format_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format == "json":
        return []
    surface = str(record.get("gitlab_surface") or "web")
    prefix = _nxc_prefix(record)
    lines: list[str] = []
    if surface in {"web", "web_and_registry"}:
        display_record = dict(record)
        stages = record.get("stages")
        data_ran = isinstance(stages, list) and any(
            isinstance(stage, dict) and stage.get("stage_name") == "data" for stage in stages
        )
        if not data_ran and not display_record.get("public_projects"):
            display_record["public_projects"] = None
        if not data_ran and not display_record.get("token_access"):
            display_record["token_access"] = None
        for old_line in _format_web_details(display_record, output_format):
            parts = old_line.split("\t", 3)
            if len(parts) != 4:
                continue
            payload = parts[3]
            if payload == " [*] Public Projects":
                projects = record.get("public_projects")
                payload += f" (projects:{len(projects) if isinstance(projects, list) else 0})"
            elif payload == " [*] Open Endpoints":
                endpoints = record.get("open_endpoints")
                payload += f" (endpoints:{len(endpoints) if isinstance(endpoints, list) else 0})"
            elif payload == " [*] Token Project Access":
                access = record.get("token_access")
                payload += f" (projects:{len(access) if isinstance(access, list) else 0})"
            lines.append(f"{prefix}{payload}")
    nested = _registry_payload(record)
    if nested is not None:
        if surface == "web_and_registry":
            auth = auth_required_text(nested.get("auth_required"), nested.get("auth_method"))
            lines.append(f"{prefix} [*] Container Registry (auth required:{auth})")
        lines.extend(oci_render._format_detail_records(nested, output_format))
    return lines


def _render_colored_gitlab_line(console: Console, line: str) -> bool:
    if not line.startswith("GITLAB"):
        return False
    if render_colored_marker_line(
        console,
        line,
        tag="GITLAB",
        include_auth_required=False,
        booleans=(BooleanColorRule("auth required", true_color="bright_green", false_color="true_red"),),
        counts=tuple(
            CountColorRule(name, "true_red", unknown_color="orange", zero_color="bright_green")
            for name in ("images", "projects", "endpoints", "repositories", "tags")
        ),
        extra_spans=lambda marker, payload: [(0, len(payload), "orange")] if marker == "[!]" else [],
    ):
        return True
    if "\t" in line:
        return render_tagged_detail_line(
            console,
            line,
            tag="GITLAB",
            default_color="white",
            resource_counts=("images", "projects", "endpoints", "repositories", "tags"),
        )
    return False


__all__ = [
    "_nxc_prefix",
    "_format_gitlab_text",
    "_format_detect_record",
    "_format_record",
    "_format_detail_records",
    "_render_colored_gitlab_line",
]
