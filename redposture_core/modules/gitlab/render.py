"""Render helpers for the gitlab audit module."""

from __future__ import annotations

from typing import Any

from ..registry import actions as oci_actions
from .actions import _format_detail_records as _format_web_details
from .actions import _format_gitlab_text, _nxc_prefix, _render_colored_gitlab_line
from .actions import _format_record as _format_web_record


def _registry_payload(record: dict[str, Any]) -> dict[str, Any] | None:
    nested = record.get("container_registry")
    if not isinstance(nested, dict):
        return None
    return {**nested, "module": "gitlab", "service": "gitlab"}


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return _format_web_record(record, output_format)
    if record.get("gitlab_surface") == "container_registry":
        nested = _registry_payload(record)
        return oci_actions._format_detect_record(nested, output_format) if nested is not None else ""
    return _format_web_record(record, output_format)


def _format_detail_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format == "json":
        return []
    surface = str(record.get("gitlab_surface") or "web")
    lines = _format_web_details(record, output_format) if surface in {"web", "web_and_registry"} else []
    nested = _registry_payload(record)
    if nested is not None:
        if surface == "web_and_registry":
            lines.append(f"{_nxc_prefix(record)} [*] Container Registry (auth required:{nested.get('auth_required')})")
        summary = oci_actions._format_record(nested, output_format)
        if summary:
            lines.append(summary)
        lines.extend(oci_actions._format_detail_records(nested, output_format))
    if (
        surface in {"web", "web_and_registry"}
        and record.get("provided_credentials_ok") is True
        and record.get("provided_username") is not None
    ):
        username = str(record["provided_username"])
        password = str(record.get("provided_password") or "")
        credential_line = f"{_nxc_prefix(record)} [+] {username}:{password}"
        if credential_line not in lines:
            lines.insert(0, credential_line)
    return lines


__all__ = [
    "_nxc_prefix",
    "_format_gitlab_text",
    "_format_record",
    "_format_detail_records",
    "_render_colored_gitlab_line",
]
