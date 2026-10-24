"""Airflow-style Portainer report rendering."""

from __future__ import annotations

import re
from typing import Any

from ... import web_panels
from ...discovery_rendering import discovery_color_spans
from ...rendering import render_colored_marker_line, render_tagged_detail_line
from ..execution_api import render as render_execution


def render_record(record: Any) -> list[str]:
    payload = record.to_dict() if hasattr(record, "to_dict") else dict(record)
    lines = web_panels.render_panel({**payload, "attempted_credentials": []}, "PORTAINER")
    prefix = f"PORTAINER\t{payload.get('host')}\t{payload.get('port')}\t"
    attempts = payload.get("attempted_credentials")
    attempts = attempts if isinstance(attempts, list) and attempts else [payload]
    auth_lines = []
    shown: set[tuple[str, str]] = set()
    blocked = False
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        state = str(attempt.get("credential_state") or attempt.get("status") or "")
        if state in {"rate_limited", "account_locked", "captcha"}:
            blocked = True
            continue
        valid = state in {"valid", "valid_credentials"}
        invalid = state in {"invalid", "invalid_credentials"}
        if attempt.get("token_provided"):
            marker = "[+]" if valid else "[-]" if invalid else "[!]"
            outcome = "accepted" if valid else "rejected" if invalid else "unverified"
            auth_lines.append(f"{prefix} {marker} Token {outcome}")
            continue
        user = attempt.get("username", attempt.get("provided_username"))
        password = attempt.get("password", attempt.get("provided_password"))
        if user is not None and password is not None and (valid or invalid):
            pair = str(user), str(password)
            if pair not in shown:
                shown.add(pair)
                text = (
                    re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", f"{user}:{password}").replace("\r", "\\r").replace("\n", "\\n")
                )
                auth_lines.append(f"{prefix} {'[+]' if valid else '[-]'} {text}")
        elif state == "unverified":
            auth_lines.append(f"{prefix} [!] Credentials unverified")
    if blocked:
        auth_lines.append(f"{prefix} [!] Credential attempts stopped: panel rate limit or lockout")
    return [lines[0], *auth_lines, *lines[1:], *_format_execution_records(payload, "txt")]


def colorize(console: Any, line: str) -> bool:
    if "Discover Secrets" in line or (" Value=" in line and " Place=" in line):
        return render_colored_marker_line(console, line, tag="PORTAINER", extra_spans=discovery_color_spans)
    if web_panels.colorize_panel_line(console, line, "PORTAINER"):
        return True
    return render_colored_marker_line(console, line, tag="PORTAINER") or render_tagged_detail_line(
        console, line, tag="PORTAINER", default_color="orange"
    )


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    return web_panels.render_panel(record, "PORTAINER")[0] if output_format == "txt" else ""


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format != "txt":
        return ""
    lines = render_record({**record, "execution": None})
    return "\n".join(line for line in lines[1:] if " Enumeration " not in line and "\t [" in line)


def _format_inventory_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []
    inventory_record = {**record, "credential_state": None, "token_provided": False, "attempted_credentials": []}
    return web_panels.render_panel(inventory_record, "PORTAINER")[1:]


def _format_execution_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []
    return render_execution("portainer", record)


_render_colored_portainer_line = colorize


__all__ = ["render_record", "colorize", "_format_execution_records"]
