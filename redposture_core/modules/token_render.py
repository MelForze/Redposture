"""Airflow-style rendering shared by token-authenticated services."""

from __future__ import annotations

import json
from typing import Any

from ..auth_detection import auth_required_text
from ..discovery_rendering import discovery_color_spans
from ..rendering import (
    BooleanColorRule,
    RegexColorRule,
    format_report_line_for_console,
    render_colored_marker_line,
    render_tagged_detail_line,
)


def prefix(module: str, record: dict[str, Any]) -> str:
    return f"{module.upper()}\t{record.get('host') or '?'}\t{record.get('port') or 0}\t"


def detect(module: str, title: str, record: dict[str, Any], fmt: str) -> str:
    if fmt != "txt" or not record.get("is_" + module):
        return ""
    line = f"{prefix(module, record)} [*] {title}"
    auth = auth_required_text(record.get("auth_required"), None)
    if auth != "unknown":
        line += f" (auth required:{auth})"
    if module == "nomad":
        value = record.get("acl_enabled")
        if type(value) is bool:
            line += f" (ACL enabled:{value})"
        probe = record.get("submit_probe")
        access = probe.get("access") if isinstance(probe, dict) else None
        if access in {"allowed", "denied"}:
            line += f" (Job registration allowed:{access == 'allowed'})"
    if record.get("rce_potential") and not record.get("execute_verified"):
        line += " (RCE:Possible)"
    if record.get("version"):
        line += f" (version:{record['version']})"
    return line


def credential(module: str, record: dict[str, Any], fmt: str) -> str:
    if fmt != "txt" or "token_valid" not in record:
        return ""
    value = record["token_valid"]
    return f"{prefix(module, record)} {'[+]' if value is True else '[-]' if value is False else '[*]'} Token {'accepted' if value is True else 'rejected' if value is False else 'verification unavailable'}"


def inventory(module: str, record: dict[str, Any], fmt: str) -> list[str]:
    if fmt != "txt":
        return []
    pre = prefix(module, record)
    lines: list[str] = []
    order = ("jobs", "nodes", "members") if module == "nomad" else ("contents", "sessions", "kernels", "terminals")
    for name in order:
        if name not in (record.get("inventory_requested") or []):
            continue
        rows = record.get(name)
        state = record.get(name + "_access", "unknown")
        count = len(rows) if isinstance(rows, list) else "unknown"
        lines.append(f"{pre} [*] {name.title()} Enumeration (access:{state}) ({name}:{count})")
        if isinstance(rows, list):
            for row in rows:
                # Job specs and notebook bodies are inspected by discovery,
                # while inventory only renders the requested resource models.
                lines.append(f"{pre} [+] {name[:-1].title()} {json.dumps(row, ensure_ascii=False)}")
        if record.get(name + "_partial"):
            reason = json.dumps(record.get(name + "_error") or "incomplete inventory", ensure_ascii=False)
            lines.append(f"{pre} [*] {name.title()} coverage (status:partial) reason={reason}")
    probe = record.get("submit_probe")
    if isinstance(probe, dict):
        state = probe.get("access")
        marker = "[+]" if state == "allowed" else "[-]" if state == "denied" else "[*]"
        lines.append(f"{pre} {marker} Job Submit (access:{state}) (execution:False)")
        if probe.get("cleanup") == "failed":
            lines.append(f"{pre} [-] Cleanup failed: {probe.get('cleanup_error') or 'unknown error'}")
    from .execution_api import render

    lines.extend(render(module, record))
    return lines


def aligned_line(line: str) -> str:
    """Use shared display padding while preserving the report's structural tabs."""
    return format_report_line_for_console(line)


def colorize(console: Any, line: str, module: str) -> bool:
    line = aligned_line(line)
    tag = module.upper()
    if render_colored_marker_line(
        console,
        line,
        tag=tag,
        include_auth_required=False,
        booleans=(
            BooleanColorRule("auth required", true_color="bright_green", false_color="true_red"),
            BooleanColorRule("ACL enabled", true_color="bright_green", false_color="true_red"),
            BooleanColorRule("Job registration allowed", true_color="true_red", false_color="bright_green"),
            BooleanColorRule("executed", true_color="true_red", false_color="orange"),
        ),
        regexes=(
            RegexColorRule(
                r"\((?:jobs|nodes|members|contents|sessions|kernels|terminals|findings):0\)", "bright_green"
            ),
            RegexColorRule(
                r"\((?:jobs|nodes|members|contents|sessions|kernels|terminals|findings):[1-9]\d*\)", "true_red"
            ),
            RegexColorRule(r"\(access:allowed\)", "true_red"),
            RegexColorRule(r"\(access:denied\)", "bright_green"),
            RegexColorRule(r"\(access:unverified\)", "orange"),
            RegexColorRule(r"\([^()]*unknown\)", "orange"),
            RegexColorRule(r"\(version:[^)]+\)", "orange"),
            RegexColorRule(r"\(RCE:Possible\)", "true_red"),
            RegexColorRule(r"\(status:(?:partial|unavailable)\)", "orange"),
            RegexColorRule(r"Token verification unavailable", "orange"),
            RegexColorRule(r"reason=.*", "orange"),
            RegexColorRule(r"\(mode:[^)]+\)", "orange"),
            RegexColorRule(r"\(exit:[^)]+\)", "orange"),
            RegexColorRule(r"Command execution unverified:.*", "orange"),
        ),
        extra_spans=lambda marker, payload: [
            *discovery_color_spans(marker, payload),
            *(
                [(0, len(payload), "true_red")]
                if marker == "[!]"
                else [(0, len(payload), "true_red")]
                if payload == "Token accepted"
                else [(0, len(payload), "bright_green")]
                if payload == "Token rejected"
                else [(0, len(payload), "orange")]
                if marker == "[+]" and not payload.startswith(("Command ", "Job Submit "))
                else []
            ),
        ],
    ):
        return True
    if line.startswith(tag) and "\t" in line:
        return render_tagged_detail_line(console, line, tag=tag, default_color="orange")
    return False
