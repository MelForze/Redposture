"""Airflow-style TXT and terminal rendering for Jenkins."""

from __future__ import annotations

import json
from typing import Any

from ...auth_detection import auth_required_text
from ...console import Console
from ...rendering import BooleanColorRule, RegexColorRule, render_colored_marker_line, render_tagged_detail_line


def _prefix(record: dict[str, Any]) -> str:
    return f"JENKINS\t{record.get('host') or '?'}\t{int(record.get('port') or 0)}\t"


def _display(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    if output_format != "txt" or record.get("is_jenkins") is not True:
        return ""
    auth = auth_required_text(record.get("auth_required"), None)
    jobs = record.get("anonymous_jobs_access")
    jobs_text = str(jobs) if isinstance(jobs, bool) else "unknown"
    return (
        f"{_prefix(record)} [*] Jenkins (auth required:{auth}) "
        f"(jobs allowed anonymously:{jobs_text}) (version:{record.get('version') or '-'})"
    )


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format != "txt" or record.get("credential_state") != "valid":
        return ""
    results = record.get("credential_results")
    username = (
        results[0].get("username") if isinstance(results, list) and results and isinstance(results[0], dict) else "?"
    )
    password = record.get("credential_password")
    pair = f"{username} (API token)" if password == "API token" else f"{username}:{password}"
    jobs_access = record.get("credential_jobs_access")
    jobs = (
        str(record["credential_jobs_count"])
        if jobs_access == "allowed" and isinstance(record.get("credential_jobs_count"), int)
        else "Access Denied"
        if jobs_access == "denied"
        else "Unknown"
    )
    return f"{_prefix(record)} [+] {pair} (Jobs:{jobs})"


def _format_credential_attempts_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []
    attempts = record.get("attempted_credentials")
    if not isinstance(attempts, list):
        if record.get("credential_state") != "invalid":
            return []
        results = record.get("credential_results")
        if not isinstance(results, list) or not results or not isinstance(results[0], dict):
            return []
        attempts = [
            {
                "username": results[0].get("username"),
                "password": record.get("credential_password"),
                "status": "invalid_credentials",
            }
        ]
    lines: list[str] = []
    selected = (record.get("credential_results") or [{}])[0]
    selected_pair = (
        (selected.get("username"), record.get("credential_password")) if isinstance(selected, dict) else None
    )
    selected_skipped = False
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        source = str(attempt.get("source") or "")
        name = str(attempt.get("username") or "?")
        password = "API token" if source == "api_token" else attempt.get("password")
        status = str(attempt.get("status") or "")
        if status == "valid_credentials" and not selected_skipped and (name, password) == selected_pair:
            selected_skipped = True
            continue
        pair = f"{name} (API token)" if source == "api_token" else f"{name}:{password}"
        if status == "valid_credentials":
            lines.append(f"{_prefix(record)} [+] {pair}")
        elif status == "invalid_credentials":
            lines.append(f"{_prefix(record)} [-] {pair}")
    return lines


def _format_inventory_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []
    prefix = _prefix(record)
    lines: list[str] = []
    for title, field, count, kind, label in (
        ("Jobs Enumeration", "jobs", "jobs_count", "jobs", "Job Name"),
        ("Builds Enumeration", "builds", "builds_count", "builds", "Build"),
        ("Plugins Enumeration", "plugins", "plugins_count", "plugins", "Plugin Name"),
        ("Nodes Enumeration", "nodes", "nodes_count", "nodes", "Node Name"),
        ("Queue Enumeration", "queue", "queue_count", "queue", "Queue Task"),
        ("Artifacts Enumeration", "artifacts", "artifacts_count", "artifacts", "Artifact Name"),
    ):
        if not record.get(f"{field}_requested"):
            continue
        entries = record.get(field)
        if not isinstance(entries, list):
            access = record.get(f"{field}_access")
            if access in {"denied", "unknown"}:
                readable = "Access Denied" if access == "denied" else "Unknown"
                lines.append(f"{prefix} [*] {title} (access:{readable})")
            continue
        total = record.get(count) if isinstance(record.get(count), int) else len(entries)
        lines.append(f"{prefix} [*] {title} ({kind}:{total})")
        for item in entries:
            if not isinstance(item, dict):
                continue
            if field == "jobs":
                lines.append(
                    f"{prefix} [+] {label}={_display(item.get('name'))} (state:{item.get('color') or 'unknown'})"
                )
            elif field == "builds":
                lines.append(
                    f"{prefix} [+] Build Job={_display(item.get('job'))} Number={item.get('number')} (result:{item.get('result') or 'unknown'})"
                )
            else:
                if field == "plugins":
                    lines.append(
                        f"{prefix} [+] {label}={_display(item.get('short_name'))} Version={_display(item.get('version'))} (active:{item.get('active')})"
                    )
                elif field == "nodes":
                    online = not item["offline"] if isinstance(item.get("offline"), bool) else "Unknown"
                    executors = item.get("executors") if isinstance(item.get("executors"), int) else "Unknown"
                    busy = item.get("busy") if isinstance(item.get("busy"), int) else "Unknown"
                    lines.append(
                        f"{prefix} [+] {label}={_display(item.get('name'))} (online:{online}) (executors:{executors}) (busy:{busy})"
                    )
                elif field == "queue":
                    lines.append(
                        f"{prefix} [+] {label}={_display(item.get('task'))} (id:{item.get('id')}) (reason:{_display(item.get('why'))})"
                    )
                elif field == "artifacts":
                    size = item.get("size_bytes") if isinstance(item.get("size_bytes"), int) else "Unknown"
                    lines.append(
                        f"{prefix} [+] {label}={_display(item.get('name'))} (job:{_display(item.get('job'))}) (build:{item.get('build')}) (size_bytes:{size})"
                    )
    return lines


def _render_colored_jenkins_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(
        console,
        line,
        tag="JENKINS",
        include_auth_required=False,
        booleans=(
            BooleanColorRule("auth required", true_color="bright_green", false_color="true_red"),
            BooleanColorRule("jobs allowed anonymously", true_color="true_red", false_color="bright_green"),
            BooleanColorRule("online", true_color="true_red", false_color="bright_green"),
        ),
        regexes=(
            RegexColorRule(r"\((?:jobs|builds|plugins|nodes|queue|artifacts|Jobs):0\)", "bright_green"),
            RegexColorRule(r"\((?:jobs|builds|plugins|nodes|queue|artifacts|Jobs):[1-9]\d*\)", "true_red"),
            RegexColorRule(r"\(busy:0\)", "bright_green"),
            RegexColorRule(r"\(busy:[1-9]\d*\)", "true_red"),
            RegexColorRule(r"\(executors:0\)", "bright_green"),
            RegexColorRule(r"\(executors:[1-9]\d*\)", "true_red"),
            RegexColorRule(r"\(size_bytes:0\)", "bright_green"),
            RegexColorRule(r"\(size_bytes:[1-9]\d*\)", "true_red"),
            RegexColorRule(r"\(Jobs:Access Denied\)", "bright_green"),
            RegexColorRule(r"\(Jobs:Unknown\)", "orange"),
            RegexColorRule(r"\(access:Access Denied\)", "bright_green"),
            RegexColorRule(r"\(access:Unknown\)", "orange"),
            RegexColorRule(r"\(version:-\)", "orange"),
        ),
        extra_spans=lambda marker, payload: (
            [(0, payload.find(" (online:"), "orange")]
            if marker == "[+]" and payload.startswith("Node Name=")
            else [(0, payload.find(" ("), "orange")]
            if marker == "[+]" and payload.startswith("Artifact Name=") and " (" in payload
            else [(0, len(payload), "orange")]
            if marker == "[+]"
            and payload.startswith(("Job Name=", "Build Job=", "Plugin Name=", "Queue Task=", "Artifact Name="))
            else [(0, payload.find(" (Jobs:"), "true_red")]
            if marker == "[+]" and " (Jobs:" in payload
            else []
        ),
    ):
        return True
    if line.startswith("JENKINS") and "\t" in line:
        return render_tagged_detail_line(console, line, tag="JENKINS", default_color="white")
    return False


__all__ = [
    "_format_detect_record",
    "_format_record",
    "_format_credential_attempts_records",
    "_format_inventory_records",
    "_render_colored_jenkins_line",
]
