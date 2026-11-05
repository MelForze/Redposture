"""Airflow-style TXT and terminal rendering for Jenkins."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from ...auth_detection import auth_required_text
from ...console import Console
from ...rendering import BooleanColorRule, RegexColorRule, render_colored_marker_line, render_tagged_detail_line
from ..execution_api import render as render_execution


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
    line = (
        f"{_prefix(record)} [*] Jenkins (auth required:{auth}) "
        f"(jobs allowed anonymously:{jobs_text}) (version:{record.get('version') or '-'})"
    )
    rce = record.get("rce")
    if type(rce) is bool:
        line = line.replace(" (version:", f" (rce:{rce}) (version:")
    elif "rce" in record:
        line = line.replace(" (version:", " (rce:unknown) (version:")
    return line


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if (
        output_format != "txt"
        or record.get("credential_state") != "valid"
        or isinstance(record.get("attempted_credentials"), list)
    ):
        return ""
    results = record.get("credential_results")
    username = (
        (results[0].get("username") if isinstance(results, list) and results and isinstance(results[0], dict) else None)
        or record.get("authenticated_identity")
        or "?"
    )
    password = record.get("credential_password")
    pair = f"{username}:{password}" + (" (type:API token)" if record.get("credential_source") == "api_token" else "")
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
        if record.get("credential_state") == "valid":
            return []
        results = record.get("credential_results")
        if not isinstance(results, list) or not results or not isinstance(results[0], dict):
            return []
        attempts = [
            {
                "username": results[0].get("username"),
                "password": record.get("credential_password"),
                "source": record.get("credential_source") or "provided",
                "status": record.get("status"),
                "reason": record.get("credential_verification_reason") or record.get("error"),
            }
        ]
    lines: list[str] = []
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        source = str(attempt.get("source") or "")
        name = str(attempt.get("username") or "?")
        password = attempt.get("password")
        status = str(attempt.get("status") or "")
        pair = f"{name}:{password}" + (" (type:API token)" if source == "api_token" else "")
        if status == "valid_credentials":
            selected = {
                **attempt,
                "host": record.get("host"),
                "port": record.get("port"),
                "credential_state": "valid",
                "credential_results": [{"username": name}],
                "credential_password": password,
                "credential_source": source,
                "api_endpoint": record.get("api_endpoint"),
            }
            lines.append(_format_record(selected, output_format))
        elif status == "invalid_credentials":
            lines.append(f"{_prefix(record)} [-] {pair}")
        else:
            verdict = "skipped" if status == "skipped" else "unverified"
            reason = str(
                attempt.get("reason")
                or attempt.get("credential_verification_reason")
                or attempt.get("error")
                or status
                or "identity unavailable"
            )
            lines.append(f"{_prefix(record)} [*] {pair} (status:{verdict}) reason={reason}")
    return lines


def _format_inventory_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt" or record.get("_jenkins_inventory_emitted"):
        return []
    return list(_iter_inventory_records(record))


def _iter_inventory_records(record: dict[str, Any]) -> Iterator[str]:
    prefix = _prefix(record)
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
                yield f"{prefix} [*] {title} (access:{readable})"
            continue
        total = record.get(count) if isinstance(record.get(count), int) else len(entries)
        yield f"{prefix} [*] {title} ({kind}:{total})"
        for item in entries:
            if not isinstance(item, dict):
                continue
            if field == "jobs":
                yield (f"{prefix} [+] {label}={_display(item.get('name'))} (state:{item.get('color') or 'unknown'})")
            elif field == "builds":
                result = item.get("result") or ("RUNNING" if item.get("building") is True else "unknown")
                yield (
                    f"{prefix} [+] Build Job={_display(item.get('job'))} Number={item.get('number')} (result:{result})"
                )
            else:
                if field == "plugins":
                    yield (
                        f"{prefix} [+] {label}={_display(item.get('short_name'))} Version={_display(item.get('version'))} (active:{item.get('active')})"
                    )
                elif field == "nodes":
                    online = not item["offline"] if isinstance(item.get("offline"), bool) else "Unknown"
                    executors = item.get("executors") if isinstance(item.get("executors"), int) else "Unknown"
                    busy = item.get("busy") if isinstance(item.get("busy"), int) else "Unknown"
                    yield (
                        f"{prefix} [+] {label}={_display(item.get('name'))} (online:{online}) (executors:{executors}) (busy:{busy})"
                    )
                elif field == "queue":
                    yield (
                        f"{prefix} [+] {label}={_display(item.get('task'))} (id:{item.get('id')}) (reason:{_display(item.get('why'))})"
                    )
                elif field == "artifacts":
                    size = item.get("size_bytes") if isinstance(item.get("size_bytes"), int) else "Unknown"
                    yield (
                        f"{prefix} [+] {label}={_display(item.get('name'))} (job:{_display(item.get('job'))}) (build:{item.get('build')}) (size_bytes:{size})"
                    )
    if record.get("job_discovery_partial"):
        reason = json.dumps(record.get("discovery_errors") or ["incomplete discovery"], ensure_ascii=False)
        yield f"{prefix} [*] Discovery coverage (status:partial) reason={reason}"
    for field in ("builds", "artifacts"):
        if record.get(field + "_partial"):
            reason = json.dumps(record.get(field + "_errors") or ["incomplete inventory"], ensure_ascii=False)
            yield f"{prefix} [*] {field.title()} coverage (status:partial) reason={reason}"


def _format_execution_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []
    return render_execution("jenkins", record)


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
            BooleanColorRule("rce", true_color="true_red", false_color="bright_green"),
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
            RegexColorRule(r"\(rce:unknown\)", "orange"),
            RegexColorRule(r"\(status:partial\)", "orange"),
            RegexColorRule(r"\(status:(?:unverified|skipped|stopped)\)", "orange"),
            RegexColorRule(r"reason=.*", "orange"),
        ),
        extra_spans=lambda marker, payload: (
            [(0, payload.find(" (online:"), "orange")]
            if marker == "[+]" and payload.startswith("Node Name=")
            else [(0, payload.find(" ("), "orange")]
            if marker == "[+]" and payload.startswith("Artifact Name=") and " (" in payload
            else [(0, len(payload), "orange")]
            if marker == "[+]"
            and payload.startswith(("Job Name=", "Build Job=", "Plugin Name=", "Queue Task=", "Artifact Name="))
            else []
        ),
    ):
        return True
    if line.startswith("JENKINS") and "\t" in line:
        return render_tagged_detail_line(console, line, tag="JENKINS", default_color="orange")
    return False


__all__ = [
    "_format_detect_record",
    "_format_record",
    "_format_credential_attempts_records",
    "_format_inventory_records",
    "_format_execution_records",
    "_render_colored_jenkins_line",
]
