"""ResourceManager output with the Airflow color convention."""

from __future__ import annotations

import json
import re
from typing import Any

from ...discovery_rendering import discovery_color_spans
from ...rendering import (
    BooleanColorRule,
    RegexColorRule,
    format_report_line_for_console,
    render_colored_marker_line,
    render_tagged_detail_line,
)
from ..execution_api import render as render_execution
from ..token_render import detect, prefix

_COUNT_METRICS = re.compile(
    r'^Metric "(?:apps(?:Submitted|Completed|Pending|Running|Failed|Killed)|'
    r"containers(?:Allocated|Reserved|Pending)|totalNodes|lostNodes|unhealthyNodes|"
    r"decommissioningNodes|decommissionedNodes|rebootedNodes|activeNodes|shutdownNodes|"
    r'totalAllocatedContainersAcrossPartition)"=([0-9]+)$'
)


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    line = detect("yarn", "Hadoop YARN ResourceManager", record, output_format)
    if line:
        line += f" (state:{record.get('cluster_state') or 'unknown'}) (HA:{record.get('ha_state') or 'unknown'})"
    return line


def _format_record(_record: dict[str, Any], _output_format: str) -> str:
    return ""


def _format_inventory_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []
    pre = prefix("yarn", record)
    lines: list[str] = []
    if record.get("rce_potential") and not record.get("execute_verified") and not record.get("inventory_requested"):
        lines.append(
            f"{pre} [!] RCE:potential (application ID allocation allowed; submission unverified; execution unverified)"
        )
    for name, label, singular in (
        ("apps", "Applications", "Application"),
        ("nodes", "Nodes", "Node"),
        ("metrics", "Metrics", "Metric"),
    ):
        if name not in record.get("inventory_requested", []):
            continue
        data = record.get(name)
        count = len(data) if isinstance(data, (list, dict)) else "unknown"
        lines.append(
            f"{pre} [*] {label} Enumeration (access:{record.get(name + '_access', 'unknown')}) ({name}:{count})"
        )
        if isinstance(data, list):
            lines.extend(f"{pre} [+] {singular} {json.dumps(row, ensure_ascii=False)}" for row in data)
        if isinstance(data, dict):
            lines.extend(
                f"{pre} [+] {singular} {json.dumps(key)}={json.dumps(value, ensure_ascii=False)}"
                for key, value in data.items()
            )
        if record.get(name + "_partial"):
            lines.append(
                f"{pre} [*] {label} coverage (status:partial) reason={json.dumps(record.get(name + '_error') or 'incomplete inventory', ensure_ascii=False)}"
            )
    probe = record.get("submit_probe")
    if isinstance(probe, dict):
        state = probe.get("access", "unverified")
        marker = "[+]" if state == "allowed" else "[-]" if state == "denied" else "[*]"
        lines.append(
            f"{pre} {marker} Application ID allocation (access:{state}) (submission unverified; execution unverified)"
        )
    return lines


def _format_execution_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []
    return render_execution("yarn", record)


def _render_colored_yarn_line(console: Any, line: str) -> bool:
    line = format_report_line_for_console(line)
    if render_colored_marker_line(
        console,
        line,
        tag="YARN",
        include_auth_required=False,
        booleans=(BooleanColorRule("auth required", true_color="bright_green", false_color="true_red"),),
        regexes=(
            RegexColorRule(r"\((?:apps|nodes|metrics|findings):0\)", "bright_green"),
            RegexColorRule(r"\((?:apps|nodes|metrics|findings):[1-9]\d*\)", "true_red"),
            RegexColorRule(r"\(access:allowed\)", "true_red"),
            RegexColorRule(r"\(access:denied\)", "bright_green"),
            RegexColorRule(r"\(access:(?:unknown|unverified|rate_limited)\)", "orange"),
            RegexColorRule(r"\([^()]*unknown\)", "orange"),
            RegexColorRule(r"\((?:state|HA):[^)]+\)", "orange"),
            RegexColorRule(r"\(status:(?:partial|unavailable)\)", "orange"),
            RegexColorRule(r"reason=.*", "orange"),
            RegexColorRule(r"\(submission unverified; execution unverified\)", "orange"),
        ),
        extra_spans=_detail_spans,
    ):
        return True
    if line.startswith("YARN") and "\t" in line:
        return render_tagged_detail_line(console, line, tag="YARN", default_color="orange")
    return False


def _detail_spans(marker: str, payload: str) -> list[tuple[int, int, str]]:
    spans = list(discovery_color_spans(marker, payload))
    count = _COUNT_METRICS.fullmatch(payload)
    if marker == "[!]":
        spans.append((0, len(payload), "true_red"))
    elif marker == "[+]" and count:
        # A zero metric is observed data, not a safe-denial verdict.  For
        # example, availableMB=0 is a capacity concern rather than safety.
        spans.append((0, len(payload), "orange"))
    elif marker == "[+]" and not payload.startswith("Application ID allocation "):
        spans.append((0, len(payload), "orange"))
    return spans
