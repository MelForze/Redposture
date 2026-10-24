"""Spark TXT output and Airflow-style terminal colors."""

from __future__ import annotations

import json
from typing import Any

from ...discovery_rendering import discovery_color_spans
from ...rendering import BooleanColorRule, RegexColorRule, render_colored_marker_line, render_tagged_detail_line
from ..execution_api import render as render_execution
from ..token_render import aligned_line, detect, prefix


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    line = detect("spark", "Apache Spark Standalone", record, output_format)
    if not line:
        return ""
    version = f" (version:{record['version']})" if record.get("version") else ""
    if version:
        line = line.removesuffix(version)
    return line + f" (surface:{record.get('surface') or 'unknown'})" + version


def _format_inventory_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []
    pre = prefix("spark", record)
    lines: list[str] = []
    for name in ("workers", "apps"):
        if name not in (record.get("inventory_requested") or []):
            continue
        rows = record.get(name)
        count = len(rows) if isinstance(rows, list) else "unknown"
        lines.append(
            f"{pre} [*] {name.title()} Enumeration (access:{record.get(name + '_access', 'unknown')}) ({name}:{count})"
        )
        if isinstance(rows, list):
            for row in rows:
                lines.append(f"{pre} [+] {name[:-1].title()} {json.dumps(row, ensure_ascii=False)}")
        if record.get(name + "_partial"):
            reason = json.dumps(record.get(name + "_error") or "incomplete inventory", ensure_ascii=False)
            lines.append(f"{pre} [*] {name.title()} coverage (status:partial) reason={reason}")
    probe = record.get("submit_probe")
    if isinstance(probe, dict):
        reachable = probe.get("parser_reachable")
        lines.append(
            f"{pre} [*] Submission Probe (parser reachable:{reachable if type(reachable) is bool else 'unknown'}) (access:{probe.get('access') or 'unverified'}) (execution:False)"
        )
    return lines


def _format_execution_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []
    return render_execution("spark", record)


def _render_colored_spark_line(console: Any, line: str) -> bool:
    return render_colored_marker_line(
        console,
        aligned_line(line),
        tag="SPARK",
        include_auth_required=False,
        booleans=(
            BooleanColorRule("auth required", true_color="bright_green", false_color="true_red"),
            BooleanColorRule("parser reachable", true_color="true_red", false_color="bright_green"),
        ),
        regexes=(
            RegexColorRule(r"\((?:workers|apps|findings):0\)", "bright_green"),
            RegexColorRule(r"\((?:workers|apps|findings):[1-9]\d*\)", "true_red"),
            RegexColorRule(r"\(access:allowed\)", "true_red"),
            RegexColorRule(r"\(access:denied\)", "bright_green"),
            RegexColorRule(r"\(access:(?:unknown|unverified|unavailable|rate_limited)\)", "orange"),
            RegexColorRule(r"\([^()]*unknown\)", "orange"),
            RegexColorRule(r"\(surface:[^)]+\)", "orange"),
            RegexColorRule(r"\(RCE:Possible\)", "true_red"),
            RegexColorRule(r"\(status:(?:partial|unavailable)\)", "orange"),
            RegexColorRule(r"reason=.*", "orange"),
        ),
        extra_spans=lambda marker, payload: [
            *discovery_color_spans(marker, payload),
            *(
                [(0, len(payload), "true_red")]
                if marker == "[!]"
                else [(0, len(payload), "orange")]
                if marker == "[+]"
                else []
            ),
        ],
    ) or render_tagged_detail_line(console, aligned_line(line), tag="SPARK", default_color="orange")
