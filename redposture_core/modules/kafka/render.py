"""Render helpers for the kafka audit module."""

from __future__ import annotations

import re

from ...console import Console
from ...rendering import CountColorRule, RegexColorRule, render_colored_marker_line
from . import actions
from .http_surfaces import product_name

_nxc_prefix = actions._nxc_prefix


def _render_colored_kafka_line(console: Console, line: str) -> bool:
    if (
        "Kafka UI" in line
        or any(
            name in line
            for name in ("AKHQ", "Redpanda Console", "Kafka REST Proxy", "Kafka Connect", "ksqlDB", "Schema Registry")
        )
        or "Anonymous READ" in line
        or "Kafbat UI" in line
        or "Clusters Enumeration" in line
        or "Brokers Enumeration" in line
        or "Topics Enumeration" in line
        or "Topics coverage:partial" in line
        or "Consumer groups coverage:partial" in line
        or "Consumer Groups Enumeration" in line
        or "Dump Topic" in line
        or "Dump coverage:partial" in line
        or "Dump completeness unverified" in line
        or "UI Export" in line
    ):
        if render_colored_marker_line(
            console,
            line,
            tag="KAFKA",
            regexes=(
                RegexColorRule(r"\(version:[^)]+\)", "orange"),
                RegexColorRule(r"coverage:partial", "orange"),
                RegexColorRule(r"Dump completeness unverified:[^\n]+", "orange"),
                RegexColorRule(r"\(reason:[^)]+\)", "orange"),
                RegexColorRule(r"\(file:[^)]+\)", "orange"),
            ),
            counts=tuple(
                CountColorRule(name, "red", zero_color="bright_green")
                for name in ("clusters", "brokers", "topics", "groups", "messages")
            ),
            extra_spans=lambda marker, right: (
                [(0, len(right), "red")]
                if marker == "[+]" and (":" in right or right.startswith("Anonymous READ"))
                else []
            ),
        ):
            return True
    return actions._render_colored_kafka_line(console, line)


def _format_detect_record(record: dict, output_format: str) -> str:
    if not record.get("is_kafka_ui"):
        return actions._format_detect_record(record, output_format)
    if output_format == "json":
        return ""
    vendor = record.get("ui_vendor")
    product = product_name(vendor) or (
        "Kafbat UI" if vendor == "kafbat" else "Provectus Kafka UI" if vendor == "provectus" else "Kafka UI"
    )
    required = record.get("auth_required")
    auth = "True" if required is True else "False" if required is False else "unknown"
    version = record.get("version") or "unknown"
    return f"{_nxc_prefix(record)} [*] {product} (auth required:{auth}) (version:{version})"


def _format_record(record: dict, output_format: str) -> str:
    if not record.get("is_kafka_ui"):
        return actions._format_record(record, output_format)
    if output_format == "json":
        return actions._format_record(record, output_format)
    status = str(record.get("status") or "")
    if status in {"open_no_auth", "unknown_auth", "rate_limited"}:
        return ""
    attempts = record.get("attempted_credentials")
    if isinstance(attempts, list) and attempts:
        return ""
    username = record.get("provided_username")
    password = record.get("provided_password")
    if username is None and password is None:
        return ""
    marker = "[+]" if status in {"valid_credentials", "weak_default_creds"} else "[-]"
    return f"{_nxc_prefix(record)} {marker} {username or ''}:{password or ''}"


def _format_credential_attempts_records(record: dict, output_format: str) -> list[str]:
    if not record.get("is_kafka_ui"):
        return actions._format_credential_attempts_records(record, output_format)
    if output_format != "txt":
        return []
    attempts = record.get("attempted_credentials")
    if not isinstance(attempts, list):
        return []
    lines: list[str] = []
    for item in attempts:
        if not isinstance(item, dict):
            continue
        if item.get("status") not in {"valid_credentials", "weak_default_creds", "invalid_credentials"}:
            continue
        marker = "[+]" if item.get("status") in {"valid_credentials", "weak_default_creds"} else "[-]"
        lines.append(f"{_nxc_prefix(record)} {marker} {item.get('username') or ''}:{item.get('password') or ''}")
    return lines


def _format_topics_detail_records(record: dict, output_format: str, *, debug: bool = False) -> list[str]:
    if record.get("is_kafka_ui"):
        return []
    return actions._format_topics_detail_records(record, output_format, debug=debug)


def _format_ui_detail_records(record: dict, output_format: str) -> list[str]:
    if output_format != "txt" or not record.get("is_kafka_ui"):
        return []
    prefix = _nxc_prefix(record)
    lines: list[str] = []
    if record.get("kafka_interface") == "http_surface" and record.get("anonymous_read") is True:
        lines.append(
            f"{prefix} [+] Anonymous READ available through {product_name(record.get('ui_vendor')) or 'Kafka HTTP surface'}"
        )
    export = record.get("ui_export")
    if isinstance(export, dict):

        def clean(value: object) -> str:
            return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", str(value)).replace("\r", " ").replace("\n", " ")

        if isinstance(export.get("count"), int):
            lines.append(
                f"{prefix} [*] UI Export (messages:{export['count']}) (file:{clean(export.get('path') or '')})"
            )
            if export.get("partial"):
                reason = clean(export.get("reason") or "incomplete")
                lines.append(f"{prefix} [*] UI Export coverage:partial (reason:{reason[:256]})")
        else:
            reason = clean(export.get("reason") or "unavailable")
            lines.append(f"{prefix} [-] UI Export unavailable (reason:{reason[:256]})")
    sections = (
        ("show_clusters", "ui_clusters", "Clusters Enumeration", "name"),
        ("show_brokers", "ui_brokers", "Brokers Enumeration", "host"),
        ("show_topics", "ui_topics", "Topics Enumeration", "name"),
        ("show_consumer_groups", "ui_consumer_groups", "Consumer Groups Enumeration", "name"),
    )
    dumps = record.get("ui_dump_records") if record.get("dump") else None
    pending_dumps = [item for item in dumps if isinstance(item, dict)] if isinstance(dumps, list) else []
    emitted_dumps: set[int] = set()

    def append_dump(item: dict) -> None:
        cluster, topic = str(item.get("cluster") or ""), str(item.get("topic") or "")
        messages = item.get("messages")
        if not isinstance(messages, list):
            messages = []
        lines.append(
            f"{prefix} [*] Dump Topic {cluster}/{topic} (messages:{len(messages)}) (max:{record.get('max_messages')})"
        )
        for message in messages:
            if not isinstance(message, dict):
                continue
            value = message.get("value")
            shown_value = str(value).replace("\r", "\\r").replace("\n", "\\n") if value is not None else "<null>"
            lines.append(
                f"{prefix} partition:{message.get('partition')} offset:{message.get('offset')} value:{shown_value}"
            )
        if item.get("error"):
            error = str(item["error"])
            if error.startswith("legacy Kafka UI cannot prove message completeness"):
                lines.append(f"{prefix} [*] Dump completeness unverified: legacy Kafka UI has no cursor")
            else:
                lines.append(f"{prefix} [-] {error}")

    for enabled, field, heading, name_field in sections:
        if not record.get(enabled):
            continue
        items = record.get(field)
        if not isinstance(items, list):
            continue
        label = field.removeprefix("ui_").replace("consumer_groups", "groups")
        lines.append(f"{prefix} [*] {heading} ({label}:{len(items)})")
        for item in items:
            if not isinstance(item, dict):
                continue
            cluster = str(item.get("cluster") or "")
            name = str(item.get(name_field) or item.get("id") or "")
            if name:
                lines.append(f"{prefix} {cluster + '/' if cluster else ''}{name}")
                if field == "ui_topics":
                    for index, dump_item in enumerate(pending_dumps):
                        if (
                            index not in emitted_dumps
                            and str(dump_item.get("cluster") or "") == cluster
                            and str(dump_item.get("topic") or "") == name
                        ):
                            append_dump(dump_item)
                            emitted_dumps.add(index)
    if record.get("ui_topics_partial"):
        lines.append(f"{prefix} [*] Topics coverage:partial (reason:page unavailable or repeated)")
    if record.get("ui_consumer_groups_partial"):
        lines.append(f"{prefix} [*] Consumer groups coverage:partial (reason:page unavailable or repeated)")
    if record.get("dump"):
        if pending_dumps:
            for index, item in enumerate(pending_dumps):
                if index not in emitted_dumps:
                    append_dump(item)
        else:
            reason = "no accessible clusters or topics" if record.get("ui_clusters") else "no accessible clusters"
            lines.append(f"{prefix} [-] Dump unavailable: {reason}")
        skipped = record.get("ui_dump_skipped_topics")
        if isinstance(skipped, int) and skipped > 0:
            lines.append(f"{prefix} [*] Dump coverage:partial (skipped topics:{skipped})")
        elif record.get("ui_dump_partial"):
            lines.append(f"{prefix} [*] Dump coverage:partial")
        if record.get("ui_dump_limit_reduced"):
            lines.append(f"{prefix} [*] Dump capped at 1000 messages per topic")
    if record.get("ui_unsupported_actions"):
        lines.append(f"{prefix} [-] {record['ui_unsupported_actions']}")
    return lines


__all__ = [
    "_nxc_prefix",
    "_format_detect_record",
    "_format_record",
    "_format_credential_attempts_records",
    "_format_topics_detail_records",
    "_format_ui_detail_records",
    "_render_colored_kafka_line",
]
