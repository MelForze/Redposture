"""RabbitMQ text rendering; structured output is owned by the runtime."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlsplit

from ...audit_models import AuditRecord
from ...console import Console
from ...rendering import BooleanColorRule, CountColorRule, render_colored_marker_line, render_tagged_detail_line


def _enumeration_key(record: dict[str, Any]) -> bytes | None:
    """Match complete views, never just a mutable cluster name or a port pair."""
    cluster_id = record.get("cluster_id")
    user = record.get("effective_username") or record.get("anonymous_username")
    enumeration = record.get("enumeration")
    if not cluster_id or not user or enumeration is None:
        return None
    if any(result.get("status") != "ok" or result.get("truncated") for result in enumeration.values()):
        return None
    endpoint = urlsplit(record.get("api_endpoint", ""))
    payload = {
        "cluster_id": cluster_id,
        "host": endpoint.hostname,
        "path": endpoint.path,
        "user": user,
        "authenticated": record.get("provided_credentials_ok"),
        "anonymous": record.get("anonymous_username"),
        "admin": record.get("admin"),
        "permissions": {
            key: value for key, value in record.items() if key.startswith(("permissions", "topic_permissions"))
        },
        "enumeration": {
            name: sorted(
                json.dumps(
                    {
                        key: value
                        for key, value in row.items()
                        if name != "queues"
                        or key not in {"messages", "messages_ready", "messages_unacknowledged", "consumers"}
                    },
                    sort_keys=True,
                )
                for row in result["items"]
            )
            for name, result in enumeration.items()
        },
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).digest()


class RabbitMQTextRenderer:
    """Per-command display state; collection and structured records stay intact."""

    def __init__(self, *, debug: bool = False) -> None:
        self.debug = debug
        self._shown: dict[bytes, str] = {}

    def __call__(self, record: AuditRecord) -> list[str]:
        payload = record.to_dict()
        key = None if self.debug else _enumeration_key(payload)
        previous = self._shown.get(key) if key is not None else None
        lines = [
            _format_detect_record(payload, "txt"),
            _format_record(payload, "txt"),
            *_format_credential_attempts_records(payload, "txt"),
        ]
        if previous is not None:
            lines.append(f"{_prefix(payload)} [*] Same cluster; enumeration shown at {_safe(previous)}")
        else:
            lines.extend(_format_detail_records(payload, "txt", debug=self.debug))
            if key is not None:
                self._shown[key] = str(payload["api_endpoint"])
        return [line for line in lines if line]


def _safe(value: Any) -> str:
    # Keep untrusted names, regexes, and routing keys on a single terminal line.
    return json.dumps(str(value), ensure_ascii=False)[1:-1]


def _prefix(record: dict[str, Any]) -> str:
    return f"RABBITMQ\t{_safe(record.get('host', '?'))}\t{record.get('port', 0)}\t"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    if output_format != "txt" or record.get("detection_status") not in {"confirmed", "probable"}:
        return ""
    auth = record.get("auth_required")
    value = str(auth) if isinstance(auth, bool) else "unknown"
    line = f"{_prefix(record)} [*] RabbitMQ Management (auth required:{value})"
    if record.get("detection_status") == "probable":
        line += " (detection:probable)"
    if record.get("version"):
        line += f" (version:{_safe(record['version'])})"
    return line


def _credential_label(username: Any, attempt: dict[str, Any] | None = None) -> str:
    user = _safe(username)
    if attempt is None or attempt.get("password") is None:
        return user
    password = "<empty>" if attempt["password"] == "" else _safe(attempt["password"])
    return f"{user}:{password}"


def _admin_text(value: Any) -> str:
    return str(value) if isinstance(value, bool) else "unknown"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format != "txt" or record.get("provided_credentials_ok") is not True:
        return ""
    admin = _admin_text(record.get("admin"))
    user = record.get("credential_username", "?")
    selected = next(
        (
            attempt
            for attempt in record.get("attempted_credentials", [])
            if attempt.get("username") == user and attempt.get("credential_state") == "valid"
        ),
        None,
    )
    return f"{_prefix(record)} [+] {_credential_label(user, selected)} (admin:{admin})"


def _format_credential_attempts_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []
    lines = []
    selected_skipped = False
    for attempt in record.get("attempted_credentials", []):
        user = attempt.get("username")
        state = attempt.get("credential_state", "unverified")
        if state == "valid" and user == record.get("credential_username") and not selected_skipped:
            selected_skipped = True
            continue
        marker = "+" if state == "valid" else "-" if state == "rejected" else "!"
        suffix = "" if state in {"valid", "rejected"} else f" ({_safe(state)})"
        if state == "valid":
            suffix = f" (admin:{_admin_text(attempt.get('admin'))})"
        lines.append(f"{_prefix(record)} [{marker}] {_credential_label(user, attempt)}{suffix}")
    return lines


def _section(prefix: str, title: str, count: int, status: str, truncated: bool, *, debug: bool) -> str:
    line = f"{prefix} [*] Show {title} (Count:{count})"
    if status != "ok" or debug:
        line += f" (status:{_safe(status)})"
    if truncated or debug:
        line += f" (truncated:{truncated})"
    return line


def _object_detail(kind: str, row: dict[str, Any], *, debug: bool) -> str:
    """MinIO-style bare object name followed by relevant metadata only."""
    used = {"name"}
    fields: tuple[tuple[str, str], ...]
    if kind == "bindings":
        source = "<default>" if row.get("source") == "" else _safe(row.get("source", "?"))
        destination = (
            "<default>"
            if row.get("destination") == "" and row.get("destination_type") == "exchange"
            else _safe(row.get("destination", "?"))
        )
        label = f"{source} -> {destination}"
        fields = (("vhost", "vhost"), ("destination_type", "type"), ("routing_key", "key"))
        used.update(("source", "destination"))
    elif kind == "nodes":
        label = _safe(row.get("name", "?"))
        fields = (("running", "running"), ("mem_alarm", "memory alarm"), ("disk_free_alarm", "disk alarm"))
        # An offline node may omit its alarms. Missing values are not False.
        row = {"running": "unknown", **row}
        if row.get("partitions"):
            fields += (("partitions", "partitions"),)
    else:
        label = "<default>" if kind == "exchanges" and row.get("name") == "" else _safe(row.get("name", "?"))
        fields = (
            (("vhost", "vhost"), ("type", "type"), ("messages", "messages"), ("consumers", "consumers"))
            if kind == "queues"
            else (("vhost", "vhost"), ("type", "type"))
            if kind == "exchanges"
            else ()
        )
    parts = [label]
    for key, title in fields:
        used.add(key)
        if key in row:
            value = '""' if row[key] == "" else _safe(row[key])
            parts.append(f"({title}:{value})")
    if debug:
        parts.extend(f"({key}:{_safe(value)})" for key, value in row.items() if key not in used)
    return " ".join(parts)


def _format_detail_records(record: dict[str, Any], output_format: str, *, debug: bool = False) -> list[str]:
    if output_format != "txt":
        return []
    prefix = _prefix(record)
    lines = []
    if record.get("anonymous_username"):
        lines.append(
            f"{prefix} [*] Anonymous identity: {_safe(record['anonymous_username'])} "
            f"(admin:{_admin_text(record.get('anonymous_admin'))})"
        )
    # Permission collection remains available in JSON. Regular credential
    # checks use only detect + identity lines; --enum or debug exposes detail.
    if "enumeration" not in record and not debug:
        return lines
    for name in ("permissions", "topic_permissions"):
        if not record.get("show_permissions", True) and not debug:
            continue
        if f"{name}_status" not in record:
            continue
        rows = record.get(name, [])
        status = record[name + "_status"]
        truncated = record.get(name + "_truncated", False)
        if not rows and status == "ok" and not truncated and not debug:
            continue
        lines.append(_section(prefix, name.replace("_", " ").title(), len(rows), status, truncated, debug=debug))
        for row in rows:
            details = " ".join(
                f"({key}:{_safe(row[key])})" for key in ("exchange", "configure", "write", "read") if key in row
            )
            lines.append(f"{prefix} {_safe(row.get('vhost', '?'))} {details}")
    for name, result in record.get("enumeration", {}).items():
        rows = result["items"]
        lines.append(_section(prefix, name.title(), len(rows), result["status"], result["truncated"], debug=debug))
        for row in rows:
            lines.append(f"{prefix} {_object_detail(name, row, debug=debug)}")
    return lines


def _render_colored_rabbitmq_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(
        console,
        line,
        tag="RABBITMQ",
        include_auth_required=False,
        booleans=(
            BooleanColorRule("auth required", true_color="bright_green", false_color="true_red"),
            BooleanColorRule("admin", true_color="true_red", false_color="bright_green"),
            BooleanColorRule("truncated", true_color="yellow", false_color="white"),
        ),
        counts=(CountColorRule("Count", "orange"),),
        regexes=(
            (r"\(status:denied\)", "bright_green"),
            (r"\(status:ok\)", "bright_green"),
            (r"\(status:(?!ok\)|denied\))[^)]+\)", "yellow"),
        ),
    ):
        return True
    return render_tagged_detail_line(
        console,
        line,
        tag="RABBITMQ",
        spans=_detail_spans(line),
        default_color="orange",
        count_pattern_color="white",
        strip_paren_wrappers=False,
    )


def _detail_spans(line: str) -> list[tuple[int, int, str]]:
    """Use MinIO's orange names/white metadata, with permission-specific colors.

    Do not try to prove arbitrary regexes restrictive. Yellow means a custom
    pattern needs review; only known all-resource patterns are colored red.
    Match up to the next field so parentheses inside a regex stay intact.
    """
    payload = line.rsplit("\t", 1)[-1]
    spans: list[tuple[int, int, str]] = []
    for match in re.finditer(r" \(([\w ]+):(.*?)\)(?= \([\w ]+:|$)", payload):
        start, end = match.start() + 1, match.end()
        if match.group(1) in {"running", "memory alarm", "disk alarm"}:
            value = match.group(2)
            good = "True" if match.group(1) == "running" else "False"
            color = "yellow" if value not in {"True", "False"} else "bright_green" if value == good else "true_red"
            spans.append((start, end, color))
            continue
        if match.group(1) not in {"configure", "write", "read"}:
            spans.append((start, end, "white"))
            continue
        value = match.group(2)
        color = "true_red" if value in {".*", "^.*$"} else "bright_green" if value == "" else "yellow"
        spans.extend(((start, start + 1, "white"), (start + 1, end - 1, color), (end - 1, end, "white")))
    return spans
