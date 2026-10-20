"""TXT/JSON rendering and terminal coloring for the Airflow module.

House convention (see minio/clickhouse): `_format_detect_record` (one-line detect
summary), `_format_record` (accepted-credential line), and
`_format_credential_attempts_records` (every `--defcreds` attempt). Coloring goes
through the shared declarative helpers; JSON is produced from the record, so the
renderers emit nothing for `json`.
"""

from __future__ import annotations

import json
from typing import Any

from ...auth_detection import auth_required_text
from ...console import Console
from ...discovery_rendering import discovery_color_spans, format_discovery_finding_line
from ...rendering import (
    BooleanColorRule,
    LiteralColorRule,
    RegexColorRule,
    render_colored_marker_line,
    render_tagged_detail_line,
)

_UNDETECTED = {"probable", "not_airflow", "not_service", "transport_failure", ""}
_AUTHENTICATED_RESOURCES = ("Dags", "Keys", "Connections")


def _prefix(record: dict[str, Any]) -> str:
    return f"AIRFLOW\t{record.get('host') or '?'}\t{int(record.get('port') or 0)}\t"


def _password_text(password: Any) -> str:
    if password is None:
        return "<no-password>"
    if password == "":
        return "<empty>"
    return str(password)


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    """Show validated anonymous collection access before credential checks."""
    if output_format != "txt":
        return ""
    if str(record.get("detection_status") or "") in _UNDETECTED:
        return ""
    auth_text = auth_required_text(record.get("auth_required"), record.get("auth_method"))
    line = f"{_prefix(record)} [*] Airflow (auth required:{auth_text})"
    for label, key in (
        ("Dags allowed", "dags_allowed"),
        ("Keys allowed", "keys_allowed"),
        ("Connections allowed", "connections_allowed"),
    ):
        allowed = record.get(key)
        line += f" ({label}:{allowed if isinstance(allowed, bool) else 'unknown'})"
    if auth_text == "sso" and record.get("sso_provider"):
        line += f" (provider:{record['sso_provider']})"
    if record.get("version"):
        line += f" (version:{record['version']})"
    return line


def _access_text(record: dict[str, Any], resource: str) -> str:
    key = resource.lower()
    status = str(record.get(f"authenticated_{key}_access") or "unknown")
    count = record.get(f"authenticated_{key}_count")
    if status == "allowed" and isinstance(count, int) and not isinstance(count, bool) and count >= 0:
        return str(count)
    if status == "denied":
        return "Access Denied"
    return "Unknown"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    """Accepted credential plus validated collection access and exact counts."""
    if output_format != "txt":
        return ""
    if str(record.get("credential_state") or "") not in {"valid", "valid_but_restricted"}:
        return ""
    # Auth and capability checks are separate runtime phases. Waiting for the
    # resource probes prevents an early bare credential line followed by the
    # same credential a second time with access counts.
    if record.get("_credential_capabilities_pending"):
        return ""
    results = record.get("credential_results") or []
    username = results[0].get("username") if results and isinstance(results[0], dict) else None
    # The password is echoed like zookeeper's `user:pass` line (kept out of JSON via
    # structured_output_redact_fields).
    password = record.get("credential_password")
    cred = f"{username or '?'}:{password}" if password is not None else f"{username or '?'}"
    suffix = "".join(f" ({resource}:{_access_text(record, resource)})" for resource in _AUTHENTICATED_RESOURCES)
    return f"{_prefix(record)} [+] {cred}{suffix}"


def _format_credential_attempts_records(record: dict[str, Any], output_format: str) -> list[str]:
    """Show each attempted pair once, distinguishing rejection from uncertainty."""
    if output_format != "txt":
        return []
    attempts = record.get("attempted_credentials")
    if not isinstance(attempts, list) or not attempts:
        state = str(record.get("credential_state") or "")
        results = record.get("credential_results") or []
        if state in {"valid", "valid_but_restricted", ""} or not results or not isinstance(results[0], dict):
            return []
        if "credential_password" not in record:
            return []
        attempts = [
            {
                "username": results[0].get("username"),
                "password": record["credential_password"],
                "credential_state": state,
            }
        ]
    prefix = _prefix(record)
    results = record.get("credential_results") or []
    selected = results[0].get("username") if results and isinstance(results[0], dict) else None
    winner_skipped = False
    lines: list[str] = []
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        username = str(attempt.get("username") or "")
        accepted = str(attempt.get("credential_state") or "") in {"valid", "valid_but_restricted"}
        if accepted and not winner_skipped and username == selected:
            winner_skipped = True
            continue
        # Show the password on both outcomes: several defaults can share a
        # username, so the operator needs the exact working pair, not just that
        # some default worked. Mirrors _format_record and the other cred modules.
        pair = f"{username}:{_password_text(attempt.get('password'))}"
        if accepted:
            lines.append(f"{prefix} [+] {pair}")
        elif str(attempt.get("credential_state") or "") == "invalid":
            lines.append(f"{prefix} [-] {pair}")
        # A proxy or SSO page that did not verify the pair is diagnostic
        # evidence, not a credential result in the normal TXT report.
    return lines


def _format_discover_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt" or not record.get("discover_requested"):
        return []
    report = record.get("discover_report")
    if not isinstance(report, dict):
        return []
    status = str(report.get("status") or "unavailable")
    raw_findings = report.get("findings")
    findings: list[Any] = raw_findings if isinstance(raw_findings, list) else []
    finding_count = len(findings)
    prefix = _prefix(record)
    summary_label = "Discover Complete" if record.get("_discover_findings_streamed") else "Discover Secrets"
    lines: list[str] = []
    if record.get("_discover_findings_streamed"):
        findings = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        place = str(finding.get("place") or _legacy_log_place(finding))
        lines.append(
            format_discovery_finding_line(
                "AIRFLOW",
                record.get("host"),
                record.get("port"),
                severity=finding.get("confidence"),
                finding_type=finding.get("type"),
                value=finding.get("value") or finding.get("masked_value"),
                place=place,
            )
        )
    lines.append(f"{prefix} [*] {summary_label} (status:{status}) (findings:{finding_count})")
    reasons = report.get("partial_reasons")
    if isinstance(reasons, list) and reasons:
        lines.append(f"{prefix} [!] Discover {status}: {','.join(str(item) for item in reasons)}")
    return lines


def _legacy_log_place(finding: dict[str, Any]) -> str:
    return (
        f"{finding.get('dag_id', '?')}/{finding.get('dag_run_id', '?')}/"
        f"{finding.get('task_id', '?')}/try:{finding.get('try_number', '?')}"
        f"/map:{finding.get('map_index', -1)}{finding.get('object_path', '$')}"
    )


def _format_show_keys_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt" or not record.get("show_keys_requested") or record.get("_show_keys_streamed"):
        return []
    prefix = _prefix(record)
    raw_keys = record.get("variable_keys")
    keys = [str(item) for item in raw_keys] if isinstance(raw_keys, list) else []
    error = record.get("variable_keys_error")
    if not isinstance(raw_keys, list) and not error:
        return []
    if error:
        if str(error) in {"http_401", "http_403", "authentication_required"} and record.get("auth_required") is True:
            return []
        return [f"{prefix} [-] Airflow Variable Keys unavailable: {error}"]
    lines = [f"{prefix} [*] Airflow Variable Keys (keys:{len(keys)})"]
    lines.extend(f"{prefix} [+] Variable Name={json.dumps(key, ensure_ascii=False)}" for key in keys)
    return lines


def _format_show_dags_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt" or not record.get("show_dags_requested"):
        return []
    prefix = _prefix(record)
    raw_dags = record.get("dag_ids")
    error = record.get("dag_ids_error")
    if not isinstance(raw_dags, list) and not error:
        return []
    dags = [str(item) for item in raw_dags] if isinstance(raw_dags, list) else []
    if error and not dags:
        if str(error) in {"http_401", "http_403", "authentication_required"} and record.get("auth_required") is True:
            return []
        return [f"{prefix} [-] Airflow DAGs unavailable: {error}"]
    lines = [f"{prefix} [*] Airflow DAGs (dags:{len(dags)})"]
    lines.extend(f"{prefix} [+] DAG Id={json.dumps(dag, ensure_ascii=False)}" for dag in dags)
    # A requested --show-dags N limit is not an incomplete API read. The
    # collector retains dag_ids_truncated for JSON callers, while TXT reports
    # partial coverage only when a page actually failed.
    if error:
        lines.append(f"{prefix} [*] Airflow DAGs coverage:partial")
    return lines


def _format_show_connections_records(record: dict[str, Any], output_format: str) -> list[str]:
    if (
        output_format != "txt"
        or not record.get("show_connections_requested")
        or record.get("_show_connections_streamed")
    ):
        return []
    prefix = _prefix(record)
    raw_connections = record.get("airflow_connections")
    connections = (
        [item for item in raw_connections if isinstance(item, dict)] if isinstance(raw_connections, list) else []
    )
    error = record.get("connections_error")
    if not isinstance(raw_connections, list) and not error:
        return []
    if error:
        if str(error) in {"http_401", "http_403", "authentication_required"} and record.get("auth_required") is True:
            return []
        return [f"{prefix} [-] Airflow Connections unavailable: {error}"]
    lines = [f"{prefix} [*] Airflow Connections (connections:{len(connections)})"]
    for connection in connections:
        connection_id = connection.get("connection_id") or connection.get("conn_id") or "?"
        encoded_id = json.dumps(str(connection_id), ensure_ascii=False)
        encoded_value = json.dumps(connection, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        lines.append(f"{prefix} [+] Connection Id={encoded_id} Value={encoded_value}")
    return lines


def _format_dump_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt" or not record.get("dump_requested"):
        return []
    report = record.get("dump_report")
    if not isinstance(report, dict):
        return []
    prefix = _prefix(record)
    records = report.get("records")
    entries = [item for item in records if isinstance(item, dict)] if isinstance(records, list) else []
    status = str(report.get("status") or "unavailable")
    lines = [f"{prefix} [*] Airflow Dump (status:{status}) (records:{len(entries)})"]
    for entry in entries:
        kind = str(entry.get("kind") or "unknown")
        object_id = json.dumps(str(entry.get("id") or ""), ensure_ascii=False)
        value = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        lines.append(f"{prefix} [+] {kind} Id={object_id} Value={value}")
    reasons = report.get("partial_reasons")
    if isinstance(reasons, list) and reasons:
        lines.append(f"{prefix} [*] Airflow Dump coverage:partial reasons={json.dumps(reasons, ensure_ascii=False)}")
    return lines


def _format_grouped_inventory_records(record: dict[str, Any], output_format: str) -> list[str]:
    """Attach DAG/variable/connection dump values to their inventory rows."""
    sections = (
        (_format_show_dags_records, "dag", record.get("dag_ids"), lambda item: str(item)),
        (_format_show_keys_records, "variable", record.get("variable_keys"), lambda item: str(item)),
        (
            _format_show_connections_records,
            "connection",
            record.get("airflow_connections"),
            lambda item: str(item.get("connection_id") or item.get("conn_id") or "") if isinstance(item, dict) else "",
        ),
    )
    if output_format != "txt" or (record.get("discover_requested") and not record.get("dump_requested")):
        return [
            line for formatter, *_rest in sections for line in formatter(record, output_format)
        ] + _format_dump_records(record, output_format)
    report = record.get("dump_report")
    entries = report.get("records") if isinstance(report, dict) else None
    if not isinstance(entries, list) or not entries:
        return [
            line for formatter, *_rest in sections for line in formatter(record, output_format)
        ] + _format_dump_records(record, output_format)
    dump_lines = _format_dump_records(record, output_format)
    lines: list[str] = []
    dump_heading_pending = dump_lines[:1]
    emitted: set[int] = set()
    by_resource: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = {}
    for index, entry in enumerate(entries):
        if isinstance(entry, dict):
            by_resource.setdefault((str(entry.get("kind") or ""), str(entry.get("id") or "")), []).append(
                (index, entry)
            )

    def append_entry(entry: dict[str, Any]) -> None:
        if dump_heading_pending:
            lines.extend(dump_heading_pending)
            dump_heading_pending.clear()
        kind = str(entry.get("kind") or "unknown")
        object_id = json.dumps(str(entry.get("id") or ""), ensure_ascii=False)
        value = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        lines.append(f"{_prefix(record)} [+] {kind} Id={object_id} Value={value}")

    for formatter, kind, raw_items, identity in sections:
        rendered = formatter(record, output_format)
        if not rendered:
            continue
        if not isinstance(raw_items, list) or not rendered[0].split("\t")[-1].startswith(" [*]"):
            lines.extend(rendered)
            continue
        lines.append(rendered[0])
        for row_line, item in zip(rendered[1:], raw_items, strict=False):
            lines.append(row_line)
            for index, entry in by_resource.get((kind, identity(item)), []):
                if index not in emitted:
                    append_entry(entry)
                    emitted.add(index)
        lines.extend(rendered[1 + len(raw_items) :])
    for index, entry in enumerate(entries):
        if index not in emitted and isinstance(entry, dict):
            append_entry(entry)
    lines.extend(dump_lines[1 + len(entries) :])
    return lines


def _console_aligned_line(line: str) -> str:
    """Align Airflow console columns while keeping stored TXT records as TSV."""

    parts = line.split("\t", 3)
    if len(parts) != 4 or parts[0] != "AIRFLOW":
        return line
    tag, host, port, payload = parts
    return f"{tag:<15} {host:<15} {port:<7}{payload}"


def _render_colored_airflow_line(console: Console, line: str) -> bool:
    console_line = _console_aligned_line(line)
    if render_colored_marker_line(
        console,
        console_line,
        tag="AIRFLOW",
        include_auth_required=False,
        booleans=(
            # auth required:True == server enforces auth (good) -> green;
            # False == open/anonymous (exposure) -> red.
            BooleanColorRule("auth required", true_color="bright_green", false_color="true_red"),
            BooleanColorRule("Dags allowed", true_color="true_red", false_color="bright_green"),
            BooleanColorRule("Keys allowed", true_color="true_red", false_color="bright_green"),
            BooleanColorRule("Connections allowed", true_color="true_red", false_color="bright_green"),
        ),
        literals=(
            LiteralColorRule("auth required:sso", "bright_green"),
            LiteralColorRule("provider:keycloak", "cyan"),
        ),
        regexes=(
            RegexColorRule(r"\(keys:0\)", "bright_green"),
            RegexColorRule(r"\(keys:[1-9]\d*\)", "true_red"),
            RegexColorRule(r"\(connections:0\)", "bright_green"),
            RegexColorRule(r"\(connections:[1-9]\d*\)", "true_red"),
            RegexColorRule(r"\(dags:0\)", "bright_green"),
            RegexColorRule(r"\(dags:[1-9]\d*\)", "true_red"),
            RegexColorRule(r"\(records:0\)", "bright_green"),
            RegexColorRule(r"\(records:[1-9]\d*\)", "true_red"),
            RegexColorRule(r"\(status:(?:partial|unavailable)\)", "orange"),
            RegexColorRule(r"coverage:partial", "orange"),
            *(
                rule
                for resource in _AUTHENTICATED_RESOURCES
                for rule in (
                    RegexColorRule(rf"\({resource}:\d+\)", "true_red"),
                    RegexColorRule(rf"\({resource}:Access Denied\)", "bright_green"),
                    RegexColorRule(rf"\({resource}:Unknown\)", "orange"),
                )
            ),
        ),
        extra_spans=lambda marker, payload: [
            *discovery_color_spans(marker, payload),
            *(
                [(0, len(payload), "orange")]
                if marker == "[+]"
                and payload.startswith(
                    ("Variable Name=", "Connection Id=", "DAG Id=", "dag Id=", "variable Id=", "connection Id=")
                )
                else []
            ),
        ],
    ):
        return True
    if line.startswith("AIRFLOW") and "\t" in line:
        return render_tagged_detail_line(console, line, tag="AIRFLOW", default_color="white")
    return False


__all__ = [
    "_format_detect_record",
    "_format_record",
    "_format_credential_attempts_records",
    "_format_grouped_inventory_records",
    "_format_discover_records",
    "_render_colored_airflow_line",
]
