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

_UNDETECTED = {"not_airflow", "transport_failure", ""}
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
    """`[*] Airflow (auth required:X) (Dags allowed anonymously:Y) [(version:Z)]`."""
    if output_format != "txt":
        return ""
    if str(record.get("detection_status") or "") in _UNDETECTED:
        return ""
    auth_text = auth_required_text(record.get("auth_required"), record.get("auth_method"))
    line = f"{_prefix(record)} [*] Airflow (auth required:{auth_text})"
    dags_allowed = record.get("dags_allowed")
    dags_text = str(dags_allowed) if isinstance(dags_allowed, bool) else "unknown"
    line += f" (Dags allowed anonymously:{dags_text})"
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
    """Per-credential lines for `--defcreds`: rejected `[-] user:pass`, other-accepted
    `[+] user`; the winner is rendered by `_format_record` and skipped here."""
    if output_format != "txt":
        return []
    attempts = record.get("attempted_credentials")
    if not isinstance(attempts, list) or len(attempts) < 2:
        return []
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
        if accepted:
            lines.append(f"{prefix} [+] {username}:{_password_text(attempt.get('password'))}")
        else:
            lines.append(f"{prefix} [-] {username}:{_password_text(attempt.get('password'))}")
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
    prefix = _prefix(record)
    summary_label = "Discover Complete" if record.get("_discover_findings_streamed") else "Discover Secrets"
    lines = [f"{prefix} [*] {summary_label} (status:{status}) (findings:{len(findings)})"]
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
    if output_format != "txt" or not record.get("show_keys_requested"):
        return []
    prefix = _prefix(record)
    raw_keys = record.get("variable_keys")
    keys = [str(item) for item in raw_keys] if isinstance(raw_keys, list) else []
    error = record.get("variable_keys_error")
    if not isinstance(raw_keys, list) and not error:
        return []
    if error:
        return [f"{prefix} [-] Airflow Variable Keys unavailable: {error}"]
    lines = [f"{prefix} [*] Airflow Variable Keys (keys:{len(keys)})"]
    lines.extend(f"{prefix} [+] Variable Name={json.dumps(key, ensure_ascii=False)}" for key in keys)
    return lines


def _format_show_connections_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt" or not record.get("show_connections_requested"):
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
        return [f"{prefix} [-] Airflow Connections unavailable: {error}"]
    lines = [f"{prefix} [*] Airflow Connections (connections:{len(connections)})"]
    for connection in connections:
        connection_id = connection.get("connection_id") or connection.get("conn_id") or "?"
        encoded_id = json.dumps(str(connection_id), ensure_ascii=False)
        encoded_value = json.dumps(connection, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        lines.append(f"{prefix} [+] Connection Id={encoded_id} Value={encoded_value}")
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
            BooleanColorRule("Dags allowed anonymously", true_color="true_red", false_color="bright_green"),
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
                if marker == "[+]" and payload.startswith(("Variable Name=", "Connection Id="))
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
    "_format_discover_records",
    "_format_show_connections_records",
    "_format_show_keys_records",
    "_render_colored_airflow_line",
]
