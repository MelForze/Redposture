"""TXT/JSON rendering and terminal coloring for the Airflow module.

House convention (see minio/clickhouse): `_format_detect_record` (one-line detect
summary), `_format_record` (accepted-credential line), and
`_format_credential_attempts_records` (every `--defcreds` attempt). Coloring goes
through the shared declarative helpers; JSON is produced from the record, so the
renderers emit nothing for `json`.
"""

from __future__ import annotations

import re
from typing import Any

from ...console import Console
from ...rendering import BooleanColorRule, render_colored_marker_line, render_tagged_detail_line

_UNDETECTED = {"not_airflow", "transport_failure", ""}
# admin/op are exposure -> red/yellow; viewer/none benign -> green; unknown -> yellow.
_ROLE_COLOR = {"admin": "true_red", "op": "yellow", "viewer": "bright_green", "none": "bright_green"}
_ROLE_RE = re.compile(r"\((anon|role):([a-z]+)\)")


def _prefix(record: dict[str, Any]) -> str:
    return f"AIRFLOW\t{record.get('host') or '?'}\t{int(record.get('port') or 0)}\t"


def _bool_text(value: Any) -> str:
    return "True" if value is True else "False" if value is False else "unknown"


def _password_text(password: Any) -> str:
    if password is None:
        return "<no-password>"
    if password == "":
        return "<empty>"
    return str(password)


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    """`[*] Airflow (auth required:X) [(anon:role)] [(version:Y)]`."""
    if output_format != "txt":
        return ""
    if str(record.get("detection_status") or "") in _UNDETECTED:
        return ""
    line = f"{_prefix(record)} [*] Airflow (auth required:{_bool_text(record.get('auth_required'))})"
    if record.get("auth_required") is False and record.get("anonymous_role") not in (None, "none", "unknown"):
        line += f" (anon:{record['anonymous_role']})"
    if record.get("version"):
        line += f" (version:{record['version']})"
    return line


def _format_record(record: dict[str, Any], output_format: str) -> str:
    """Accepted-credential line `[+] user:pass (role:X)`."""
    if output_format != "txt":
        return ""
    if str(record.get("credential_state") or "") not in {"valid", "valid_but_restricted"}:
        return ""
    results = record.get("credential_results") or []
    username = results[0].get("username") if results and isinstance(results[0], dict) else None
    # The password is echoed like zookeeper's `user:pass` line (kept out of JSON via
    # structured_output_redact_fields).
    password = record.get("credential_password")
    cred = f"{username or '?'}:{password}" if password is not None else f"{username or '?'}"
    role = record.get("role")
    suffix = f" (role:{role})" if role else ""
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


def _airflow_role_spans(_marker: str, payload: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for match in _ROLE_RE.finditer(payload):
        color = _ROLE_COLOR.get(match.group(2), "yellow")
        spans.append((match.start(1), match.end(2), color))  # color `anon:admin` / `role:op`
    return spans


def _render_colored_airflow_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(
        console,
        line,
        tag="AIRFLOW",
        include_auth_required=False,
        booleans=(
            # auth required:True == server enforces auth (good) -> green;
            # False == open/anonymous (exposure) -> red.
            BooleanColorRule("auth required", true_color="bright_green", false_color="true_red"),
        ),
        extra_spans=_airflow_role_spans,
    ):
        return True
    if line.startswith("AIRFLOW") and "\t" in line:
        return render_tagged_detail_line(console, line, tag="AIRFLOW", default_color="white")
    return False


__all__ = [
    "_format_detect_record",
    "_format_record",
    "_format_credential_attempts_records",
    "_render_colored_airflow_line",
]
