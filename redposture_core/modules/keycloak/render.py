"""Airflow-style Keycloak TXT and color rendering."""

from __future__ import annotations

from typing import Any

from ...auth_detection import auth_required_text
from ...console import Console
from ...rendering import BooleanColorRule, RegexColorRule, render_colored_marker_line, render_tagged_detail_line


def _prefix(record: dict[str, Any]) -> str:
    return f"KEYCLOAK\t{record.get('host') or '?'}\t{int(record.get('port') or 0)}\t"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    if output_format != "txt" or record.get("is_keycloak") is not True:
        return ""
    auth = auth_required_text(record.get("auth_required"), None)
    version = str(record.get("version") or "-")
    realm = str(record.get("detected_realm") or "-")
    return f"{_prefix(record)} [*] Keycloak (auth required:{auth}) (realm:{realm}) (version:{version})"


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format != "txt":
        return ""
    if record.get("provided_credentials_ok") is True:
        return f"{_prefix(record)} [+] Bearer token accepted"
    if record.get("credential_state") == "invalid":
        return f"{_prefix(record)} [-] Bearer token rejected"
    return ""


def _format_inventory_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []
    prefix = _prefix(record)
    lines: list[str] = []
    realms = record.get("visible_realms")
    if isinstance(realms, list):
        lines.append(f"{prefix} [*] Realms Enumeration (realms:{len(realms)})")
        lines.extend(f"{prefix} [+] Realm Name={name}" for name in realms)
    clients = record.get("visible_clients")
    if isinstance(clients, list):
        lines.append(f"{prefix} [*] Clients Enumeration (clients:{len(clients)})")
        lines.extend(f"{prefix} [+] Client Name={name}" for name in clients)
    return lines


def _render_colored_keycloak_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(
        console,
        line,
        tag="KEYCLOAK",
        include_auth_required=False,
        booleans=(BooleanColorRule("auth required", true_color="bright_green", false_color="true_red"),),
        regexes=(
            RegexColorRule(r"\((?:realms|clients):0\)", "bright_green"),
            RegexColorRule(r"\((?:realms|clients):[1-9]\d*\)", "true_red"),
            RegexColorRule(r"\(auth required:unknown\)", "orange"),
        ),
        extra_spans=lambda marker, payload: (
            [(0, len(payload), "orange")]
            if marker == "[+]" and payload.startswith(("Realm Name=", "Client Name="))
            else [(0, len(payload), "true_red")]
            if marker == "[+]" and payload == "Bearer token accepted"
            else []
        ),
    ):
        return True
    if line.startswith("KEYCLOAK") and "\t" in line:
        return render_tagged_detail_line(console, line, tag="KEYCLOAK", default_color="white")
    return False


__all__ = ["_format_detect_record", "_format_record", "_format_inventory_records", "_render_colored_keycloak_line"]
