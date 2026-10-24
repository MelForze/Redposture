"""Airflow-style Vault output with distinct verified and unknown states."""

from __future__ import annotations

from typing import Any

from ...auth_detection import auth_required_text
from ...console import Console
from ...discovery_rendering import discovery_color_spans
from ...rendering import BooleanColorRule, RegexColorRule, render_colored_marker_line, render_tagged_detail_line
from ..token_render import aligned_line


def _prefix(record: dict[str, Any]) -> str:
    return f"VAULT\t{record.get('host') or '?'}\t{int(record.get('port') or 0)}\t"


def _format_detect_record(record: dict[str, Any], output_format: str) -> str:
    if output_format != "txt" or record.get("is_vault") is not True:
        return ""
    auth = auth_required_text(record.get("auth_required"), None)
    line = f"{_prefix(record)} [*] HashiCorp Vault"
    if auth != "unknown":
        line += f" (auth required:{auth})"
    line += (
        f" (initialized:{record.get('initialized')}) (sealed:{record.get('sealed')}) (standby:{record.get('standby')})"
    )
    if record.get("version"):
        line += f" (version:{record['version']})"
    return line


def _format_record(record: dict[str, Any], output_format: str) -> str:
    if output_format != "txt":
        return ""
    if record.get("token_valid") is True:
        policies = record.get("token_policies") or []
        return (
            f"{_prefix(record)} [+] Vault token accepted "
            f"(policies:{len(policies)}) (TTL:{record.get('token_ttl') if record.get('token_ttl') is not None else 'unknown'})"
        )
    if record.get("token_valid") is False:
        return f"{_prefix(record)} [-] Vault token rejected"
    if record.get("credential_state") == "unverified":
        return f"{_prefix(record)} [*] Vault token verification unavailable"
    return ""


def _format_inventory_records(record: dict[str, Any], output_format: str) -> list[str]:
    if output_format != "txt":
        return []
    prefix = _prefix(record)
    lines: list[str] = []
    if record.get("init_takeover_possible") is True:
        lines.append(f"{prefix} [!] Initialization possible (Vault not initialized)")
    if record.get("weak_token_accepted") is True:
        lines.append(f"{prefix} [!] Common development token accepted (dev mode unverified)")
    if "mounts" in (record.get("inventory_requested") or []):
        mounts = record.get("mounts")
        count = len(mounts) if isinstance(mounts, list) else record.get("mounts_count")
        count = count if type(count) is int and count >= 0 else "unknown"
        access = record.get("mounts_access") or "unknown"
        lines.append(f"{prefix} [*] Secret Engines (access:{access}) (mounts:{count})")
        if isinstance(mounts, list):
            lines.extend(
                f"{prefix} [+] Mount Path={item['path']} (type:{item.get('type') or 'unknown'})" for item in mounts
            )
    if "auth" in (record.get("inventory_requested") or []):
        methods = record.get("auth_methods")
        access = record.get("auth_methods_access") or "unknown"
        lines.append(
            f"{prefix} [*] Auth Methods (access:{access}) (methods:{len(methods) if isinstance(methods, list) else 'unknown'})"
        )
        if isinstance(methods, list):
            lines.extend(
                f"{prefix} [+] Auth Path={item['path']} (type:{item.get('type') or 'unknown'})" for item in methods
            )
    if "kv_secrets_read" in record:
        status = "partial" if record.get("kv_discovery_partial") else "complete"
        lines.append(f"{prefix} [*] KV Read (status:{status}) (secrets:{record['kv_secrets_read']})")
    return lines


def _render_colored_vault_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(
        console,
        aligned_line(line),
        tag="VAULT",
        include_auth_required=False,
        booleans=(
            BooleanColorRule("auth required", true_color="bright_green", false_color="true_red"),
            BooleanColorRule("initialized", true_color="bright_green", false_color="true_red"),
            BooleanColorRule("sealed", true_color="bright_green", false_color="orange"),
        ),
        regexes=(
            RegexColorRule(r"\((?:mounts|methods|secrets|policies):0\)", "bright_green"),
            RegexColorRule(r"\((?:mounts|methods|secrets|policies):[1-9]\d*\)", "true_red"),
            RegexColorRule(r"\(access:allowed\)", "true_red"),
            RegexColorRule(r"\(access:denied\)", "bright_green"),
            RegexColorRule(r"\((?:access|version|TTL):unknown\)", "orange"),
            RegexColorRule(r"\(standby:(?:True|False)\)", "orange"),
            RegexColorRule(r"\(type:[^)]+\)", "orange"),
            RegexColorRule(r"\(version:[^)]+\)", "orange"),
            RegexColorRule(r"Vault token verification unavailable", "orange"),
        ),
        extra_spans=lambda marker, payload: [
            *discovery_color_spans(marker, payload),
            *(
                [(0, len(payload), "true_red")]
                if marker == "[!]" and not payload.startswith("CVE-")
                else [(0, len("Vault token accepted"), "true_red")]
                if payload.startswith("Vault token accepted")
                else [(0, len(payload), "bright_green")]
                if payload == "Vault token rejected"
                else [(0, len(payload), "orange")]
                if marker == "[+]"
                else []
            ),
        ],
    ):
        return True
    if line.startswith("VAULT") and "\t" in line:
        return render_tagged_detail_line(console, line, tag="VAULT", default_color="white")
    return False


__all__ = ["_format_detect_record", "_format_record", "_format_inventory_records", "_render_colored_vault_line"]
