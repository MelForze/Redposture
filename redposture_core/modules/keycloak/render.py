"""Airflow-style Keycloak TXT and color rendering."""

from __future__ import annotations

import json
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
    public_realms = record.get("public_realms")
    if isinstance(public_realms, list):
        lines.append(f"{prefix} [*] Public Realms Enumeration (realms:{len(public_realms)})")
        lines.extend(f"{prefix} [+] Public Realm Name={name}" for name in public_realms)
    realms = record.get("visible_realms")
    if isinstance(realms, list):
        lines.append(f"{prefix} [*] Realms Enumeration (realms:{len(realms)})")
        settings = {
            item["realm"]: item
            for item in record.get("realm_settings", [])
            if isinstance(item, dict) and isinstance(item.get("realm"), str)
        }
        denied = record.get("realm_settings_access")
        for name in realms:
            config = settings.get(name)
            if config is None:
                lines.append(f"{prefix} [+] Realm Name={name}")
                if record.get("provided_credentials_ok") is True and isinstance(denied, dict) and name in denied:
                    lines.append(f"{prefix} [*] Realm Settings Name={name} (access:{denied[name]})")
                continue
            password_policy = config.get("password_policy")
            policy = (
                json.dumps(password_policy[:160], ensure_ascii=False)
                if isinstance(password_policy, str) and password_policy
                else "none"
                if password_policy == ""
                else "unknown"
            )
            lines.append(
                f"{prefix} [+] Realm Name={name} "
                f"(brute-force protected:{_bool_text(config.get('brute_force_protected'))}) "
                f"(registration allowed:{_bool_text(config.get('registration_allowed'))}) "
                f"(SSL required:{config.get('ssl_required') or 'unknown'}) "
                f"(password policy:{policy})"
            )
    elif record.get("provided_credentials_ok") is True and record.get("realms_access") in {"denied", "unknown"}:
        lines.append(f"{prefix} [*] Realms Enumeration (access:{record['realms_access']})")
    clients = record.get("visible_clients")
    if isinstance(clients, list):
        lines.append(f"{prefix} [*] Clients Enumeration (clients:{len(clients)})")
        settings = {
            f"{item['realm']}/{item['client_id']}": item
            for item in record.get("client_settings", [])
            if isinstance(item, dict) and isinstance(item.get("realm"), str) and isinstance(item.get("client_id"), str)
        }
        for name in clients:
            config = settings.get(name)
            if config is None:
                lines.append(f"{prefix} [+] Client Name={name}")
                continue
            redirects = config.get("redirect_uris")
            origins = config.get("web_origins")
            lines.append(
                f"{prefix} [+] Client Name={name} (type:{config.get('type') or 'unknown'}) "
                f"(direct grants:{_bool_text(config.get('direct_access_grants'))}) "
                f"(implicit:{_bool_text(config.get('implicit_flow'))}) "
                f"(redirect URIs:{_count_text(config.get('redirect_uri_count'), config.get('redirects_truncated'))}) "
                f"(web origins:{_count_text(config.get('web_origin_count'), config.get('origins_truncated'))})"
            )
            if isinstance(redirects, list):
                lines.extend(
                    f"{prefix} [+] Client Redirect URI={json.dumps(value, ensure_ascii=False)} (client:{name})"
                    for value in redirects
                )
            if isinstance(origins, list):
                lines.extend(
                    f"{prefix} [+] Client Web Origin={json.dumps(value, ensure_ascii=False)} (client:{name})"
                    for value in origins
                )
    denied_clients = record.get("clients_access")
    if record.get("provided_credentials_ok") is True and isinstance(denied_clients, dict):
        lines.extend(
            f"{prefix} [*] Clients Name={realm} (access:{status})" for realm, status in sorted(denied_clients.items())
        )
    return lines


def _bool_text(value: Any) -> str:
    return str(value) if isinstance(value, bool) else "unknown"


def _count_text(value: Any, truncated: Any) -> str:
    return f"{value}{'+' if truncated else ''}" if isinstance(value, int) and not isinstance(value, bool) else "unknown"


def _render_colored_keycloak_line(console: Console, line: str) -> bool:
    if render_colored_marker_line(
        console,
        line,
        tag="KEYCLOAK",
        include_auth_required=False,
        booleans=(
            BooleanColorRule("auth required", true_color="bright_green", false_color="true_red"),
            BooleanColorRule("brute-force protected", true_color="bright_green", false_color="true_red"),
            BooleanColorRule("registration allowed", true_color="true_red", false_color="bright_green"),
            BooleanColorRule("direct grants", true_color="true_red", false_color="bright_green"),
            BooleanColorRule("implicit", true_color="true_red", false_color="bright_green"),
        ),
        regexes=(
            RegexColorRule(r"\((?:realms|clients|redirect URIs|web origins):0\)", "bright_green"),
            RegexColorRule(r"\((?:realms|clients|redirect URIs|web origins):[1-9]\d*\+?\)", "true_red"),
            RegexColorRule(r"\(auth required:unknown\)", "orange"),
            RegexColorRule(
                r"\((?:brute-force protected|registration allowed|direct grants|implicit):unknown\)", "orange"
            ),
            RegexColorRule(r"\(SSL required:all\)", "bright_green"),
            RegexColorRule(r"\(SSL required:external\)", "orange"),
            RegexColorRule(r"\(SSL required:none\)", "true_red"),
            RegexColorRule(r"\(SSL required:unknown\)", "orange"),
            RegexColorRule(r"\(password policy:none\)", "true_red"),
            RegexColorRule(r"\(password policy:unknown\)", "orange"),
            RegexColorRule(r'\(password policy:"(?:\\.|[^"\\])*"\)', "orange"),
            RegexColorRule(r"\(type:(?:public|confidential|bearer-only|unknown)\)", "orange"),
            RegexColorRule(r"\(access:denied\)", "bright_green"),
            RegexColorRule(r"\(access:unknown\)", "orange"),
            RegexColorRule(r"\(realm:[^)]+\)", "orange"),
            RegexColorRule(r"\((?:realms|clients|redirect URIs|web origins):unknown\)", "orange"),
        ),
        extra_spans=lambda marker, payload: (
            [(0, payload.find(" ("), "orange")]
            if marker == "[+]" and payload.startswith(("Realm Name=", "Client Name=")) and " (" in payload
            else [(0, len(payload), "orange")]
            if marker == "[+]"
            and payload.startswith(
                ("Realm Name=", "Client Name=", "Public Realm Name=", "Client Redirect URI=", "Client Web Origin=")
            )
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
