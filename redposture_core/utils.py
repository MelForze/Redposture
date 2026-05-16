"""General utility helpers."""

from __future__ import annotations

import base64
import os
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone

from .constants import HTTP_METHOD_PREFIXES
from .scheduler import BoundedScheduler
from .targeting import (
    ScanExecutionGroup,
    ScanTargetSpec,
    TargetParsePolicy,
    build_scan_execution_groups,
    collect_scan_ports,
    collect_scan_target_specs,
    collect_scan_targets,
    normalize_ip_literal,
    normalize_scan_host,
    parse_scan_target_specs,
)

__all__ = [
    "ScanExecutionGroup",
    "ScanTargetSpec",
    "TargetParsePolicy",
    "UsernamePasswordCredential",
    "build_scan_execution_groups",
    "collect_scan_ports",
    "collect_scan_target_specs",
    "collect_scan_targets",
    "filter_open_tcp_hosts_for_credential_file",
    "is_http_inline_command",
    "is_http_request_prefix",
    "is_signature_compat_typeerror",
    "normalize_ip_literal",
    "normalize_scan_host",
    "parse_scan_target_specs",
    "parse_basic_auth",
    "parse_proxmox_api_token_auth",
    "parse_username_password_credential_file",
    "prometheus_label_escape",
    "safe_decode",
    "utc_now_iso",
]

_UNEXPECTED_KWARG_RE = re.compile(r"(?:got an )?unexpected keyword argument ['\"](?P<kw>[^'\"]+)['\"]")


@dataclass(frozen=True)
class UsernamePasswordCredential:
    username: str
    password: str
    source: str = "file"


def parse_username_password_credential_file(
    username_value: str | None,
    password_value: str | None,
) -> list[UsernamePasswordCredential] | None:
    """Parse -u/--username as a credential file when it points to an existing file."""

    raw_username = str(username_value or "").strip()
    if not raw_username or not os.path.isfile(raw_username):
        return None

    entries: list[tuple[str, str | None]] = []
    has_colon = False
    has_plain = False
    with open(raw_username, encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            if ":" in line:
                has_colon = True
                user, secret = line.split(":", 1)
                user = user.strip()
                if not user:
                    raise ValueError(f"{raw_username}:{line_no}: username must not be empty")
                entries.append((user, secret.strip()))
            else:
                has_plain = True
                user = line.strip()
                if not user:
                    raise ValueError(f"{raw_username}:{line_no}: username must not be empty")
                entries.append((user, None))

    if not entries:
        raise ValueError(f"{raw_username}: credential file is empty")
    if has_colon and has_plain:
        raise ValueError(f"{raw_username}: mixed username and username:password formats are not supported")
    if has_colon and password_value is not None:
        raise ValueError("-p/--password cannot be combined with username:password credential file")
    if has_plain and password_value is None:
        raise ValueError("-p/--password is required when -u points to a username-only file")

    shared_password = "" if password_value is None else str(password_value)
    result: list[UsernamePasswordCredential] = []
    seen: set[tuple[str, str]] = set()
    for username, password in entries:
        secret = shared_password if password is None else password
        key = (username, secret)
        if key in seen:
            continue
        seen.add(key)
        result.append(UsernamePasswordCredential(username=username, password=secret))
    return result


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_decode(value: bytes | None) -> str | None:
    if value is None:
        return None
    return value.decode("utf-8", errors="replace")


def parse_basic_auth(header_value: str | None) -> tuple[str | None, str | None]:
    if not header_value:
        return None, None
    if not header_value.lower().startswith("basic "):
        return None, None

    encoded = header_value.split(" ", 1)[1].strip()
    try:
        decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
    except Exception:
        return None, None

    if ":" in decoded:
        username, password = decoded.split(":", 1)
    else:
        username, password = decoded, ""
    return username, password


def parse_proxmox_api_token_auth(header_value: str | None) -> tuple[str | None, str | None]:
    if not header_value:
        return None, None
    raw = header_value.strip()
    if not raw:
        return None, None

    prefix_eq = "PVEAPIToken="
    prefix_sp = "PVEAPIToken "
    if raw.startswith(prefix_eq):
        token_blob = raw[len(prefix_eq) :].strip()
    elif raw.startswith(prefix_sp):
        token_blob = raw[len(prefix_sp) :].strip()
    else:
        return None, None

    if not token_blob:
        return None, None
    if "=" in token_blob:
        token_id, token_secret = token_blob.split("=", 1)
    else:
        token_id, token_secret = token_blob, ""
    token_id = token_id.strip()
    return (token_id or None), token_secret


def is_signature_compat_typeerror(
    exc: TypeError,
    *,
    expected_keywords: set[str] | list[str] | tuple[str, ...],
    allow_positional_mismatch: bool = False,
) -> bool:
    """Return True only for expected wrapper-compat TypeError keyword mismatches."""

    message = str(exc or "")
    if not message:
        return False
    if allow_positional_mismatch and ("positional argument" in message or "positional arguments" in message):
        return True
    match = _UNEXPECTED_KWARG_RE.search(message)
    if match is None:
        return False
    keyword = str(match.group("kw") or "").strip()
    if not keyword:
        return False
    return keyword in set(expected_keywords)


def is_http_request_prefix(data: bytes) -> bool:
    return any(data.startswith(prefix) for prefix in HTTP_METHOD_PREFIXES)


def is_http_inline_command(command: list[str]) -> bool:
    if len(command) < 3:
        return False
    method = command[0].upper().encode("ascii", errors="ignore") + b" "
    if method not in HTTP_METHOD_PREFIXES:
        return False
    return command[-1].upper().startswith("HTTP/")


def prometheus_label_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def filter_open_tcp_hosts_for_credential_file(
    hosts: list[str],
    port: int,
    *,
    timeout: float,
    workers: int,
    enabled: bool = True,
) -> list[str]:
    """Return hosts with an open TCP port before credential-file auth loops.

    Credential files can contain many pairs. Without this prefilter every pair
    repeats the same closed-port scan across the full target set. The helper is
    intentionally TCP-only and fail-closed per host; modules should disable it
    when a proxy transport must be honored.
    """

    if not enabled or not hosts:
        return list(hosts)

    indexed_hosts = list(enumerate(hosts))

    def _probe(indexed_host: tuple[int, str]) -> tuple[int, str, bool]:
        idx, host = indexed_host
        try:
            with socket.create_connection((host, int(port)), timeout=max(0.1, float(timeout))):
                return idx, host, True
        except OSError:
            return idx, host, False

    scheduler: BoundedScheduler[tuple[int, str], tuple[int, str, bool]] = BoundedScheduler(
        max_workers=max(1, int(workers)),
        max_inflight=max(1, int(workers)) * 4,
    )
    probe_results = scheduler.map_ordered(indexed_hosts, _probe)
    open_by_index = {idx: host for idx, host, ok in probe_results if ok}

    return [open_by_index[idx] for idx, _host in indexed_hosts if idx in open_by_index]
