"""General utility helpers."""

from __future__ import annotations

import base64
import ipaddress
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from .constants import HTTP_METHOD_PREFIXES

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


def normalize_scan_host(value: str) -> str | None:
    raw = (value or "").strip()
    if not raw:
        return None
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="")
    host = parsed.hostname or raw
    host = host.strip()
    return host or None


def normalize_ip_literal(value: str) -> str | None:
    host = normalize_scan_host(value)
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    return host


@dataclass(frozen=True)
class ScanTargetSpec:
    host: str
    scheme: str | None = None
    explicit_port: int | None = None


@dataclass(frozen=True)
class ScanExecutionGroup:
    hosts: list[str]
    port: int
    scheme_hint: str | None = None


def _expand_network_targets(token: str, max_hosts: int) -> list[str]:
    network = ipaddress.ip_network(token, strict=False)

    if network.version == 4:
        estimated = int(network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2)
    else:
        estimated = int(network.num_addresses if network.prefixlen >= 127 else network.num_addresses)

    if estimated > max_hosts:
        raise ValueError(f"target network '{token}' expands to {estimated} hosts (limit: {max_hosts})")

    hosts = [str(addr) for addr in network.hosts()]
    if not hosts:
        hosts = [str(network.network_address)]
    return hosts


def collect_scan_target_specs(targets: str | None, max_network_hosts: int = 4096) -> list[ScanTargetSpec]:
    if not targets:
        return []

    unique: list[ScanTargetSpec] = []
    seen_specs: set[tuple[str, str | None, int | None]] = set()
    processed_files: set[str] = set()

    def _append_spec(spec: ScanTargetSpec) -> None:
        key = (spec.host, spec.scheme, spec.explicit_port)
        if key in seen_specs:
            return
        seen_specs.add(key)
        unique.append(spec)

    def _consume_token(token: str) -> None:
        item = token.strip()
        if not item:
            return

        if os.path.isfile(item):
            real = os.path.realpath(item)
            if real in processed_files:
                return
            processed_files.add(real)
            with open(real, encoding="utf-8") as fh:
                for raw in fh:
                    clean = raw.split("#", 1)[0].strip()
                    if not clean:
                        continue
                    for part in clean.split(","):
                        _consume_token(part)
            return

        if "://" in item:
            parsed = urlparse(item)
            scheme = str(parsed.scheme or "").strip().lower()
            if scheme not in {"http", "https"}:
                raise ValueError(
                    f"unsupported target URL scheme '{scheme or '-'}' in '{item}' (supported: http, https)"
                )
            host = (parsed.hostname or "").strip()
            if not host:
                raise ValueError(f"invalid URL target '{item}': missing host")
            try:
                explicit_port = parsed.port
            except ValueError as exc:
                raise ValueError(f"invalid URL target '{item}': {exc}") from exc
            _append_spec(ScanTargetSpec(host=host, scheme=scheme, explicit_port=explicit_port))
            return

        if "/" in item:
            try:
                expanded = _expand_network_targets(item, max_hosts=max_network_hosts)
            except ValueError as exc:
                raise ValueError(f"invalid network target '{item}': {exc}") from exc
            for host in expanded:
                _append_spec(ScanTargetSpec(host=host, scheme=None, explicit_port=None))
            return

        host = normalize_scan_host(item)
        if not host:
            return
        _append_spec(ScanTargetSpec(host=host, scheme=None, explicit_port=None))

    for token in targets.split(","):
        _consume_token(token)

    return unique


def build_scan_execution_groups(
    target_specs: list[ScanTargetSpec],
    port_matrix: list[int],
    *,
    include_scheme_in_key: bool = True,
) -> list[ScanExecutionGroup]:
    if not target_specs:
        return []

    unique_ports = [int(port) for port in dict.fromkeys(port_matrix)]
    groups: dict[tuple[int, str | None], list[str]] = {}
    seen_group_hosts: set[tuple[int, str | None, str]] = set()

    for spec in target_specs:
        ports = [int(spec.explicit_port)] if spec.explicit_port is not None else unique_ports
        for port in ports:
            scheme_hint = spec.scheme if include_scheme_in_key else None
            group_key = (int(port), scheme_hint)
            if group_key not in groups:
                groups[group_key] = []
            host_key = (int(port), scheme_hint, spec.host)
            if host_key in seen_group_hosts:
                continue
            seen_group_hosts.add(host_key)
            groups[group_key].append(spec.host)

    result: list[ScanExecutionGroup] = []
    for (port, scheme_hint), hosts in groups.items():
        if not hosts:
            continue
        result.append(ScanExecutionGroup(hosts=hosts, port=port, scheme_hint=scheme_hint))
    return result


def collect_scan_targets(targets: str | None, max_network_hosts: int = 4096) -> list[str]:
    if not targets:
        return []

    unique: list[str] = []
    seen_targets: set[str] = set()
    processed_files: set[str] = set()

    def _append_target(value: str) -> None:
        if value in seen_targets:
            return
        seen_targets.add(value)
        unique.append(value)

    def _consume_token(token: str) -> None:
        item = token.strip()
        if not item:
            return

        if os.path.isfile(item):
            real = os.path.realpath(item)
            if real in processed_files:
                return
            processed_files.add(real)
            with open(real, encoding="utf-8") as fh:
                for raw in fh:
                    clean = raw.split("#", 1)[0].strip()
                    if not clean:
                        continue
                    for part in clean.split(","):
                        _consume_token(part)
            return

        if "://" not in item and "/" in item:
            try:
                expanded = _expand_network_targets(item, max_hosts=max_network_hosts)
            except ValueError as exc:
                raise ValueError(f"invalid network target '{item}': {exc}") from exc
            for host in expanded:
                _append_target(host)
            return

        host = normalize_scan_host(item)
        if not host:
            return
        _append_target(host)

    for token in targets.split(","):
        _consume_token(token)

    return unique


def collect_scan_ports(ports: str | None) -> list[int]:
    if not ports:
        return []

    unique: list[int] = []
    seen: set[int] = set()
    processed_files: set[str] = set()

    def _add_port(value: int) -> None:
        if value in seen:
            return
        seen.add(value)
        unique.append(value)

    def _consume_token(token: str) -> None:
        item = token.strip()
        if not item:
            return

        if os.path.isfile(item):
            real = os.path.realpath(item)
            if real in processed_files:
                return
            processed_files.add(real)
            with open(real, encoding="utf-8") as fh:
                for raw in fh:
                    clean = raw.split("#", 1)[0].strip()
                    if not clean:
                        continue
                    for part in clean.split(","):
                        _consume_token(part)
            return

        if "-" in item:
            left, right = item.split("-", 1)
            try:
                start = int(left.strip())
                end = int(right.strip())
            except ValueError as exc:
                raise ValueError(f"invalid port range '{item}'") from exc
            if start < 1 or start > 65535 or end < 1 or end > 65535:
                raise ValueError(f"port range '{item}' must be within 1..65535")
            if start > end:
                raise ValueError(f"port range '{item}' must be ascending")
            for port in range(start, end + 1):
                _add_port(port)
            return

        try:
            value = int(item)
        except ValueError as exc:
            raise ValueError(f"invalid port '{item}'") from exc
        if value < 1 or value > 65535:
            raise ValueError(f"port '{item}' must be within 1..65535")
        _add_port(value)

    for token in ports.split(","):
        _consume_token(token)

    return unique


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
    open_by_index: dict[int, str] = {}

    def _probe(host: str) -> bool:
        try:
            with socket.create_connection((host, int(port)), timeout=max(0.1, float(timeout))):
                return True
        except OSError:
            return False

    with ThreadPoolExecutor(max_workers=max(1, int(workers))) as executor:
        future_map = {executor.submit(_probe, host): (idx, host) for idx, host in indexed_hosts}
        for future in as_completed(future_map):
            idx, host = future_map[future]
            try:
                if bool(future.result()):
                    open_by_index[idx] = host
            except OSError:
                continue

    return [open_by_index[idx] for idx, _host in indexed_hosts if idx in open_by_index]
