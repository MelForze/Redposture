"""General utility helpers."""

from __future__ import annotations

import base64
import ipaddress
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

from .constants import HTTP_METHOD_PREFIXES


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
            with open(real, "r", encoding="utf-8") as fh:
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
            except ValueError:
                expanded = []
            if expanded:
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
            with open(real, "r", encoding="utf-8") as fh:
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
