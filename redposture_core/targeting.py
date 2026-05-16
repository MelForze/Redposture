"""Target and port parsing helpers shared by stage modules."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse


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


TargetUrlMode = Literal["preserve", "strip", "reject"]


@dataclass(frozen=True)
class TargetParsePolicy:
    """Canonical target parsing policy.

    `preserve` keeps URL scheme/explicit port for HTTP/API modules.
    `strip` accepts URLs but returns host-only specs for plain TCP modules.
    `reject` is useful for commands that must fail hard on URL targets.
    """

    max_network_hosts: int = 4096
    url_mode: TargetUrlMode = "preserve"


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


def parse_scan_target_specs(
    targets: str | None,
    *,
    policy: TargetParsePolicy | None = None,
) -> list[ScanTargetSpec]:
    """Parse target tokens into normalized specs using one shared implementation."""

    if not targets:
        return []

    active_policy = policy or TargetParsePolicy()
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
            if active_policy.url_mode == "reject":
                raise ValueError(f"URL targets are not supported here: '{item}'")
            host = (parsed.hostname or "").strip()
            if not host:
                raise ValueError(f"invalid URL target '{item}': missing host")
            try:
                explicit_port = parsed.port
            except ValueError as exc:
                raise ValueError(f"invalid URL target '{item}': {exc}") from exc
            if active_policy.url_mode == "strip":
                _append_spec(ScanTargetSpec(host=host, scheme=None, explicit_port=None))
            else:
                _append_spec(ScanTargetSpec(host=host, scheme=scheme, explicit_port=explicit_port))
            return

        if "/" in item:
            try:
                expanded = _expand_network_targets(item, max_hosts=active_policy.max_network_hosts)
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


def collect_scan_target_specs(targets: str | None, max_network_hosts: int = 4096) -> list[ScanTargetSpec]:
    return parse_scan_target_specs(targets, policy=TargetParsePolicy(max_network_hosts=max_network_hosts))


def collect_scan_targets(targets: str | None, max_network_hosts: int = 4096) -> list[str]:
    """Return unique host tokens through the canonical parser in URL-strip mode."""

    specs = parse_scan_target_specs(
        targets,
        policy=TargetParsePolicy(max_network_hosts=max_network_hosts, url_mode="strip"),
    )
    hosts: list[str] = []
    seen: set[str] = set()
    for spec in specs:
        if spec.host in seen:
            continue
        seen.add(spec.host)
        hosts.append(spec.host)
    return hosts


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
