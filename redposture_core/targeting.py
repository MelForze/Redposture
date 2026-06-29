"""Target and port parsing helpers shared by stage modules."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse, urlunsplit

DEFAULT_MAX_NETWORK_HOSTS = 65_536
DEFAULT_STREAM_TARGET_WINDOW_SIZE = 4_096


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
    raw: str | None = field(default=None, compare=False)
    path: str = ""
    query: str = ""
    fragment: str = ""
    source: str | None = field(default=None, compare=False)
    normalized_key: str | None = field(default=None, compare=False)


@dataclass(frozen=True)
class ScanExecutionGroup:
    hosts: list[str]
    port: int
    scheme_hint: str | None = None
    target_specs: list[ScanTargetSpec] | None = field(default=None, compare=False)


@dataclass(frozen=True)
class _ListTargetEntry:
    specs: tuple[ScanTargetSpec, ...]

    @property
    def count(self) -> int:
        return len(self.specs)

    def iter_specs(self) -> Iterator[ScanTargetSpec]:
        yield from self.specs


@dataclass(frozen=True)
class _IPv4RangeTargetEntry:
    ranges: tuple[tuple[int, int], ...]
    raw: str
    source: str | None

    @property
    def count(self) -> int:
        return sum(end - start + 1 for start, end in self.ranges)

    def iter_specs(self) -> Iterator[ScanTargetSpec]:
        for start, end in self.ranges:
            for value in range(start, end + 1):
                host = str(ipaddress.IPv4Address(value))
                yield ScanTargetSpec(
                    host=host,
                    scheme=None,
                    explicit_port=None,
                    raw=self.raw,
                    source=self.source,
                    normalized_key=host,
                )


@dataclass(frozen=True)
class StreamingTargetPlan:
    """A non-materialized target plan for command execution.

    The plan stores literal targets as small tuples, while large IPv4 CIDR
    inputs stay as integer ranges. Iterating the plan may generate millions of
    hosts, but constructing/counting it does not.
    """

    _entries: tuple[_ListTargetEntry | _IPv4RangeTargetEntry, ...]
    target_count: int
    no_port_count: int
    explicit_port_counts: dict[int, int] = field(default_factory=dict)
    explicit_ports: tuple[int, ...] = ()
    schemes: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.target_count > 0

    @property
    def has_explicit_port_targets(self) -> bool:
        return bool(self.explicit_port_counts)

    def iter_specs(self) -> Iterator[ScanTargetSpec]:
        for entry in self._entries:
            yield from entry.iter_specs()

    def iter_hosts(self) -> Iterator[str]:
        for spec in self.iter_specs():
            yield spec.host

    def iter_specs_for_port(self, port: int, matrix_ports: tuple[int, ...]) -> Iterator[ScanTargetSpec]:
        """Yield specs whose effective port matches `port`. A spec with an explicit port
        matches only when it equals `port`; a spec without one matches when `port` is in
        the per-run matrix. Single source of truth for the per-port filter previously
        copy-pasted across stage_collect, stage_scan, and stage_runtime."""
        matrix_port_set = set(matrix_ports)
        port_int = int(port)
        for spec in self.iter_specs():
            if spec.explicit_port is not None:
                if int(spec.explicit_port) != port_int:
                    continue
            elif port_int not in matrix_port_set:
                continue
            yield spec

    def iter_hosts_for_port(self, port: int, matrix_ports: tuple[int, ...]) -> Iterator[str]:
        for spec in self.iter_specs_for_port(port, matrix_ports):
            yield spec.host

    def first_spec(self) -> ScanTargetSpec | None:
        return next(self.iter_specs(), None)

    def single_spec(self) -> ScanTargetSpec | None:
        if self.target_count != 1:
            return None
        return self.first_spec()

    def execution_ports(self, default_ports: tuple[int, ...]) -> tuple[int, ...]:
        return tuple(dict.fromkeys((*default_ports, *self.explicit_ports)))

    def count_for_ports(self, default_ports: tuple[int, ...]) -> int:
        total = self.no_port_count * len(default_ports)
        for count in self.explicit_port_counts.values():
            total += count
        return total

    def hosts_sample(self, limit: int) -> list[str]:
        result: list[str] = []
        for host in self.iter_hosts():
            result.append(host)
            if len(result) >= limit:
                break
        return result

    def has_scheme(self, scheme: str) -> bool:
        return str(scheme or "").strip().lower() in self.schemes


TargetUrlMode = Literal["preserve", "strip", "reject"]
TargetPathPolicy = Literal["preserve", "strip", "reject"]


@dataclass(frozen=True)
class TargetParsePolicy:
    """Canonical target parsing policy.

    `preserve` keeps URL scheme/explicit port for HTTP/API modules.
    `strip` accepts URLs but returns host-only specs for plain TCP modules.
    `reject` is useful for commands that must fail hard on URL targets.
    """

    max_network_hosts: int = DEFAULT_MAX_NETWORK_HOSTS
    url_mode: TargetUrlMode = "preserve"
    path_policy: TargetPathPolicy = "preserve"
    allowed_schemes: tuple[str, ...] = ("http", "https")
    source: str | None = None


def _make_normalized_key(
    *,
    host: str,
    scheme: str | None,
    port: int | None,
    path: str = "",
    query: str = "",
    fragment: str = "",
) -> str:
    if scheme:
        netloc = host
        if port is not None:
            netloc = f"{host}:{int(port)}"
        return urlunsplit((scheme, netloc, path or "", query or "", fragment or ""))
    if port is not None:
        return f"{host}:{int(port)}"
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


def _network_host_count(network: ipaddress._BaseNetwork) -> int:
    if network.version == 4:
        return int(network.num_addresses if network.prefixlen >= 31 else max(0, network.num_addresses - 2))
    return int(network.num_addresses if network.prefixlen >= 127 else network.num_addresses)


def _ipv4_network_host_range(network: ipaddress.IPv4Network) -> tuple[int, int] | None:
    start = int(network.network_address)
    end = int(network.broadcast_address)
    if network.prefixlen < 31:
        start += 1
        end -= 1
    if start > end:
        return None
    return start, end


def _subtract_ranges(base: tuple[int, int], excluded: list[tuple[int, int]]) -> list[tuple[int, int]]:
    segments = [base]
    for ex_start, ex_end in excluded:
        next_segments: list[tuple[int, int]] = []
        for start, end in segments:
            if ex_end < start or ex_start > end:
                next_segments.append((start, end))
                continue
            if ex_start > start:
                next_segments.append((start, ex_start - 1))
            if ex_end < end:
                next_segments.append((ex_end + 1, end))
        segments = next_segments
        if not segments:
            break
    return segments


def _merge_ipv4_range(ranges: list[tuple[int, int]], new_range: tuple[int, int]) -> list[tuple[int, int]]:
    ranges.append(new_range)
    ranges.sort()
    merged: list[tuple[int, int]] = []
    for start, end in ranges:
        if not merged or start > merged[-1][1] + 1:
            merged.append((start, end))
            continue
        prev_start, prev_end = merged[-1]
        merged[-1] = (prev_start, max(prev_end, end))
    return merged


def _range_contains(ranges: list[tuple[int, int]], value: int) -> bool:
    for start, end in ranges:
        if value < start:
            return False
        if start <= value <= end:
            return True
    return False


def _consume_target_tokens(
    targets: str,
    *,
    policy: TargetParsePolicy,
    processed_files: set[str],
    append_spec: Callable[[ScanTargetSpec], None],
    handle_network: Callable[[str, str | None], None],
) -> None:
    """Walk comma/file/URL/CIDR target tokens, delegating the strategy-specific
    parts to callbacks.

    `append_spec` receives each resolved single-host spec (bare host or URL).
    `handle_network` receives each ``host/prefix`` token (and its source) so the
    caller can either materialize hosts or keep them as ranges. File inclusion,
    URL parsing/validation, and bare-host normalization are shared here so the
    streaming and eager parsers cannot drift apart.
    """

    def _consume_token(token: str, *, source: str | None = None) -> None:
        item = token.strip()
        if not item:
            return

        if os.path.isfile(item):
            real = os.path.realpath(item)
            if real in processed_files:
                return
            processed_files.add(real)
            with open(real, encoding="utf-8") as fh:
                for line_no, raw in enumerate(fh, start=1):
                    clean = raw.split("#", 1)[0].strip()
                    if not clean:
                        continue
                    for part in clean.split(","):
                        _consume_token(part, source=f"{real}:{line_no}")
            return

        if "://" in item:
            parsed = urlparse(item)
            scheme = str(parsed.scheme or "").strip().lower()
            if scheme not in policy.allowed_schemes:
                raise ValueError(
                    f"unsupported target URL scheme '{scheme or '-'}' in '{item}' "
                    f"(supported: {', '.join(policy.allowed_schemes)})"
                )
            if policy.url_mode == "reject":
                raise ValueError(f"URL targets are not supported here: '{item}'")
            host = (parsed.hostname or "").strip()
            if not host:
                raise ValueError(f"invalid URL target '{item}': missing host")
            try:
                explicit_port = parsed.port
            except ValueError as exc:
                raise ValueError(f"invalid URL target '{item}': {exc}") from exc
            if policy.url_mode == "strip":
                append_spec(
                    ScanTargetSpec(
                        host=host,
                        scheme=None,
                        explicit_port=None,
                        raw=item,
                        source=source or policy.source,
                        normalized_key=host,
                    )
                )
            else:
                path = parsed.path or ""
                query = parsed.query or ""
                fragment = parsed.fragment or ""
                if policy.path_policy == "reject" and (path not in {"", "/"} or query or fragment):
                    raise ValueError(f"URL path/query are not supported here: '{item}'")
                if policy.path_policy == "strip":
                    path = ""
                    query = ""
                    fragment = ""
                normalized_key = _make_normalized_key(
                    host=host,
                    scheme=scheme,
                    port=explicit_port,
                    path=path,
                    query=query,
                    fragment=fragment,
                )
                append_spec(
                    ScanTargetSpec(
                        host=host,
                        scheme=scheme,
                        explicit_port=explicit_port,
                        raw=item,
                        path=path,
                        query=query,
                        fragment=fragment,
                        source=source or policy.source,
                        normalized_key=normalized_key,
                    )
                )
            return

        if "/" in item:
            handle_network(item, source)
            return

        host = normalize_scan_host(item) or ""
        if not host:
            return
        append_spec(
            ScanTargetSpec(
                host=host,
                scheme=None,
                explicit_port=None,
                raw=item,
                source=source or policy.source,
                normalized_key=host,
            )
        )

    for token in targets.split(","):
        _consume_token(token)


def stream_scan_target_specs(
    targets: str | None,
    *,
    policy: TargetParsePolicy | None = None,
) -> StreamingTargetPlan:
    """Parse targets into a lazy plan.

    IPv4 CIDR targets are not bounded by `max_network_hosts` here. They are
    represented by ranges and generated on demand. IPv6 CIDR expansion remains
    bounded because its address space is too large to represent safely in the
    current execution model.
    """

    active_policy = policy or TargetParsePolicy()
    entries: list[_ListTargetEntry | _IPv4RangeTargetEntry] = []
    seen_specs: set[str] = set()
    seen_ipv4_ranges: list[tuple[int, int]] = []
    processed_files: set[str] = set()
    target_count = 0
    no_port_count = 0
    explicit_port_counts: dict[int, int] = {}
    explicit_ports: list[int] = []
    schemes: list[str] = []

    def _remember_count(spec: ScanTargetSpec, count: int = 1) -> None:
        nonlocal no_port_count
        if spec.explicit_port is None:
            no_port_count += count
        else:
            port = int(spec.explicit_port)
            if port not in explicit_port_counts:
                explicit_ports.append(port)
            explicit_port_counts[port] = explicit_port_counts.get(port, 0) + count
        if spec.scheme:
            scheme = str(spec.scheme).lower()
            if scheme not in schemes:
                schemes.append(scheme)

    def _append_list_spec(spec: ScanTargetSpec) -> None:
        nonlocal target_count, seen_ipv4_ranges
        key = spec.normalized_key or _make_normalized_key(
            host=spec.host,
            scheme=spec.scheme,
            port=spec.explicit_port,
            path=spec.path,
            query=spec.query,
            fragment=spec.fragment,
        )
        if spec.scheme is None and spec.explicit_port is None:
            try:
                ip_value = ipaddress.ip_address(spec.host)
            except ValueError:
                ip_value = None
            if isinstance(ip_value, ipaddress.IPv4Address):
                ip_int = int(ip_value)
                if _range_contains(seen_ipv4_ranges, ip_int):
                    return
                seen_ipv4_ranges = _merge_ipv4_range(seen_ipv4_ranges, (ip_int, ip_int))
        if key in seen_specs:
            return
        seen_specs.add(key)
        entries.append(_ListTargetEntry((spec,)))
        target_count += 1
        _remember_count(spec)

    def _append_ipv4_network(item: str, network: ipaddress.IPv4Network, source: str | None) -> None:
        nonlocal target_count, no_port_count, seen_ipv4_ranges
        host_range = _ipv4_network_host_range(network)
        if host_range is None:
            return
        remaining = _subtract_ranges(host_range, seen_ipv4_ranges)
        seen_ipv4_ranges = _merge_ipv4_range(seen_ipv4_ranges, host_range)
        if not remaining:
            return
        entry = _IPv4RangeTargetEntry(tuple(remaining), item, source or active_policy.source)
        entries.append(entry)
        target_count += entry.count
        no_port_count += entry.count

    def _append_ipv6_network(item: str, network: ipaddress.IPv6Network, source: str | None) -> None:
        estimated = _network_host_count(network)
        if estimated > active_policy.max_network_hosts:
            raise ValueError(
                f"invalid network target '{item}': target network '{item}' expands to {estimated} hosts "
                f"(limit: {active_policy.max_network_hosts})"
            )
        for host in _expand_network_targets(item, active_policy.max_network_hosts):
            _append_list_spec(
                ScanTargetSpec(
                    host=host,
                    scheme=None,
                    explicit_port=None,
                    raw=item,
                    source=source or active_policy.source,
                    normalized_key=host,
                )
            )

    def _handle_network(item: str, source: str | None) -> None:
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid network target '{item}': {exc}") from exc
        if isinstance(network, ipaddress.IPv4Network):
            _append_ipv4_network(item, network, source)
        else:
            _append_ipv6_network(item, network, source)

    if targets:
        _consume_target_tokens(
            targets,
            policy=active_policy,
            processed_files=processed_files,
            append_spec=_append_list_spec,
            handle_network=_handle_network,
        )

    return StreamingTargetPlan(
        _entries=tuple(entries),
        target_count=target_count,
        no_port_count=no_port_count,
        explicit_port_counts=dict(explicit_port_counts),
        explicit_ports=tuple(explicit_ports),
        schemes=tuple(schemes),
    )


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
    seen_specs: set[str] = set()
    processed_files: set[str] = set()

    def _append_spec(spec: ScanTargetSpec) -> None:
        key = spec.normalized_key or _make_normalized_key(
            host=spec.host,
            scheme=spec.scheme,
            port=spec.explicit_port,
            path=spec.path,
            query=spec.query,
            fragment=spec.fragment,
        )
        if key in seen_specs:
            return
        seen_specs.add(key)
        unique.append(spec)

    def _handle_network(item: str, source: str | None) -> None:
        try:
            expanded = _expand_network_targets(item, max_hosts=active_policy.max_network_hosts)
        except ValueError as exc:
            raise ValueError(f"invalid network target '{item}': {exc}") from exc
        for host in expanded:
            _append_spec(
                ScanTargetSpec(
                    host=host,
                    scheme=None,
                    explicit_port=None,
                    raw=item,
                    source=source or active_policy.source,
                    normalized_key=host,
                )
            )

    _consume_target_tokens(
        targets,
        policy=active_policy,
        processed_files=processed_files,
        append_spec=_append_spec,
        handle_network=_handle_network,
    )

    return unique


def collect_scan_target_specs(
    targets: str | None, max_network_hosts: int = DEFAULT_MAX_NETWORK_HOSTS
) -> list[ScanTargetSpec]:
    return parse_scan_target_specs(targets, policy=TargetParsePolicy(max_network_hosts=max_network_hosts))


def chunked_hosts(hosts: Iterable[Any], size: int = DEFAULT_STREAM_TARGET_WINDOW_SIZE) -> Iterator[list[str]]:
    """Yield host strings in fixed-size batches. Shared helper used by stage_scan,
    stage_collect, and any future stage that needs to chunk a streaming host iterator."""
    chunk: list[str] = []
    for host in hosts:
        chunk.append(str(host))
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def collect_scan_targets(targets: str | None, max_network_hosts: int = DEFAULT_MAX_NETWORK_HOSTS) -> list[str]:
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
    group_specs: dict[tuple[int, str | None], list[ScanTargetSpec]] = {}
    seen_group_hosts: set[tuple[int, str | None, str]] = set()

    for spec in target_specs:
        ports = [int(spec.explicit_port)] if spec.explicit_port is not None else unique_ports
        for port in ports:
            scheme_hint = spec.scheme if include_scheme_in_key else None
            group_key = (int(port), scheme_hint)
            if group_key not in groups:
                groups[group_key] = []
                group_specs[group_key] = []
            host_key = (int(port), scheme_hint, spec.host)
            if host_key in seen_group_hosts:
                continue
            seen_group_hosts.add(host_key)
            groups[group_key].append(spec.host)
            group_specs[group_key].append(spec)

    result: list[ScanExecutionGroup] = []
    for (port, scheme_hint), hosts in groups.items():
        if not hosts:
            continue
        result.append(
            ScanExecutionGroup(
                hosts=hosts,
                port=port,
                scheme_hint=scheme_hint,
                target_specs=group_specs.get((port, scheme_hint), []),
            )
        )
    return result
