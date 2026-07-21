"""Target and port parsing helpers shared by stage modules."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace
from typing import Any, Literal
from urllib.parse import urlparse, urlunsplit

DEFAULT_MAX_NETWORK_HOSTS = 65_536
DEFAULT_STREAM_TARGET_WINDOW_SIZE = 4_096


def normalize_scan_host(value: str) -> str | None:
    raw = (value or "").strip()
    if not raw:
        return None

    # B1 fix: `urlparse('//2001:db8::1').hostname` returns '2001' — the
    # library interprets the colon as a host/port boundary and silently
    # truncates the IPv6 literal. Detect unbracketed IPv6 first and hand
    # it to ipaddress so users get the real address instead of a hextet.
    if "://" not in raw and raw.count(":") >= 2 and not (raw.startswith("[") or "/" in raw):
        try:
            return str(ipaddress.IPv6Address(raw))
        except ValueError:
            pass

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
    bare_explicit_port_counts: dict[int, int] = field(default_factory=dict)
    explicit_ports: tuple[int, ...] = ()
    schemes: tuple[str, ...] = ()
    include_matrix_ports_for_bare_explicit_targets: bool = False

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

    def _spec_matches_port(
        self,
        spec: ScanTargetSpec,
        port: int,
        matrix_port_set: set[int],
    ) -> bool:
        port_int = int(port)
        if spec.explicit_port is None:
            return port_int in matrix_port_set
        if int(spec.explicit_port) == port_int:
            return True
        return (
            self.include_matrix_ports_for_bare_explicit_targets and spec.scheme is None and port_int in matrix_port_set
        )

    def iter_specs_for_port(self, port: int, matrix_ports: tuple[int, ...]) -> Iterator[ScanTargetSpec]:
        """Yield specs whose effective port matches ``port``.

        Target-specific ports override the module matrix by default. When the
        command line explicitly supplied a port option, bare ``host:port``
        targets also inherit that matrix as additional ports. URL ports keep
        their existing override-only semantics.
        """
        matrix_port_set = {int(matrix_port) for matrix_port in matrix_ports}
        port_int = int(port)
        literal_bare_hosts = {
            spec.host
            for entry in self._entries
            if isinstance(entry, _ListTargetEntry)
            for spec in entry.specs
            if spec.scheme is None and self._spec_matches_port(spec, port_int, matrix_port_set)
        }
        seen_bare_hosts: set[str] = set()
        for entry in self._entries:
            if isinstance(entry, _IPv4RangeTargetEntry):
                if port_int not in matrix_port_set:
                    continue
                for spec in entry.iter_specs():
                    if spec.host in literal_bare_hosts:
                        continue
                    yield spec
                continue

            for spec in entry.specs:
                if not self._spec_matches_port(spec, port_int, matrix_port_set):
                    continue
                if spec.scheme is None:
                    if spec.host in seen_bare_hosts:
                        continue
                    seen_bare_hosts.add(spec.host)
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
        matrix_ports = tuple(dict.fromkeys(int(port) for port in default_ports))
        total = self.no_port_count * len(matrix_ports)
        for count in self.explicit_port_counts.values():
            total += count
        if self.include_matrix_ports_for_bare_explicit_targets:
            for target_port, count in self.bare_explicit_port_counts.items():
                total += count * sum(1 for port in matrix_ports if port != target_port)

        # The parser intentionally keeps distinct source pairs such as
        # ``host:8001`` and ``host:50051``. An additive CLI port can make both
        # resolve to the same effective host:port, which must execute once.
        # Correct the O(1) baseline using only materialized literal targets;
        # large CIDR ranges remain represented as intervals.
        ipv4_ranges = sorted(
            target_range
            for entry in self._entries
            if isinstance(entry, _IPv4RangeTargetEntry)
            for target_range in entry.ranges
        )
        bare_no_port_hosts: set[str] = set()
        bare_explicit_ports_by_host: dict[str, set[int]] = {}
        for entry in self._entries:
            if not isinstance(entry, _ListTargetEntry):
                continue
            for spec in entry.specs:
                if spec.scheme is not None:
                    continue
                if spec.explicit_port is None:
                    bare_no_port_hosts.add(spec.host)
                else:
                    bare_explicit_ports_by_host.setdefault(spec.host, set()).add(int(spec.explicit_port))

        def _host_has_matrix_target(host: str) -> bool:
            if host in bare_no_port_hosts:
                return True
            if not ipv4_ranges:
                return False
            try:
                ip_value = ipaddress.ip_address(host)
            except ValueError:
                return False
            return isinstance(ip_value, ipaddress.IPv4Address) and _range_contains(
                ipv4_ranges,
                int(ip_value),
            )

        matrix_port_set = set(matrix_ports)
        for host, target_ports in bare_explicit_ports_by_host.items():
            has_matrix_target = _host_has_matrix_target(host)
            if self.include_matrix_ports_for_bare_explicit_targets:
                occurrences_per_matrix_port = len(target_ports) + int(has_matrix_target)
                total -= max(0, occurrences_per_matrix_port - 1) * len(matrix_ports)
            elif has_matrix_target:
                total -= len(target_ports & matrix_port_set)
        return total

    def with_additional_ports_for_bare_explicit_targets(
        self,
        enabled: bool = True,
    ) -> StreamingTargetPlan:
        """Apply the run's explicit CLI port matrix to bare ``host:port`` targets."""

        enabled_bool = bool(enabled)
        if enabled_bool == self.include_matrix_ports_for_bare_explicit_targets:
            return self
        return replace(self, include_matrix_ports_for_bare_explicit_targets=enabled_bool)

    def hosts_sample(self, limit: int) -> list[str]:
        result: list[str] = []
        for host in self.iter_hosts():
            result.append(host)
            if len(result) >= limit:
                break
        return result

    def has_scheme(self, scheme: str) -> bool:
        return str(scheme or "").strip().lower() in self.schemes

    def with_scheme_default_ports(self, defaults: dict[str, int]) -> StreamingTargetPlan:
        """Return a plan where URL targets without ports receive scheme defaults.

        Bare hosts and CIDR ranges remain matrix-driven. Explicit URL/host ports
        always retain priority.
        """

        normalized_defaults: dict[str, int] = {}
        for raw_scheme, raw_port in defaults.items():
            scheme = str(raw_scheme or "").strip().lower()
            port = int(raw_port)
            if not scheme:
                continue
            if port < 1 or port > 65535:
                raise ValueError(f"default port for {scheme} must be within 1..65535")
            normalized_defaults[scheme] = port
        if not normalized_defaults:
            return self

        entries: list[_ListTargetEntry | _IPv4RangeTargetEntry] = []
        seen_specs: set[str] = set()
        target_count = 0
        no_port_count = 0
        explicit_port_counts: dict[int, int] = {}
        bare_explicit_port_counts: dict[int, int] = {}
        explicit_ports: list[int] = []
        schemes: list[str] = []

        for entry in self._entries:
            if isinstance(entry, _IPv4RangeTargetEntry):
                entries.append(entry)
                target_count += entry.count
                no_port_count += entry.count
                continue

            mapped_specs: list[ScanTargetSpec] = []
            for spec in entry.specs:
                mapped = spec
                scheme = str(spec.scheme or "").strip().lower()
                if spec.explicit_port is None and scheme in normalized_defaults:
                    mapped_port = normalized_defaults[scheme]
                    mapped = replace(
                        spec,
                        explicit_port=mapped_port,
                        normalized_key=_make_normalized_key(
                            host=spec.host,
                            scheme=spec.scheme,
                            port=mapped_port,
                            path=spec.path,
                            query=spec.query,
                            fragment=spec.fragment,
                        ),
                    )

                key = mapped.normalized_key or _make_normalized_key(
                    host=mapped.host,
                    scheme=mapped.scheme,
                    port=mapped.explicit_port,
                    path=mapped.path,
                    query=mapped.query,
                    fragment=mapped.fragment,
                )
                if key in seen_specs:
                    continue
                seen_specs.add(key)
                mapped_specs.append(mapped)
                target_count += 1

                if mapped.explicit_port is None:
                    no_port_count += 1
                else:
                    port = int(mapped.explicit_port)
                    if port not in explicit_port_counts:
                        explicit_ports.append(port)
                    explicit_port_counts[port] = explicit_port_counts.get(port, 0) + 1
                    if mapped.scheme is None:
                        bare_explicit_port_counts[port] = bare_explicit_port_counts.get(port, 0) + 1
                if scheme and scheme not in schemes:
                    schemes.append(scheme)

            if mapped_specs:
                entries.append(_ListTargetEntry(tuple(mapped_specs)))

        return StreamingTargetPlan(
            _entries=tuple(entries),
            target_count=target_count,
            no_port_count=no_port_count,
            explicit_port_counts=explicit_port_counts,
            bare_explicit_port_counts=bare_explicit_port_counts,
            explicit_ports=tuple(explicit_ports),
            schemes=tuple(schemes),
            include_matrix_ports_for_bare_explicit_targets=(self.include_matrix_ports_for_bare_explicit_targets),
        )


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
        # urlsplit() removes brackets from an IPv6 hostname. Add them back
        # before building a URL key, otherwise ``host:port`` is ambiguous and
        # distinct IPv6 targets can collapse during de-duplication.
        netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
        if port is not None:
            netloc = f"{host}:{int(port)}"
            if ":" in host and not host.startswith("["):
                netloc = f"[{host}]:{int(port)}"
        return urlunsplit((scheme, netloc, path or "", query or "", fragment or ""))
    if port is not None:
        bare_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        return f"{bare_host}:{int(port)}"
    return host


def _parse_bare_target_authority(item: str, *, source: str | None = None) -> tuple[str, int | None]:
    """Parse ``host[:port]`` without confusing an unbracketed IPv6 literal.

    IPv6 ports are deliberately accepted only in the unambiguous
    ``[address]:port`` form. This helper is shared by eager and streaming
    target parsing through ``_consume_target_tokens``.
    """

    def _error(reason: str) -> ValueError:
        location = f" at {source}" if source else ""
        return ValueError(f"invalid target '{item}'{location}: {reason}")

    def _parse_port(raw_port: str) -> int:
        if not raw_port:
            raise _error("missing port")
        if not raw_port.isdecimal():
            raise _error(f"port '{raw_port}' must be an integer")
        port = int(raw_port)
        if port < 1 or port > 65535:
            raise _error(f"port '{raw_port}' must be within 1..65535")
        return port

    if item.startswith("[") or "]" in item:
        if not item.startswith("["):
            raise _error("malformed bracketed IPv6 address")
        closing = item.find("]")
        if closing < 0:
            raise _error("missing closing ']' in IPv6 address")
        raw_host = item[1:closing]
        suffix = item[closing + 1 :]
        if not raw_host:
            raise _error("missing IPv6 address")
        try:
            host = str(ipaddress.IPv6Address(raw_host))
        except ValueError as exc:
            raise _error(f"invalid IPv6 address '{raw_host}'") from exc
        if not suffix:
            return host, None
        if not suffix.startswith(":"):
            raise _error("unexpected text after bracketed IPv6 address")
        return host, _parse_port(suffix[1:])

    colon_count = item.count(":")
    if colon_count >= 2:
        try:
            return str(ipaddress.IPv6Address(item)), None
        except ValueError as exc:
            raise _error("invalid IPv6 address; use '[address]:port' when specifying a port") from exc

    if colon_count == 1:
        raw_host, raw_port = item.rsplit(":", 1)
        host = normalize_scan_host(raw_host) or ""
        if not host:
            raise _error("missing host")
        return host, _parse_port(raw_port)

    host = normalize_scan_host(item) or ""
    if not host:
        raise _error("missing host")
    return host, None


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

        # B6 fix: only treat a token as a file-of-targets when it clearly looks
        # like a path (contains `/`, `\`, starts with `.`, or ends with a
        # common list extension). Previously `-t localhost` silently read a
        # local file named `./localhost` instead of scanning that hostname.
        def _looks_like_target_file(candidate: str) -> bool:
            lowered = candidate.lower()
            if candidate.startswith((".", "/", "~")) or "\\" in candidate or "/" in candidate:
                return True
            return lowered.endswith((".txt", ".list", ".hosts", ".csv"))

        if _looks_like_target_file(item) and os.path.isfile(item):
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

        host, explicit_port = _parse_bare_target_authority(item, source=source or policy.source)
        append_spec(
            ScanTargetSpec(
                host=host,
                scheme=None,
                explicit_port=explicit_port,
                raw=item,
                source=source or policy.source,
                normalized_key=_make_normalized_key(
                    host=host,
                    scheme=None,
                    port=explicit_port,
                ),
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
    bare_explicit_port_counts: dict[int, int] = {}
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
            if spec.scheme is None:
                bare_explicit_port_counts[port] = bare_explicit_port_counts.get(port, 0) + count
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
        bare_explicit_port_counts=dict(bare_explicit_port_counts),
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
    include_matrix_ports_for_bare_explicit_targets: bool = False,
) -> list[ScanExecutionGroup]:
    if not target_specs:
        return []

    unique_ports = [int(port) for port in dict.fromkeys(port_matrix)]
    groups: dict[tuple[int, str | None], list[str]] = {}
    group_specs: dict[tuple[int, str | None], list[ScanTargetSpec]] = {}
    seen_group_hosts: set[tuple[int, str | None, str]] = set()

    for spec in target_specs:
        if spec.explicit_port is None:
            ports = unique_ports
        elif include_matrix_ports_for_bare_explicit_targets and spec.scheme is None:
            ports = list(dict.fromkeys((int(spec.explicit_port), *unique_ports)))
        else:
            ports = [int(spec.explicit_port)]
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
