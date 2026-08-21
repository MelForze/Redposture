"""Discovery scan stage."""

from __future__ import annotations

import argparse
import os
import ssl
import sys
import time
from collections.abc import Iterable, Iterator
from typing import Any

from .console import Console
from .exporters.discover import scan_exporter_presence
from .exporters.http_client import build_exporter_tls_context
from .exporters.output import emit_line as emit_output_line
from .exporters.output import format_scan_record
from .logger import AttemptLogger
from .profiles import default_exporter_ports, load_profiles
from .stage_runtime import progress_total_from_groups, should_use_global_progress, start_command_progress
from .utils import (
    DEFAULT_MAX_NETWORK_HOSTS,
    TargetParsePolicy,
    build_scan_execution_groups,
    collect_scan_ports,
    collect_scan_target_specs,
    stream_scan_target_specs,
)


def _chunk_target_specs_by_scheme(
    specs: Iterable[Any],
    *,
    size: int = 4096,
) -> Iterator[tuple[str, list[str]]]:
    buckets: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}
    for spec in specs:
        scheme = str(getattr(spec, "scheme", None) or "http").lower()
        host = str(spec.host)
        if host in seen.setdefault(scheme, set()):
            continue
        seen[scheme].add(host)
        bucket = buckets.setdefault(scheme, [])
        bucket.append(host)
        if len(bucket) >= size:
            yield scheme, bucket
            buckets[scheme] = []
    for scheme, bucket in buckets.items():
        if bucket:
            yield scheme, bucket


def _exporter_transport_kwargs(scheme: str, tls_context: ssl.SSLContext | None) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if scheme != "http":
        kwargs["scheme"] = scheme
    if tls_context is not None:
        kwargs["tls_context"] = tls_context
    return kwargs


def _emit_scan_summary(
    *,
    output_path: str | None,
    output_format: str,
    emit_line,
    hosts: int,
    checks: int,
    found: int,
    errors: int,
    found_by_host: dict[str, list[dict[str, object]]],
) -> None:
    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "type": "summary",
        "hosts": hosts,
        "checks": checks,
        "found": found,
        "errors": errors,
        "output_path": output_path,
        "found_exporters_by_host": {
            host: [str(item["exporter"]) for item in hits] for host, hits in found_by_host.items()
        },
    }
    line = format_scan_record(summary, output_format)
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "a", encoding="utf-8") as out_fh:
            emit_output_line(out_fh, emit_line, line)
    else:
        emit_output_line(None, emit_line, line)


def _run_large_scan_stage(
    args: argparse.Namespace,
    logger: AttemptLogger | None,
    console: Console,
    *,
    target_plan,
    custom_ports: list[int],
    profiles: dict[str, object],
    emit_line,
    stream_to_stdout: bool,
    tls_context: ssl.SSLContext | None,
) -> int:
    discovery_exporters = list(profiles["discovery_exporters"])  # type: ignore[call-overload]
    default_ports = default_exporter_ports(discovery_exporters)
    checks = 0
    found = 0
    errors = 0
    found_by_host: dict[str, list[dict[str, object]]] = {}
    chunk_index = 0
    try:
        if not target_plan.has_explicit_port_targets:
            for scheme, hosts in _chunk_target_specs_by_scheme(target_plan.iter_specs()):
                part_stats: dict[str, int] = {}
                part_checks, part_found, part_found_by_host = scan_exporter_presence(
                    hosts=hosts,
                    timeout=args.timeout,
                    output_path=args.output,
                    output_format=args.output_format,
                    logger=logger if args.debug else None,
                    emit_line=emit_line,
                    workers=args.workers,
                    retries=args.retries,
                    discovery_exporters=discovery_exporters,
                    custom_ports=custom_ports or None,
                    emit_summary=False,
                    show_progress=False,
                    output_mode="a" if chunk_index else "w",
                    progress_owner=getattr(args, "_progress_owner", None),
                    stats_sink=part_stats,
                    **_exporter_transport_kwargs(scheme, tls_context),
                )
                chunk_index += 1
                checks += part_checks
                found += part_found
                errors += int(part_stats.get("errors", 0))
                found_by_host.update({host: hits for host, hits in part_found_by_host.items() if hits})
        else:
            matrix_ports = tuple(custom_ports or default_ports)
            for port in target_plan.execution_ports(matrix_ports):
                for scheme, hosts in _chunk_target_specs_by_scheme(
                    target_plan.iter_specs_for_port(int(port), matrix_ports)
                ):
                    part_stats = {}
                    part_checks, part_found, part_found_by_host = scan_exporter_presence(
                        hosts=hosts,
                        timeout=args.timeout,
                        output_path=args.output,
                        output_format=args.output_format,
                        logger=logger if args.debug else None,
                        emit_line=emit_line,
                        workers=args.workers,
                        retries=args.retries,
                        discovery_exporters=discovery_exporters,
                        custom_ports=[int(port)],
                        emit_summary=False,
                        show_progress=False,
                        output_mode="a" if chunk_index else "w",
                        progress_owner=getattr(args, "_progress_owner", None),
                        stats_sink=part_stats,
                        **_exporter_transport_kwargs(scheme, tls_context),
                    )
                    chunk_index += 1
                    checks += part_checks
                    found += part_found
                    errors += int(part_stats.get("errors", 0))
                    found_by_host.update({host: hits for host, hits in part_found_by_host.items() if hits})
    except OSError as exc:
        console.error(f"failed to process scan output: {exc}")
        return 2

    _emit_scan_summary(
        output_path=args.output,
        output_format=args.output_format,
        emit_line=emit_line,
        hosts=target_plan.target_count,
        checks=checks,
        found=found,
        errors=errors,
        found_by_host=found_by_host,
    )
    if stream_to_stdout and args.output_format == "txt":
        console.info(f"scan complete: checks={checks} detected={found} errors={errors}")
    elif not stream_to_stdout:
        console.info(
            f"scan complete: checks={checks} detected={found} errors={errors} "
            f"format={args.output_format} output={args.output}"
        )
    if found == 0 and errors > 0:
        console.error(f"scan inconclusive: no exporter confirmed; {errors}/{checks} requests failed")
        return 1
    return 0


def run_scan_stage(args: argparse.Namespace, logger: AttemptLogger | None = None) -> int:
    console = Console(debug=args.debug)

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
        return 2

    targets = getattr(args, "targets", None) or getattr(args, "hosts", None)
    hosts_file = getattr(args, "hosts_file", None)
    if hosts_file:
        targets = f"{targets},{hosts_file}" if targets else hosts_file

    try:
        target_plan = stream_scan_target_specs(
            targets,
            policy=TargetParsePolicy(url_mode="preserve", path_policy="preserve"),
            exclude_targets=getattr(args, "out_targets", None),
        )
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2
    # D5 fix: previously any URL path in `-t http://host/api/metrics` was
    # silently discarded because the probe hard-codes `/metrics`. Warn the
    # operator so they know their path was ignored rather than sending them
    # in the dark against a different endpoint than they typed.
    paths_ignored: list[str] = []
    try:
        specs_for_path_check = target_plan.iter_specs() if target_plan.target_count <= DEFAULT_MAX_NETWORK_HOSTS else ()
        for spec in specs_for_path_check:
            path_val = str(getattr(spec, "path", "") or "").strip()
            if path_val and path_val not in {"/", "/metrics"}:
                paths_ignored.append(f"{spec.host}{path_val}")
    except AttributeError:
        pass
    if paths_ignored:
        console.warn(
            "ignoring path on {} target(s) — presence scan always probes /metrics: {}".format(
                len(paths_ignored),
                ", ".join(paths_ignored[:5]) + ("..." if len(paths_ignored) > 5 else ""),
            )
        )
    try:
        target_specs = (
            []
            if target_plan.target_count > DEFAULT_MAX_NETWORK_HOSTS
            else collect_scan_target_specs(targets, exclude_targets=getattr(args, "out_targets", None))
        )
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2
    hosts = list(dict.fromkeys(spec.host for spec in target_specs))

    try:
        custom_ports = collect_scan_ports(getattr(args, "ports", None))
    except ValueError as exc:
        console.error(f"failed to parse --ports: {exc}")
        return 2
    target_plan = target_plan.with_additional_ports_for_bare_explicit_targets(bool(custom_ports))

    try:
        profiles = load_profiles(args.profiles_file)
    except (OSError, ValueError) as exc:
        console.error(f"failed to load profiles: {exc}")
        return 2

    try:
        tls_context = build_exporter_tls_context(
            insecure=bool(getattr(args, "insecure", False)),
            ca_file=getattr(args, "tls_ca", None),
            cert_file=getattr(args, "tls_cert", None),
            key_file=getattr(args, "tls_key", None),
        )
    except (OSError, ValueError, ssl.SSLError) as exc:
        console.error(f"invalid exporter TLS configuration: {exc}")
        return 2

    if not target_plan or (target_plan.target_count <= DEFAULT_MAX_NETWORK_HOSTS and not target_specs):
        if targets and getattr(args, "out_targets", None):
            console.error("all targets were excluded by --out-target")
            return 2
        console.error("scan requires -t/--targets")
        return 2

    stream_to_stdout = not bool(args.output)
    stage_started_at = time.monotonic()

    def _split_tabbed_tag(left: str) -> tuple[str, str]:
        parts = left.split("\t", 1)
        if len(parts) != 2:
            return left.strip(), ""
        tag = parts[0].strip()
        rest = "\t" + parts[1]
        return tag, rest

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if " [*] " in line:
            if args.debug:
                console.plain(line, color="cyan")
            return
        if " [+] " in line:
            left, right = line.split(" [+] ", 1)
            tag, rest = _split_tabbed_tag(left)
            if tag == "SCAN":
                tag_text = f"{tag:<8}"
                rest_text = rest
            else:
                tag_text = tag
                rest_text = ""
            colored = (
                f"{console._paint(tag_text, 'blue', sys.stdout)}"
                f"{console._paint(rest_text, 'white', sys.stdout)} "
                f"{console._paint('[+]', 'green', sys.stdout)} "
                f"{console._paint(right, 'white', sys.stdout)}"
            )
            console.plain(colored)
            return
        if not args.debug and " [!] " not in line:
            return
        if " [!] " in line:
            console.plain(line, color="red")
            return
        if " [-] " in line:
            console.plain(line, color="yellow")
            return
        console.plain(line)

    if stream_to_stdout and args.output_format == "txt":
        ports_hint = f" ports={len(custom_ports)}(custom)" if custom_ports else ""
        console.info(
            f"scan started: hosts={target_plan.target_count} targets={target_plan.target_count} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} format=txt{ports_hint}"
        )
    if not stream_to_stdout:
        ports_hint = f" ports={len(custom_ports)}(custom)" if custom_ports else ""
        console.info(
            f"scan started: hosts={target_plan.target_count} targets={target_plan.target_count} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} "
            f"format={args.output_format} output={args.output}{ports_hint}"
        )

    if target_plan.target_count > DEFAULT_MAX_NETWORK_HOSTS:
        return _run_large_scan_stage(
            args,
            logger,
            console,
            target_plan=target_plan,
            custom_ports=custom_ports,
            profiles=profiles,
            emit_line=emit_line,
            stream_to_stdout=stream_to_stdout,
            tls_context=tls_context,
        )

    if args.debug:
        console.debug(f"pass=1 detect start total={len(hosts)}")
    detect_started_at = time.monotonic()

    has_target_overrides = any(spec.explicit_port is not None or spec.scheme is not None for spec in target_specs)
    if not has_target_overrides:
        scan_stats: dict[str, int] = {}
        try:
            checks, found, found_by_host = scan_exporter_presence(
                hosts=hosts,
                timeout=args.timeout,
                output_path=args.output,
                output_format=args.output_format,
                logger=logger if args.debug else None,
                emit_line=emit_line,
                workers=args.workers,
                retries=args.retries,
                discovery_exporters=profiles["discovery_exporters"],
                custom_ports=custom_ports or None,
                show_progress=should_use_global_progress(args.output_format, len(hosts)),
                progress_owner=getattr(args, "_progress_owner", None),
                stats_sink=scan_stats,
                **_exporter_transport_kwargs("http", tls_context),
            )
            errors = int(scan_stats.get("errors", 0))
        except OSError as exc:
            console.error(f"failed to process scan output: {exc}")
            return 2
    else:
        default_ports = default_exporter_ports(list(profiles["discovery_exporters"]))
        execution_groups = build_scan_execution_groups(
            target_specs,
            custom_ports or default_ports,
            include_scheme_in_key=True,
            include_matrix_ports_for_bare_explicit_targets=bool(custom_ports),
        )
        checks = 0
        found = 0
        errors = 0
        found_by_host = {host: [] for host in hosts}
        seen_hits: dict[str, set[tuple[str, int, str]]] = {host: set() for host in hosts}
        use_single_global_progress = should_use_global_progress(args.output_format, len(execution_groups))
        outer_progress = None
        if use_single_global_progress:
            global_total = progress_total_from_groups(group.hosts for group in execution_groups)
            outer_progress = start_command_progress(args, "SCAN", global_total, enabled=True, leave=True)
        try:
            for idx, group in enumerate(execution_groups):
                part_stats: dict[str, int] = {}
                part_checks, part_found, part_found_by_host = scan_exporter_presence(
                    hosts=group.hosts,
                    timeout=args.timeout,
                    output_path=args.output,
                    output_format=args.output_format,
                    logger=logger if args.debug else None,
                    emit_line=emit_line,
                    workers=args.workers,
                    retries=args.retries,
                    discovery_exporters=profiles["discovery_exporters"],
                    custom_ports=[group.port],
                    emit_summary=False,
                    show_progress=not use_single_global_progress,
                    progress_leave=False,
                    output_mode="a" if idx > 0 else "w",
                    progress_owner=getattr(args, "_progress_owner", None),
                    stats_sink=part_stats,
                    **_exporter_transport_kwargs(group.scheme_hint or "http", tls_context),
                )
                checks += part_checks
                found += part_found
                errors += int(part_stats.get("errors", 0))
                if outer_progress is not None:
                    outer_progress.advance(part_checks)
                for host, hits in part_found_by_host.items():
                    for hit in hits:
                        exporter = str(hit.get("exporter") or "")
                        try:
                            hit_port = int(hit.get("port", ""))
                        except (TypeError, ValueError):
                            continue
                        hit_key = (exporter, hit_port, str(hit.get("url") or ""))
                        if hit_key in seen_hits.setdefault(host, set()):
                            continue
                        seen_hits[host].add(hit_key)
                        found_by_host.setdefault(host, []).append(hit)
        except OSError as exc:
            console.error(f"failed to process scan output: {exc}")
            return 2
        finally:
            if outer_progress is not None:
                outer_progress.close()
        _emit_scan_summary(
            output_path=args.output,
            output_format=args.output_format,
            emit_line=emit_line,
            hosts=len(hosts),
            checks=checks,
            found=found,
            errors=errors,
            found_by_host=found_by_host,
        )

    detect_ms = int((time.monotonic() - detect_started_at) * 1000)
    deep_candidates = sum(1 for host in hosts if found_by_host.get(host))
    if args.debug:
        console.debug(f"pass=1 detect complete checks={checks} detected={found}")
        console.debug(f"stage_trace stage_name=detect_protocol attempt=1 duration_ms={detect_ms} result=ok error=-")
        console.debug(f"pass=2 deep start total={deep_candidates}")
        for host in hosts:
            host_hits = found_by_host.get(host, [])
            if host_hits:
                console.debug(f"{host} stage2_gate=run reason=detected={len(host_hits)}")
            else:
                console.debug(f"{host} stage2_gate=skip reason=detected=0")
        console.debug(f"pass=2 deep complete processed={deep_candidates}")
        console.debug("stage_trace stage_name=data attempt=1 duration_ms=0 result=ok error=-")
        total_ms = int((time.monotonic() - stage_started_at) * 1000)
        console.debug(
            f"stage_timing_summary status=ok attempts=1/1 detect_ms={detect_ms} data_ms=0 total_ms={total_ms}"
        )

    if stream_to_stdout:
        if args.output_format == "txt":
            console.info(f"scan complete: checks={checks} detected={found} errors={errors}")
        if found == 0 and errors > 0:
            console.error(f"scan inconclusive: no exporter confirmed; {errors}/{checks} requests failed")
            return 1
        return 0

    for host in hosts:
        hits = found_by_host.get(host, [])
        if not hits:
            console.warn(f"{host}: no known exporters detected")
            continue
        exporters = ", ".join(str(hit["exporter"]) for hit in hits)
        console.success(f"{host}: detected {len(hits)} exporter(s) [{exporters}]")
        for hit in hits:
            console.debug(
                f"{host}:{hit['port']} exporter={hit['exporter']} "
                f"status={hit['status']} method={hit['method']} url={hit['url']}"
            )

    console.info(
        f"scan complete: checks={checks} detected={found} errors={errors} "
        f"format={args.output_format} output={args.output}"
    )
    console.debug("debug mode enabled; detailed scan events emitted in text logs")
    if found == 0 and errors > 0:
        console.error(f"scan inconclusive: no exporter confirmed; {errors}/{checks} requests failed")
        return 1
    return 0
