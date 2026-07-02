"""Discovery scan stage."""

from __future__ import annotations

import argparse
import os
import sys
import time

from .console import Console
from .exporters.discover import scan_exporter_presence
from .exporters.output import emit_line as emit_output_line
from .exporters.output import format_scan_record
from .logger import AttemptLogger
from .profiles import default_exporter_ports, load_profiles
from .stage_runtime import progress_total_from_groups, should_use_global_progress, start_command_progress
from .utils import (
    DEFAULT_MAX_NETWORK_HOSTS,
    TargetParsePolicy,
    build_scan_execution_groups,
    chunked_hosts,
    collect_scan_ports,
    collect_scan_target_specs,
    stream_scan_target_specs,
)


def _emit_scan_summary(
    *,
    output_path: str | None,
    output_format: str,
    emit_line,
    hosts: int,
    checks: int,
    found: int,
    found_by_host: dict[str, list[dict[str, object]]],
) -> None:
    if not output_path:
        return
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "type": "summary",
        "hosts": hosts,
        "checks": checks,
        "found": found,
        "output_path": output_path,
        "found_exporters_by_host": {
            host: [str(item["exporter"]) for item in hits] for host, hits in found_by_host.items()
        },
    }
    with open(output_path, "a", encoding="utf-8") as out_fh:
        emit_output_line(out_fh, emit_line, format_scan_record(summary, output_format))


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
) -> int:
    discovery_exporters = list(profiles["discovery_exporters"])  # type: ignore[call-overload]
    default_ports = default_exporter_ports(discovery_exporters)
    checks = 0
    found = 0
    found_by_host: dict[str, list[dict[str, object]]] = {}
    chunk_index = 0
    try:
        if not target_plan.has_explicit_port_targets:
            for hosts in chunked_hosts(target_plan.iter_hosts()):
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
                )
                chunk_index += 1
                checks += part_checks
                found += part_found
                found_by_host.update({host: hits for host, hits in part_found_by_host.items() if hits})
        else:
            matrix_ports = tuple(custom_ports or default_ports)
            for port in target_plan.execution_ports(matrix_ports):
                for hosts in chunked_hosts(target_plan.iter_hosts_for_port(int(port), matrix_ports)):
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
                    )
                    chunk_index += 1
                    checks += part_checks
                    found += part_found
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
        found_by_host=found_by_host,
    )
    if stream_to_stdout and args.output_format == "txt":
        console.info(f"scan complete: checks={checks} detected={found}")
    elif not stream_to_stdout:
        console.info(
            f"scan complete: checks={checks} detected={found} format={args.output_format} output={args.output}"
        )
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
        )
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2
    if target_plan.has_scheme("https"):
        console.error("exporters scan accepts only http:// URL targets for -t/--targets")
        return 2
    # D5 fix: previously any URL path in `-t http://host/api/metrics` was
    # silently discarded because the probe hard-codes `/metrics`. Warn the
    # operator so they know their path was ignored rather than sending them
    # in the dark against a different endpoint than they typed.
    paths_ignored: list[str] = []
    try:
        for spec in target_plan.iter_specs():
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
            [] if target_plan.target_count > DEFAULT_MAX_NETWORK_HOSTS else collect_scan_target_specs(targets)
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

    try:
        profiles = load_profiles(args.profiles_file)
    except (OSError, ValueError) as exc:
        console.error(f"failed to load profiles: {exc}")
        return 2

    if not target_plan or (target_plan.target_count <= DEFAULT_MAX_NETWORK_HOSTS and not target_specs):
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
        if not args.debug:
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
        )

    if args.debug:
        console.debug(f"pass=1 detect start total={len(hosts)}")
    detect_started_at = time.monotonic()

    has_explicit_port_targets = any(spec.explicit_port is not None for spec in target_specs)
    if not has_explicit_port_targets:
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
            )
        except OSError as exc:
            console.error(f"failed to process scan output: {exc}")
            return 2
    else:
        default_ports = default_exporter_ports(list(profiles["discovery_exporters"]))
        execution_groups = build_scan_execution_groups(
            target_specs,
            custom_ports or default_ports,
            include_scheme_in_key=False,
        )
        checks = 0
        found = 0
        found_by_host = {host: [] for host in hosts}
        seen_hits: dict[str, set[tuple[str, int]]] = {host: set() for host in hosts}
        use_single_global_progress = should_use_global_progress(args.output_format, len(execution_groups))
        outer_progress = None
        if use_single_global_progress:
            global_total = progress_total_from_groups(group.hosts for group in execution_groups)
            outer_progress = start_command_progress(args, "SCAN", global_total, enabled=True, leave=True)
        try:
            for idx, group in enumerate(execution_groups):
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
                )
                checks += part_checks
                found += part_found
                if outer_progress is not None:
                    outer_progress.advance(part_checks)
                for host, hits in part_found_by_host.items():
                    for hit in hits:
                        exporter = str(hit.get("exporter") or "")
                        try:
                            hit_port = int(hit.get("port", ""))
                        except (TypeError, ValueError):
                            continue
                        hit_key = (exporter, hit_port)
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
            console.info(f"scan complete: checks={checks} detected={found}")
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

    console.info(f"scan complete: checks={checks} detected={found} format={args.output_format} output={args.output}")
    console.debug("debug mode enabled; detailed scan events emitted in text logs")
    return 0
