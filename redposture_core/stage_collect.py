"""Collect stage."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from .constants import COLLECT_DEEP_ENDPOINT_TEMPLATES
from .console import Console
from .logger import AttemptLogger
from .profiles import load_profiles
from .scanner import collect_exporter_debug_data, scan_exporter_presence
from .stage_validate import run_validation_records
from .utils import collect_scan_targets

COLLECT_VALIDATE_INPUT_FORMAT = "auto"
COLLECT_VALIDATE_SHOW = True
COLLECT_VALIDATE_MAX_LINES = 0
COLLECT_VALIDATE_FAIL_ON_CREDS = False


def _materialize_collect_endpoint(template: str, pprof_seconds: int, trace_seconds: int) -> str:
    return (
        str(template)
        .replace("{pprof_seconds}", str(pprof_seconds))
        .replace("{trace_seconds}", str(trace_seconds))
        .strip()
    )


def _build_collect_endpoints(
    base_endpoints: list[str] | tuple[str, ...],
    *,
    deep: bool,
    pprof_seconds: int,
    trace_seconds: int,
) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()

    for endpoint in base_endpoints:
        rendered = _materialize_collect_endpoint(endpoint, pprof_seconds, trace_seconds)
        if not rendered or not rendered.startswith("/") or rendered in seen:
            continue
        seen.add(rendered)
        result.append(rendered)

    if deep:
        for template in COLLECT_DEEP_ENDPOINT_TEMPLATES:
            rendered = _materialize_collect_endpoint(template, pprof_seconds, trace_seconds)
            if not rendered or rendered in seen:
                continue
            seen.add(rendered)
            result.append(rendered)

    return tuple(result)


def run_collect_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
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
        hosts = collect_scan_targets(targets)
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2

    try:
        profiles = load_profiles(args.profiles_file)
    except (OSError, ValueError) as exc:
        console.error(f"failed to load profiles: {exc}")
        return 2

    if not hosts:
        console.error("collect requires -t/--targets")
        return 2

    stream_to_stdout = not bool(args.output)
    save_responses_dir = getattr(args, "save_responses_dir", None)
    deep = bool(getattr(args, "deep", False))
    pprof_seconds = int(getattr(args, "pprof_seconds", 5))
    trace_seconds = int(getattr(args, "trace_seconds", 2))
    collected_records: list[dict[str, Any]] = []
    collect_endpoints = _build_collect_endpoints(
        profiles["collect_debug_endpoints"],
        deep=deep,
        pprof_seconds=pprof_seconds,
        trace_seconds=trace_seconds,
    )
    if args.debug:
        mode = "deep" if deep else "default"
        console.debug(f"collect endpoints mode={mode} count={len(collect_endpoints)}")

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
        if line.startswith("SCAN"):
            if not args.debug:
                return
        if " [*] " in line:
            if args.debug:
                console.plain(line, color="cyan")
            return
        if " [+] " in line:
            left, right = line.split(" [+] ", 1)
            tag, rest = _split_tabbed_tag(left)
            if tag in {"SCAN", "COLLECT"}:
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

    if args.debug and stream_to_stdout and args.output_format == "txt":
        save_suffix = f" save_responses={save_responses_dir}" if save_responses_dir else ""
        console.info(
            f"collect started: hosts={len(hosts)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} format=txt{save_suffix}"
        )
    if args.debug and not stream_to_stdout:
        save_suffix = f" save_responses={save_responses_dir}" if save_responses_dir else ""
        console.info(
            f"collect started: hosts={len(hosts)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} "
            f"format={args.output_format} output={args.output}{save_suffix}"
        )

    scan_checks = 0
    scan_found = 0
    requests = 0
    success = 0
    found_by_host: dict[str, list[dict[str, Any]]] = {host: [] for host in hosts}
    collect_output_mode = "w"
    collect_index_mode = "w"

    for host in hosts:
        try:
            host_checks, host_found, host_found_map = scan_exporter_presence(
                hosts=[host],
                timeout=args.timeout,
                output_path=None,
                output_format="txt",
                logger=logger if args.debug else None,
                emit_line=emit_line if args.output_format == "txt" else None,
                workers=args.workers,
                retries=args.retries,
                discovery_exporters=profiles["discovery_exporters"],
                emit_summary=False,
            )
        except OSError as exc:
            console.error(f"failed to process collect discovery scan: {exc}")
            return 2

        scan_checks += host_checks
        scan_found += host_found
        host_hits = list(host_found_map.get(host, []))
        found_by_host[host] = host_hits

        if args.debug:
            console.debug(f"collect discovery host={host}: checks={host_checks} detected={host_found}")

        if host_found <= 0:
            continue

        try:
            host_requests, host_success = collect_exporter_debug_data(
                logger=logger if args.debug else None,
                hosts=[host],
                timeout=args.timeout,
                output_path=args.output,
                output_format=args.output_format,
                emit_line=emit_line,
                workers=args.workers,
                retries=args.retries,
                collect_exporters=profiles["collect_exporters"],
                collect_debug_endpoints=collect_endpoints,
                found_by_host={host: host_hits},
                save_responses_dir=save_responses_dir,
                records_sink=collected_records,
                output_mode=collect_output_mode,
                index_mode=collect_index_mode,
                emit_summary=False,
            )
        except OSError as exc:
            console.error(f"failed to process collect output: {exc}")
            return 2

        requests += host_requests
        success += host_success
        if args.output:
            collect_output_mode = "a"
        if save_responses_dir:
            collect_index_mode = "a"

    if args.debug:
        console.debug(f"collect discovery: checks={scan_checks} detected={scan_found}")

    if scan_found <= 0:
        if save_responses_dir:
            os.makedirs(save_responses_dir, exist_ok=True)
            index_path = os.path.join(save_responses_dir, "index.jsonl")
            with open(index_path, "w", encoding="utf-8"):
                pass
        if stream_to_stdout and args.output_format == "txt":
            save_suffix = f" saved={save_responses_dir}" if save_responses_dir else ""
            console.info(
                f"collect complete: hosts={len(hosts)} checks={scan_checks} detected=0 requests=0 success=0{save_suffix}"
            )
        if not stream_to_stdout:
            save_suffix = f" saved={save_responses_dir}" if save_responses_dir else ""
            console.info(
                f"collect complete: hosts={len(hosts)} checks={scan_checks} detected=0 requests=0 success=0 "
                f"format={args.output_format} output={args.output}{save_suffix}"
            )
            if args.debug:
                console.debug("debug mode enabled; detailed collect events emitted in text logs")
        validate_rc = run_validation_records(
            collected_records,
            input_format=COLLECT_VALIDATE_INPUT_FORMAT,
            show=COLLECT_VALIDATE_SHOW,
            max_lines=COLLECT_VALIDATE_MAX_LINES,
            fail_on_creds=COLLECT_VALIDATE_FAIL_ON_CREDS,
            debug=bool(args.debug),
            console=console,
        )
        if validate_rc == 2:
            return 2
        if validate_rc == 1:
            return 1
        return 0

    if stream_to_stdout:
        if args.output_format == "txt":
            save_suffix = f" saved={save_responses_dir}" if save_responses_dir else ""
            console.info(
                f"collect complete: hosts={len(hosts)} checks={scan_checks} "
                f"detected={scan_found} requests={requests} success={success}{save_suffix}"
            )
    else:
        save_suffix = f" saved={save_responses_dir}" if save_responses_dir else ""
        console.info(
            f"collect complete: hosts={len(hosts)} checks={scan_checks} detected={scan_found} "
            f"requests={requests} success={success} "
            f"format={args.output_format} output={args.output}{save_suffix}"
        )
        if args.debug:
            console.debug("debug mode enabled; detailed collect events emitted in text logs")
    validate_rc = run_validation_records(
        collected_records,
        input_format=COLLECT_VALIDATE_INPUT_FORMAT,
        show=COLLECT_VALIDATE_SHOW,
        max_lines=COLLECT_VALIDATE_MAX_LINES,
        fail_on_creds=COLLECT_VALIDATE_FAIL_ON_CREDS,
        debug=bool(args.debug),
        console=console,
    )
    if validate_rc == 2:
        return 2
    if validate_rc == 1:
        return 1
    return 0
