"""Collect stage."""

from __future__ import annotations

import argparse

from .console import Console
from .logger import AttemptLogger
from .profiles import load_profiles
from .scanner import collect_exporter_debug_data
from .utils import collect_scan_targets


def run_collect_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.max_bytes <= 0:
        console.error("--max-bytes must be > 0")
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

    def emit_line(line: str) -> None:
        if args.output_format != "txt":
            print(line, flush=True)
            return
        if line.startswith("[OK"):
            console.plain(line, color="green")
            return
        if line.startswith("[FAIL]"):
            console.plain(line, color="yellow")
            return
        if line.startswith("[SUMMARY]"):
            console.plain(line, color="cyan")
            return
        console.plain(line)

    if stream_to_stdout and args.output_format == "txt":
        console.info(
            f"collect started: hosts={len(hosts)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} format=txt"
        )
    if not stream_to_stdout:
        console.info(
            f"collect started: hosts={len(hosts)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} "
            f"format={args.output_format} output={args.output}"
        )
    try:
        requests, success = collect_exporter_debug_data(
            logger=logger if args.debug else None,
            hosts=hosts,
            timeout=args.timeout,
            output_path=args.output,
            output_format=args.output_format,
            max_bytes=args.max_bytes,
            emit_line=emit_line,
            workers=args.workers,
            retries=args.retries,
            collect_exporters=profiles["collect_exporters"],
            collect_debug_endpoints=profiles["collect_debug_endpoints"],
        )
    except OSError as exc:
        console.error(f"failed to process collect output: {exc}")
        return 2

    if stream_to_stdout:
        if args.output_format == "txt":
            console.info(f"collect complete: hosts={len(hosts)} requests={requests} success={success}")
        return 0

    console.info(
        f"collect complete: hosts={len(hosts)} requests={requests} success={success} "
        f"format={args.output_format} output={args.output}"
    )
    console.debug("debug mode enabled; detailed collect events emitted in text logs")
    return 0
