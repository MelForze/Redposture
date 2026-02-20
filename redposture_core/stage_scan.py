"""Discovery scan stage."""

from __future__ import annotations

import argparse
import sys

from .console import Console
from .logger import AttemptLogger
from .profiles import load_profiles
from .scanner import scan_exporter_presence
from .utils import collect_scan_ports, collect_scan_targets


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
        hosts = collect_scan_targets(targets)
    except (OSError, ValueError) as exc:
        console.error(f"failed to parse targets: {exc}")
        return 2

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

    if not hosts:
        console.error("scan requires -t/--targets")
        return 2

    stream_to_stdout = not bool(args.output)

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
            f"scan started: hosts={len(hosts)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} format=txt{ports_hint}"
        )
    if not stream_to_stdout:
        ports_hint = f" ports={len(custom_ports)}(custom)" if custom_ports else ""
        console.info(
            f"scan started: hosts={len(hosts)} timeout={args.timeout}s "
            f"workers={args.workers} retries={args.retries} "
            f"format={args.output_format} output={args.output}{ports_hint}"
        )

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
        )
    except OSError as exc:
        console.error(f"failed to process scan output: {exc}")
        return 2

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

    console.info(
        f"scan complete: checks={checks} detected={found} "
        f"format={args.output_format} output={args.output}"
    )
    console.debug("debug mode enabled; detailed scan events emitted in text logs")
    return 0
