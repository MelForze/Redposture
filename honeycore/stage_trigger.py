"""Trigger stage."""

from __future__ import annotations

import argparse
import time
from typing import Any

from .console import Console
from .listener_runtime import start_listeners_for_trigger, stop_started_listeners
from .logger import AttemptLogger
from .profiles import load_profiles
from .scanner import scan_exporters_and_trigger
from .servers import RunningServer
from .utils import collect_scan_targets, normalize_ip_literal, normalize_scan_host


def _run_trigger_requests(
    args: argparse.Namespace,
    logger: AttemptLogger,
    console: Console,
    hosts: list[str],
    callback_targets: list[str],
    trigger_exporters: list[dict[str, Any]],
    show_trigger_info: bool,
    log_trigger_attempts: bool,
) -> dict[str, Any]:
    callbacks = ",".join(callback_targets)
    if show_trigger_info:
        console.info(
            f"trigger started: hosts={len(hosts)} callbacks={callbacks} "
            f"timeout={args.timeout}s workers={args.workers} retries={args.retries}"
        )
    trigger_logger = logger if log_trigger_attempts else None
    summary = scan_exporters_and_trigger(
        logger=trigger_logger,
        hosts=hosts,
        callback_targets=callback_targets,
        timeout=args.timeout,
        workers=args.workers,
        retries=args.retries,
        trigger_exporters=trigger_exporters,
        log_trigger_events_only=not args.debug,
    )
    if show_trigger_info:
        console.info(
            "trigger complete: "
            f"hosts={len(hosts)} detected={summary['detected_exporters']} "
            f"attempts={summary['attempted']} success={summary['triggered']} fail={summary['failed']}"
        )
        for target in callback_targets:
            stats = summary["by_callback"].get(target, {"success": 0, "fail": 0})
            console.info(f"callback={target} success={stats['success']} fail={stats['fail']}")
    for host, stats in sorted(summary["by_host"].items()):
        console.debug(
            f"host={host} detected={stats['detected']} "
            f"attempts={stats['attempted']} success={stats['success']} fail={stats['fail']}"
        )
    if show_trigger_info:
        console.debug("debug mode enabled; detailed trigger events emitted in text logs")
    return summary


def run_trigger_stage(args: argparse.Namespace, logger: AttemptLogger) -> int:
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
        console.error("trigger requires -t/--targets")
        return 2

    callback_targets: list[str] = []

    callback_ip = normalize_ip_literal(args.callback_ip or "")
    if args.callback_ip and not callback_ip:
        console.error("--callback-ip must be a valid IP address")
        return 2
    if callback_ip:
        callback_targets.append(callback_ip)

    callback_dns = normalize_scan_host(args.callback_dns or "")
    if args.callback_dns and not callback_dns:
        console.error("--callback-dns must be a valid DNS name or host")
        return 2
    if callback_dns and callback_dns not in callback_targets:
        callback_targets.append(callback_dns)

    if not callback_targets:
        console.error("trigger requires --callback-ip and/or --callback-dns")
        return 2

    output_path = getattr(args, "output", None)
    if output_path:
        try:
            logger.set_text_output(output_path)
        except OSError as exc:
            console.error(f"failed to open trigger output file: {exc}")
            return 2
        if not args.with_listen:
            console.info(f"trigger output file: {output_path}")

    if not args.with_listen:
        _run_trigger_requests(
            args,
            logger,
            console,
            hosts,
            callback_targets,
            profiles["trigger_exporters"],
            show_trigger_info=True,
            log_trigger_attempts=True,
        )
        return 0

    running: list[RunningServer] = []
    temp_cert_dir: str | None = None
    try:
        running, temp_cert_dir = start_listeners_for_trigger(args, logger, console)
        _run_trigger_requests(
            args,
            logger,
            console,
            hosts,
            callback_targets,
            profiles["trigger_exporters"],
            show_trigger_info=False,
            log_trigger_attempts=False,
        )
        console.info("listeners are up; waiting for incoming events (Ctrl+C to stop)")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.info("stopping listeners...")
        return 0
    except OSError as exc:
        console.error(f"failed to start service: {exc}")
        return 1
    except ValueError as exc:
        console.error(str(exc))
        return 2
    finally:
        stop_started_listeners(running, temp_cert_dir)

    return 0
