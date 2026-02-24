"""Trigger stage."""

from __future__ import annotations

import argparse
import sys
import threading
import time
from typing import Any
from urllib.parse import urlparse

from .console import Console
from .listener_runtime import start_listeners_for_trigger, stop_started_listeners
from .logger import AttemptLogger
from .profiles import load_profiles
from .scanner import scan_exporters_and_trigger
from .servers import RunningServer
from .utils import collect_scan_targets, normalize_ip_literal, normalize_scan_host

_TRIGGER_EXPORTER_DISPLAY_NAMES = {
    "blackbox_exporter": "Blackbox Exporter",
    "postgres_exporter": "Postgres Exporter",
    "redis_exporter": "Redis Exporter",
    "proxmox_exporter": "Proxmox Exporter",
}

_EXPORTER_TO_LISTENER_SERVICE = {
    "blackbox_exporter": "blackbox",
    "postgres_exporter": "postgres",
    "redis_exporter": "redis",
    "proxmox_exporter": "proxmox",
}


def _clip_text(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return value[: width - 3] + "..."


def _render_trigger_row(console: Console, target: str, marker: str, body: str) -> None:
    marker_color = {"[*]": "cyan", "[+]": "green", "[-]": "yellow", "[!]": "red"}.get(marker, "white")
    clipped_target = _clip_text(target, 64)
    target_segment = "\t" + clipped_target + "\t-\t"
    line = (
        f"{console._paint('TRIGGER ', 'blue', sys.stdout)}"
        f"{console._paint(target_segment, 'white', sys.stdout)}"
        f" {console._paint(marker, marker_color, sys.stdout)} "
        f"{console._paint(body, 'white', sys.stdout)}"
    )
    console.plain(line)


def _render_trigger_callback_row(
    console: Console,
    callback_target: str,
    callback_port: str,
    marker: str,
    exporter_name: str,
    stage_tag: str = "TRIGGER",
) -> None:
    marker_color = {"[*]": "cyan", "[+]": "green", "[-]": "yellow", "[!]": "red"}.get(marker, "white")
    clipped_target = _clip_text(callback_target, 64)
    clipped_port = _clip_text(callback_port, 16)
    target_segment = "\t" + clipped_target + "\t" + clipped_port + "\t"
    line = (
        f"{console._paint(f'{stage_tag:<8}', 'blue', sys.stdout)}"
        f"{console._paint(target_segment, 'white', sys.stdout)}"
        f" {console._paint(marker, marker_color, sys.stdout)} "
        f"{console._paint(exporter_name, 'white', sys.stdout)}"
    )
    console.plain(line)


def _exporter_display_name(raw_name: str) -> str:
    key = (raw_name or "").strip().lower()
    return _TRIGGER_EXPORTER_DISPLAY_NAMES.get(key, raw_name)


def _with_listen_target_fmt(exporter: dict[str, Any], args: argparse.Namespace) -> str | None:
    name = str(exporter.get("name") or "")
    trigger_path = str(exporter.get("trigger_path") or "").strip()
    exporter_name = name.strip().lower()
    redis_port = int(getattr(args, "redis_port", 16379))
    postgres_port = int(getattr(args, "postgres_port", 15432))
    blackbox_port = int(getattr(args, "blackbox_port", 19115))
    proxmox_port = int(getattr(args, "proxmox_port", 18006))
    proxmox_tls = bool(getattr(args, "proxmox_tls", False))
    if exporter_name == "redis_exporter":
        return f"{{our_host}}:{redis_port}"
    if exporter_name == "postgres_exporter":
        return f"postgresql://postgres:postgres@{{our_host}}:{postgres_port}/postgres?sslmode=disable"
    if exporter_name == "blackbox_exporter":
        raw_target_fmt = str(exporter.get("target_fmt") or "").strip()
        parsed = urlparse(raw_target_fmt if "://" in raw_target_fmt else f"http://{raw_target_fmt}", scheme="http")
        scheme = parsed.scheme.lower() if parsed.scheme else "http"

        auth_prefix = ""
        if parsed.username is not None:
            auth_prefix = parsed.username
            if parsed.password is not None:
                auth_prefix += f":{parsed.password}"
            auth_prefix += "@"

        path = parsed.path or ""
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{auth_prefix}{{our_host}}:{blackbox_port}{path}{query}"
    if exporter_name == "proxmox_exporter":
        if trigger_path == "/pve":
            return f"{{our_host}}:{proxmox_port}"
        scheme = "https" if proxmox_tls else "http"
        return f"{scheme}://{{our_host}}:{proxmox_port}/api2/json/access/ticket"
    return None


def _patch_trigger_exporters_for_with_listen(
    trigger_exporters: list[dict[str, Any]],
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    patched: list[dict[str, Any]] = []
    for exporter in trigger_exporters:
        item = dict(exporter)
        override_target_fmt = _with_listen_target_fmt(item, args)
        if override_target_fmt:
            item["target_fmt"] = override_target_fmt
        patched.append(item)
    return patched


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
    callback_emit_lock = threading.Lock()
    emitted_scan_rows: set[tuple[str, str, str]] = set()

    def _emit_trigger_event(event: dict[str, Any]) -> None:
        phase = str(event.get("phase") or "")
        if phase == "detect_hit":
            scan_target = str(event.get("host") or "-")
            scan_port = str(event.get("exporter_port") or "-")
        elif phase == "callback_attempt":
            # Backward compatibility fallback for older scanner emitters.
            scan_target = str(event.get("host") or event.get("callback_target") or "-")
            scan_port = str(event.get("exporter_port") or event.get("callback_port") or "-")
        else:
            return
        exporter_name = _exporter_display_name(str(event.get("exporter") or "-"))
        row_key = (scan_target, scan_port, exporter_name)
        with callback_emit_lock:
            if row_key in emitted_scan_rows:
                return
            emitted_scan_rows.add(row_key)
            _render_trigger_callback_row(
                console,
                scan_target,
                scan_port,
                "[*]",
                exporter_name,
                stage_tag="SCAN",
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
        emit_trigger_event=_emit_trigger_event if args.with_listen else None,
    )
    attempted = int(summary.get("attempted", 0))
    display_success = int(summary.get("triggered", 0))
    display_fail = int(summary.get("failed", max(0, attempted - display_success)))

    if args.with_listen:
        callback_stats = logger.get_trigger_callback_stats()
        by_service = callback_stats.get("by_service", {})
        callback_based_success = 0
        by_exporter = summary.get("by_exporter")
        if isinstance(by_exporter, dict) and by_exporter:
            for exporter_name, exporter_stats in by_exporter.items():
                if not isinstance(exporter_stats, dict):
                    continue
                service_name = _EXPORTER_TO_LISTENER_SERVICE.get(str(exporter_name))
                if service_name is None:
                    continue
                exporter_attempted = int(exporter_stats.get("attempted", 0))
                callback_hits = int(by_service.get(service_name, 0))
                callback_based_success += min(exporter_attempted, callback_hits)
        else:
            callback_based_success = int(callback_stats.get("total", 0))

        display_success = min(attempted, callback_based_success)
        display_fail = max(0, attempted - display_success)
        if args.debug:
            console.debug(
                "with-listen summary mode: "
                f"callback_success={display_success} callback_fail={display_fail} "
                f"trigger_success={summary.get('triggered', 0)} trigger_fail={summary.get('failed', 0)}"
            )

    if show_trigger_info:
        console.info(
            "trigger complete: "
            f"hosts={len(hosts)} detected={summary['detected_exporters']} "
            f"attempts={attempted} success={display_success} fail={display_fail}"
        )
        if args.debug:
            for host, stats in sorted(summary["by_host"].items()):
                marker = "[+]" if stats["success"] > 0 else ("[-]" if stats["detected"] > 0 else "[!]")
                _render_trigger_row(
                    console,
                    host,
                    marker,
                    (
                        f"detected={stats['detected']} attempts={stats['attempted']} "
                        f"success={stats['success']} fail={stats['fail']}"
                    ),
                )
            for target in callback_targets:
                stats = summary["by_callback"].get(target, {"attempted": 0, "success": 0, "fail": 0})
                callback_attempted = int(stats.get("attempted", 0))
                callback_success = int(stats.get("success", 0))
                callback_fail = int(stats.get("fail", 0))
                marker = "[+]" if callback_success > 0 else ("[-]" if callback_attempted > 0 else "[!]")
                _render_trigger_row(
                    console,
                    f"callback={target}",
                    marker,
                    f"attempts={callback_attempted} success={callback_success} fail={callback_fail}",
                )
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
        console.info(f"trigger output file: {output_path}")

    trigger_exporters = profiles["trigger_exporters"]
    if args.with_listen:
        trigger_exporters = _patch_trigger_exporters_for_with_listen(trigger_exporters, args)
        proxmox_tls_enabled = bool(getattr(args, "proxmox_tls", False))
        proxmox_requires_tls = any(
            str(item.get("name") or "").strip().lower() == "proxmox_exporter"
            and str(item.get("trigger_path") or "").strip() == "/pve"
            for item in trigger_exporters
        )
        if proxmox_requires_tls and not proxmox_tls_enabled:
            console.warn(
                "proxmox callback likely to fail: proxmox_exporter /pve uses HTTPS target; "
                "enable --proxmox-tls to capture proxmox callbacks"
            )
        if args.debug:
            for item in trigger_exporters:
                console.debug(f"trigger exporter={item.get('name')} target_fmt={item.get('target_fmt')}")

    if not args.with_listen:
        _run_trigger_requests(
            args,
            logger,
            console,
            hosts,
            callback_targets,
            trigger_exporters,
            show_trigger_info=True,
            log_trigger_attempts=True,
        )
        return 0

    running: list[RunningServer] = []
    temp_cert_dir: str | None = None
    try:
        logger.set_trigger_callback_mode(
            True,
            callback_targets=callback_targets,
            deduplicate=not args.debug,
        )
        running, temp_cert_dir = start_listeners_for_trigger(args, logger, console)
        _run_trigger_requests(
            args,
            logger,
            console,
            hosts,
            callback_targets,
            trigger_exporters,
            show_trigger_info=True,
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
        logger.set_trigger_callback_mode(False)
        stop_started_listeners(running, temp_cert_dir)

    return 0
