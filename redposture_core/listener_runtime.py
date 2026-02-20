"""Listener runtime for RedPosture service emulation mode."""

from __future__ import annotations

import argparse
import os
import shutil
import time

from .console import Console
from .constants import SUPPORTED_SERVICES
from .logger import AttemptLogger
from .servers import (
    RunningServer,
    build_ssl_context,
    make_blackbox_handler,
    make_http_server,
    make_postgres_server,
    make_proxmox_handler,
    make_redis_server,
    prepare_cert_files,
    start_server,
)

_ADDRESS_IN_USE_ERRNOS = {48, 98, 10048}
_AUTO_CERT_KEY_PAIRS: tuple[tuple[str, str], ...] = (
    ("cert.pem", "key.pem"),
    ("server.crt", "server.key"),
    ("tls.crt", "tls.key"),
    ("fullchain.pem", "privkey.pem"),
)


def _autodetect_cert_key_files(search_dir: str) -> tuple[str | None, str | None]:
    for cert_name, key_name in _AUTO_CERT_KEY_PAIRS:
        cert_path = os.path.join(search_dir, cert_name)
        key_path = os.path.join(search_dir, key_name)
        if os.path.isfile(cert_path) and os.path.isfile(key_path):
            return cert_path, key_path
    return None, None


def parse_services(raw: str) -> set[str]:
    selected = {part.strip().lower() for part in raw.split(",") if part.strip()}
    unknown = selected - SUPPORTED_SERVICES
    if unknown:
        raise ValueError(f"unsupported services: {', '.join(sorted(unknown))}")
    if not selected:
        raise ValueError("at least one service must be selected")
    return selected


def _build_bind_error(service: str, bind: str, port: int, exc: OSError) -> str:
    detail = str(exc)
    if getattr(exc, "errno", None) in _ADDRESS_IN_USE_ERRNOS or "address already in use" in detail.lower():
        return f"{service} listener {bind}:{port} is already in use"
    return f"{service} listener {bind}:{port} failed to start: {detail}"


def _start_servers(
    args: argparse.Namespace,
    logger: AttemptLogger,
    services: set[str],
    console: Console,
) -> tuple[list[RunningServer], str | None]:
    running: list[RunningServer] = []
    temp_cert_dir: str | None = None

    need_tls = ("postgres" in services and args.postgres_tls) or ("proxmox" in services and args.proxmox_tls)
    cert_path: str | None = None
    key_path: str | None = None

    if need_tls:
        selected_cert = args.cert_file
        selected_key = args.key_file
        has_custom_cert = bool(selected_cert and selected_key)
        auto_detected = False
        if not has_custom_cert:
            detected_cert, detected_key = _autodetect_cert_key_files(os.getcwd())
            if detected_cert and detected_key:
                selected_cert = detected_cert
                selected_key = detected_key
                has_custom_cert = True
                auto_detected = True
        if not has_custom_cert:
            console.warn("TLS enabled without custom cert/key; using bundled self-signed certificate")
        elif auto_detected:
            console.info(f"TLS enabled; auto-detected cert/key: {selected_cert} + {selected_key}")
        cert_path, key_path, temp_cert_dir = prepare_cert_files(
            selected_cert,
            selected_key,
            generate_local_selfcert=False,
        )

    postgres_ssl_context = build_ssl_context(cert_path, key_path) if ("postgres" in services and args.postgres_tls) else None
    proxmox_ssl_context = build_ssl_context(cert_path, key_path) if ("proxmox" in services and args.proxmox_tls) else None

    if "postgres" in services:
        try:
            pg_server = make_postgres_server(
                args.bind,
                args.postgres_port,
                logger,
                postgres_tls=args.postgres_tls,
                ssl_context=postgres_ssl_context,
            )
            running.append(start_server("postgres", args.bind, args.postgres_port, pg_server, tls=args.postgres_tls))
        except OSError as exc:
            raise OSError(_build_bind_error("postgres", args.bind, args.postgres_port, exc)) from exc

    if "redis" in services:
        try:
            redis_server = make_redis_server(args.bind, args.redis_port, logger)
            running.append(start_server("redis", args.bind, args.redis_port, redis_server, tls=False))
        except OSError as exc:
            raise OSError(_build_bind_error("redis", args.bind, args.redis_port, exc)) from exc

    if "proxmox" in services:
        try:
            proxmox_handler = make_proxmox_handler(logger)
            proxmox_server = make_http_server(args.bind, args.proxmox_port, proxmox_handler, ssl_context=proxmox_ssl_context)
            running.append(start_server("proxmox", args.bind, args.proxmox_port, proxmox_server, tls=args.proxmox_tls))
        except OSError as exc:
            raise OSError(_build_bind_error("proxmox", args.bind, args.proxmox_port, exc)) from exc

    if "blackbox" in services:
        try:
            blackbox_handler = make_blackbox_handler(logger)
            blackbox_server = make_http_server(args.bind, args.blackbox_port, blackbox_handler, ssl_context=None)
            running.append(start_server("blackbox", args.bind, args.blackbox_port, blackbox_server, tls=False))
        except OSError as exc:
            raise OSError(_build_bind_error("blackbox", args.bind, args.blackbox_port, exc)) from exc

    console.success("listeners started")
    for item in running:
        scheme = "https" if item.tls and item.name == "proxmox" else "tcp"
        if item.name == "blackbox":
            scheme = "http"
        if item.name == "proxmox" and not item.tls:
            scheme = "http"
        console.info(f"{item.name}: {scheme}://{item.bind}:{item.port}")
    console.debug(f"services={','.join(sorted(services))}")
    return running, temp_cert_dir


def stop_started_listeners(running: list[RunningServer], temp_cert_dir: str | None) -> None:
    for item in running:
        try:
            item.server.shutdown()
            item.server.server_close()
        except Exception:
            pass
    if temp_cert_dir:
        shutil.rmtree(temp_cert_dir, ignore_errors=True)


def start_listeners_for_trigger(
    args: argparse.Namespace,
    logger: AttemptLogger,
    console: Console,
) -> tuple[list[RunningServer], str | None]:
    services = parse_services(args.services)
    return _start_servers(args, logger, services, console)


def run_listeners(args: argparse.Namespace, logger: AttemptLogger) -> int:
    console = Console(debug=args.debug)

    try:
        services = parse_services(args.services)
    except ValueError as exc:
        console.error(str(exc))
        return 2

    running: list[RunningServer] = []
    temp_cert_dir: str | None = None

    try:
        running, temp_cert_dir = _start_servers(args, logger, services, console)
        console.info("press Ctrl+C to stop")

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.info("stopping servers...")
    except OSError as exc:
        console.error(f"failed to start service: {exc}")
        return 1
    except ValueError as exc:
        console.error(str(exc))
        return 2
    finally:
        stop_started_listeners(running, temp_cert_dir)

    return 0
