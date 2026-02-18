"""Honeypot listener runtime."""

from __future__ import annotations

import argparse
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


def parse_services(raw: str) -> set[str]:
    selected = {part.strip().lower() for part in raw.split(",") if part.strip()}
    unknown = selected - SUPPORTED_SERVICES
    if unknown:
        raise ValueError(f"unsupported services: {', '.join(sorted(unknown))}")
    if not selected:
        raise ValueError("at least one service must be selected")
    return selected


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
        if not (args.cert_file and args.key_file):
            console.warn("TLS enabled without custom cert/key; using bundled self-signed certificate")
        cert_path, key_path, temp_cert_dir = prepare_cert_files(args.cert_file, args.key_file)

    postgres_ssl_context = build_ssl_context(cert_path, key_path) if ("postgres" in services and args.postgres_tls) else None
    proxmox_ssl_context = build_ssl_context(cert_path, key_path) if ("proxmox" in services and args.proxmox_tls) else None

    if "postgres" in services:
        pg_server = make_postgres_server(
            args.bind,
            args.postgres_port,
            logger,
            postgres_tls=args.postgres_tls,
            ssl_context=postgres_ssl_context,
        )
        running.append(start_server("postgres", args.bind, args.postgres_port, pg_server, tls=args.postgres_tls))

    if "redis" in services:
        redis_server = make_redis_server(args.bind, args.redis_port, logger)
        running.append(start_server("redis", args.bind, args.redis_port, redis_server, tls=False))

    if "proxmox" in services:
        proxmox_handler = make_proxmox_handler(logger)
        proxmox_server = make_http_server(args.bind, args.proxmox_port, proxmox_handler, ssl_context=proxmox_ssl_context)
        running.append(start_server("proxmox", args.bind, args.proxmox_port, proxmox_server, tls=args.proxmox_tls))

    if "blackbox" in services:
        blackbox_handler = make_blackbox_handler(logger)
        blackbox_server = make_http_server(args.bind, args.blackbox_port, blackbox_handler, ssl_context=None)
        running.append(start_server("blackbox", args.bind, args.blackbox_port, blackbox_server, tls=False))

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
