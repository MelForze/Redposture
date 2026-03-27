"""Main CLI orchestration."""

from __future__ import annotations

import contextlib
import os
import sys
import threading
from collections.abc import Iterator
from typing import Any, TextIO

from .cli_args import (
    COMMAND_CLICKHOUSE,
    COMMAND_COLLECT,
    COMMAND_CONSUL,
    COMMAND_DB,
    COMMAND_ETCD,
    COMMAND_EXPORTERS,
    COMMAND_GITLAB,
    COMMAND_GRAFANA,
    COMMAND_KAFKA,
    COMMAND_KUBEAPI,
    COMMAND_POSTGRES,
    COMMAND_PROXMOX,
    COMMAND_QDRANT,
    COMMAND_REDIS,
    COMMAND_REGISTRY,
    COMMAND_SCAN,
    COMMAND_SELFCERT,
    COMMAND_TRIGGER,
    COMMAND_ZOOKEEPER,
    parse_args,
)
from .logger import AttemptLogger
from .network_proxy import parse_proxy_config, proxy_socket_context
from .stage_clickhouse import run_clickhouse_stage
from .stage_collect import run_collect_stage
from .stage_consul import run_consul_stage
from .stage_etcd import run_etcd_stage
from .stage_gitlab import run_gitlab_stage
from .stage_grafana import run_grafana_stage
from .stage_kafka import run_kafka_stage
from .stage_kubeapi import run_kubeapi_stage
from .stage_postgres import run_postgres_stage
from .stage_proxmox import run_proxmox_stage
from .stage_qdrant import run_qdrant_stage
from .stage_redis import run_redis_stage
from .stage_registry import run_registry_stage
from .stage_scan import run_scan_stage
from .stage_selfcert import run_selfcert_stage
from .stage_trigger import run_trigger_stage
from .stage_zookeeper import run_zookeeper_stage


def _should_auto_init_runtime_db(args: Any) -> bool:
    command = getattr(args, "command", None)
    if command in {None, COMMAND_SELFCERT, COMMAND_DB}:
        return False
    return True


def _try_auto_init_runtime_db(args: Any) -> None:
    if not _should_auto_init_runtime_db(args):
        return
    try:
        from .db.config import resolve_database_settings
        from .db.services import initialize_runtime_database

        db_url = resolve_database_settings().db_url
        initialize_runtime_database(db_url)
    except Exception as exc:
        if getattr(args, "debug", False):
            print(f"[warn] db auto-init failed: {exc}", file=sys.stderr)


def _module_name_for_auto_ingest(args: Any) -> str | None:
    command = getattr(args, "command", None)
    if command in {
        COMMAND_REDIS,
        COMMAND_REGISTRY,
        COMMAND_GRAFANA,
        COMMAND_GITLAB,
        COMMAND_CONSUL,
        COMMAND_QDRANT,
        COMMAND_KUBEAPI,
        COMMAND_KAFKA,
        COMMAND_POSTGRES,
        COMMAND_CLICKHOUSE,
        COMMAND_ETCD,
        COMMAND_PROXMOX,
        COMMAND_ZOOKEEPER,
    }:
        return str(command)
    if command == COMMAND_EXPORTERS:
        action = getattr(args, "exporters_action", None)
        if action in {COMMAND_SCAN, COMMAND_TRIGGER, COMMAND_COLLECT}:
            return COMMAND_EXPORTERS
    if command in {COMMAND_SCAN, COMMAND_TRIGGER, COMMAND_COLLECT}:
        return COMMAND_EXPORTERS
    return None


def _should_auto_ingest_output(args: Any) -> bool:
    if getattr(args, "command", None) in {COMMAND_DB, COMMAND_SELFCERT, None}:
        return False
    if str(getattr(args, "output_format", "") or "").strip().lower() != "json":
        return False
    if _module_name_for_auto_ingest(args) is None:
        return False
    output_path = str(getattr(args, "output", "") or "").strip()
    return bool(output_path)


def _try_auto_ingest_output(args: Any) -> None:
    if not _should_auto_ingest_output(args):
        return

    output_path = str(getattr(args, "output", "") or "").strip()
    if not output_path or not os.path.exists(output_path):
        print("[warn] db auto-ingest skipped: JSON output file was not created", file=sys.stderr)
        return

    module_name = _module_name_for_auto_ingest(args)
    if module_name is None:
        return

    try:
        from .db.config import resolve_database_settings
        from .db.services import DatabaseService, IngestService, initialize_runtime_database

        db_url = resolve_database_settings().db_url
        initialize_runtime_database(db_url)
        db = DatabaseService(db_url)
        try:
            ingest_service = IngestService(db.session_factory)
            ingest_service.ingest_file(
                workspace_slug=None,
                module_name=module_name,
                json_file=output_path,
            )
        finally:
            db.close()
    except Exception as exc:
        print(f"[warn] db auto-ingest failed for {module_name}: {exc}", file=sys.stderr)


class _TeeStream:
    def __init__(self, primary: TextIO, mirror: TextIO, lock: threading.Lock) -> None:
        self._primary = primary
        self._mirror = mirror
        self._lock = lock

    @property
    def encoding(self) -> str | None:
        return getattr(self._primary, "encoding", None)

    def write(self, data: str) -> int:
        with self._lock:
            self._primary.write(data)
            self._mirror.write(data)
        return len(data)

    def flush(self) -> None:
        with self._lock:
            self._primary.flush()
            self._mirror.flush()

    def isatty(self) -> bool:
        try:
            return bool(self._primary.isatty())
        except Exception:
            return False

    def fileno(self) -> int:
        return self._primary.fileno()


@contextlib.contextmanager
def _tee_console_output(log_path: str) -> Iterator[None]:
    path = str(log_path).strip()
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(path, "a", encoding="utf-8") as log_fh:
        stdout_orig = sys.stdout
        stderr_orig = sys.stderr
        lock = threading.Lock()
        sys.stdout = _TeeStream(stdout_orig, log_fh, lock)  # type: ignore[assignment]
        sys.stderr = _TeeStream(stderr_orig, log_fh, lock)  # type: ignore[assignment]
        try:
            yield
        finally:
            try:
                sys.stdout.flush()
                sys.stderr.flush()
            finally:
                sys.stdout = stdout_orig
                sys.stderr = stderr_orig


def _run_command(args: Any, logger: AttemptLogger) -> int:
    if args.command == COMMAND_EXPORTERS:
        action = getattr(args, "exporters_action", None)
        if action == COMMAND_SCAN:
            return run_scan_stage(args, logger)
        if action == COMMAND_TRIGGER:
            return run_trigger_stage(args, logger)
        if action == COMMAND_COLLECT:
            return run_collect_stage(args, logger)
        print(f"[error] unsupported exporters action: {action}", file=sys.stderr)
        return 2

    if args.command == COMMAND_DB:
        from .db.cli import run_db_command

        return run_db_command(args)

    if args.command == COMMAND_SCAN:
        return run_scan_stage(args, logger)

    if args.command == COMMAND_TRIGGER:
        return run_trigger_stage(args, logger)

    if args.command == COMMAND_COLLECT:
        return run_collect_stage(args, logger)

    if args.command == COMMAND_REDIS:
        return run_redis_stage(args, logger)

    if args.command == COMMAND_REGISTRY:
        return run_registry_stage(args, logger)

    if args.command == COMMAND_GRAFANA:
        return run_grafana_stage(args, logger)

    if args.command == COMMAND_GITLAB:
        return run_gitlab_stage(args, logger)

    if args.command == COMMAND_CONSUL:
        return run_consul_stage(args, logger)

    if args.command == COMMAND_QDRANT:
        return run_qdrant_stage(args, logger)

    if args.command == COMMAND_KUBEAPI:
        return run_kubeapi_stage(args, logger)

    if args.command == COMMAND_KAFKA:
        return run_kafka_stage(args, logger)

    if args.command == COMMAND_POSTGRES:
        return run_postgres_stage(args, logger)

    if args.command == COMMAND_CLICKHOUSE:
        return run_clickhouse_stage(args, logger)

    if args.command == COMMAND_ETCD:
        return run_etcd_stage(args, logger)

    if args.command == COMMAND_PROXMOX:
        return run_proxmox_stage(args, logger)

    if args.command == COMMAND_ZOOKEEPER:
        return run_zookeeper_stage(args, logger)

    if args.command == COMMAND_SELFCERT:
        return run_selfcert_stage(args)

    print(f"[error] unsupported command: {args.command}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logger = AttemptLogger()
    log_path = str(getattr(args, "log", "") or "").strip()
    raw_proxy = str(getattr(args, "proxy", "") or "").strip()
    proxy_cfg = None
    if raw_proxy and getattr(args, "command", None) != COMMAND_PROXMOX:
        proxy_cfg, proxy_error = parse_proxy_config(raw_proxy)
        if proxy_error:
            print(f"[error] failed to parse --proxy: {proxy_error}", file=sys.stderr)
            return 2
    try:
        with proxy_socket_context(proxy_cfg):
            if log_path:
                try:
                    with _tee_console_output(log_path):
                        _try_auto_init_runtime_db(args)
                        rc = _run_command(args, logger)
                        if rc == 0:
                            _try_auto_ingest_output(args)
                        return rc
                except OSError as exc:
                    print(f"[error] failed to open --log file '{log_path}': {exc}", file=sys.stderr)
                    return 2
            _try_auto_init_runtime_db(args)
            rc = _run_command(args, logger)
            if rc == 0:
                _try_auto_ingest_output(args)
            return rc
    finally:
        logger.close()
