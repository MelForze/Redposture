"""Main CLI orchestration."""

from __future__ import annotations

import contextlib
import os
import sys
import threading
from collections.abc import Iterator
from typing import Any, TextIO

from .cli_args import (
    COMMAND_COLLECT,
    COMMAND_CONSUL,
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
    try:
        if log_path:
            try:
                with _tee_console_output(log_path):
                    return _run_command(args, logger)
            except OSError as exc:
                print(f"[error] failed to open --log file '{log_path}': {exc}", file=sys.stderr)
                return 2
        return _run_command(args, logger)
    finally:
        logger.close()
