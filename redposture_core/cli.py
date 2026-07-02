"""Main CLI orchestration."""

from __future__ import annotations

import contextlib
import datetime as _dt
import os
import sys
import threading
from collections.abc import Iterator
from typing import Any, TextIO

from .cli_args import (
    COMMAND_EXPORTERS,
    parse_args,
)
from .console import set_console_no_color
from .logger import AttemptLogger
from .module_registry import (
    COMMAND_SPECS_BY_NAME,
    DIRECT_RUNTIME_SPECS_BY_NAME,
    EXPORTERS_ACTION_SPECS_BY_NAME,
    resolve_command_runner,
)
from .network_proxy import RuntimeNetworkConfig, parse_proxy_config, proxy_socket_context
from .progress import CommandProgressOwner


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
        # F10 fix: mark the start of a new run so downstream parsers can
        # detect where one invocation ends and the next begins even when
        # previous runs were aborted mid-write.
        try:
            _now = _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            log_fh.write(f"\n===== redposture run start {_now} =====\n")
            log_fh.flush()
        except Exception:
            pass
        stdout_orig = sys.stdout
        stderr_orig = sys.stderr
        lock = threading.Lock()
        sys.stdout = _TeeStream(stdout_orig, log_fh, lock)
        sys.stderr = _TeeStream(stderr_orig, log_fh, lock)
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
        action_spec = EXPORTERS_ACTION_SPECS_BY_NAME.get(str(action or ""))
        if action_spec is not None:
            try:
                return int(resolve_command_runner(action_spec)(args, logger))
            except LookupError as exc:
                print(f"[error] {exc}", file=sys.stderr)
                return 2
        print(f"[error] unsupported exporters action: {action}", file=sys.stderr)
        return 2

    spec = COMMAND_SPECS_BY_NAME.get(str(args.command or "")) or DIRECT_RUNTIME_SPECS_BY_NAME.get(
        str(args.command or "")
    )
    if spec is not None:
        try:
            runner = resolve_command_runner(spec)
        except LookupError as exc:
            print(f"[error] {exc}", file=sys.stderr)
            return 2
        if str(args.command or "") == "selfcert":
            return int(runner(args))
        return int(runner(args, logger))

    print(f"[error] unsupported command: {args.command}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    set_console_no_color(bool(getattr(args, "no_color", False)))
    logger = AttemptLogger()
    progress_owner = CommandProgressOwner(enabled=True)
    args._progress_owner = progress_owner
    log_path = str(getattr(args, "log", "") or "").strip()
    raw_proxy = str(getattr(args, "proxy", "") or "").strip()

    # F4 fix: open the --log tee BEFORE parsing --proxy so that a proxy-parse
    # failure (or a subsequent log-open failure surfaced as a message) still
    # lands in the log file. If the log file itself can't be opened we
    # unavoidably fall back to bare stderr.
    tee_ctx: Any = None
    if log_path:
        try:
            tee_ctx = _tee_console_output(log_path)
            tee_ctx.__enter__()
        except OSError as exc:
            print(f"[error] failed to open --log file '{log_path}': {exc}", file=sys.stderr)
            return 2

    def _teardown_tee(exc_type=None, exc=None, tb=None):
        if tee_ctx is not None:
            try:
                tee_ctx.__exit__(exc_type, exc, tb)
            except Exception:
                pass

    try:
        proxy_cfg = None
        if raw_proxy:
            proxy_cfg, proxy_error = parse_proxy_config(raw_proxy)
            if proxy_error:
                print(f"[error] failed to parse --proxy: {proxy_error}", file=sys.stderr)
                return 2
        args._proxy_config = proxy_cfg
        args._runtime_network = RuntimeNetworkConfig.from_args(args, proxy=proxy_cfg)
        try:
            with proxy_socket_context(proxy_cfg):
                return _run_command(args, logger)
        except KeyboardInterrupt:
            # F1 fix: without this the interpreter dumps a full traceback on
            # Ctrl+C. 130 is the shell-conventional SIGINT exit code.
            print("[!] interrupted by user (Ctrl+C)", file=sys.stderr)
            return 130
    finally:
        progress_owner.close()
        set_console_no_color(False)
        logger.close()
        _teardown_tee()
