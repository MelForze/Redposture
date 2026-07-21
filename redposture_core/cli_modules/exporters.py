"""CLI parser builders."""

from __future__ import annotations

import argparse
import math
from collections.abc import Callable


def _positive_seconds(value: str) -> float:
    """F6 fix: reject 0 / negative / NaN listen-second values at parse time."""
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--listen-seconds must be a number") from exc
    if not math.isfinite(number):
        raise argparse.ArgumentTypeError("--listen-seconds must be finite")
    if number <= 0:
        raise argparse.ArgumentTypeError("--listen-seconds must be > 0")
    return number


def configure_listen_parser(
    parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_listener_flags: Callable[..., None],
) -> None:
    add_output_flags(parser)
    add_log_flag(parser)
    add_listener_flags(parser)


def configure_scan_parser(
    parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_save_flag: Callable[..., None],
) -> None:
    common = parser.add_argument_group("Common")
    actions = parser.add_argument_group("Actions")
    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common)
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Scan output format for stdout/file.",
    )
    actions.add_argument(
        "-p",
        "--port",
        "--ports",
        dest="ports",
        default=None,
        metavar="ports",
        help="Optional custom ports to probe: single port, comma-separated list/range, or file path.",
    )


def configure_trigger_parser(
    parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_save_flag: Callable[..., None],
    add_listener_flags: Callable[..., None],
) -> None:
    common = parser.add_argument_group("Common")
    actions = parser.add_argument_group("Actions")
    listener = parser.add_argument_group("Listener")

    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common)
    add_save_flag(common, "Optional output file path. Use --format json for structured trigger records.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Trigger output format for stdout/file.",
    )
    common.add_argument(
        "-p",
        "--port",
        "--ports",
        dest="ports",
        default=None,
        metavar="ports",
        help="Optional custom exporter ports: single port, comma-separated list/range, or file path.",
    )
    actions.add_argument(
        "--callback-ip",
        dest="callback_ip",
        default=None,
        metavar="ip",
        help="Callback IP used in trigger target values.",
    )
    actions.add_argument(
        "--callback-dns",
        dest="callback_dns",
        default=None,
        metavar="name",
        help="Optional callback DNS name; trigger sends targets for both IP and DNS.",
    )
    actions.add_argument(
        "--with-listen",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Start listeners first, then run trigger stage, then keep listeners running.",
    )
    actions.add_argument(
        "--listen-seconds",
        dest="listen_seconds",
        type=_positive_seconds,
        default=None,
        metavar="seconds",
        help="With --with-listen, stop listeners automatically after N seconds.",
    )
    actions.add_argument(
        "-e",
        "--exporters",
        dest="trigger_exporters_filter",
        default=None,
        metavar="names",
        help=(
            "Comma-separated exporter filter for trigger "
            "(aliases: redis,postgres,blackbox,proxmox or full names like redis_exporter)."
        ),
    )
    actions.add_argument(
        "-check",
        "--check-credentials",
        action="store_true",
        help=(
            "With --with-listen, validate captured Redis/Postgres credentials against source exporter IPs "
            "(Redis:6379, Postgres:5432)."
        ),
    )
    actions.add_argument(
        "--postgres-auth-module",
        dest="postgres_auth_modules",
        action="append",
        default=None,
        metavar="name",
        help=(
            "Postgres exporter auth_module value(s) for /probe (repeatable; comma-separated values supported). "
            "Examples: stage,prod,test. When multiple are provided, trigger attempts are repeated per auth_module."
        ),
    )
    add_listener_flags(listener)
    parser.set_defaults(workers=50)
    for action in parser._actions:
        if getattr(action, "dest", None) == "workers":
            action.default = 50
            break


def configure_collect_parser(
    parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_save_flag: Callable[..., None],
    positive_int: Callable[[str], int],
) -> None:
    common = parser.add_argument_group("Common")
    actions = parser.add_argument_group("Actions")
    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common)
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Collect output format for stdout/file.",
    )
    common.add_argument(
        "-p",
        "--port",
        "--ports",
        dest="ports",
        default=None,
        metavar="ports",
        help="Optional custom ports to probe: single port, comma-separated list/range, or file path.",
    )
    actions.add_argument(
        "--save-responses-dir",
        dest="save_responses_dir",
        default=None,
        metavar="dir",
        help=("Save raw response bodies from collect endpoints to directory tree and write metadata index.jsonl."),
    )
    actions.add_argument(
        "--deep",
        action="store_true",
        help="Enable deep collect paths (pprof internals, profile/trace dumps).",
    )
    actions.add_argument(
        "--pprof-seconds",
        dest="pprof_seconds",
        type=positive_int,
        default=5,
        metavar="seconds",
        help="Duration for /debug/pprof/profile?seconds=... when --deep is enabled.",
    )
    actions.add_argument(
        "--trace-seconds",
        dest="trace_seconds",
        type=positive_int,
        default=2,
        metavar="seconds",
        help="Duration for /debug/pprof/trace?seconds=... when --deep is enabled.",
    )
    actions.add_argument(
        "--resume",
        action="store_true",
        help="Resume collect run by skipping endpoint jobs already present in checkpoint file.",
    )
    actions.add_argument(
        "--checkpoint-file",
        dest="checkpoint_file",
        default=None,
        metavar="file",
        help=(
            "Checkpoint JSONL file for collect resume state. Default: <output>.checkpoint.jsonl (or save dir fallback)."
        ),
    )
    actions.add_argument(
        "--max-inflight",
        dest="max_inflight",
        type=positive_int,
        default=None,
        metavar="count",
        help="Maximum in-flight collect HTTP requests (default: adaptive from worker count).",
    )
    actions.add_argument(
        "--adaptive-collect",
        dest="adaptive_collect",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable adaptive preflight planning to reduce unnecessary collect requests.",
    )
    actions.add_argument(
        "-e",
        "--exporters",
        dest="collect_exporters_filter",
        default=None,
        metavar="names",
        help=(
            "Comma-separated exporter filter for collect "
            "(aliases: redis,postgres,kafka or full names like redis_exporter)."
        ),
    )


__all__ = ["configure_listen_parser", "configure_scan_parser", "configure_trigger_parser", "configure_collect_parser"]
