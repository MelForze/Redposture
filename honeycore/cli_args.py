"""Argument parser for RedPosture CLI."""

from __future__ import annotations

import argparse
import re
import sys
from importlib import metadata
from pathlib import Path


COMMAND_LISTEN = "listen"
COMMAND_SCAN = "scan"
COMMAND_TRIGGER = "trigger"
COMMAND_COLLECT = "collect"


def _package_version() -> str:
    try:
        return metadata.version("redposture")
    except metadata.PackageNotFoundError:
        return _local_package_version()


def _local_package_version() -> str:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    if not pyproject.exists():
        return "0+local"

    in_project = False
    version_pattern = re.compile(r'^version\s*=\s*["\']([^"\']+)["\']\s*$')
    try:
        with pyproject.open("r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if line.startswith("["):
                    in_project = line == "[project]"
                    continue
                if not in_project:
                    continue
                match = version_pattern.match(line)
                if match:
                    return f"{match.group(1)}+local"
    except OSError:
        return "0+local"

    return "0+local"


def _port(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if number < 1 or number > 65535:
        raise argparse.ArgumentTypeError("port must be in range 1..65535")
    return number


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a number") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be > 0")
    return number


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be > 0")
    return number


def _non_negative_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("value must be >= 0")
    return number


def _add_listener_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-s",
        "--services",
        default="postgres,redis,proxmox,blackbox",
        metavar="services",
        help="Comma-separated services: postgres,redis,proxmox,blackbox.",
    )
    parser.add_argument("-b", "--bind", default="0.0.0.0", metavar="addr", help="Listen address for all services.")
    parser.add_argument(
        "--postgres-port",
        type=_port,
        default=5432,
        metavar="port",
        help="Postgres honeypot listen port.",
    )
    parser.add_argument(
        "--postgres-tls",
        action="store_true",
        default=False,
        help="Enable STARTTLS for postgres SSLRequest (default: off).",
    )
    parser.add_argument(
        "--redis-port",
        type=_port,
        default=6379,
        metavar="port",
        help="Redis honeypot listen port.",
    )
    parser.add_argument(
        "--proxmox-port",
        type=_port,
        default=8006,
        metavar="port",
        help="Proxmox honeypot listen port.",
    )
    parser.add_argument(
        "--proxmox-tls",
        action="store_true",
        default=False,
        help="Serve proxmox honeypot via HTTPS (default: off).",
    )
    parser.add_argument(
        "--blackbox-port",
        type=_port,
        default=9115,
        metavar="port",
        help="Blackbox honeypot listen port.",
    )
    parser.add_argument("--cert-file", default=None, metavar="path", help="TLS cert path for postgres/proxmox HTTPS.")
    parser.add_argument("--key-file", default=None, metavar="path", help="TLS key path for postgres/proxmox HTTPS.")


def _add_output_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable verbose debug output.",
    )


def _add_scan_host_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-t",
        "--targets",
        dest="targets",
        default=None,
        metavar="targets",
        help="Targets list: dns/ip/cidr/file (comma-separated). Files may contain dns/ip/cidr per line.",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=_positive_float,
        default=1.0,
        metavar="seconds",
        help="HTTP timeout in seconds.",
    )
    parser.add_argument(
        "-w",
        "--workers",
        dest="workers",
        type=_positive_int,
        default=10,
        metavar="count",
        help="Worker threads used for parallel network checks.",
    )
    parser.add_argument(
        "-r",
        "--retries",
        dest="retries",
        type=_non_negative_int,
        default=3,
        metavar="count",
        help="Retry attempts for network requests (with exponential backoff).",
    )
    parser.add_argument(
        "--profiles-file",
        dest="profiles_file",
        default=None,
        metavar="file",
        help="Optional JSON file with exporter profile overrides.",
    )
    parser.add_argument(
        "--hosts",
        dest="hosts",
        default=None,
        metavar="hosts",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-i",
        "--hosts-file",
        dest="hosts_file",
        default=None,
        metavar="file",
        help=argparse.SUPPRESS,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=(
            "Python3 honeypot utility for postgres, redis, proxmox and blackbox. "
            "Use one module command: listen, scan, trigger, collect."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_package_version()}")
    subparsers = parser.add_subparsers(dest="command")

    listen_parser = subparsers.add_parser(
        COMMAND_LISTEN,
        help="Start honeypot listeners.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_output_flags(listen_parser)
    _add_listener_flags(listen_parser)

    scan_parser = subparsers.add_parser(
        COMMAND_SCAN,
        help="Discover exporters and write scan report.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_output_flags(scan_parser)
    _add_scan_host_flags(scan_parser)
    scan_parser.add_argument(
        "-o",
        "--output",
        dest="output",
        default=None,
        metavar="file",
        help="Optional output file path. If omitted, results are printed to stdout.",
    )
    scan_parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Scan output format for stdout/file.",
    )
    scan_parser.add_argument(
        "-m",
        "--max-bytes",
        dest="max_bytes",
        type=_positive_int,
        default=32 * 1024,
        metavar="bytes",
        help="Max response bytes per scanned /metrics body.",
    )

    trigger_parser = subparsers.add_parser(
        COMMAND_TRIGGER,
        help="Trigger discovered exporters to your target host.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    trigger_options = trigger_parser.add_argument_group("Trigger options")
    listen_options = trigger_parser.add_argument_group("Listen options")

    _add_output_flags(trigger_options)
    _add_scan_host_flags(trigger_options)
    trigger_options.add_argument(
        "-o",
        "--output",
        dest="output",
        default=None,
        metavar="file",
        help="Optional output txt file for trigger/listener event logs.",
    )
    trigger_options.add_argument(
        "--callback-ip",
        dest="callback_ip",
        default=None,
        metavar="ip",
        help="Callback IP used in trigger target values.",
    )
    trigger_options.add_argument(
        "--callback-dns",
        dest="callback_dns",
        default=None,
        metavar="name",
        help="Optional callback DNS name; trigger sends targets for both IP and DNS.",
    )
    trigger_options.add_argument(
        "--with-listen",
        action="store_true",
        help="Start listeners first, then run trigger stage, then keep listeners running.",
    )
    _add_listener_flags(listen_options)

    collect_parser = subparsers.add_parser(
        COMMAND_COLLECT,
        help="Collect debug endpoints from exporter list.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_output_flags(collect_parser)
    _add_scan_host_flags(collect_parser)
    collect_parser.add_argument(
        "-o",
        "--output",
        dest="output",
        default=None,
        metavar="file",
        help="Optional output file path. If omitted, results are printed to stdout.",
    )
    collect_parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Collect output format for stdout/file.",
    )
    collect_parser.add_argument(
        "-m",
        "--max-bytes",
        dest="max_bytes",
        type=_positive_int,
        default=64 * 1024,
        metavar="bytes",
        help="Max response bytes per collected endpoint body.",
    )

    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    if not raw_argv:
        return parser.parse_args([COMMAND_LISTEN])

    if raw_argv[0] in {"-h", "--help", "--version"}:
        return parser.parse_args(raw_argv)

    if raw_argv[0].startswith("-"):
        # Backward compatibility: no command means listener mode.
        return parser.parse_args([COMMAND_LISTEN, *raw_argv])

    return parser.parse_args(raw_argv)
