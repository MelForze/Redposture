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
COMMAND_REDIS = "redis"
COMMAND_POSTGRES = "postgres"
COMMAND_ETCD = "etcd"
COMMAND_GRAFANA = "grafana"
COMMAND_KAFKA = "kafka"
COMMAND_SELFCERT = "selfcert"
COMMAND_EXPORTERS = "exporters"


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
        help="Postgres listener port.",
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
        help="Redis listener port.",
    )
    parser.add_argument(
        "--proxmox-port",
        type=_port,
        default=8006,
        metavar="port",
        help="Proxmox listener port.",
    )
    parser.add_argument(
        "--proxmox-tls",
        action="store_true",
        default=False,
        help="Serve proxmox listener via HTTPS (default: off).",
    )
    parser.add_argument(
        "--blackbox-port",
        type=_port,
        default=9115,
        metavar="port",
        help="Blackbox listener port.",
    )
    parser.add_argument("--cert-file", default=None, metavar="path", help="TLS cert path for postgres/proxmox HTTPS.")
    parser.add_argument("--key-file", default=None, metavar="path", help="TLS key path for postgres/proxmox HTTPS.")


def _add_output_flags(parser: argparse.ArgumentParser, *, short: bool = True) -> None:
    if short:
        parser.add_argument(
            "-d",
            "--debug",
            action="store_true",
            help="Enable verbose debug output.",
        )
        return
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug output.",
    )


def _add_log_flag(parser: argparse.ArgumentParser | argparse._ArgumentGroup) -> None:
    parser.add_argument(
        "-log",
        "--log",
        dest="log",
        default=None,
        metavar="file",
        help="Write console output to log file while still printing to terminal.",
    )


def _add_save_flag(parser: argparse.ArgumentParser | argparse._ArgumentGroup, help_text: str) -> None:
    parser.add_argument(
        "-o",
        "--output",
        "--save",
        dest="output",
        default=None,
        metavar="file",
        help=help_text,
    )


def _add_scan_host_flags(parser: argparse.ArgumentParser, *, include_profiles: bool = True) -> None:
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
        help="Network timeout in seconds.",
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
    if include_profiles:
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


def _build_selfcert_option_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Generate local self-signed TLS cert/key files and exit.",
    )
    _add_output_flags(parser)
    _add_log_flag(parser)
    parser.add_argument(
        "--selfcert",
        "-selfcert",
        dest="selfcert",
        action="store_true",
        default=False,
        help="Generate local self-signed TLS cert/key files and exit.",
    )
    parser.add_argument(
        "--cert-out",
        dest="cert_out",
        default="cert.pem",
        metavar="path",
        help="Output path for certificate PEM file.",
    )
    parser.add_argument(
        "--key-out",
        dest="key_out",
        default="key.pem",
        metavar="path",
        help="Output path for private key PEM file.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output files if they already exist.",
    )
    return parser


def _configure_listen_parser(parser: argparse.ArgumentParser) -> None:
    _add_output_flags(parser)
    _add_log_flag(parser)
    _add_listener_flags(parser)


def _configure_scan_parser(parser: argparse.ArgumentParser) -> None:
    _add_output_flags(parser)
    _add_log_flag(parser)
    _add_scan_host_flags(parser)
    _add_save_flag(parser, "Optional output file path. If omitted, results are printed to stdout.")
    parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Scan output format for stdout/file.",
    )
    parser.add_argument(
        "-p",
        "--ports",
        dest="ports",
        default=None,
        metavar="ports",
        help="Optional custom ports to probe (e.g. 9100,9115,9200-9210).",
    )


def _configure_trigger_parser(parser: argparse.ArgumentParser) -> None:
    trigger_options = parser.add_argument_group("Trigger options")
    listen_options = parser.add_argument_group("Listen options")

    _add_output_flags(trigger_options)
    _add_log_flag(trigger_options)
    _add_scan_host_flags(trigger_options)
    _add_save_flag(trigger_options, "Optional output txt file for trigger/listener event logs.")
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


def _configure_collect_parser(parser: argparse.ArgumentParser) -> None:
    _add_output_flags(parser)
    _add_log_flag(parser)
    _add_scan_host_flags(parser)
    _add_save_flag(parser, "Optional output file path. If omitted, results are printed to stdout.")
    parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Collect output format for stdout/file.",
    )
    parser.add_argument(
        "--save-responses-dir",
        dest="save_responses_dir",
        default=None,
        metavar="dir",
        help=(
            "Save raw response bodies from collect endpoints to directory tree and "
            "write metadata index.jsonl."
        ),
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Enable deep collect paths (pprof internals, profile/trace dumps).",
    )
    parser.add_argument(
        "--pprof-seconds",
        dest="pprof_seconds",
        type=_positive_int,
        default=5,
        metavar="seconds",
        help="Duration for /debug/pprof/profile?seconds=... when --deep is enabled.",
    )
    parser.add_argument(
        "--trace-seconds",
        dest="trace_seconds",
        type=_positive_int,
        default=2,
        metavar="seconds",
        help="Duration for /debug/pprof/trace?seconds=... when --deep is enabled.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=(
            "Python3 security toolkit for listener emulation, endpoint discovery/trigger/collect, and Redis/Postgres/etcd/Grafana/Kafka auditing. "
            "Use one module command: exporters, grafana, kafka, postgres, redis, etcd. "
            "Listener mode is available inside trigger via --with-listen."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_package_version()}")
    subparsers = parser.add_subparsers(dest="command")

    exporters_parser = subparsers.add_parser(
        COMMAND_EXPORTERS,
        help="Unified exporter workflows: scan/collect/trigger.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    exporters_subparsers = exporters_parser.add_subparsers(dest="exporters_action", required=True)

    exporters_scan_parser = exporters_subparsers.add_parser(
        COMMAND_SCAN,
        help="Discover observability endpoints and write scan report.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _configure_scan_parser(exporters_scan_parser)

    exporters_collect_parser = exporters_subparsers.add_parser(
        COMMAND_COLLECT,
        help="Collect debug/runtime endpoints from a target service list.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _configure_collect_parser(exporters_collect_parser)

    exporters_trigger_parser = exporters_subparsers.add_parser(
        COMMAND_TRIGGER,
        help="Trigger discovered endpoints/exporters to your callback target.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _configure_trigger_parser(exporters_trigger_parser)

    grafana_parser = subparsers.add_parser(
        COMMAND_GRAFANA,
        help="Audit Grafana auth exposure and datasource access.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_output_flags(grafana_parser)
    _add_log_flag(grafana_parser)
    _add_scan_host_flags(grafana_parser, include_profiles=False)
    grafana_parser.add_argument(
        "--port",
        dest="port",
        type=_port,
        default=3000,
        metavar="port",
        help="Grafana HTTP port to audit.",
    )
    grafana_parser.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional Grafana username for credential check.",
    )
    grafana_parser.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional Grafana password for credential check.",
    )
    grafana_parser.add_argument(
        "--defcreds",
        action="store_true",
        help="Try default Grafana credentials admin:admin and admin:prom-operator.",
    )
    grafana_parser.add_argument(
        "--show-datasources",
        "--show-datasource",
        dest="show_datasources",
        action="store_true",
        help="Show datasource details after successful access.",
    )
    grafana_parser.add_argument(
        "--ssrf-target",
        dest="ssrf_target",
        default=None,
        metavar="url",
        help="Optional URL/host/cidr for temporary Prometheus egress-check datasource (http/https).",
    )
    grafana_parser.add_argument(
        "--ssrf-port",
        dest="ssrf_port",
        type=str,
        default=None,
        metavar="port",
        help="Optional port override for --ssrf-target when URL has no explicit port.",
    )
    grafana_parser.add_argument(
        "--ssrf-path",
        dest="ssrf_path",
        type=str,
        default=None,
        metavar="path",
        help="Optional path/query override for generated --ssrf-target URLs (example: /debug/vars).",
    )
    _add_save_flag(grafana_parser, "Optional output file path. If omitted, results are printed to stdout.")
    grafana_parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Grafana audit output format for stdout/file.",
    )

    postgres_parser = subparsers.add_parser(
        COMMAND_POSTGRES,
        help="Audit Postgres auth exposure and risky privileges.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_output_flags(postgres_parser, short=False)
    _add_log_flag(postgres_parser)
    _add_scan_host_flags(postgres_parser, include_profiles=False)
    postgres_parser.add_argument(
        "--port",
        dest="port",
        type=_port,
        default=5432,
        metavar="port",
        help="Postgres TCP port to audit.",
    )
    postgres_parser.add_argument(
        "-d",
        "--database",
        dest="database",
        default="postgres",
        metavar="name",
        help="Database name used for authentication and privilege checks.",
    )
    postgres_parser.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional Postgres username for credential check.",
    )
    postgres_parser.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional Postgres password for credential check.",
    )
    postgres_parser.add_argument(
        "--defcreds",
        action="store_true",
        help="Try default Postgres credentials postgres:postgres when auth is required.",
    )
    postgres_parser.add_argument(
        "--show-databases",
        action="store_true",
        help="Show available database names in output after successful access/auth.",
    )
    postgres_parser.add_argument(
        "--show-tables",
        action="store_true",
        help="Show readable table names in output after successful access/auth.",
    )
    postgres_parser.add_argument(
        "--table",
        dest="tables",
        action="append",
        default=None,
        metavar="name",
        help="Target table (schema.table or table). Can be used multiple times or with comma-separated values.",
    )
    postgres_parser.add_argument(
        "--show-columns",
        action="store_true",
        help="Show column names for --table target(s).",
    )
    postgres_parser.add_argument(
        "--dump",
        action="store_true",
        help="Dump table rows. With --table dumps selected table(s); without --table dumps all readable tables.",
    )
    postgres_parser.add_argument(
        "--column",
        "--columns",
        dest="columns",
        action="append",
        default=None,
        metavar="name",
        help="Column filter for --show-columns/--dump (repeatable, comma-separated is also supported). Applies to all --table targets.",
    )
    postgres_parser.add_argument(
        "-x",
        "--execute",
        dest="execute",
        default=None,
        metavar="command",
        help="Try executing OS command via Postgres COPY FROM PROGRAM and print output.",
    )
    postgres_parser.add_argument(
        "--os-shell",
        action="store_true",
        help="Interactive command mode via Postgres COPY FROM PROGRAM (single target).",
    )
    _add_save_flag(postgres_parser, "Optional output file path. If omitted, results are printed to stdout.")
    postgres_parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Postgres audit output format for stdout/file.",
    )

    redis_parser = subparsers.add_parser(
        COMMAND_REDIS,
        help="Audit Redis auth exposure and default credentials.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_output_flags(redis_parser)
    _add_log_flag(redis_parser)
    _add_scan_host_flags(redis_parser, include_profiles=False)
    redis_parser.add_argument(
        "--port",
        dest="port",
        type=_port,
        default=6379,
        metavar="port",
        help="Redis TCP port to audit.",
    )
    redis_parser.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional Redis username for credential check.",
    )
    redis_parser.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional Redis password for credential check.",
    )
    redis_parser.add_argument(
        "--defcreds",
        action="store_true",
        help="Try default Redis credentials redis:redis when auth is required.",
    )
    redis_parser.add_argument(
        "--show-keys",
        action="store_true",
        help="Show Redis key names only (SCAN).",
    )
    redis_parser.add_argument(
        "--dump-keys",
        action="store_true",
        help="Dump all Redis keys with values.",
    )
    redis_parser.add_argument(
        "-key",
        "--key",
        dest="key",
        default=None,
        metavar="name",
        help="Dump one specific Redis key by name (with value).",
    )
    _add_save_flag(redis_parser, "Optional output file path. If omitted, results are printed to stdout.")
    redis_parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Redis audit output format for stdout/file.",
    )

    etcd_parser = subparsers.add_parser(
        COMMAND_ETCD,
        help="Audit etcd API exposure and auth requirements.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_output_flags(etcd_parser)
    _add_log_flag(etcd_parser)
    _add_scan_host_flags(etcd_parser, include_profiles=False)
    etcd_parser.add_argument(
        "--port",
        dest="port",
        type=_port,
        default=2379,
        metavar="port",
        help="etcd HTTP port to audit.",
    )
    etcd_parser.add_argument(
        "--show-keys",
        action="store_true",
        help="Show etcd key names only when auth is not required.",
    )
    etcd_parser.add_argument(
        "--dump-keys",
        action="store_true",
        help="Dump all etcd keys with values when auth is not required.",
    )
    etcd_parser.add_argument(
        "-key",
        "--key",
        dest="key",
        default=None,
        metavar="path",
        help="Dump specific etcd key (example: /redposture/env) when auth is not required.",
    )
    _add_save_flag(etcd_parser, "Optional output file path. If omitted, results are printed to stdout.")
    etcd_parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="etcd audit output format for stdout/file.",
    )

    kafka_parser = subparsers.add_parser(
        COMMAND_KAFKA,
        help="Audit Kafka broker auth exposure and topic visibility.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_output_flags(kafka_parser)
    _add_log_flag(kafka_parser)
    _add_scan_host_flags(kafka_parser, include_profiles=False)
    kafka_parser.add_argument(
        "--port",
        dest="port",
        type=_port,
        default=9092,
        metavar="port",
        help="Kafka broker TCP port to audit.",
    )
    kafka_parser.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional Kafka username for credential check (SASL/PLAIN).",
    )
    kafka_parser.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional Kafka password for credential check (SASL/PLAIN).",
    )
    kafka_parser.add_argument(
        "--show-topics",
        action="store_true",
        help="Show topic names after successful access/auth.",
    )
    kafka_parser.add_argument(
        "--topic",
        dest="topic",
        default=None,
        metavar="name",
        help="Show one topic detail by name (partition count / not found).",
    )
    kafka_parser.add_argument(
        "--read-topic",
        action="store_true",
        help="Read topic messages for --topic.",
    )
    kafka_parser.add_argument(
        "--max-messages",
        dest="max_messages",
        type=int,
        default=1000,
        metavar="count",
        help="Maximum number of topic messages to read with --read-topic.",
    )
    _add_save_flag(kafka_parser, "Optional output file path. If omitted, results are printed to stdout.")
    kafka_parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Kafka audit output format for stdout/file.",
    )

    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    if not raw_argv:
        parser.print_help()
        raise SystemExit(0)

    if raw_argv[0] in {"-h", "--help", "--version"}:
        return parser.parse_args(raw_argv)

    if "-selfcert" in raw_argv or "--selfcert" in raw_argv:
        if raw_argv[0] not in {"--selfcert", "-selfcert"}:
            parser.error("'-selfcert/--selfcert' must be used as a top-level option, e.g. 'redposture.py --selfcert'.")
        selfcert_parser = _build_selfcert_option_parser()
        args = selfcert_parser.parse_args(raw_argv)
        if not getattr(args, "selfcert", False):
            selfcert_parser.error("missing --selfcert")
        setattr(args, "command", COMMAND_SELFCERT)
        return args

    if raw_argv[0] == COMMAND_LISTEN:
        parser.error("direct 'listen' mode removed; use 'exporters trigger --with-listen ...'")

    if raw_argv[0] == COMMAND_SCAN:
        parser.error("direct 'scan' mode removed; use 'exporters scan ...'")
    if raw_argv[0] == COMMAND_COLLECT:
        parser.error("direct 'collect' mode removed; use 'exporters collect ...'")
    if raw_argv[0] == COMMAND_TRIGGER:
        parser.error("direct 'trigger' mode removed; use 'exporters trigger ...'")

    if raw_argv[0].startswith("-"):
        parser.error("module command is required: exporters, grafana, kafka, postgres, redis, etcd, or --selfcert")

    return parser.parse_args(raw_argv)
