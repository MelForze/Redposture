"""Argument parser for RedPosture CLI."""

from __future__ import annotations

import argparse
import inspect
import math
import re
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

from . import module_registry as _registry
from .module_registry import ParserHelperSet, command_names_for_error, configure_cli_subcommands

COMMAND_LISTEN = _registry.COMMAND_LISTEN
COMMAND_SCAN = _registry.COMMAND_SCAN
COMMAND_TRIGGER = _registry.COMMAND_TRIGGER
COMMAND_COLLECT = _registry.COMMAND_COLLECT
COMMAND_REDIS = _registry.COMMAND_REDIS
COMMAND_REGISTRY = _registry.COMMAND_REGISTRY
COMMAND_POSTGRES = _registry.COMMAND_POSTGRES
COMMAND_CLICKHOUSE = _registry.COMMAND_CLICKHOUSE
COMMAND_ETCD = _registry.COMMAND_ETCD
COMMAND_PROXMOX = _registry.COMMAND_PROXMOX
COMMAND_GRAFANA = _registry.COMMAND_GRAFANA
COMMAND_GITLAB = _registry.COMMAND_GITLAB
COMMAND_CONSUL = _registry.COMMAND_CONSUL
COMMAND_QDRANT = _registry.COMMAND_QDRANT
COMMAND_KUBEAPI = _registry.COMMAND_KUBEAPI
COMMAND_KAFKA = _registry.COMMAND_KAFKA
COMMAND_ZOOKEEPER = _registry.COMMAND_ZOOKEEPER
COMMAND_KEEPER = _registry.COMMAND_KEEPER
COMMAND_ELASTIC = _registry.COMMAND_ELASTIC
COMMAND_GRPC = _registry.COMMAND_GRPC
COMMAND_MONGODB = _registry.COMMAND_MONGODB
COMMAND_DOCKER = _registry.COMMAND_DOCKER
COMMAND_ORACLE = _registry.COMMAND_ORACLE
COMMAND_SELFCERT = _registry.COMMAND_SELFCERT
COMMAND_EXPORTERS = _registry.COMMAND_EXPORTERS


_ARGPARSE_SUPPORTS_COLOR = "color" in inspect.signature(argparse.ArgumentParser.__init__).parameters


class _NoColorArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if _ARGPARSE_SUPPORTS_COLOR:
            kwargs.setdefault("color", False)
        super().__init__(*args, **kwargs)


def _package_version() -> str:
    # Prefer version from local source tree when running from repository checkout.
    local_version = _local_package_version()
    if local_version != "0+local":
        return local_version
    try:
        return metadata.version("redposture")
    except metadata.PackageNotFoundError:
        return local_version


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


def _port_spec(value: str) -> str | int:
    """Accept the same syntax `--ports` used to require (list/range/file) so
    `--port` alone covers every case. Returns:
      - `int` when the value is a single valid port (backward-compatible with
        the previous `_port(int)` behavior — downstream reads args.port as int).
      - `str` for everything else (list/range/file path). Downstream port
        collection sees it via `getattr(args, "ports", None)` — see
        `build_basic_audit_plan` at redposture_core/stage_runtime.py.
    """
    raw = str(value or "").strip()
    if not raw:
        raise argparse.ArgumentTypeError("port must not be empty")
    # Single integer: enforce range for the historically-strict path.
    try:
        number = int(raw)
    except ValueError:
        return raw  # list / range / file → parsed later by collect_scan_ports
    if number < 1 or number > 65535:
        raise argparse.ArgumentTypeError("port must be in range 1..65535")
    return number


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a number") from exc
    if not math.isfinite(number):
        raise argparse.ArgumentTypeError("value must be finite")
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


def _mirror_group_actions(group: object, *actions: argparse.Action) -> None:
    # Help-only duplication: show shared actions under multiple sections without re-registering flags.
    group_actions = getattr(group, "_group_actions", None)
    if not isinstance(group_actions, list):
        return
    for action in actions:
        if action not in group_actions:
            group_actions.append(action)


def _append_selected_defaults(parser: argparse.ArgumentParser, *dests: str) -> None:
    selected = set(dests)
    for action in parser._actions:
        if action.dest not in selected:
            continue
        if not isinstance(action.help, str) or action.help == argparse.SUPPRESS:
            continue
        if "%(default)" in action.help or "(default:" in action.help:
            continue
        action.help = f"{action.help} (default: %(default)s)"


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
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable STARTTLS for postgres SSLRequest listener.",
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
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Serve proxmox listener via HTTPS.",
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
        parser.add_argument(
            "--no-color",
            action="store_true",
            help="Disable ANSI colors in console output.",
        )
        return
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug output.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in console output.",
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


def _add_save_flag(
    parser: argparse.ArgumentParser | argparse._ArgumentGroup,
    help_text: str,
    *,
    include_save_alias: bool = True,
) -> None:
    option_strings = ["-o", "--output"]
    if include_save_alias:
        option_strings.append("--save")
    parser.add_argument(
        *option_strings,
        dest="output",
        default=None,
        metavar="file",
        help=help_text,
    )


def _add_multi_ports_flag(parser: argparse.ArgumentParser | argparse._ArgumentGroup) -> None:
    # `--port` now accepts the same list/range/file syntax that `--ports`
    # used to require, so this flag is a deprecated alias kept for backward
    # compatibility with existing scripts. Suppressed from `--help` so the
    # UX only shows one canonical way to set ports.
    parser.add_argument(
        "--ports",
        dest="ports",
        default=None,
        metavar="ports",
        help=argparse.SUPPRESS,
    )


def _add_scan_host_flags(parser: argparse.ArgumentParser, *, include_profiles: bool = True) -> None:
    parser.add_argument(
        "-t",
        "--targets",
        dest="targets",
        default=None,
        metavar="targets",
        help=(
            "Targets list: dns[:port]/ipv4[:port]/[ipv6]:port/cidr/http(s)://host[:port]/file "
            "(comma-separated). A target-specific port overrides module defaults; an explicitly supplied "
            "port option adds ports to bare host:port targets. URL scheme/path/query are preserved for "
            "URL-aware modules and host/port are used for TCP modules. "
            "Existing local file paths are treated as target files. "
            "Files may contain targets per line."
        ),
    )
    parser.add_argument(
        "-ot",
        "--out-target",
        dest="out_targets",
        action="append",
        default=None,
        metavar="exclusions",
        help=(
            "Exclude targets before scanning: DNS names, IP addresses, CIDR networks, URL hosts, or existing "
            "files (comma-separated; repeatable). Matching ignores scheme and port."
        ),
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=_positive_float,
        default=3.0,
        metavar="seconds",
        help="Network timeout in seconds.",
    )
    parser.add_argument(
        "-w",
        "--workers",
        dest="workers",
        type=_positive_int,
        default=50,
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
        "--proxy",
        dest="proxy",
        default=None,
        metavar="url",
        help=(
            "Optional outbound proxy URL for module requests "
            "(http[s]://host:port, socks4[a]://host:port, or socks5[h]://[user:pass@]host:port)."
        ),
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


def _normalize_multi_port_port_flag(raw_argv: list[str]) -> list[str]:
    """Accept list/range/file syntax in --port by normalizing into hidden --ports."""
    argv = list(raw_argv)
    idx = 0
    while idx < len(argv):
        token = argv[idx]

        if token == "--port" and idx + 1 < len(argv):
            value = str(argv[idx + 1]).strip()
            if value and not value.isdigit():
                if "," in value or "-" in value:
                    first = value.split(",", 1)[0].strip()
                    if "-" in first:
                        first = first.split("-", 1)[0].strip()
                    if first.isdigit():
                        argv[idx + 1] = first
                        argv.insert(idx + 2, "--ports")
                        argv.insert(idx + 3, value)
                        idx += 4
                        continue
                argv[idx] = "--ports"
                idx += 2
                continue

        if token.startswith("--port="):
            value = token.split("=", 1)[1].strip()
            if value and not value.isdigit():
                first = value.split(",", 1)[0].strip()
                if "-" in first:
                    first = first.split("-", 1)[0].strip()
                if ("," in value or "-" in value) and first.isdigit():
                    argv[idx] = f"--port={first}"
                    argv.insert(idx + 1, "--ports")
                    argv.insert(idx + 2, value)
                    idx += 3
                    continue
                argv[idx] = f"--ports={value}"
                idx += 1
                continue

        idx += 1
    return argv


def _port_option_provided(raw_argv: list[str]) -> bool:
    """Return whether the user explicitly supplied an audit port option.

    This must inspect argv before normalization because several modules expose
    numeric parser defaults, while ``--port`` list/range/file forms may be
    rewritten to the hidden ``--ports`` compatibility option.
    """

    return any(token in {"--port", "--ports"} or token.startswith(("--port=", "--ports=")) for token in raw_argv)


def _option_provided(raw_argv: list[str], *options: str) -> bool:
    """Return whether one of ``options`` was explicitly present in argv.

    Keep the provenance separate from argparse defaults so modules may safely
    tune defaults for large plans while preserving every user-supplied value.
    Both ``--option=value`` and compact short forms such as ``-w200`` are
    accepted by argparse and therefore need to be recognized here as well.
    """

    long_options = tuple(option for option in options if option.startswith("--"))
    short_options = tuple(option for option in options if option.startswith("-") and not option.startswith("--"))
    for token in raw_argv:
        if token in options:
            return True
        if any(token.startswith(f"{option}=") for option in long_options):
            return True
        if any(token.startswith(option) and len(token) > len(option) for option in short_options):
            return True
    return False


def _build_selfcert_option_parser() -> argparse.ArgumentParser:
    parser = _NoColorArgumentParser(
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


def build_parser() -> argparse.ArgumentParser:
    parser = _NoColorArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=(
            "Security toolkit for module-focused auditing (exporters, registry, grafana, proxmox, gitlab, "
            "consul, kubeapi, postgres, mongodb, docker, oracle, clickhouse, redis, etcd, qdrant, elastic, kafka, "
            "zookeeper, keeper, grpc). "
            "Use '<module> -h' for grouped flags by topic."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_package_version()}")
    parser.set_defaults(_port_option_provided=False)
    subparsers = parser.add_subparsers(dest="command", parser_class=_NoColorArgumentParser)
    configure_cli_subcommands(
        subparsers,
        parser_class=_NoColorArgumentParser,
        helpers=ParserHelperSet(
            add_output_flags=_add_output_flags,
            add_log_flag=_add_log_flag,
            add_scan_host_flags=_add_scan_host_flags,
            add_multi_ports_flag=_add_multi_ports_flag,
            add_save_flag=_add_save_flag,
            add_listener_flags=_add_listener_flags,
            append_selected_defaults=_append_selected_defaults,
            mirror_group_actions=_mirror_group_actions,
            port_type=_port_spec,
            positive_int=_positive_int,
        ),
    )

    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    port_option_was_provided = _port_option_provided(raw_argv)
    workers_option_was_provided = _option_provided(raw_argv, "-w", "--workers")
    retries_option_was_provided = _option_provided(raw_argv, "-r", "--retries")
    timeout_option_was_provided = _option_provided(raw_argv, "--timeout")
    raw_argv = _normalize_multi_port_port_flag(raw_argv)
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
        args.command = COMMAND_SELFCERT
        return args

    if raw_argv[0] == COMMAND_LISTEN:
        parser.error("direct 'listen' mode removed; use 'exporters trigger --with-listen ...'")

    if raw_argv[0] == COMMAND_SCAN:
        parser.error("direct 'scan' mode removed; use 'exporters scan ...'")
    if raw_argv[0] == COMMAND_COLLECT:
        parser.error("direct 'collect' mode removed; use 'exporters collect ...'")
    if raw_argv[0] == COMMAND_TRIGGER:
        parser.error("direct 'trigger' mode removed; use 'exporters trigger ...'")

    if len(raw_argv) >= 2 and raw_argv[0] == COMMAND_EXPORTERS and raw_argv[1] == COMMAND_COLLECT:
        if "-oA" in raw_argv or "--output-all" in raw_argv:
            parser.error("exporters collect credential artifact bundle export was removed; use -o/--output")

    if raw_argv[0].startswith("-"):
        parser.error(f"module command is required: {command_names_for_error()}")

    parsed = parser.parse_args(raw_argv)
    parsed._port_option_provided = port_option_was_provided
    parsed._workers_option_provided = workers_option_was_provided
    parsed._retries_option_provided = retries_option_was_provided
    parsed._timeout_option_provided = timeout_option_was_provided
    return parsed
