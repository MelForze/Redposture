"""Argument parser for RedPosture CLI."""

from __future__ import annotations

import argparse
import inspect
import re
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

COMMAND_LISTEN = "listen"
COMMAND_SCAN = "scan"
COMMAND_TRIGGER = "trigger"
COMMAND_COLLECT = "collect"
COMMAND_REDIS = "redis"
COMMAND_REGISTRY = "registry"
COMMAND_POSTGRES = "postgres"
COMMAND_CLICKHOUSE = "clickhouse"
COMMAND_ETCD = "etcd"
COMMAND_PROXMOX = "proxmox"
COMMAND_GRAFANA = "grafana"
COMMAND_GITLAB = "gitlab"
COMMAND_CONSUL = "consul"
COMMAND_QDRANT = "qdrant"
COMMAND_KUBEAPI = "kubeapi"
COMMAND_KAFKA = "kafka"
COMMAND_ZOOKEEPER = "zookeeper"
COMMAND_SELFCERT = "selfcert"
COMMAND_EXPORTERS = "exporters"
COMMAND_DB = "db"


_ARGPARSE_SUPPORTS_COLOR = "color" in inspect.signature(argparse.ArgumentParser.__init__).parameters


class _NoColorArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if _ARGPARSE_SUPPORTS_COLOR:
            kwargs.setdefault("color", False)
        super().__init__(*args, **kwargs)


class _PostgresHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action: argparse.Action) -> str:
        if getattr(action, "_hide_metavar_in_help", False):
            return ", ".join(action.option_strings)
        return super()._format_action_invocation(action)


class _DbHelpFormatter(argparse.RawDescriptionHelpFormatter):
    pass


_DB_SHOW_INVENTORY_VIEWS = (
    ("hosts", "Host inventory."),
    ("endpoints", "Endpoint inventory."),
    ("findings", "Findings."),
    ("runs", "Run history."),
    ("artifacts", "Stored payloads."),
)

_DB_SHOW_MODULES = (
    "exporters",
    "registry",
    "grafana",
    "proxmox",
    "gitlab",
    "consul",
    "kubeapi",
    "postgres",
    "clickhouse",
    "redis",
    "etcd",
    "qdrant",
    "kafka",
    "zookeeper",
)


class _DbShowParser(_NoColorArgumentParser):
    def format_help(self) -> str:
        module_lines = "\n".join(f"  {name}" for name in _DB_SHOW_MODULES)
        return (
            "usage: redposture.py db show [-h] [--json] [--db-url url] [-v|--debug] [item] ...\n\n"
            "Read stored assessment data.\n\n"
            "Module Views:\n"
            f"{module_lines}\n\n"
            "  Run `redposture.py db show <module> -h` for module-specific help.\n"
            "  Run `redposture.py db show hosts -h` for inventory command help.\n\n"
            "Options:\n"
            "  -h, --help    show this help message and exit\n"
            "  --json        Print JSON instead of table output.\n"
            "  --db-url url  Database URL. If omitted, uses local .redposture sqlite DB.\n"
            "  -v, --debug   Show expanded details in text output.\n"
        )


class _DbShowModuleParser(_NoColorArgumentParser):
    def format_help(self) -> str:
        module_name = str(getattr(self, "_db_help_module_name", "module"))
        usage = f"usage: redposture.py db show {module_name} [-h] [--json] [--db-url url] [-v|--debug] "
        if module_name == "exporters":
            usage += "[--summary|--hosts|--list-host|--endpoints|--findings|--runs|--artifacts] [--host value]"
            usage += " [--collect|--trigger]"
        else:
            usage += "[--summary|--hosts|--endpoints|--findings|--runs|--artifacts]"
        usage += "\n\n"

        options_lines = [
            "  -h, --help    show this help message and exit",
            "  --json        Print JSON instead of table output.",
            "  --db-url url  Database URL. If omitted, uses local .redposture sqlite DB.",
            "",
            "  -v, --debug   Show expanded details in text output.",
            "  --summary     Show counts-only summary.",
            f"  --hosts       Shortcut for 'db show {module_name} hosts'.",
        ]
        if module_name == "exporters":
            options_lines.extend(
                [
                    "",
                    "  --list-host   Exporters only: alias for '--hosts'.",
                    "  --host value  Exporters only: show only landing results for this host.",
                    "",
                    f"  --endpoints   Shortcut for 'db show {module_name} endpoints'.",
                    "",
                    f"  --findings    Shortcut for 'db show {module_name} findings'.",
                    f"  --runs        Shortcut for 'db show {module_name} runs'.",
                    f"  --artifacts   Shortcut for 'db show {module_name} artifacts'.",
                    "",
                    "  --collect     Exporters only: show collect findings only.",
                    "  --trigger     Exporters only: show trigger findings only.",
                ]
            )
        else:
            options_lines.extend(
                [
                    f"  --endpoints   Shortcut for 'db show {module_name} endpoints'.",
                    "",
                    f"  --findings    Shortcut for 'db show {module_name} findings'.",
                    f"  --runs        Shortcut for 'db show {module_name} runs'.",
                    f"  --artifacts   Shortcut for 'db show {module_name} artifacts'.",
                ]
            )

        examples_lines = [
            f"  redposture.py db show {module_name}",
            f"  redposture.py db show {module_name} --summary",
            f"  redposture.py db show {module_name} --hosts",
        ]
        if module_name == "exporters":
            examples_lines.extend(
                [
                    "  redposture.py db show exporters --list-host",
                    "  redposture.py db show exporters --host 10.10.10.10",
                    f"  redposture.py db show {module_name} --endpoints",
                    f"  redposture.py db show {module_name} --findings",
                    "  redposture.py db show exporters --collect",
                    "  redposture.py db show exporters --trigger",
                ]
            )
        else:
            examples_lines.extend(
                [
                    f"  redposture.py db show {module_name} --endpoints",
                    f"  redposture.py db show {module_name} --findings",
                    f"  redposture.py db show {module_name} --runs",
                    f"  redposture.py db show {module_name} --artifacts",
                ]
            )

        return (
            usage
            + f"Inspect stored {module_name} data.\n\n"
            + "Default:\n"
            + f"  redposture.py db show {module_name}  -> recent useful hits/results\n\n"
            + "Options:\n"
            + "\n".join(options_lines)
            + "\n\n"
            + "Examples:\n"
            + "\n".join(examples_lines)
            + "\n"
        )


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
    parser.add_argument(
        "--ports",
        dest="ports",
        default=None,
        metavar="ports",
        help=("Optional additional ports: single port, comma-separated list/range, or file path with port values."),
    )


def _add_db_url_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--db-url",
        dest="db_url",
        default=None,
        metavar="url",
        help="Database URL. If omitted, uses local .redposture sqlite DB.",
    )


def _add_db_json_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Print JSON instead of table output.",
    )


def _add_db_debug_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-v",
        "--debug",
        dest="debug",
        action="store_true",
        help="Show expanded details in text output.",
    )


def _add_db_module_flag(parser: argparse.ArgumentParser, *, include_alias: bool = False) -> None:
    parser.add_argument(
        "--module",
        dest="module_name",
        default=None,
        metavar="name",
        help="Only this module.",
    )
    if include_alias:
        parser.add_argument(
            "--module-name",
            dest="module_name",
            default=None,
            metavar="name",
            help=argparse.SUPPRESS,
        )


def _db_show_description(modules: tuple[str, ...]) -> str:
    del modules
    return "Read stored assessment data."


_DB_SHOW_EXAMPLES = """Examples:
  redposture.py db show
  redposture.py db show hosts
  redposture.py db show hosts --module grafana
  redposture.py db show findings --module postgres
  redposture.py db show module grafana
  redposture.py db show module grafana summary
  redposture.py db show module grafana findings
"""


def _db_module_show_description(module_name: str) -> str:
    if module_name == "exporters":
        return (
            "Inspect stored exporters data.\n\n"
            "Default:\n"
            "  redposture.py db show exporters\n"
            "  # latest useful hits/results\n\n"
            "Sections:\n"
            "  redposture.py db show exporters summary\n"
            "  redposture.py db show exporters findings\n"
            "  redposture.py db show exporters hosts\n"
            "  redposture.py db show exporters endpoints\n"
            "  redposture.py db show exporters runs\n"
            "  redposture.py db show exporters artifacts"
        )
    return (
        f"Inspect stored {module_name} data.\n\n"
        "Default:\n"
        f"  redposture.py db show {module_name}\n\n"
        "Sections:\n"
        f"  redposture.py db show {module_name} summary\n"
        f"  redposture.py db show {module_name} hosts\n"
        f"  redposture.py db show {module_name} endpoints\n"
        f"  redposture.py db show {module_name} findings\n"
        f"  redposture.py db show {module_name} runs\n"
        f"  redposture.py db show {module_name} artifacts"
    )


def _db_module_command_description(modules: tuple[str, ...]) -> str:
    return (
        "Inspect one module.\n\n"
        "Default:\n"
        "  db show module <name>  -> recent useful hits/results\n\n"
        f"Modules:\n  {', '.join(modules)}"
    )


def _add_db_show_module_flags(parser: argparse.ArgumentParser, *, module_name: str) -> None:
    parser.add_argument(
        "--summary",
        dest="module_show_summary",
        action="store_true",
        help="Show counts-only summary for this module.",
    )
    parser.add_argument(
        "--hosts",
        dest="module_show_hosts",
        action="store_true",
        help="Show hosts related to this module.",
    )
    if module_name == "exporters":
        parser.add_argument(
            "--list-host",
            dest="module_show_hosts",
            action="store_true",
            help="Exporters only: alias for '--hosts'.",
        )
        parser.add_argument(
            "--host",
            dest="exporters_host_filter",
            default=None,
            metavar="value",
            help="Exporters only: show only landing results for this host.",
        )
    else:
        parser.add_argument(
            "--host",
            dest="module_show_hosts",
            action="store_true",
            help=argparse.SUPPRESS,
        )
    parser.add_argument(
        "--endpoints",
        dest="module_show_endpoints",
        action="store_true",
        help="Show endpoints related to this module.",
    )
    parser.add_argument(
        "--findings",
        dest="module_show_findings",
        action="store_true",
        help="Show findings related to this module.",
    )
    parser.add_argument(
        "--runs",
        dest="module_show_runs",
        action="store_true",
        help="Show runs related to this module.",
    )
    parser.add_argument(
        "--artifacts",
        dest="module_show_artifacts",
        action="store_true",
        help="Show artifacts related to this module.",
    )
    if module_name == "exporters":
        exporters_phase_group = parser.add_mutually_exclusive_group()
        exporters_phase_group.add_argument(
            "--collect",
            dest="exporters_collect_only",
            action="store_true",
            help="Exporters only: show collect findings only.",
        )
        exporters_phase_group.add_argument(
            "--trigger",
            dest="exporters_trigger_only",
            action="store_true",
            help="Exporters only: show trigger findings only.",
        )


def _set_db_show_module_defaults(parser: argparse.ArgumentParser, *, module_name: str) -> None:
    parser.set_defaults(
        module_name=module_name,
        db_handler_name="show_module_dashboard",
        host_id=None,
        target=None,
        run_id=None,
        protocol=None,
        severity=None,
        status=None,
        tag=None,
        date_from=None,
        date_to=None,
        module_show_summary=False,
        module_show_hosts=False,
        module_show_endpoints=False,
        module_show_findings=False,
        module_show_runs=False,
        module_show_artifacts=False,
        exporters_host_filter=None,
        exporters_collect_only=False,
        exporters_trigger_only=False,
    )


def _configure_db_parser(db_parser: argparse.ArgumentParser) -> None:
    db_subparsers = db_parser.add_subparsers(
        dest="db_action",
        required=True,
        parser_class=_NoColorArgumentParser,
    )

    db_init_parser = db_subparsers.add_parser(
        "init",
        help="Create or migrate the local DB.",
        formatter_class=_DbHelpFormatter,
    )
    _add_db_url_flag(db_init_parser)
    db_init_parser.set_defaults(db_handler_name="init")

    db_migrate_parser = db_subparsers.add_parser(
        "migrate",
        help="Apply pending DB migrations.",
        formatter_class=_DbHelpFormatter,
    )
    _add_db_url_flag(db_migrate_parser)
    db_migrate_parser.set_defaults(db_handler_name="migrate")

    db_ingest_parser = db_subparsers.add_parser(
        "ingest",
        help="Import module JSON/JSONL results.",
        formatter_class=_DbHelpFormatter,
    )
    db_ingest_parser.add_argument("module", metavar="module", help="Module name to ingest.")
    db_ingest_parser.add_argument("json_file", metavar="json-file", help="Path to JSON or JSONL file.")
    _add_db_json_flag(db_ingest_parser)
    _add_db_url_flag(db_ingest_parser)
    db_ingest_parser.set_defaults(db_handler_name="ingest")

    db_show_parser = db_subparsers.add_parser(
        "show",
        help="Read inventory and findings.",
        formatter_class=_DbHelpFormatter,
        description=_db_show_description(_DB_SHOW_MODULES),
        epilog=_DB_SHOW_EXAMPLES,
    )
    db_show_parser.__class__ = _DbShowParser
    _add_db_json_flag(db_show_parser)
    _add_db_url_flag(db_show_parser)
    db_show_parser.set_defaults(db_handler_name="show_overview")
    db_show_subparsers = db_show_parser.add_subparsers(
        dest="db_show_action",
        required=False,
        title="Views",
        parser_class=_NoColorArgumentParser,
    )
    db_show_common_parent = _NoColorArgumentParser(add_help=False)
    _add_db_json_flag(db_show_common_parent)
    _add_db_url_flag(db_show_common_parent)
    _add_db_debug_flag(db_show_common_parent)

    db_show_hosts_parser = db_show_subparsers.add_parser(
        "hosts",
        help="Host inventory.",
        formatter_class=_DbHelpFormatter,
    )
    _add_db_module_flag(db_show_hosts_parser)
    _add_db_json_flag(db_show_hosts_parser)
    _add_db_url_flag(db_show_hosts_parser)
    _add_db_debug_flag(db_show_hosts_parser)
    db_show_hosts_parser.set_defaults(db_handler_name="show_hosts")

    db_show_endpoints_parser = db_show_subparsers.add_parser(
        "endpoints",
        help="Endpoint inventory.",
        formatter_class=_DbHelpFormatter,
    )
    _add_db_module_flag(db_show_endpoints_parser)
    db_show_endpoints_parser.add_argument(
        "--host-id", dest="host_id", type=int, default=None, metavar="id", help="Optional host id filter."
    )
    _add_db_json_flag(db_show_endpoints_parser)
    _add_db_url_flag(db_show_endpoints_parser)
    _add_db_debug_flag(db_show_endpoints_parser)
    db_show_endpoints_parser.set_defaults(db_handler_name="show_endpoints")

    db_show_findings_parser = db_show_subparsers.add_parser(
        "findings",
        help="Findings.",
        formatter_class=_DbHelpFormatter,
    )
    _add_db_module_flag(db_show_findings_parser, include_alias=True)
    db_show_findings_parser.add_argument(
        "--protocol", dest="protocol", default=None, metavar="name", help="Optional protocol filter."
    )
    db_show_findings_parser.add_argument(
        "--severity", dest="severity", default=None, metavar="level", help="Optional severity filter."
    )
    db_show_findings_parser.add_argument(
        "--status", dest="status", default=None, metavar="state", help="Optional finding status filter."
    )
    db_show_findings_parser.add_argument("--tag", dest="tag", default=None, metavar="name", help="Optional tag filter.")
    db_show_findings_parser.add_argument(
        "--date-from", dest="date_from", default=None, metavar="ts", help="Lower bound for last_seen_at."
    )
    db_show_findings_parser.add_argument(
        "--date-to", dest="date_to", default=None, metavar="ts", help="Upper bound for last_seen_at."
    )
    _add_db_json_flag(db_show_findings_parser)
    _add_db_url_flag(db_show_findings_parser)
    _add_db_debug_flag(db_show_findings_parser)
    db_show_findings_parser.set_defaults(db_handler_name="show_findings")

    db_show_runs_parser = db_show_subparsers.add_parser(
        "runs",
        help="Run history.",
        formatter_class=_DbHelpFormatter,
    )
    _add_db_module_flag(db_show_runs_parser)
    db_show_runs_parser.add_argument(
        "--target", dest="target", default=None, metavar="value", help="Optional target_text filter."
    )
    _add_db_json_flag(db_show_runs_parser)
    _add_db_url_flag(db_show_runs_parser)
    _add_db_debug_flag(db_show_runs_parser)
    db_show_runs_parser.set_defaults(db_handler_name="show_runs")

    db_show_artifacts_parser = db_show_subparsers.add_parser(
        "artifacts",
        help="Stored payloads.",
        formatter_class=_DbHelpFormatter,
    )
    _add_db_module_flag(db_show_artifacts_parser)
    db_show_artifacts_parser.add_argument(
        "--run-id", dest="run_id", type=int, default=None, metavar="id", help="Optional run id filter."
    )
    _add_db_json_flag(db_show_artifacts_parser)
    _add_db_url_flag(db_show_artifacts_parser)
    _add_db_debug_flag(db_show_artifacts_parser)
    db_show_artifacts_parser.set_defaults(db_handler_name="show_artifacts")

    for module_name in _DB_SHOW_MODULES:
        module_parser = db_show_subparsers.add_parser(
            module_name,
            parents=[db_show_common_parent],
            help=argparse.SUPPRESS,
            formatter_class=_DbHelpFormatter,
            prog=f"redposture.py db show {module_name}",
            description=_db_module_show_description(module_name),
        )
        module_parser.__class__ = _DbShowModuleParser
        module_parser._db_help_module_name = module_name  # type: ignore[attr-defined]
        _add_db_show_module_flags(module_parser, module_name=module_name)
        _set_db_show_module_defaults(module_parser, module_name=module_name)

        module_subparsers = module_parser.add_subparsers(
            dest="db_show_module_action",
            required=False,
            title="Sections",
            metavar="section",
            parser_class=_NoColorArgumentParser,
        )

        module_summary_parser = module_subparsers.add_parser(
            "summary",
            parents=[db_show_common_parent],
            help=argparse.SUPPRESS,
            formatter_class=_DbHelpFormatter,
        )
        _set_db_show_module_defaults(module_summary_parser, module_name=module_name)
        module_summary_parser.set_defaults(db_handler_name="show_module_summary")

        module_hosts_parser = module_subparsers.add_parser(
            "hosts",
            parents=[db_show_common_parent],
            help=argparse.SUPPRESS,
            formatter_class=_DbHelpFormatter,
        )
        _set_db_show_module_defaults(module_hosts_parser, module_name=module_name)
        module_hosts_parser.set_defaults(db_handler_name="show_hosts")

        module_endpoints_parser = module_subparsers.add_parser(
            "endpoints",
            parents=[db_show_common_parent],
            help=argparse.SUPPRESS,
            formatter_class=_DbHelpFormatter,
        )
        module_endpoints_parser.add_argument(
            "--host-id",
            dest="host_id",
            type=int,
            default=None,
            metavar="id",
            help="Optional host id filter.",
        )
        _set_db_show_module_defaults(module_endpoints_parser, module_name=module_name)
        module_endpoints_parser.set_defaults(db_handler_name="show_endpoints")

        module_findings_parser = module_subparsers.add_parser(
            "findings",
            parents=[db_show_common_parent],
            help=argparse.SUPPRESS,
            formatter_class=_DbHelpFormatter,
        )
        module_findings_parser.add_argument(
            "--protocol", dest="protocol", default=None, metavar="name", help="Optional protocol filter."
        )
        module_findings_parser.add_argument(
            "--severity", dest="severity", default=None, metavar="level", help="Optional severity filter."
        )
        module_findings_parser.add_argument(
            "--status", dest="status", default=None, metavar="state", help="Optional finding status filter."
        )
        module_findings_parser.add_argument(
            "--tag", dest="tag", default=None, metavar="name", help="Optional tag filter."
        )
        module_findings_parser.add_argument(
            "--date-from", dest="date_from", default=None, metavar="ts", help="Lower bound for last_seen_at."
        )
        module_findings_parser.add_argument(
            "--date-to", dest="date_to", default=None, metavar="ts", help="Upper bound for last_seen_at."
        )
        _set_db_show_module_defaults(module_findings_parser, module_name=module_name)
        module_findings_parser.set_defaults(db_handler_name="show_findings")

        module_runs_parser = module_subparsers.add_parser(
            "runs",
            parents=[db_show_common_parent],
            help=argparse.SUPPRESS,
            formatter_class=_DbHelpFormatter,
        )
        module_runs_parser.add_argument(
            "--target",
            dest="target",
            default=None,
            metavar="value",
            help="Optional target_text filter.",
        )
        _set_db_show_module_defaults(module_runs_parser, module_name=module_name)
        module_runs_parser.set_defaults(db_handler_name="show_runs")

        module_artifacts_parser = module_subparsers.add_parser(
            "artifacts",
            parents=[db_show_common_parent],
            help=argparse.SUPPRESS,
            formatter_class=_DbHelpFormatter,
        )
        module_artifacts_parser.add_argument(
            "--run-id",
            dest="run_id",
            type=int,
            default=None,
            metavar="id",
            help="Optional run id filter.",
        )
        _set_db_show_module_defaults(module_artifacts_parser, module_name=module_name)
        module_artifacts_parser.set_defaults(db_handler_name="show_artifacts")

    db_export_parser = db_subparsers.add_parser(
        "export",
        help="Export findings, hosts, or the whole DB.",
        formatter_class=_DbHelpFormatter,
    )
    db_export_subparsers = db_export_parser.add_subparsers(
        dest="db_export_action",
        required=True,
        parser_class=_NoColorArgumentParser,
    )

    db_export_findings_parser = db_export_subparsers.add_parser(
        "findings",
        help="Export findings.",
        formatter_class=_DbHelpFormatter,
    )
    _add_db_module_flag(db_export_findings_parser)
    db_export_findings_parser.add_argument(
        "--format",
        dest="output_format",
        choices=("json", "csv"),
        default="json",
        metavar="format",
        help="Export format.",
    )
    db_export_findings_parser.add_argument(
        "--output", dest="output", default=None, metavar="file", help="Optional output file path."
    )
    _add_db_url_flag(db_export_findings_parser)
    db_export_findings_parser.set_defaults(db_handler_name="export_findings")

    db_export_hosts_parser = db_export_subparsers.add_parser(
        "hosts",
        help="Export hosts.",
        formatter_class=_DbHelpFormatter,
    )
    _add_db_module_flag(db_export_hosts_parser)
    db_export_hosts_parser.add_argument(
        "--format",
        dest="output_format",
        choices=("json", "csv"),
        default="json",
        metavar="format",
        help="Export format.",
    )
    db_export_hosts_parser.add_argument(
        "--output", dest="output", default=None, metavar="file", help="Optional output file path."
    )
    _add_db_url_flag(db_export_hosts_parser)
    db_export_hosts_parser.set_defaults(db_handler_name="export_hosts")

    db_export_database_parser = db_export_subparsers.add_parser(
        "database",
        help="Export the whole sqlite database file.",
        formatter_class=_DbHelpFormatter,
    )
    db_export_database_parser.add_argument(
        "--output",
        dest="output",
        required=True,
        metavar="file",
        help="Output sqlite file path.",
    )
    _add_db_url_flag(db_export_database_parser)
    db_export_database_parser.set_defaults(db_handler_name="export_database")

    db_import_parser = db_subparsers.add_parser(
        "import",
        help="Import the whole sqlite database file.",
        formatter_class=_DbHelpFormatter,
    )
    db_import_subparsers = db_import_parser.add_subparsers(
        dest="db_import_action",
        required=True,
        parser_class=_NoColorArgumentParser,
    )
    db_import_database_parser = db_import_subparsers.add_parser(
        "database",
        help="Import a whole sqlite database file.",
        formatter_class=_DbHelpFormatter,
    )
    db_import_database_parser.add_argument(
        "--input",
        dest="input",
        required=True,
        metavar="file",
        help="Input sqlite file path.",
    )
    _add_db_url_flag(db_import_database_parser)
    db_import_database_parser.set_defaults(db_handler_name="import_database")

    db_search_parser = db_subparsers.add_parser(
        "search",
        help="Search stored findings and payloads.",
        formatter_class=_DbHelpFormatter,
    )
    db_search_parser.add_argument("query", metavar="query", help="Search query.")
    _add_db_json_flag(db_search_parser)
    _add_db_url_flag(db_search_parser)
    db_search_parser.set_defaults(db_handler_name="search")


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
            "(http[s]://host:port or socks5[h]://[user:pass@]host:port)."
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
        help="Optional custom ports to probe: single port, comma-separated list/range, or file path.",
    )


def _configure_trigger_parser(parser: argparse.ArgumentParser) -> None:
    trigger_options = parser.add_argument_group("Trigger options")
    listen_options = parser.add_argument_group("Listen options")

    _add_output_flags(trigger_options)
    _add_log_flag(trigger_options)
    _add_scan_host_flags(trigger_options)
    _add_save_flag(trigger_options, "Optional output file path. Use --format json for structured trigger records.")
    trigger_options.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Trigger output format for stdout/file.",
    )
    trigger_options.add_argument(
        "-p",
        "--ports",
        dest="ports",
        default=None,
        metavar="ports",
        help="Optional custom exporter ports: single port, comma-separated list/range, or file path.",
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
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Start listeners first, then run trigger stage, then keep listeners running.",
    )
    trigger_options.add_argument(
        "--listen-seconds",
        dest="listen_seconds",
        type=float,
        default=None,
        metavar="seconds",
        help="With --with-listen, stop listeners automatically after N seconds.",
    )
    trigger_options.add_argument(
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
    trigger_options.add_argument(
        "-check",
        "--check-credentials",
        action="store_true",
        help=(
            "With --with-listen, validate captured Redis/Postgres credentials against source exporter IPs "
            "(Redis:6379, Postgres:5432)."
        ),
    )
    trigger_options.add_argument(
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
    _add_listener_flags(listen_options)
    parser.set_defaults(workers=50)
    for action in parser._actions:
        if getattr(action, "dest", None) == "workers":
            action.default = 50
            break


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
        "-p",
        "--ports",
        dest="ports",
        default=None,
        metavar="ports",
        help="Optional custom ports to probe: single port, comma-separated list/range, or file path.",
    )
    parser.add_argument(
        "--save-responses-dir",
        dest="save_responses_dir",
        default=None,
        metavar="dir",
        help=("Save raw response bodies from collect endpoints to directory tree and write metadata index.jsonl."),
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
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume collect run by skipping endpoint jobs already present in checkpoint file.",
    )
    parser.add_argument(
        "--checkpoint-file",
        dest="checkpoint_file",
        default=None,
        metavar="file",
        help=(
            "Checkpoint JSONL file for collect resume state. Default: <output>.checkpoint.jsonl (or save dir fallback)."
        ),
    )
    parser.add_argument(
        "--max-inflight",
        dest="max_inflight",
        type=_positive_int,
        default=None,
        metavar="count",
        help="Maximum in-flight collect HTTP requests (default: adaptive from worker count).",
    )
    parser.add_argument(
        "--adaptive-collect",
        dest="adaptive_collect",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable adaptive preflight planning to reduce unnecessary collect requests.",
    )


def _configure_gitlab_parser(parser: argparse.ArgumentParser) -> None:
    _add_output_flags(parser)
    _add_log_flag(parser)
    _add_scan_host_flags(parser, include_profiles=False)
    parser.add_argument(
        "--port",
        dest="port",
        type=_port,
        default=80,
        metavar="port",
        help="GitLab HTTP port spec: single port, list/range, or file (examples: 80, 80,443,8080, ./ports.txt).",
    )
    _add_multi_ports_flag(parser)
    parser.add_argument(
        "--https",
        action="store_true",
        help="Use HTTPS for GitLab web/API probing (default is HTTP).",
    )
    parser.add_argument(
        "--token",
        dest="token",
        default=None,
        metavar="value",
        help="Optional GitLab Personal/Group Access Token for API auth and permission checks.",
    )
    parser.add_argument(
        "--project",
        dest="project",
        action="append",
        default=None,
        metavar="name",
        help="Project filter (path_with_namespace or numeric id). Repeatable; comma-separated values are also supported.",
    )
    parser.add_argument(
        "--clone",
        action="store_true",
        help="Clone accessible projects. With --project clones selected project(s); otherwise clones all accessible projects.",
    )
    parser.add_argument(
        "--clone-dir",
        dest="clone_dir",
        default="./gitlab_clones",
        metavar="dir",
        help="Output directory root for --clone repositories.",
    )
    _add_save_flag(parser, "Optional output file path. If omitted, results are printed to stdout.")
    parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="GitLab audit output format for stdout/file.",
    )


def _configure_kubeapi_parser(parser: argparse.ArgumentParser) -> None:
    _add_output_flags(parser)
    _add_log_flag(parser)
    _add_scan_host_flags(parser, include_profiles=False)
    parser.add_argument(
        "--port",
        dest="port",
        type=_port,
        default=6443,
        metavar="port",
        help="Kubernetes API port spec: single port, list/range, or file (examples: 6443, 6443,8443, ./ports.txt).",
    )
    _add_multi_ports_flag(parser)
    parser.add_argument(
        "--https",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use HTTPS for Kubernetes API requests.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS certificate verification (useful for self-signed clusters).",
    )
    parser.add_argument(
        "--ca-file",
        dest="ca_file",
        default=None,
        metavar="path",
        help="Custom CA certificate file for Kubernetes API TLS verification.",
    )
    parser.add_argument(
        "--token",
        dest="token",
        default=None,
        metavar="value",
        help="Optional Kubernetes Bearer token for API authentication.",
    )
    parser.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional Kubernetes API username for Basic auth.",
    )
    parser.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional Kubernetes API password for Basic auth.",
    )
    parser.add_argument(
        "--namespaces",
        action="store_true",
        help="Enumerate namespaces accessible with no-auth or provided credentials.",
    )
    parser.add_argument(
        "--pods",
        action="store_true",
        help="Enumerate pods across all namespaces or only selected --namespace values.",
    )
    parser.add_argument(
        "--namespace",
        dest="namespace",
        action="append",
        default=None,
        metavar="name",
        help="Namespace filter for --pods/--secrets (repeatable; comma-separated values also supported).",
    )
    parser.add_argument(
        "--pod",
        dest="pod",
        default=None,
        metavar="name",
        help="Target pod for exec (name or namespace/pod).",
    )
    parser.add_argument(
        "-X",
        "--exec-command",
        dest="exec_command",
        default=None,
        metavar="command",
        help="Execute shell command in --pod via Kubernetes API exec websocket (/bin/sh -c).",
    )
    parser.add_argument(
        "--secrets",
        action="store_true",
        help="Enumerate and decode readable Kubernetes Secret objects.",
    )
    _add_save_flag(parser, "Optional output file path. If omitted, results are printed to stdout.")
    parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Kubernetes API audit output format for stdout/file.",
    )


def _configure_consul_parser(parser: argparse.ArgumentParser) -> None:
    _add_output_flags(parser)
    _add_log_flag(parser)
    _add_scan_host_flags(parser, include_profiles=False)
    parser.add_argument(
        "--port",
        dest="port",
        type=_port,
        default=8500,
        metavar="port",
        help="Consul port(s): single, list/range, or file (e.g. 8500, 8500,8501, ./ports.txt).",
    )
    _add_multi_ports_flag(parser)
    parser.add_argument(
        "--token",
        dest="token",
        default=None,
        metavar="value",
        help="Consul ACL token (X-Consul-Token) for API auth.",
    )
    parser.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Basic auth username (for proxied/fronted Consul).",
    )
    parser.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Basic auth password (for proxied/fronted Consul).",
    )
    ssrf_options = parser.add_argument_group("SSRF")
    dump_options = parser.add_argument_group("Dump / Discovery")
    revshell_options = parser.add_argument_group("Reverse-shell")

    ssrf_options.add_argument(
        "--ssrf-target",
        dest="ssrf_target",
        default=None,
        metavar="target",
        help=("SSRF target(s): ip/dns/cidr/url (comma-separated). Enables agent-check SSRF probing."),
    )
    ssrf_options.add_argument(
        "--ssrf-port",
        dest="ssrf_port",
        default=None,
        metavar="ports",
        help="Ports for --ssrf-target (single/list/range/file syntax).",
    )
    ssrf_options.add_argument(
        "--ssrf-path",
        dest="ssrf_path",
        default=None,
        metavar="path",
        help="Path/query override for generated SSRF URLs (e.g. /debug/vars).",
    )
    dump_options.add_argument(
        "--keys",
        dest="show_keys",
        action="store_true",
        help="List KV keys (names only; use --dump for values).",
    )
    dump_options.add_argument(
        "--key",
        dest="kv_key",
        default=None,
        metavar="namekey",
        help="KV key to dump with --dump.",
    )
    revshell_options.add_argument(
        "--revshell",
        dest="revshell",
        action="store_true",
        help="Script-check RCE actions: create payload check or cleanup with --delete.",
    )
    revshell_options.add_argument(
        "--lhost",
        dest="revshell_host",
        default=None,
        metavar="addr",
        help="Listener host for default --revshell payload.",
    )
    revshell_options.add_argument(
        "--lport",
        dest="revshell_port",
        type=_port,
        default=None,
        metavar="port",
        help="Listener port for default --revshell payload.",
    )
    revshell_options.add_argument(
        "--listen",
        dest="revshell_listen",
        action="store_true",
        help="Auto-start local listener on --lport (prefers rlwrap+nc, fallback nc).",
    )
    revshell_options.add_argument(
        "--payload",
        dest="revshell_payload",
        default=None,
        metavar="cmd",
        help=("Custom command for --revshell. Replaces the default payload and makes --lhost/--lport optional."),
    )
    dump_options.add_argument(
        "--services",
        dest="show_services",
        action="store_true",
        help="List catalog services (use --dump for instances/details).",
    )
    dump_options.add_argument(
        "--service",
        dest="service_dump_name",
        default=None,
        metavar="name",
        help="Catalog service name for --dump.",
    )
    dump_options.add_argument(
        "--agents",
        dest="show_agents",
        action="store_true",
        help="List agent members (use --dump for details).",
    )
    dump_options.add_argument(
        "--agent",
        dest="agent_name",
        default=None,
        metavar="name",
        help="Agent member name for --dump.",
    )
    checks_action = dump_options.add_argument(
        "--checks",
        dest="show_checks",
        action="store_true",
        help="List agent checks (use --dump for details/status/output/definition).",
    )
    dump_options.add_argument(
        "--nodes",
        dest="show_nodes",
        action="store_true",
        help="List catalog nodes (use --dump for details).",
    )
    dump_options.add_argument(
        "--node",
        dest="node_name",
        default=None,
        metavar="name",
        help="Catalog node name for --dump.",
    )
    dump_options.add_argument(
        "--dump",
        dest="dump",
        action="store_true",
        help=("Dump details for selected data. Without selectors, dumps KV/services/agents/checks/nodes."),
    )
    revshell_options.add_argument(
        "--delete",
        dest="delete_revshell",
        action="store_true",
        help="Delete revshell check(s): all rev-rp-* or a specific --check-id.",
    )
    check_id_action = revshell_options.add_argument(
        "--check-id",
        dest="revshell_check_id",
        default=None,
        metavar="id",
        help=(
            "Consul check ID for --dump filter, targeted --delete, or custom --revshell create ID "
            "(supports id:<value>)."
        ),
    )
    # Help-only duplication for shared flags that are relevant to both dump and revshell workflows.
    _mirror_group_actions(dump_options, check_id_action)
    dump_group_actions = getattr(dump_options, "_group_actions", None)
    if (
        isinstance(dump_group_actions, list)
        and check_id_action in dump_group_actions
        and checks_action in dump_group_actions
    ):
        dump_group_actions.remove(check_id_action)
        dump_group_actions.insert(dump_group_actions.index(checks_action) + 1, check_id_action)
    _add_save_flag(parser, "Optional output file path. If omitted, results are printed to stdout.")
    parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Consul audit output format for stdout/file.",
    )


def _configure_qdrant_parser(parser: argparse.ArgumentParser) -> None:
    _add_output_flags(parser)
    _add_log_flag(parser)
    _add_scan_host_flags(parser, include_profiles=False)
    parser.add_argument(
        "--port",
        dest="port",
        type=_port,
        default=6333,
        metavar="port",
        help="Qdrant port(s): single, list/range, or file (e.g. 6333, 6333,6334, ./ports.txt).",
    )
    _add_multi_ports_flag(parser)
    parser.add_argument(
        "--api-key",
        dest="api_key",
        default=None,
        metavar="value",
        help="Qdrant API key for auth-required endpoints (anonymous check still runs).",
    )

    dump_options = parser.add_argument_group("Dump / Discovery")
    ssrf_options = parser.add_argument_group("SSRF")

    dump_options.add_argument(
        "--collections",
        dest="show_collections",
        action="store_true",
        help="List collection names (use --dump for collection info).",
    )
    dump_options.add_argument(
        "--collection",
        dest="collection",
        default=None,
        metavar="name",
        help="Collection name for --dump and snapshot-restore SSRF probe.",
    )
    dump_options.add_argument(
        "--dump",
        dest="dump",
        action="store_true",
        help="Dump collection info (all with --collections, or one with --collection).",
    )

    ssrf_options.add_argument(
        "--ssrf-target",
        dest="ssrf_target",
        default=None,
        metavar="target",
        help="SSRF target(s): ip/dns/cidr/url (comma-separated) via snapshot recover.",
    )
    ssrf_options.add_argument(
        "--ssrf-port",
        dest="ssrf_port",
        default=None,
        metavar="ports",
        help="Ports for --ssrf-target (single/list/range/file syntax).",
    )
    ssrf_options.add_argument(
        "--ssrf-path",
        dest="ssrf_path",
        default=None,
        metavar="path",
        help="Path/query override for SSRF URLs (e.g. /snapshot).",
    )
    ssrf_options.add_argument(
        "--listen",
        dest="ssrf_listen",
        action="store_true",
        help="Start local HTTP SSRF capture listener on --ssrf-port (best effort).",
    )

    _add_save_flag(parser, "Optional output file path. If omitted, results are printed to stdout.")
    parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Qdrant audit output format for stdout/file.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = _NoColorArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=(
            "Python3 security toolkit for listener emulation, endpoint discovery/trigger/collect, and Redis/Postgres/ClickHouse/etcd/Proxmox/Qdrant/Consul/Registry/Grafana/GitLab/Kubernetes API/Kafka/ZooKeeper auditing. "
            "Use one module command: exporters, registry, grafana, proxmox, gitlab, consul, kubeapi, postgres, clickhouse, redis, etcd, qdrant, kafka, zookeeper. "
            "Listener mode is available inside trigger via --with-listen."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_package_version()}")
    subparsers = parser.add_subparsers(dest="command", parser_class=_NoColorArgumentParser)

    exporters_parser = subparsers.add_parser(
        COMMAND_EXPORTERS,
        help="Unified exporter workflows: scan/collect/trigger.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    db_parser = subparsers.add_parser(
        COMMAND_DB,
        help="Local assessment DB: ingest, show, export, search.",
        formatter_class=_DbHelpFormatter,
        description=(
            "Store and read RedPosture assessment data.\n\n"
            "Common flow:\n"
            "  redposture.py db init\n"
            "  redposture.py db ingest grafana result.json\n"
            "  redposture.py db show module grafana\n"
            "  redposture.py db export findings --format csv"
        ),
    )
    _configure_db_parser(db_parser)
    exporters_subparsers = exporters_parser.add_subparsers(
        dest="exporters_action",
        required=True,
        parser_class=_NoColorArgumentParser,
    )

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

    registry_parser = subparsers.add_parser(
        COMMAND_REGISTRY,
        help="Audit Docker Registry v2 / Harbor / GitLab / Nexus exposure and image metadata.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=(
            "Registry audit supports four modes: generic Docker Registry v2/OCI, Harbor, "
            "GitLab Container Registry, and Nexus Repository. By default it performs minimal "
            "detection and prints only the detected type + basic access status. "
            "Use --harbor/--gitlab/--nexus for vendor API parsing, and use shared Docker/OCI "
            "flags (--repository/--show-tags/--tag/--metadata/--inspect/--download) to inspect "
            "image tags and config metadata on any compatible v2 registry endpoint."
        ),
    )
    registry_common = registry_parser.add_argument_group("Common")
    _add_output_flags(registry_common)  # type: ignore[arg-type]
    _add_log_flag(registry_common)
    _add_scan_host_flags(registry_common, include_profiles=False)  # type: ignore[arg-type]
    registry_common.add_argument(
        "--port",
        dest="port",
        type=_port,
        default=5000,
        metavar="port",
        help="Docker Registry port spec: single port, list/range, or file (examples: 5000, 5000,15000-15002, ./ports.txt).",
    )
    _add_multi_ports_flag(registry_common)
    _add_save_flag(registry_common, "Optional output file path. If omitted, results are printed to stdout.")
    registry_common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Registry audit output format for stdout/file.",
    )

    registry_common.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional Registry/Harbor/GitLab/Nexus username for Basic auth.",
    )
    registry_common.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional Registry/Harbor/GitLab/Nexus password for Basic auth.",
    )
    registry_common.add_argument(
        "--token",
        dest="token",
        default=None,
        metavar="value",
        help="Optional Bearer token for Registry/Harbor/GitLab API auth.",
    )

    registry_docker = registry_parser.add_argument_group(
        "Docker / OCI (Registry v2)",
        (
            "Shared OCI content operations. These flags work with plain Docker Registry v2 and "
            "also with vendor-backed Docker registry endpoints (Harbor/GitLab/Nexus Docker)."
        ),
    )
    registry_docker.add_argument(
        "--docker",
        action="store_true",
        help="Enable explicit Docker Registry v2/OCI mode (for clarity with vendor-specific flags).",
    )
    registry_images_action = registry_docker.add_argument(
        "--images",
        action="store_true",
        help="List repositories/images from /v2/_catalog and tags (when accessible).",
    )
    registry_repository_action = registry_docker.add_argument(
        "--repository",
        dest="repository",
        default=None,
        metavar="name",
        help="Repository name for targeted tag listing/metadata (example: gitlab/project-api).",
    )
    registry_show_tags_action = registry_docker.add_argument(
        "--show-tags",
        dest="show_tags",
        action="store_true",
        help="Show tags for --repository.",
    )
    registry_tag_action = registry_docker.add_argument(
        "--tag",
        dest="tag",
        default=None,
        metavar="name",
        help="Tag name used with --repository for --metadata.",
    )
    registry_metadata_action = registry_docker.add_argument(
        "--metadata",
        dest="metadata",
        action="store_true",
        help="Show config metadata (ENV/LABELS/CMD) for --repository + --tag.",
    )
    registry_inspect_action = registry_docker.add_argument(
        "--inspect",
        action="store_true",
        help="Inspect image metadata (ENV, exposed ports, labels, history).",
    )
    registry_image_action = registry_docker.add_argument(
        "--image",
        dest="image",
        default=None,
        metavar="name",
        help="Image reference for --inspect/--download (example: library/nginx:latest).",
    )
    registry_download_action = registry_docker.add_argument(
        "--download",
        action="store_true",
        help="Download image blobs for --image (asks confirmation when image size exceeds 100MB).",
    )
    registry_download_dir_action = registry_docker.add_argument(
        "--download-dir",
        dest="download_dir",
        default="./registry_downloads",
        metavar="dir",
        help="Output directory for --download files.",
    )

    registry_harbor = registry_parser.add_argument_group(
        "Harbor",
        (
            "Harbor API deep parsing for projects/repositories/artifacts. Combine with shared "
            "Docker/OCI flags above (--repository/--show-tags/--tag/--metadata) to inspect "
            "specific image tags."
        ),
    )
    registry_harbor.add_argument(
        "--harbor",
        action="store_true",
        help="Enable Harbor API deep parsing (projects/repositories/artifacts).",
    )

    registry_gitlab = registry_parser.add_argument_group(
        "GitLab Container Registry",
        (
            "GitLab registry challenge/token endpoint probing and repository enumeration. "
            "Combine with shared Docker/OCI flags above for tags/metadata on a selected repo "
            "(typically with --token for API access)."
        ),
    )
    registry_gitlab.add_argument(
        "--gitlab",
        action="store_true",
        help="Enable GitLab Container Registry deep parsing (Bearer challenge/token endpoint metadata).",
    )

    registry_nexus = registry_parser.add_argument_group(
        "Nexus Repository",
        (
            "Nexus REST API deep parsing for repositories/components. Use --assets to print "
            "downloadUrl + checksums. Shared Docker/OCI flags above work against Nexus Docker "
            "registry endpoints for tags and metadata."
        ),
    )
    registry_nexus.add_argument(
        "--nexus",
        action="store_true",
        help="Enable Nexus Repository deep parsing (status/repositories via REST API).",
    )
    registry_nexus.add_argument(
        "--assets",
        dest="assets",
        action="store_true",
        help="With --nexus, show asset downloadUrl and checksums for repository components.",
    )
    for vendor_group in (registry_harbor, registry_gitlab, registry_nexus):
        _mirror_group_actions(
            vendor_group,
            registry_images_action,
            registry_repository_action,
            registry_show_tags_action,
            registry_tag_action,
            registry_metadata_action,
            registry_inspect_action,
            registry_image_action,
            registry_download_action,
            registry_download_dir_action,
        )

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
        help="Grafana port spec: single port, list/range, or file (examples: 3000, 3000,3001, ./ports.txt).",
    )
    _add_multi_ports_flag(grafana_parser)
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

    proxmox_parser = subparsers.add_parser(
        COMMAND_PROXMOX,
        help="Audit Proxmox API with PVE API token and search leaked credentials in API responses.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_output_flags(proxmox_parser)
    _add_log_flag(proxmox_parser)
    _add_scan_host_flags(proxmox_parser, include_profiles=False)
    proxmox_parser.set_defaults(timeout=3.0)
    proxmox_parser.add_argument(
        "--port",
        dest="port",
        type=_port,
        default=8006,
        metavar="port",
        help="Proxmox API port spec: single port, list/range, or file (examples: 8006, 8006,18006, ./ports.txt).",
    )
    _add_multi_ports_flag(proxmox_parser)
    proxmox_parser.add_argument(
        "--https",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use HTTPS for Proxmox API requests.",
    )
    proxmox_parser.add_argument(
        "--insecure",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Skip TLS certificate verification (recommended for self-signed Proxmox certs).",
    )
    proxmox_parser.add_argument(
        "--pveapitoken",
        dest="pve_api_token",
        required=True,
        metavar="value",
        help="Proxmox API token value: either '<user@realm!tokenid>=<secret>' or full 'PVEAPIToken=...'.",
    )
    proxmox_parser.add_argument(
        "--discover-creds",
        action="store_true",
        help="Enable extended endpoint crawl and credential discovery in API responses.",
    )
    proxmox_parser.add_argument(
        "--nodes",
        action="store_true",
        help="Show discovered Proxmox node names.",
    )
    proxmox_parser.add_argument(
        "--users",
        action="store_true",
        help="Show users returned by /access/users for current token.",
    )
    proxmox_parser.add_argument(
        "-add-user",
        "--add-user",
        dest="add_user",
        type=str,
        default=None,
        metavar="username",
        help="Create user via /access/users and generate random 20-char password.",
    )
    _add_save_flag(proxmox_parser, "Optional output file path. If omitted, results are printed to stdout.")
    proxmox_parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Proxmox audit output format for stdout/file.",
    )

    gitlab_parser = subparsers.add_parser(
        COMMAND_GITLAB,
        help="Audit GitLab public/unprotected endpoints, public projects, token access, and cloning.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=(
            "GitLab module checks login-page presence alongside public/unprotected endpoints, "
            "enumerates public projects by default, optionally validates PAT/GAT token API access "
            "and per-project capabilities (repo/issues/members), and can clone selected or all "
            "accessible repositories."
        ),
    )
    _configure_gitlab_parser(gitlab_parser)

    consul_parser = subparsers.add_parser(
        COMMAND_CONSUL,
        help="Audit Consul API exposure, anonymous access, and agent SSRF via health checks.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=(
            "Consul module detects Consul agents/servers by API responses, checks anonymous access to KV, services, "
            "agent members, and health checks, inspects script-check settings (EnableLocalScriptChecks / "
            "EnableRemoteScriptChecks), and can perform SSRF probes via temporary agent HTTP checks."
        ),
    )
    _configure_consul_parser(consul_parser)

    kubeapi_parser = subparsers.add_parser(
        COMMAND_KUBEAPI,
        help="Audit Kubernetes API exposure, auth requirements, and resource visibility.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=(
            "Kubernetes API module checks whether the cluster API is reachable without authentication, "
            "supports Bearer token or Basic auth, and can enumerate namespaces, pods, and secrets "
            "visible to the current access level."
        ),
    )
    _configure_kubeapi_parser(kubeapi_parser)

    postgres_parser = subparsers.add_parser(
        COMMAND_POSTGRES,
        help="Audit Postgres auth exposure and risky privileges.",
        formatter_class=_PostgresHelpFormatter,
    )
    _add_scan_host_flags(postgres_parser, include_profiles=False)
    postgres_parser.add_argument(
        "--port",
        dest="port",
        type=_port,
        default=5432,
        metavar="port",
        help="Postgres port spec: single port, list/range, or file (examples: 5432, 5432,15432, ./ports.txt).",
    )
    _add_multi_ports_flag(postgres_parser)
    _add_save_flag(
        postgres_parser,
        "Optional output file path. If omitted, results are printed to stdout.",
        include_save_alias=False,
    )
    postgres_parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Postgres audit output format for stdout/file.",
    )
    _add_log_flag(postgres_parser)
    _add_output_flags(postgres_parser, short=False)

    postgres_auth = postgres_parser.add_argument_group("Database / Auth")
    postgres_discovery = postgres_parser.add_argument_group("Discovery / Dump")
    postgres_exec = postgres_parser.add_argument_group("Execute / Shell")

    postgres_auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional Postgres username for credential check.",
    )
    postgres_auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional Postgres password for credential check.",
    )
    postgres_auth.add_argument(
        "--defcreds",
        action="store_true",
        help="Try default Postgres credentials postgres:postgres when auth is required.",
    )
    postgres_discovery.add_argument(
        "--show-databases",
        action="store_true",
        help="Show available database names in output after successful access/auth.",
    )
    postgres_discovery.add_argument(
        "--database",
        dest="database",
        default=None,
        metavar="name",
        help=(
            "Target database for table/dump/SQL operations. "
            "When omitted, --show-tables and --dump without --table walk all accessible databases."
        ),
    )
    postgres_discovery.add_argument(
        "--show-tables",
        action="store_true",
        help="Show readable table names with inline Rows:N after successful access/auth.",
    )
    postgres_discovery.add_argument(
        "--table",
        dest="tables",
        action="append",
        default=None,
        metavar="name",
        help="Target table (schema.table or table). Can be used multiple times or with comma-separated values.",
    )
    postgres_discovery.add_argument(
        "--show-columns",
        action="store_true",
        help="Show column names for --table target(s).",
    )
    postgres_discovery.add_argument(
        "--column",
        dest="columns",
        action="append",
        default=None,
        metavar="name",
        help="Column filter for --show-columns/--dump (repeatable, comma-separated is also supported). Applies to all --table targets.",
    )
    postgres_discovery.add_argument(
        "--rows",
        action="store_true",
        help="Compatibility alias for inline Rows:N output with --show-tables semantics.",
    )
    postgres_discovery.add_argument(
        "--dump",
        nargs="?",
        const=0,
        type=_positive_int,
        metavar="count",
        help=(
            "Dump table rows. Optional count limits dumped rows; without count dumps all rows. "
            "With --table dumps selected table(s); without --table dumps all readable tables."
        ),
    )
    postgres_execute_action = postgres_exec.add_argument(
        "-x",
        "--execute",
        dest="execute",
        default=None,
        metavar="command",
        help="Try executing OS command via Postgres COPY FROM PROGRAM and print output.",
    )
    postgres_execute_action._hide_metavar_in_help = True
    postgres_exec.add_argument(
        "--os-shell",
        action="store_true",
        help="Interactive command mode via Postgres COPY FROM PROGRAM (single target).",
    )
    postgres_exec.add_argument(
        "--sql-shell",
        action="store_true",
        help="Interactive SQL mode (single target).",
    )
    postgres_exec.add_argument(
        "--sql-cmd",
        dest="sql_cmd",
        default=None,
        metavar="query",
        help="Execute SQL query after successful connection/auth and print result rows.",
    )
    _append_selected_defaults(postgres_parser, "timeout", "workers", "retries", "port", "output_format")

    clickhouse_parser = subparsers.add_parser(
        COMMAND_CLICKHOUSE,
        help="Audit ClickHouse auth exposure and privileges.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_output_flags(clickhouse_parser, short=False)
    _add_log_flag(clickhouse_parser)
    _add_scan_host_flags(clickhouse_parser, include_profiles=False)
    clickhouse_parser.add_argument(
        "--port",
        dest="port",
        type=_port,
        default=9000,
        metavar="port",
        help="ClickHouse port spec: single port, list/range, or file (examples: 9000, 8123, 9000,8123, ./ports.txt).",
    )
    _add_multi_ports_flag(clickhouse_parser)
    clickhouse_parser.add_argument(
        "--http",
        action="store_true",
        help="Use ClickHouse HTTP/HTTPS API mode. By default native protocol is used.",
    )
    clickhouse_parser.add_argument(
        "-d",
        "--database",
        dest="database",
        default="default",
        metavar="name",
        help="Database used for authentication context and table operations.",
    )
    clickhouse_parser.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional ClickHouse username for credential check.",
    )
    clickhouse_parser.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional ClickHouse password for credential check.",
    )
    clickhouse_parser.add_argument(
        "--defcreds",
        action="store_true",
        help="Try default ClickHouse credentials default:<empty> and default:default.",
    )
    clickhouse_parser.add_argument(
        "--show-databases",
        action="store_true",
        help="Show database names after successful access/auth.",
    )
    clickhouse_parser.add_argument(
        "--show-tables",
        action="store_true",
        help="Show readable table names after successful access/auth.",
    )
    clickhouse_parser.add_argument(
        "--table",
        dest="tables",
        action="append",
        default=None,
        metavar="name",
        help="Target table (db.table or table). Can be used multiple times or with comma-separated values.",
    )
    clickhouse_parser.add_argument(
        "--show-columns",
        action="store_true",
        help="Show column names for --table target(s).",
    )
    clickhouse_parser.add_argument(
        "--column",
        dest="columns",
        action="append",
        default=None,
        metavar="name",
        help="Column filter for --show-columns/--dump (repeatable, comma-separated is also supported).",
    )
    clickhouse_parser.add_argument(
        "--dump",
        action="store_true",
        help="Dump table rows. With --table dumps selected table(s); without --table dumps all readable tables.",
    )
    clickhouse_parser.add_argument(
        "-x",
        "--execute",
        dest="execute",
        default=None,
        metavar="command",
        help="Execute OS command via ClickHouse executable() path when available (or SYSTEM command if prefixed with SYSTEM).",
    )
    clickhouse_parser.add_argument(
        "--sql-cmd",
        dest="sql_cmd",
        default=None,
        metavar="query",
        help="Execute SQL query after successful connection/auth and print result rows.",
    )
    clickhouse_parser.add_argument(
        "--os-shell",
        action="store_true",
        help="Interactive OS command mode (single target).",
    )
    clickhouse_parser.add_argument(
        "--sql-shell",
        action="store_true",
        help="Interactive SQL mode (single target).",
    )
    _add_save_flag(clickhouse_parser, "Optional output file path. If omitted, results are printed to stdout.")
    clickhouse_parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="ClickHouse audit output format for stdout/file.",
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
        help="Redis port spec: single port, list/range, or file (examples: 6379, 6379,16379, ./ports.txt).",
    )
    _add_multi_ports_flag(redis_parser)
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
        "--dump",
        dest="dump",
        action="store_true",
        help="Dump Redis key values. With -key/--key dumps one key; without -key dumps all keys.",
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
        help="etcd port spec: single port, list/range, or file (examples: 2379, 2379,22379, ./ports.txt).",
    )
    _add_multi_ports_flag(etcd_parser)
    etcd_parser.add_argument(
        "--show-keys",
        action="store_true",
        help="Show etcd key names only when auth is not required.",
    )
    etcd_parser.add_argument(
        "--dump",
        dest="dump",
        action="store_true",
        help="Dump etcd key values. With -key/--key dumps one key; without -key dumps all keys.",
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

    qdrant_parser = subparsers.add_parser(
        COMMAND_QDRANT,
        help="Audit Qdrant collections exposure, dump collection info, and snapshot-recover SSRF.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=(
            "Qdrant module checks anonymous access to /collections, lists and dumps collection metadata, "
            "probes collection update reachability with a no-op PATCH {} request, and can test SSRF "
            "via collection snapshot restore from a supplied URL."
        ),
    )
    _configure_qdrant_parser(qdrant_parser)

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
        help="Kafka port spec: single port, list/range, or file (examples: 9092, 9092,29092, ./ports.txt).",
    )
    _add_multi_ports_flag(kafka_parser)
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
        "--dump",
        action="store_true",
        help="Dump topic messages: with --topic dumps only that topic, otherwise dumps all topics.",
    )
    kafka_parser.add_argument(
        "--max-messages",
        dest="max_messages",
        type=int,
        default=1000,
        metavar="count",
        help="Maximum number of topic messages to read per topic with --dump.",
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

    zookeeper_parser = subparsers.add_parser(
        COMMAND_ZOOKEEPER,
        help="Audit ZooKeeper exposure, auth requirements, and znode visibility.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_output_flags(zookeeper_parser)
    _add_log_flag(zookeeper_parser)
    _add_scan_host_flags(zookeeper_parser, include_profiles=False)
    zookeeper_parser.add_argument(
        "--port",
        dest="port",
        type=_port,
        default=2181,
        metavar="port",
        help="ZooKeeper port spec: single port, list/range, or file (examples: 2181, 2181,22181, ./ports.txt).",
    )
    _add_multi_ports_flag(zookeeper_parser)
    zookeeper_parser.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional ZooKeeper username for digest auth credential check.",
    )
    zookeeper_parser.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional ZooKeeper password for digest auth credential check.",
    )
    zookeeper_parser.add_argument(
        "--show-znodes",
        action="store_true",
        help="Show znode paths after successful access/auth.",
    )
    zookeeper_parser.add_argument(
        "--dump",
        dest="dump",
        action="store_true",
        help="Dump znode values. With --znode dumps only that znode; without --znode dumps all enumerated znodes.",
    )
    zookeeper_parser.add_argument(
        "-znode",
        "--znode",
        dest="znode",
        default=None,
        metavar="path",
        help="Show one znode detail by path (example: /brokers/ids).",
    )
    zookeeper_parser.add_argument(
        "--max-znodes",
        dest="max_znodes",
        type=_positive_int,
        default=2000,
        metavar="count",
        help="Maximum znodes to enumerate per target.",
    )
    _add_save_flag(zookeeper_parser, "Optional output file path. If omitted, results are printed to stdout.")
    zookeeper_parser.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="ZooKeeper audit output format for stdout/file.",
    )

    return parser


def _rewrite_db_show_module_alias(argv: list[str]) -> list[str]:
    if len(argv) < 4 or argv[0] != COMMAND_DB or argv[1] != "show":
        return argv
    if argv[2] != "module":
        return argv
    if argv[3] not in _DB_SHOW_MODULES:
        return argv
    return [argv[0], argv[1], argv[3], *argv[4:]]


def _normalize_db_module_show_flags(args: argparse.Namespace, parser: argparse.ArgumentParser) -> argparse.Namespace:
    if getattr(args, "command", None) != COMMAND_DB:
        return args
    if getattr(args, "db_action", None) != "show":
        return args
    if getattr(args, "db_show_action", None) not in _DB_SHOW_MODULES:
        return args

    selected_flags = {
        "summary": bool(getattr(args, "module_show_summary", False)),
        "hosts": bool(getattr(args, "module_show_hosts", False)),
        "endpoints": bool(getattr(args, "module_show_endpoints", False)),
        "findings": bool(getattr(args, "module_show_findings", False)),
        "runs": bool(getattr(args, "module_show_runs", False)),
        "artifacts": bool(getattr(args, "module_show_artifacts", False)),
    }
    exporters_host_filter = str(getattr(args, "exporters_host_filter", "") or "").strip() or None
    chosen = [name for name, enabled in selected_flags.items() if enabled]
    if not chosen:
        if (
            exporters_host_filter
            and getattr(args, "db_show_action", None) == "exporters"
            and getattr(args, "db_show_module_action", None)
        ):
            parser.error("--host cannot be combined with an explicit module section")
        return args

    if len(chosen) > 1:
        parser.error("--summary/--hosts/--endpoints/--findings/--runs/--artifacts cannot be combined")

    if exporters_host_filter:
        parser.error(
            "--host cannot be combined with --summary/--hosts/--list-host/--endpoints/--findings/--runs/--artifacts"
        )

    if getattr(args, "db_show_module_action", None):
        parser.error(
            "--summary/--hosts/--endpoints/--findings/--runs/--artifacts cannot be combined with an explicit module section"
        )

    selected = chosen[0]
    args.db_show_module_action = selected
    handler_map = {
        "summary": "show_module_summary",
        "hosts": "show_hosts",
        "endpoints": "show_endpoints",
        "findings": "show_findings",
        "runs": "show_runs",
        "artifacts": "show_artifacts",
    }
    args.db_handler_name = handler_map[selected]
    return args


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    raw_argv = _normalize_multi_port_port_flag(raw_argv)
    raw_argv = _rewrite_db_show_module_alias(raw_argv)
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

    if raw_argv[0].startswith("-"):
        parser.error(
            "module command is required: db, exporters, registry, grafana, gitlab, consul, kubeapi, postgres, clickhouse, redis, etcd, proxmox, qdrant, kafka, zookeeper, or --selfcert"
        )

    args = parser.parse_args(raw_argv)
    return _normalize_db_module_show_flags(args, parser)
