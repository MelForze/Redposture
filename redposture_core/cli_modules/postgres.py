"""Postgres CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from typing import Any, cast

from ..show_limits import optional_dump_count_kwargs, optional_show_count_kwargs


class PostgresHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action: argparse.Action) -> str:
        if getattr(action, "_hide_metavar_in_help", False):
            return ", ".join(action.option_strings)
        return super()._format_action_invocation(action)


def configure_postgres_parser(
    postgres_parser: argparse.ArgumentParser,
    *,
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_output_flags: Callable[..., None],
    append_selected_defaults: Callable[..., None],
    port_type: Callable[[str], int],
    positive_int: Callable[[str], int],
) -> None:
    common = postgres_parser.add_argument_group("Common")
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=None,
        metavar="port",
        help=(
            "Postgres port spec: single port, list/range, or file "
            "(examples: 5432, 5432,15432, ./ports.txt). "
            "If omitted, scans 5432, 6432, 15432."
        ),
    )
    add_multi_ports_flag(common)
    # F9 fix: previously postgres/mongo/docker/oracle rejected `--save` while
    # every other module accepted it, breaking batch scripts. Align the four
    # holdouts with the rest.
    add_save_flag(
        common,
        "Optional output file path. If omitted, results are printed to stdout.",
    )
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Postgres audit output format for stdout/file.",
    )
    add_log_flag(common)
    add_output_flags(common, short=False)

    auth = postgres_parser.add_argument_group("Database / Auth")
    discovery = postgres_parser.add_argument_group("Discovery / Dump")
    exec_group = postgres_parser.add_argument_group("Execute / Shell")

    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional Postgres username or credential file for credential check.",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional Postgres password for credential check.",
    )
    auth.add_argument(
        "--defcreds",
        action="store_true",
        help=(
            "Try the curated Postgres/PgBouncer credential set, including postgres:postgres "
            "and pgbouncer:pgbouncer, after provided or file credentials."
        ),
    )
    tls = postgres_parser.add_argument_group("TLS")
    tls.add_argument(
        "--sslmode",
        choices=("disable", "prefer", "require", "verify-ca", "verify-full"),
        default="prefer",
        help="PostgreSQL TLS mode (default: prefer).",
    )
    tls.add_argument("--ssl-ca", dest="ssl_ca", default=None, metavar="file", help="CA bundle for TLS verification.")
    tls.add_argument(
        "--ssl-cert", dest="ssl_cert", default=None, metavar="file", help="Client certificate for PostgreSQL mTLS."
    )
    tls.add_argument(
        "--ssl-key", dest="ssl_key", default=None, metavar="file", help="Client private key for PostgreSQL mTLS."
    )
    tls.add_argument(
        "--ssl-server-name",
        dest="ssl_server_name",
        default=None,
        metavar="name",
        help="TLS SNI/certificate hostname override.",
    )
    discovery.add_argument(
        "--show-databases",
        **optional_show_count_kwargs(
            "Show available database names in output after successful access/auth. Optional count limits output."
        ),
    )
    discovery.add_argument(
        "--database",
        dest="database",
        default=None,
        metavar="name",
        help=(
            "Target database for table/dump/SQL operations. "
            "When omitted, --show-tables and --dump without --table walk all accessible databases."
        ),
    )
    discovery.add_argument(
        "--show-tables",
        **optional_show_count_kwargs(
            "Show readable table names with inline Rows:N after successful access/auth. Optional count limits output."
        ),
    )
    discovery.add_argument(
        "--table",
        dest="tables",
        action="append",
        default=None,
        metavar="name",
        help=(
            "Target table (schema.table or table). Used alone, shows the selected table with its row count. "
            "Can be used multiple times or with comma-separated values."
        ),
    )
    discovery.add_argument(
        "--show-columns",
        **optional_show_count_kwargs("Show column names for --table target(s). Optional count limits output."),
    )
    discovery.add_argument(
        "--column",
        dest="columns",
        action="append",
        default=None,
        metavar="name",
        help=(
            "Column filter for --show-columns/--dump (repeatable, comma-separated is also supported). "
            "Applies to all --table targets."
        ),
    )
    discovery.add_argument(
        "--rows",
        action="store_true",
        help="Compatibility alias for inline Rows:N output with --show-tables semantics.",
    )
    discovery.add_argument(
        "--dump",
        **optional_dump_count_kwargs(
            "Dump table rows. Optional count limits dumped rows; without count dumps all rows. With --table dumps selected table(s)."
        ),
    )
    discovery.add_argument(
        "--privesc-check",
        action="store_true",
        help="Check Postgres privilege-escalation and server-side file/command execution capability risks.",
    )
    execute_action = exec_group.add_argument(
        "-x",
        "--execute",
        dest="execute",
        default=None,
        metavar="command",
        help="Try executing OS command via Postgres COPY FROM PROGRAM and print output.",
    )
    cast(Any, execute_action)._hide_metavar_in_help = True
    exec_group.add_argument(
        "--os-read",
        dest="os_read",
        default=None,
        metavar="path",
        help=("Read server-side filesystem path. Tries pg_read_file first, then pg_ls_dir/lo_import fallback."),
    )
    exec_group.add_argument(
        "--os-shell",
        action="store_true",
        help="Interactive command mode via Postgres COPY FROM PROGRAM (single target).",
    )
    exec_group.add_argument(
        "--sql-shell",
        action="store_true",
        help="Interactive SQL mode (single target).",
    )
    exec_group.add_argument(
        "--sql-cmd",
        dest="sql_cmd",
        default=None,
        metavar="query",
        help="Execute SQL query after successful connection/auth and print result rows.",
    )
    append_selected_defaults(postgres_parser, "timeout", "workers", "retries", "port", "output_format")


__all__ = ["PostgresHelpFormatter", "configure_postgres_parser"]
