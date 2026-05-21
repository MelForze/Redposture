"""ClickHouse CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..show_limits import optional_show_count_kwargs


def configure_clickhouse_parser(
    parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    port_type: Callable[[str], int],
) -> None:
    common = parser.add_argument_group("Common")
    auth = parser.add_argument_group("Auth")
    actions = parser.add_argument_group("Actions")
    exec_group = parser.add_argument_group("Execute / Shell")
    add_output_flags(common, short=False)  # type: ignore[arg-type]
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)  # type: ignore[arg-type]
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=9000,
        metavar="port",
        help="ClickHouse port spec: single port, list/range, or file (examples: 9000, 8123, 9000,8123, ./ports.txt).",
    )
    add_multi_ports_flag(common)
    common.add_argument(
        "--http",
        action="store_true",
        help="Use ClickHouse HTTP/HTTPS API mode. By default native protocol is used.",
    )
    common.add_argument(
        "-d",
        "--database",
        dest="database",
        default="default",
        metavar="name",
        help="Database used for authentication context and table operations.",
    )
    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional ClickHouse username or credential file for credential check.",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional ClickHouse password for credential check.",
    )
    auth.add_argument(
        "--defcreds",
        action="store_true",
        help="Try default ClickHouse credentials default:<empty> and default:default.",
    )
    actions.add_argument(
        "--show-databases",
        **optional_show_count_kwargs("Show database names after successful access/auth. Optional count limits output."),
    )
    actions.add_argument(
        "--show-tables",
        **optional_show_count_kwargs(
            "Show readable table names after successful access/auth. Optional count limits output."
        ),
    )
    actions.add_argument(
        "--table",
        dest="tables",
        action="append",
        default=None,
        metavar="name",
        help="Target table (db.table or table). Can be used multiple times or with comma-separated values.",
    )
    actions.add_argument(
        "--show-columns",
        **optional_show_count_kwargs("Show column names for --table target(s). Optional count limits output."),
    )
    actions.add_argument(
        "--column",
        dest="columns",
        action="append",
        default=None,
        metavar="name",
        help="Column filter for --show-columns/--dump (repeatable, comma-separated is also supported).",
    )
    actions.add_argument(
        "--dump",
        action="store_true",
        help="Dump table rows. With --table dumps selected table(s); without --table dumps all readable tables.",
    )
    exec_group.add_argument(
        "-x",
        "--execute",
        dest="execute",
        default=None,
        metavar="command",
        help="Execute OS command via ClickHouse executable() path when available (or SYSTEM command if prefixed with SYSTEM).",
    )
    exec_group.add_argument(
        "--sql-cmd",
        dest="sql_cmd",
        default=None,
        metavar="query",
        help="Execute SQL query after successful connection/auth and print result rows.",
    )
    exec_group.add_argument("--os-shell", action="store_true", help="Interactive OS command mode (single target).")
    exec_group.add_argument("--sql-shell", action="store_true", help="Interactive SQL mode (single target).")
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="ClickHouse audit output format for stdout/file.",
    )


__all__ = ["configure_clickhouse_parser"]
