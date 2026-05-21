"""MongoDB CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..show_limits import optional_show_count_kwargs


class MongoDBHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action: argparse.Action) -> str:
        if getattr(action, "_hide_metavar_in_help", False):
            return ", ".join(action.option_strings)
        return super()._format_action_invocation(action)


def configure_mongodb_parser(
    parser: argparse.ArgumentParser,
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
    common = parser.add_argument_group("Common")
    add_scan_host_flags(common, include_profiles=False)  # type: ignore[arg-type]
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=27017,
        metavar="port",
        help="MongoDB port spec: single port, list/range, or file (examples: 27017, 27017,37017, ./ports.txt).",
    )
    add_multi_ports_flag(common)
    add_save_flag(
        common, "Optional output file path. If omitted, results are printed to stdout.", include_save_alias=False
    )
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="MongoDB audit output format for stdout/file.",
    )
    add_log_flag(common)
    add_output_flags(common, short=False)  # type: ignore[arg-type]

    auth = parser.add_argument_group("Database / Auth")
    discovery = parser.add_argument_group("Discovery / Dump")
    nosql = parser.add_argument_group("NoSQL / Shell")

    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional MongoDB username or credential file for credential check.",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional MongoDB password for credential check.",
    )
    auth.add_argument(
        "--auth-db",
        dest="auth_db",
        default="admin",
        metavar="name",
        help="Authentication database used for MongoDB credentials.",
    )
    auth.add_argument(
        "--defcreds",
        action="store_true",
        help="Try default MongoDB credentials root:root, admin:admin, root:password, mongo:mongo, mongodb:mongodb.",
    )

    discovery.add_argument(
        "--show-databases",
        **optional_show_count_kwargs("Show available database names. Optional count limits output."),
    )
    discovery.add_argument(
        "--database",
        dest="database",
        default=None,
        metavar="name",
        help="Target database for collection/index/dump/query operations. Omitted value walks user databases.",
    )
    discovery.add_argument(
        "--show-collections",
        **optional_show_count_kwargs("Show collection names and document counts. Optional count limits output."),
    )
    discovery.add_argument(
        "--collection",
        dest="collections",
        action="append",
        default=None,
        metavar="name",
        help="Target collection (collection or db.collection). Can be repeated or comma-separated.",
    )
    discovery.add_argument(
        "--document",
        dest="document",
        default=None,
        metavar="id",
        help="Target document by _id for selected --collection target(s).",
    )
    discovery.add_argument(
        "--show-indexes",
        **optional_show_count_kwargs(
            "Show index names for selected/readable collections. Optional count limits output."
        ),
    )
    discovery.add_argument(
        "--index",
        dest="index",
        default=None,
        metavar="name",
        help="Filter/show index by name for selected/readable collections.",
    )
    discovery.add_argument(
        "--dump",
        nargs="?",
        const=0,
        type=positive_int,
        metavar="count",
        help=(
            "Dump MongoDB documents. Optional count limits documents per collection; without count uses a safety cap. "
            "With --collection dumps selected collection(s); without --collection dumps readable collections."
        ),
    )
    discovery.add_argument(
        "--query",
        dest="query",
        default=None,
        metavar="json",
        help="MongoDB find() query JSON for --collection target(s). Defaults to {} when omitted.",
    )
    discovery.add_argument(
        "--projection",
        dest="projection",
        default=None,
        metavar="json",
        help="MongoDB find() projection JSON for --query/--document/--dump.",
    )

    nosql.add_argument(
        "--nosql-cmd",
        dest="nosql_cmd",
        default=None,
        metavar="json",
        help="Execute MongoDB db.command() JSON once after successful access/auth.",
    )
    nosql.add_argument(
        "--nosql-shell",
        action="store_true",
        help="Interactive MongoDB JSON command shell for a single target.",
    )

    append_selected_defaults(parser, "timeout", "workers", "retries", "port", "auth_db", "output_format")


__all__ = ["MongoDBHelpFormatter", "configure_mongodb_parser"]
