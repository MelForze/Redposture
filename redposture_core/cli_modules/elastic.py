"""Elasticsearch CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def configure_elastic_parser(
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

    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=None,
        metavar="port",
        help=(
            "Elasticsearch port spec: single port, list/range, or file "
            "(examples: 9200, 9200,19200, ./ports.txt). "
            "If omitted, scans 9200, 19200."
        ),
    )
    add_multi_ports_flag(common)
    common.add_argument(
        "--ca-file",
        dest="ca_file",
        default=None,
        metavar="path",
        help="Custom CA certificate file for HTTPS verification.",
    )
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Elastic audit output format for stdout/file.",
    )

    # F3 fix: every other datastore module exposes both `-u/--username` and
    # `-p/--password`. Elastic used to accept only the short forms; scripts
    # using long-form flags failed exclusively against elastic. Add the long
    # options so the CLI surface is consistent.
    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Basic auth username or credential file.",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Basic auth password.",
    )
    auth.add_argument(
        "--apitoken",
        dest="apitoken",
        default=None,
        metavar="value",
        help="API key token sent as Authorization: ApiKey <value>.",
    )
    auth.add_argument(
        "--defcreds",
        action="store_true",
        help="Try default Elasticsearch credentials elastic:changeme, elastic:elastic, elastic:password.",
    )

    actions.add_argument(
        "--endpoints",
        action="store_true",
        help="List available _cat endpoints from /_cat?help.",
    )
    actions.add_argument(
        "--plugins",
        action="store_true",
        help="List installed plugins from GET /_cat/plugins.",
    )
    actions.add_argument(
        "--cluster",
        action="store_true",
        help="Show cluster health and nodes.",
    )
    actions.add_argument(
        "--user",
        action="store_true",
        help="Show security users via /_security/user.",
    )
    actions.add_argument(
        "--discover",
        action="store_true",
        help="Search all indices for potential secret leaks using query_string.",
    )


__all__ = ["configure_elastic_parser"]
