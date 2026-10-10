"""Jenkins audit command-line options."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..show_limits import optional_show_count_kwargs


def configure_jenkins_parser(
    parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    port_type: Callable[[str], int | str],
) -> None:
    common = parser.add_argument_group("Common")
    auth = parser.add_argument_group("Auth")
    inventory = parser.add_argument_group("Inventory")
    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port",
        type=port_type,
        default=None,
        metavar="port",
        help="Jenkins HTTP port spec (default: 8080, 8443, 18080 for bare hosts).",
    )
    add_multi_ports_flag(common)
    add_save_flag(common, "Optional output file path.")
    common.add_argument(
        "-f", "--format", dest="output_format", choices=("json", "txt"), default="txt", help="Output format."
    )
    auth.add_argument(
        "-u", "--username", metavar="user", help="Jenkins username for Basic or API-token authentication."
    )
    auth.add_argument("-p", "--password", metavar="password", help="Jenkins password for Basic authentication.")
    token = auth.add_mutually_exclusive_group()
    token.add_argument("--api-token", metavar="token", help="Jenkins API token; requires -u.")
    token.add_argument("--api-token-file", metavar="file", help="Read a Jenkins API token from a file; requires -u.")
    auth.add_argument(
        "--defcreds",
        action="store_true",
        help="Try a bounded set of common weak pairs; Jenkins has no universal initial password.",
    )
    inventory.add_argument(
        "--show-jobs", **optional_show_count_kwargs("List jobs visible to the selected identity or anonymously.")
    )
    inventory.add_argument(
        "--show-builds", **optional_show_count_kwargs("List recent builds of visible jobs; implies --show-jobs.")
    )
    inventory.add_argument(
        "--show-plugins", **optional_show_count_kwargs("List installed plugins and versions when permitted.")
    )
    inventory.add_argument(
        "--show-nodes", **optional_show_count_kwargs("List visible agents, online state and executor usage.")
    )
    inventory.add_argument(
        "--show-queue", **optional_show_count_kwargs("Show a bounded snapshot of queued builds and their reasons.")
    )
    inventory.add_argument(
        "--show-artifacts",
        **optional_show_count_kwargs(
            "List names and available sizes of artifacts from recent builds; implies --show-builds."
        ),
    )


__all__ = ["configure_jenkins_parser"]
