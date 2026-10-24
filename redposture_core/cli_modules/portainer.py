"""Portainer management API CLI flags."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..discovery_options import add_discovery_budget_flags
from ..modules.execution_api import add_flags as add_execution_flags


def configure_portainer_parser(
    parser: argparse.ArgumentParser,
    *,
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_output_flags: Callable[..., None],
    append_selected_defaults: Callable[..., None],
    port_type: Callable[[str], int],
) -> None:
    common = parser.add_argument_group("Common")
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port",
        type=port_type,
        default=None,
        metavar="port",
        help="Portainer HTTP(S) port. If omitted, scans 9443, 9000.",
    )
    add_multi_ports_flag(common)
    add_save_flag(common, "Optional output file path.")
    common.add_argument("-f", "--format", dest="output_format", choices=("txt", "json"), default="txt")
    add_log_flag(common)
    add_output_flags(common, short=False)
    auth = parser.add_argument_group("Auth")
    auth.add_argument("-u", "--username", metavar="name", help="Portainer username or credential file.")
    auth.add_argument("-p", "--password", metavar="value", help="Portainer password.")
    token = auth.add_mutually_exclusive_group()
    token.add_argument("--token", metavar="value", help="Portainer API key (ptr_...) or JWT.")
    token.add_argument("--token-file", metavar="file", help="Read a Portainer API key or JWT from a file.")
    auth.add_argument(
        "--defcreds",
        action="store_true",
        help="Try a small set of weak Portainer pairs; no factory password is assumed.",
    )
    inventory = parser.add_argument_group("Inventory")
    inventory.add_argument(
        "--show-endpoints", dest="endpoints", action="store_true", help="List visible Portainer environments."
    )
    inventory.add_argument(
        "--endpoint", metavar="id|name", help="Restrict read-only inventory to one visible environment."
    )
    inventory.add_argument("--container", metavar="id|name", help="Select an existing container for --execute.")
    for name in ("containers", "images", "networks", "volumes", "system"):
        inventory.add_argument(
            "--show-" + name, dest=name, action="store_true", help="Read visible environment " + name + "."
        )
    add_discovery_budget_flags(inventory, default_time=300.0, default_bytes=50 * 1024 * 1024)
    execution = parser.add_argument_group("Execution")
    add_execution_flags(execution)
    append_selected_defaults(parser, "timeout", "workers", "retries", "port", "output_format")


__all__ = ["configure_portainer_parser"]
