"""HashiCorp Nomad audit flags."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..discovery_options import add_discovery_budget_flags
from ..modules.execution_api import add_flags


def configure_nomad_parser(
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
    tls = parser.add_argument_group("TLS")
    execution = parser.add_argument_group("Execution")

    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument("--port", type=port_type, default=None, metavar="port", help="Nomad API port (default: 4646).")
    add_multi_ports_flag(common)
    add_save_flag(common, "Optional output file path.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("txt", "json"),
        default="txt",
        help="Nomad audit output format for stdout/file.",
    )
    token = auth.add_mutually_exclusive_group()
    token.add_argument(
        "--token",
        default=None,
        metavar="value",
        help="Nomad token for API checks, inventory and explicitly requested actions.",
    )
    token.add_argument("--token-file", default=None, metavar="file", help="Read a Nomad token from a file.")
    inventory.add_argument("--show-jobs", action="store_true", help="List visible jobs.")
    inventory.add_argument("--show-nodes", action="store_true", help="List visible cluster nodes.")
    inventory.add_argument("--show-members", action="store_true", help="List agent members.")
    inventory.add_argument(
        "--namespace", default="default", metavar="name", help="Job namespace for inventory and discovery."
    )
    add_discovery_budget_flags(inventory, default_time=300.0, default_bytes=50 * 1024 * 1024)
    add_flags(execution)
    execution.add_argument(
        "--allocation",
        metavar="id",
        help="Execute in this existing allocation instead of creating a temporary batch job.",
    )
    execution.add_argument(
        "--task", metavar="name", help="Task within --allocation; required when multiple tasks are running."
    )
    execution.add_argument(
        "--probe-submit",
        action="store_true",
        help="Verify job registration with a temporary stopped job, then purge it; no task is executed.",
    )
    tls.add_argument("--tls-ca", default=None, metavar="file", help="CA bundle for Nomad TLS verification.")
    tls.add_argument("--tls-cert", default=None, metavar="file", help="Client certificate for mTLS.")
    tls.add_argument("--tls-key", default=None, metavar="file", help="Client private key for mTLS.")


__all__ = ["configure_nomad_parser"]
