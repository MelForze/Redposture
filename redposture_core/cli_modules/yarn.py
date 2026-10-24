"""Hadoop YARN ResourceManager audit flags."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..discovery_options import add_discovery_budget_flags
from ..modules.execution_api import add_flags


def configure_yarn_parser(
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
    inventory = parser.add_argument_group("Inventory")
    probe = parser.add_argument_group("Allocation probe")
    execution = parser.add_argument_group("Execution")
    tls = parser.add_argument_group("TLS")
    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port", type=port_type, default=None, metavar="port", help="YARN ResourceManager API port (default: 8088)."
    )
    add_multi_ports_flag(common)
    add_save_flag(common, "Optional output file path.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("txt", "json"),
        default="txt",
        help="YARN audit output format for stdout/file.",
    )
    inventory.add_argument(
        "--show-apps", action="store_true", help="List visible applications (bounded snapshot, up to 5000)."
    )
    inventory.add_argument("--show-nodes", action="store_true", help="List visible cluster nodes (up to 5000).")
    inventory.add_argument("--show-metrics", action="store_true", help="Show visible cluster metrics.")
    add_discovery_budget_flags(inventory, default_time=300.0, default_bytes=50 * 1024 * 1024)
    probe.add_argument(
        "--probe-submit",
        action="store_true",
        help="Explicitly allocate an application ID through new-application; no application is submitted or executed. Submission permission remains unverified.",
    )
    add_flags(execution)
    execution.add_argument(
        "--execute-node-url",
        metavar="url",
        default=None,
        help="NodeManager URL for reading command logs when the advertised node address is unreachable.",
    )
    tls.add_argument("--tls-ca", default=None, metavar="file", help="CA bundle for YARN TLS verification.")
    tls.add_argument("--tls-cert", default=None, metavar="file", help="Client certificate for mTLS.")
    tls.add_argument("--tls-key", default=None, metavar="file", help="Client private key for mTLS.")


__all__ = ["configure_yarn_parser"]
