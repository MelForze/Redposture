"""Apache Spark Standalone audit flags."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..discovery_options import add_discovery_budget_flags
from ..modules.execution_api import add_flags


def configure_spark_parser(
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
    probe = parser.add_argument_group("Submission probe")
    execution = parser.add_argument_group("Execution")
    tls = parser.add_argument_group("TLS")
    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port",
        type=port_type,
        default=None,
        metavar="port",
        help="Spark HTTP ports (default: 8080 Master UI, 6066 submission REST). Native RPC port 7077 is not audited.",
    )
    add_multi_ports_flag(common)
    add_save_flag(common, "Optional output file path.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("txt", "json"),
        default="txt",
        help="Spark audit output format for stdout/file.",
    )
    inventory.add_argument(
        "--show-workers", action="store_true", help="List visible Master UI worker metadata (up to 5000 workers)."
    )
    inventory.add_argument(
        "--show-apps",
        action="store_true",
        help="List active applications exposed by the Master UI (up to 5000 applications).",
    )
    add_discovery_budget_flags(inventory, default_time=300.0, default_bytes=50 * 1024 * 1024)
    probe.add_argument(
        "--probe-submit",
        action="store_true",
        help="POST an invalid create request without launch fields to test REST parser reachability; never submits an application or proves submission permission.",
    )
    add_flags(execution)
    execution.add_argument(
        "--execute-worker-url",
        metavar="url",
        default=None,
        help="Worker Web UI URL for reading the command proof when the advertised worker address is unreachable.",
    )
    tls.add_argument("--tls-ca", default=None, metavar="file", help="CA bundle for Spark TLS verification.")
    tls.add_argument("--tls-cert", default=None, metavar="file", help="Client certificate for mTLS.")
    tls.add_argument("--tls-key", default=None, metavar="file", help="Client private key for mTLS.")


__all__ = ["configure_spark_parser"]
