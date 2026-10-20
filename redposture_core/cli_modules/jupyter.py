"""Jupyter Server/Notebook audit flags."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..discovery_options import add_discovery_budget_flags
from ..modules.execution_api import add_flags


def configure_jupyter_parser(
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
    common.add_argument(
        "--port", type=port_type, default=None, metavar="port", help="Jupyter API port (default: 8888)."
    )
    add_multi_ports_flag(common)
    add_save_flag(common, "Optional output file path.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("txt", "json"),
        default="txt",
        help="Jupyter audit output format for stdout/file.",
    )
    token = auth.add_mutually_exclusive_group()
    token.add_argument(
        "--token",
        default=None,
        metavar="value",
        help="Jupyter token for API checks, inventory and explicitly requested actions.",
    )
    token.add_argument("--token-file", default=None, metavar="file", help="Read a Jupyter token from a file.")
    inventory.add_argument(
        "--show-contents", action="store_true", help="List visible files and notebooks without executing them."
    )
    inventory.add_argument("--show-sessions", action="store_true", help="List current notebook sessions.")
    inventory.add_argument("--show-kernels", action="store_true", help="List existing kernels without creating any.")
    inventory.add_argument(
        "--show-terminals", action="store_true", help="List existing terminals without creating any."
    )
    inventory.add_argument(
        "--path", default="", metavar="path", help="Limit content listing and discovery to this relative path."
    )
    add_discovery_budget_flags(inventory, default_time=300.0, default_bytes=50 * 1024 * 1024)
    add_flags(execution)
    execution.add_argument(
        "--execute-via",
        choices=("auto", "kernel", "terminal"),
        default="auto",
        help="Execution channel; auto tries a new Python kernel, then a terminal only if kernel creation is denied.",
    )
    execution.add_argument(
        "--kernel", default="python3", metavar="name", help="Python kernel spec for --execute (default: python3)."
    )
    tls.add_argument("--tls-ca", default=None, metavar="file", help="CA bundle for Jupyter TLS verification.")
    tls.add_argument("--tls-cert", default=None, metavar="file", help="Client certificate for mTLS.")
    tls.add_argument("--tls-key", default=None, metavar="file", help="Client private key for mTLS.")


__all__ = ["configure_jupyter_parser"]
