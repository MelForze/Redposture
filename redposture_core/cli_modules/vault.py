"""HashiCorp Vault audit flags."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..discovery_options import add_discovery_budget_flags


def configure_vault_parser(
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

    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument("--port", type=port_type, default=None, metavar="port", help="Vault API port (default: 8200).")
    add_multi_ports_flag(common)
    add_save_flag(common, "Optional output file path.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("txt", "json"),
        default="txt",
        help="Vault audit output format for stdout/file.",
    )
    token = auth.add_mutually_exclusive_group()
    token.add_argument(
        "--token", default=None, metavar="value", help="Vault token for lookup-self and read-only inventory."
    )
    token.add_argument("--token-file", default=None, metavar="file", help="Read a Vault token from a file.")
    auth.add_argument(
        "--defcreds",
        action="store_true",
        help="Check the common development token root once; acceptance does not prove dev mode.",
    )
    inventory.add_argument("--show-mounts", action="store_true", help="List visible secrets engines and their types.")
    inventory.add_argument("--show-auth", action="store_true", help="List visible authentication methods.")
    inventory.add_argument("--mount", default=None, metavar="path", help="Limit --discover to this KV mount path.")
    add_discovery_budget_flags(inventory, default_time=300.0, default_bytes=50 * 1024 * 1024)
    tls.add_argument("--tls-ca", default=None, metavar="file", help="CA bundle for Vault TLS verification.")
    tls.add_argument("--tls-cert", default=None, metavar="file", help="Client certificate for mTLS.")
    tls.add_argument("--tls-key", default=None, metavar="file", help="Client private key for mTLS.")


__all__ = ["configure_vault_parser"]
