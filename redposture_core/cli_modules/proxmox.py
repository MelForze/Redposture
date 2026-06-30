"""Proxmox CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def configure_proxmox_parser(
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
    parser.set_defaults(timeout=3.0)
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=None,
        metavar="port",
        help=(
            "Proxmox API port spec: single port, list/range, or file "
            "(examples: 8006, 8006,18006, ./ports.txt). "
            "If omitted, scans 8006, 18006."
        ),
    )
    add_multi_ports_flag(common)
    common.add_argument(
        "--https",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use HTTPS for Proxmox API requests.",
    )
    common.add_argument(
        "--insecure",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Skip TLS certificate verification (recommended for self-signed Proxmox certs).",
    )
    auth.add_argument(
        "--pveapitoken",
        dest="pve_api_token",
        default=None,
        metavar="value",
        help="Proxmox API token value: either '<user@realm!tokenid>=<secret>' or full 'PVEAPIToken=...'.",
    )
    auth.add_argument(
        "-u",
        "--username",
        default=None,
        metavar="username|file",
        help="Proxmox username, or a credential file with username:password pairs.",
    )
    auth.add_argument(
        "-p",
        "--password",
        default=None,
        metavar="password",
        help="Proxmox password for -u/--username.",
    )
    auth.add_argument(
        "--defcreds",
        action="store_true",
        help="Try a compact set of common Proxmox username/password pairs.",
    )
    actions.add_argument(
        "--discover-creds",
        action="store_true",
        help="Enable extended endpoint crawl and credential discovery in API responses.",
    )
    actions.add_argument("--nodes", action="store_true", help="Show discovered Proxmox node names.")
    actions.add_argument("--users", action="store_true", help="Show users returned by /access/users.")
    actions.add_argument(
        "-add-user",
        "--add-user",
        dest="add_user",
        type=str,
        default=None,
        metavar="username",
        help="Create user via /access/users and generate random 20-char password.",
    )
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Proxmox audit output format for stdout/file.",
    )


__all__ = ["configure_proxmox_parser"]
