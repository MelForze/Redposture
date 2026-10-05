"""Keycloak audit CLI flags."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..show_limits import optional_show_count_kwargs


def configure_keycloak_parser(
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
    enumeration = parser.add_argument_group("Enumeration")
    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port",
        type=port_type,
        default=None,
        metavar="port",
        help="Keycloak HTTP port spec. If omitted, scans 8080, 8443, 18080.",
    )
    add_multi_ports_flag(common)
    add_save_flag(common, "Optional output file path.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Keycloak audit output format for stdout/file.",
    )
    token = auth.add_mutually_exclusive_group()
    token.add_argument("--token", default=None, metavar="token", help="Bearer token for read-only API checks.")
    token.add_argument("--token-file", default=None, metavar="file", help="Read bearer token from a file.")
    enumeration.add_argument(
        "--realm",
        action="append",
        metavar="name",
        help="Realm to check (default: master); repeatable.",
    )
    enumeration.add_argument(
        "--enum-realms",
        action="store_true",
        help="Check a bounded list of common realm names.",
    )
    enumeration.add_argument(
        "--show-realms",
        action="store_true",
        help="List realms visible to the token.",
    )
    enumeration.add_argument(
        "--show-clients",
        **optional_show_count_kwargs("List visible clients in checked realms."),
    )


__all__ = ["configure_keycloak_parser"]
