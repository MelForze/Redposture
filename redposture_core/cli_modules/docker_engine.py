"""Docker Engine API CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def configure_docker_parser(
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
        dest="port",
        type=port_type,
        default=2375,
        metavar="port",
        help="Docker Engine API port. If omitted, docker scans 2375,2376,4243.",
    )
    add_multi_ports_flag(common)
    add_save_flag(
        common, "Optional output file path. If omitted, results are printed to stdout.", include_save_alias=False
    )
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Docker audit output format for stdout/file.",
    )
    add_log_flag(common)
    add_output_flags(common, short=False)

    tls = parser.add_argument_group("TLS")
    tls.add_argument("--insecure", action="store_true", help="Disable Docker API TLS certificate verification.")
    tls.add_argument("--tls-ca", dest="tls_ca", default=None, metavar="file", help="CA certificate for Docker TLS API.")
    tls.add_argument(
        "--tls-cert", dest="tls_cert", default=None, metavar="file", help="Client certificate for Docker TLS API."
    )
    tls.add_argument("--tls-key", dest="tls_key", default=None, metavar="file", help="Client key for Docker TLS API.")

    inventory = parser.add_argument_group("Inventory")
    inventory.add_argument("--containers", action="store_true", help="List Docker containers visible through the API.")
    inventory.add_argument("--images", action="store_true", help="List Docker images visible through the API.")
    inventory.add_argument("--networks", action="store_true", help="List Docker networks visible through the API.")
    inventory.add_argument("--volumes", action="store_true", help="List Docker volumes visible through the API.")
    inventory.add_argument("--system", action="store_true", help="Show Docker system info and disk usage summary.")

    exec_group = parser.add_argument_group("Exec")
    exec_group.add_argument(
        "--container",
        dest="container",
        default=None,
        metavar="id|name",
        help="Existing container id/name used with --exec-cmd.",
    )
    exec_group.add_argument(
        "--exec-cmd",
        dest="exec_cmd",
        default=None,
        metavar="cmd",
        help="Command to execute in --container via Docker exec API.",
    )

    append_selected_defaults(parser, "timeout", "workers", "retries", "port", "output_format")


__all__ = ["configure_docker_parser"]
