"""RabbitMQ Management audit CLI."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def configure_rabbitmq_parser(
    parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    port_type: Callable[..., int | str],
    positive_int: Callable[[str], int],
) -> None:
    parser.allow_abbrev = False
    common = parser.add_argument_group("Common")
    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port",
        type=port_type,
        default=None,
        help="Management port spec (default: 15672,15671). HTTP/HTTPS is detected automatically.",
    )
    add_multi_ports_flag(common)
    add_save_flag(common, "Optional output file path.")
    common.add_argument("-f", "--format", dest="output_format", choices=("txt", "json"), default="txt")
    auth = parser.add_argument_group("Auth")
    auth.add_argument("-u", "--username", default=None, help="Management API username.")
    auth.add_argument("-p", "--password", default=None, help="Password (an empty string is supported).")
    auth.add_argument(
        "--defcreds",
        action="store_true",
        help="Check 16 default/weak credential pairs, including guest:guest; try every pair.",
    )
    enum = parser.add_argument_group("Enumeration")
    enum.add_argument("--enum", action="store_true", help="Show all sections, including permissions and cluster nodes.")
    enum.add_argument("--show-vhosts", action="store_true", help="List visible virtual hosts.")
    enum.add_argument("--show-queues", action="store_true", help="List queues and message/consumer counts.")
    enum.add_argument("--show-exchanges", action="store_true", help="List exchanges and their types.")
    enum.add_argument("--show-bindings", action="store_true", help="List exchange routing bindings.")
    enum.add_argument(
        "--show-permissions", action="store_true", help="Show resource and topic permissions for the user."
    )
    enum.add_argument(
        "--show-nodes", action="store_true", help="List cluster nodes, running state and resource alarms."
    )
    enum.add_argument(
        "--vhost", default=None, help="Scope topology and permissions to a vhost; nodes remain cluster-wide."
    )
    enum.add_argument("--limit", type=positive_int, default=1000, help="Maximum retained items per collection.")
    enum.add_argument("--page-size", type=positive_int, default=100, help="API page size (maximum 500).")
