"""ClickHouse Keeper CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from .zookeeper import _configure_zookeeper_protocol_parser


def configure_keeper_parser(
    parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    port_type: Callable[[str], int],
    positive_int: Callable[[str], int],
) -> None:
    _configure_zookeeper_protocol_parser(
        parser,
        service_name="ClickHouse Keeper",
        default_port=9181,
        default_ports=(9181, 19181, 29181),
        add_output_flags=add_output_flags,
        add_log_flag=add_log_flag,
        add_scan_host_flags=add_scan_host_flags,
        add_multi_ports_flag=add_multi_ports_flag,
        add_save_flag=add_save_flag,
        port_type=port_type,
        positive_int=positive_int,
    )
    for action in parser._actions:
        if action.dest == "probe_write":
            action.help = (
                "Also test root-scoped create/delete permissions with a temporary znode. "
                "The Keeper DDL queue is probed by default."
            )
            break
    ddl = parser.add_argument_group("Keeper DDL user creation")
    ddl.add_argument(
        "--create-user", metavar="username", help="Create a ClickHouse user through a writable Keeper DDL queue."
    )
    ddl.add_argument(
        "--create-userpass", metavar="password", help="Password for --create-user (stored in the task as SHA-256 hash)."
    )
    ddl.add_argument(
        "--grant-admin",
        action="store_true",
        help="Also queue GRANT ALL ON *.* WITH GRANT OPTION after confirmed creation.",
    )
    ddl.add_argument(
        "--yes",
        action="store_true",
        help="Skip interactive topology selection and both confirmations; intended for automation.",
    )
    ddl.add_argument(
        "--clickhouse-host", metavar="host", help="DDL worker host ID when the queue has no usable existing task."
    )
    ddl.add_argument("--clickhouse-port", type=port_type, default=9000, metavar="port", help="DDL worker native port.")
    ddl.add_argument(
        "--clickhouse-cluster",
        metavar="name",
        help="ClickHouse cluster name when the queue has no usable existing task.",
    )
    inventory = parser.add_argument_group("Keeper DDL topology")
    inventory.add_argument(
        "--show-cluster", action="store_true", help="List cluster names found in existing DDL tasks (read-only)."
    )
    inventory.add_argument("--show-hosts", action="store_true", help="List DDL worker host IDs by cluster (read-only).")


__all__ = ["configure_keeper_parser"]
