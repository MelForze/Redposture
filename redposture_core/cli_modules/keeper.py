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


__all__ = ["configure_keeper_parser"]
