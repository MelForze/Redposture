"""ZooKeeper CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..show_limits import optional_dump_count_kwargs, optional_show_count_kwargs


def configure_zookeeper_parser(
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
    common = parser.add_argument_group("Common")
    auth = parser.add_argument_group("Auth")
    actions = parser.add_argument_group("Actions")
    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    # ZooKeeper often requires a longer handshake window on real networks.
    # Keep module-local default timeout at 5s without changing other modules.
    for action in parser._actions:
        if action.dest == "timeout":
            action.default = 5.0
            break
    parser.set_defaults(timeout=5.0)
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=2181,
        metavar="port",
        help="ZooKeeper port spec: single port, list/range, or file (examples: 2181, 2181,22181, ./ports.txt).",
    )
    add_multi_ports_flag(common)
    common.add_argument(
        "--enum-workers",
        dest="enum_workers",
        type=positive_int,
        default=3,
        metavar="count",
        help="Parallel workers for znode enumeration during deep checks.",
    )
    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional ZooKeeper username or credential file for digest auth credential check.",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional ZooKeeper password for digest auth credential check.",
    )
    actions.add_argument(
        "--show-znodes",
        **optional_show_count_kwargs(
            "Show znode paths after successful access/auth. Optional count overrides --max-znodes for display."
        ),
    )
    actions.add_argument(
        "--dump",
        dest="dump",
        **optional_dump_count_kwargs(
            "Dump znode values. Optional count limits dumped znodes when no --znode is selected."
        ),
    )
    actions.add_argument(
        "-znode",
        "--znode",
        dest="znode",
        default=None,
        metavar="path",
        help="Show one znode detail by path (example: /brokers/ids).",
    )
    actions.add_argument(
        "--max-znodes",
        dest="max_znodes",
        type=positive_int,
        default=2000,
        metavar="count",
        help="Maximum znodes to include in --show-znodes/--dump output per target (znode count remains full).",
    )
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="ZooKeeper audit output format for stdout/file.",
    )


__all__ = ["configure_zookeeper_parser"]
