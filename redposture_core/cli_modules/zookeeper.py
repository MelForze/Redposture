"""ZooKeeper CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..show_limits import optional_dump_count_kwargs, optional_show_count_kwargs


def _configure_zookeeper_protocol_parser(
    parser: argparse.ArgumentParser,
    *,
    service_name: str,
    default_port: int,
    default_ports: tuple[int, ...],
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    port_type: Callable[[str], int],
    positive_int: Callable[[str], int],
) -> None:
    common = parser.add_argument_group("Common")
    transport = parser.add_argument_group("TLS (transport auto-detected)")
    auth = parser.add_argument_group("Auth")
    actions = parser.add_argument_group("Actions")
    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    # ZooKeeper-protocol services often require a longer handshake window on real networks.
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
        default=None,
        metavar="port",
        help=(
            f"{service_name} port spec: single port, list/range, or file "
            f"(examples: {default_port}, {default_port},{default_port + 10000}, ./ports.txt). "
            f"If omitted, scans {', '.join(str(port) for port in default_ports)}."
        ),
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
    transport.add_argument(
        "--ca-file",
        default=None,
        metavar="file",
        help=f"CA certificate for {service_name} TLS verification.",
    )
    transport.add_argument(
        "--insecure",
        action="store_true",
        help=f"Allow an untrusted or self-signed {service_name} TLS certificate.",
    )
    transport.add_argument(
        "--tls-cert",
        dest="tls_cert",
        default=None,
        metavar="file",
        help="TLS client certificate for mTLS.",
    )
    transport.add_argument(
        "--tls-key",
        dest="tls_key",
        default=None,
        metavar="file",
        help="TLS client key for mTLS.",
    )
    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help=f"Optional {service_name} username or credential file for digest auth credential check.",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help=f"Optional {service_name} password for digest auth credential check.",
    )
    auth.add_argument(
        "--defcreds",
        action="store_true",
        help=(
            f"Try the built-in {service_name} digest credential set after explicit/file credentials. "
            "Each candidate performs a network auth attempt and may trigger server lockout policy."
        ),
    )
    actions.add_argument(
        "--show-znodes",
        **optional_show_count_kwargs(
            "Show znode paths after successful access/auth. Optional count is a hard traversal limit and "
            "overrides --max-znodes."
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
        "--znode",
        dest="znode",
        default=None,
        metavar="path",
        help=(
            "Show one znode detail by path "
            f"(example: {'/clickhouse/tables' if default_port == 9181 else '/brokers/ids'})."
        ),
    )
    actions.add_argument(
        "--probe-write",
        action="store_true",
        help=(
            "Explicitly create and delete a unique ephemeral znode under / to test the selected identity's "
            "root-scoped create/delete permissions. Without this flag the audit is read-only."
        ),
    )
    actions.add_argument(
        "--max-znodes",
        dest="max_znodes",
        type=positive_int,
        default=2000,
        metavar="count",
        help="Hard maximum number of znodes visited by --show-znodes/--dump per target.",
    )
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help=f"{service_name} audit output format for stdout/file.",
    )


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
    _configure_zookeeper_protocol_parser(
        parser,
        service_name="Apache ZooKeeper",
        default_port=2181,
        default_ports=(2181, 12181, 22181),
        add_output_flags=add_output_flags,
        add_log_flag=add_log_flag,
        add_scan_host_flags=add_scan_host_flags,
        add_multi_ports_flag=add_multi_ports_flag,
        add_save_flag=add_save_flag,
        port_type=port_type,
        positive_int=positive_int,
    )


__all__ = ["configure_zookeeper_parser"]
