"""CLI parser builders for datastore-style modules."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..show_limits import (
    non_negative_int,
    optional_dump_count_kwargs,
    optional_show_count_kwargs,
    positive_int,
)


def configure_redis_parser(
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
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=None,
        metavar="port",
        help=(
            "Redis port spec: single port, list/range, or file "
            "(examples: 6379, 6379,16379, ./ports.txt). "
            "If omitted, scans 6379, 16379, 26379."
        ),
    )
    add_multi_ports_flag(common)
    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional Redis username or credential file for credential check.",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional Redis password for credential check.",
    )
    auth.add_argument(
        "--defcreds",
        action="store_true",
        help="Try default Redis credentials redis:redis when auth is required.",
    )
    actions.add_argument(
        "--show-keys",
        **optional_show_count_kwargs("Show Redis key names only (SCAN). Optional count limits scanned/shown keys."),
    )
    actions.add_argument(
        "--dump",
        dest="dump",
        **optional_dump_count_kwargs(
            "Dump Redis key values. Optional count limits dumped keys when no -key/--key is selected."
        ),
    )
    actions.add_argument(
        "--dump-batch",
        dest="dump_batch",
        type=positive_int,
        default=10000,
        metavar="N",
        help="Dump page size: keys are dumped gradually in pages of N (default 10000) instead of one big dump.",
    )
    actions.add_argument(
        "--dump-delay",
        dest="dump_delay",
        type=non_negative_int,
        default=20,
        metavar="MS",
        help="Pause in milliseconds between dump pages to pace server load (default 20, 0 disables).",
    )
    actions.add_argument(
        "-key",
        "--key",
        dest="key",
        default=None,
        metavar="name",
        help="Dump one specific Redis key by name (with value).",
    )
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Redis audit output format for stdout/file.",
    )


def configure_etcd_parser(
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
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=None,
        metavar="port",
        help=(
            "etcd port spec: single port, list/range, or file "
            "(examples: 2379, 2379,22379, ./ports.txt). "
            "If omitted, scans 2379, 12379."
        ),
    )
    add_multi_ports_flag(common)
    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional etcd username for /v3/auth/authenticate credential check.",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional etcd password for /v3/auth/authenticate credential check.",
    )
    auth.add_argument(
        "--defcreds",
        action="store_true",
        help="Try default etcd credentials (root:root, root:etcd, etcd:etcd) when auth is required.",
    )
    actions.add_argument(
        "--show-keys",
        **optional_show_count_kwargs(
            "Show etcd key names only when auth is not required. Optional count limits output."
        ),
    )
    actions.add_argument(
        "--dump",
        dest="dump",
        **optional_dump_count_kwargs(
            "Dump etcd key values. Optional count limits dumped keys when no -key/--key is selected."
        ),
    )
    actions.add_argument(
        "--dump-batch",
        dest="dump_batch",
        type=positive_int,
        default=10000,
        metavar="N",
        help="Dump page size: v3 keys are dumped gradually in ranges of N (default 10000) instead of one big dump.",
    )
    actions.add_argument(
        "--dump-delay",
        dest="dump_delay",
        type=non_negative_int,
        default=20,
        metavar="MS",
        help="Pause in milliseconds between dump pages to pace server load (default 20, 0 disables).",
    )
    actions.add_argument(
        "-key",
        "--key",
        dest="key",
        default=None,
        metavar="path",
        help="Dump specific etcd key (example: /redposture/env) when auth is not required.",
    )
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="etcd audit output format for stdout/file.",
    )


def configure_kafka_parser(
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
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=None,
        metavar="port",
        help=(
            "Kafka port spec: single port, list/range, or file "
            "(examples: 9092, 9092,29092, ./ports.txt). "
            "If omitted, scans 9092, 19092."
        ),
    )
    add_multi_ports_flag(common)
    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional Kafka username or credential file for credential check (SASL/PLAIN).",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional Kafka password for credential check (SASL/PLAIN).",
    )
    auth.add_argument(
        "--defcreds",
        action="store_true",
        help="Try default Kafka credentials admin:admin, kafka:kafka, kafka:password.",
    )
    actions.add_argument(
        "--show-topics",
        **optional_show_count_kwargs("Show topic names after successful access/auth. Optional count limits output."),
    )
    actions.add_argument(
        "--topic",
        dest="topic",
        default=None,
        metavar="name",
        help="Show one topic detail by name (partition count / not found).",
    )
    actions.add_argument(
        "--dump",
        **optional_dump_count_kwargs(
            "Dump topic messages. Optional count limits messages per topic and must not conflict with --max-messages."
        ),
    )
    actions.add_argument(
        "--max-messages",
        dest="max_messages",
        # F5 fix: previously `type=int` accepted 0 or negative values silently,
        # so `--max-messages 0` reported "success" with an empty dump.
        type=positive_int,
        default=None,
        metavar="count",
        help="Maximum number of topic messages to read per topic with --dump.",
    )
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Kafka audit output format for stdout/file.",
    )


__all__ = ["configure_etcd_parser", "configure_kafka_parser", "configure_redis_parser"]
