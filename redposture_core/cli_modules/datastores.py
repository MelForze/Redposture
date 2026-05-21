"""CLI parser builders for datastore-style modules."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..show_limits import optional_show_count_kwargs


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
    add_output_flags(common)  # type: ignore[arg-type]
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)  # type: ignore[arg-type]
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=6379,
        metavar="port",
        help="Redis port spec: single port, list/range, or file (examples: 6379, 6379,16379, ./ports.txt).",
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
        action="store_true",
        help="Dump Redis key values. With -key/--key dumps one key; without -key dumps all keys.",
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
    actions = parser.add_argument_group("Actions")
    add_output_flags(common)  # type: ignore[arg-type]
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)  # type: ignore[arg-type]
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=2379,
        metavar="port",
        help="etcd port spec: single port, list/range, or file (examples: 2379, 2379,22379, ./ports.txt).",
    )
    add_multi_ports_flag(common)
    actions.add_argument(
        "--show-keys",
        **optional_show_count_kwargs(
            "Show etcd key names only when auth is not required. Optional count limits output."
        ),
    )
    actions.add_argument(
        "--dump",
        dest="dump",
        action="store_true",
        help="Dump etcd key values. With -key/--key dumps one key; without -key dumps all keys.",
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
    add_output_flags(common)  # type: ignore[arg-type]
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)  # type: ignore[arg-type]
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=9092,
        metavar="port",
        help="Kafka port spec: single port, list/range, or file (examples: 9092, 9092,29092, ./ports.txt).",
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
        action="store_true",
        help="Dump topic messages: with --topic dumps only that topic, otherwise dumps all topics.",
    )
    actions.add_argument(
        "--max-messages",
        dest="max_messages",
        type=int,
        default=1000,
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
