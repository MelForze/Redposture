"""Qdrant CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..show_limits import optional_dump_count_kwargs


def configure_qdrant_parser(
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
    ssrf_options = parser.add_argument_group("SSRF / Probes")

    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=6333,
        metavar="port",
        help="Qdrant port(s): single, list/range, or file (e.g. 6333, 6333,6334, ./ports.txt).",
    )
    add_multi_ports_flag(common)
    auth.add_argument(
        "--api-key",
        dest="api_key",
        default=None,
        metavar="value",
        help="Qdrant API key for auth-required endpoints (anonymous check still runs).",
    )

    actions.add_argument(
        "--collections",
        dest="show_collections",
        action="store_true",
        help="List collection names (use --dump for collection info).",
    )
    actions.add_argument(
        "--collection",
        dest="collection",
        default=None,
        metavar="name",
        help="Collection name for --dump and snapshot-restore SSRF probe.",
    )
    actions.add_argument(
        "--dump",
        dest="dump",
        **optional_dump_count_kwargs(
            "Dump collection info. Optional count limits collection dumps when dumping all collections."
        ),
    )

    ssrf_options.add_argument(
        "--ssrf-target",
        dest="ssrf_target",
        default=None,
        metavar="target",
        help="SSRF target(s): ip/dns/cidr/url (comma-separated) via snapshot recover.",
    )
    ssrf_options.add_argument(
        "--ssrf-port",
        dest="ssrf_port",
        default=None,
        metavar="ports",
        help="Ports for --ssrf-target (single/list/range/file syntax).",
    )
    ssrf_options.add_argument(
        "--ssrf-path",
        dest="ssrf_path",
        default=None,
        metavar="path",
        help="Path/query override for SSRF URLs (e.g. /snapshot).",
    )
    ssrf_options.add_argument(
        "--listen",
        dest="ssrf_listen",
        action="store_true",
        help="Start local HTTP SSRF capture listener on --ssrf-port (best effort).",
    )

    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Qdrant audit output format for stdout/file.",
    )


__all__ = ["configure_qdrant_parser"]
