"""CLI parser builders."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def configure_kubeapi_parser(
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
        default=6443,
        metavar="port",
        help="Kubernetes API port spec: single port, list/range, or file (examples: 6443, 6443,8443, ./ports.txt).",
    )
    add_multi_ports_flag(common)
    common.add_argument(
        "--https",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use HTTPS for Kubernetes API requests.",
    )
    common.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS certificate verification (useful for self-signed clusters).",
    )
    common.add_argument(
        "--ca-file",
        dest="ca_file",
        default=None,
        metavar="path",
        help="Custom CA certificate file for Kubernetes API TLS verification.",
    )
    auth.add_argument(
        "--token",
        dest="token",
        default=None,
        metavar="value",
        help="Optional Kubernetes Bearer token for API authentication.",
    )
    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional Kubernetes API username or credential file for Basic auth.",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional Kubernetes API password for Basic auth.",
    )
    actions.add_argument(
        "--namespaces",
        action="store_true",
        help="Enumerate namespaces accessible with no-auth or provided credentials.",
    )
    actions.add_argument(
        "--pods",
        action="store_true",
        help="Enumerate pods across all namespaces or only selected --namespace values.",
    )
    actions.add_argument(
        "--namespace",
        dest="namespace",
        action="append",
        default=None,
        metavar="name",
        help="Namespace filter for --pods/--secrets (repeatable; comma-separated values also supported).",
    )
    actions.add_argument(
        "--pod",
        dest="pod",
        default=None,
        metavar="name",
        help="Target pod for exec (name or namespace/pod).",
    )
    actions.add_argument(
        "-X",
        "--exec-command",
        dest="exec_command",
        default=None,
        metavar="command",
        help="Execute shell command in --pod via Kubernetes API exec websocket (/bin/sh -c).",
    )
    actions.add_argument(
        "--secrets",
        action="store_true",
        help="Enumerate and decode readable Kubernetes Secret objects.",
    )
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Kubernetes API audit output format for stdout/file.",
    )


__all__ = ["configure_kubeapi_parser"]
