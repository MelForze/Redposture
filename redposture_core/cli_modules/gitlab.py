"""CLI parser builders."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def configure_gitlab_parser(
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
        default=80,
        metavar="port",
        help="GitLab HTTP port spec: single port, list/range, or file (examples: 80, 80,443,8080, ./ports.txt).",
    )
    add_multi_ports_flag(common)
    common.add_argument(
        "--https",
        action="store_true",
        help="Use HTTPS for GitLab web/API probing (default is HTTP).",
    )
    auth.add_argument(
        "--token",
        dest="token",
        default=None,
        metavar="value",
        help="Optional GitLab Personal/Group Access Token for API auth and permission checks.",
    )
    actions.add_argument(
        "--project",
        dest="project",
        action="append",
        default=None,
        metavar="name",
        help="Project filter (path_with_namespace or numeric id). Repeatable; comma-separated values are also supported.",
    )
    actions.add_argument(
        "--clone",
        action="store_true",
        help="Clone accessible projects. With --project clones selected project(s); otherwise clones all accessible projects.",
    )
    actions.add_argument(
        "--clone-dir",
        dest="clone_dir",
        default="./gitlab_clones",
        metavar="dir",
        help="Output directory root for --clone repositories.",
    )
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="GitLab audit output format for stdout/file.",
    )


__all__ = ["configure_gitlab_parser"]
