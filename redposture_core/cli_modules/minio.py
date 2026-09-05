"""MinIO CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def configure_minio_parser(
    minio_parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    port_type: Callable[[str], int],
) -> None:
    common = minio_parser.add_argument_group("Common")
    auth = minio_parser.add_argument_group("Auth")
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
            "MinIO port spec: single port, list/range, or file. If omitted, scans "
            "9000,9001,80,443,10080,10443,19000,19001,20080,20443,29000,29001."
        ),
    )
    add_multi_ports_flag(common)
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="MinIO audit output format for stdout/file.",
    )
    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="access-key",
        help="Access key (username == access key).",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="secret-key",
        help="Secret key (password == secret key).",
    )
    auth.add_argument(
        "--session-token",
        dest="session_token",
        default=None,
        metavar="token",
        help="Optional STS session token (x-amz-security-token).",
    )
    auth.add_argument(
        "--defcreds",
        dest="defcreds",
        action="store_true",
        help="Try a curated catalog of MinIO default credentials (incl. minioadmin:minioadmin).",
    )
    auth.add_argument(
        "--probe-write",
        dest="probe_write",
        action="store_true",
        help="(reserved) intent to actively test write/delete perms; inert in this phase.",
    )
    # Transport is fully automatic: the scheme (http/https) is probed and cached
    # per target, and TLS certificates are always accepted (audit tool inspecting
    # exposure, not establishing trust). No --https/--insecure/--ca-file flags.

    enum = minio_parser.add_argument_group("Enumeration / Discovery")
    enum.add_argument(
        "--show-buckets", dest="show_buckets", action="store_true", help="List buckets (bounded by --limit)."
    )
    enum.add_argument(
        "--bucket",
        dest="bucket",
        default=None,
        metavar="name",
        help="Target a specific bucket for object listing/discovery.",
    )
    enum.add_argument(
        "--show-objects",
        dest="show_objects",
        action="store_true",
        help="List objects in --bucket (streaming, bounded by --limit).",
    )
    enum.add_argument(
        "--prefix", dest="prefix", default="", metavar="p", help="Object key prefix filter for listing/discovery."
    )
    enum.add_argument(
        "--object",
        dest="object",
        default=None,
        metavar="bucket/key",
        help="Target a single object (bucket/key) for --dump or --download.",
    )
    enum.add_argument(
        "--dump",
        dest="dump",
        action="store_true",
        help="Print the content of --object to stdout.",
    )
    enum.add_argument(
        "--download",
        dest="download",
        default=None,
        metavar="dir",
        help="Download --object into this directory (saved as <dir>/<bucket>/<key>).",
    )
    enum.add_argument(
        "--discover",
        dest="discover",
        action="store_true",
        help="Secret discovery: bounded content inspection of candidate objects.",
    )
    enum.add_argument(
        "--max-object-size",
        dest="max_object_size",
        type=int,
        default=100 * 1024 * 1024,
        metavar="bytes",
        help=(
            "Max bytes read per object for discovery / --dump / --download; larger objects are "
            "scanned in chunks, not skipped (default 100MiB)."
        ),
    )
    enum.add_argument(
        "--max-objects",
        dest="max_objects",
        type=int,
        default=1000,
        metavar="n",
        help="Max objects inspected during discovery (default 1000).",
    )
    enum.add_argument(
        "--discover-time",
        dest="discover_time",
        type=float,
        default=30.0,
        metavar="seconds",
        help="Time budget for discovery (default 30s).",
    )


__all__ = ["configure_minio_parser"]
