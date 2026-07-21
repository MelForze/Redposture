"""CLI parser builders."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def configure_grpc_parser(
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
    analysis = parser.add_argument_group("Analysis")
    invoke = parser.add_argument_group("Invoke / Metadata")
    schema = parser.add_argument_group("Schema")
    export = parser.add_argument_group("Export")

    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=50051,
        metavar="port",
        help="gRPC port spec: single port, list/range, or file (examples: 50051, 50051,25052, ./ports.txt).",
    )
    add_multi_ports_flag(common)
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="gRPC audit output format for stdout/file.",
    )

    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Basic auth username or credential file (use with -p for username-only files).",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Basic auth password (use with -u).",
    )
    auth.add_argument(
        "--token",
        dest="token",
        default=None,
        metavar="value",
        help="Bearer token sent as Authorization: Bearer <value>.",
    )
    auth.add_argument(
        "--defcreds",
        action="store_true",
        help="Try compact default basic/token credentials when auth is required.",
    )

    analysis.add_argument(
        "--analyze",
        action="store_true",
        help=(
            "After detection, enumerate Reflection services/descriptors and run per-service Health checks. "
            "Implied by --invoke and --openapi."
        ),
    )

    invoke.add_argument(
        "--invoke",
        dest="invoke",
        default=None,
        metavar="/package.Service/Method",
        help="Invoke one unary gRPC method after detection/auth.",
    )
    invoke.add_argument(
        "--data",
        dest="data",
        default=None,
        metavar="json|@file",
        help='JSON request body for --invoke (default: "{}"; @file reads JSON from disk).',
    )
    invoke.add_argument(
        "--meta",
        dest="meta",
        action="append",
        default=None,
        metavar="key=value",
        help="Additional request metadata header for --invoke (repeatable).",
    )

    schema.add_argument(
        "--proto",
        dest="proto",
        action="append",
        default=None,
        metavar="file",
        help="Proto file used as an additional schema source for invoke/OpenAPI (repeatable).",
    )
    schema.add_argument(
        "--proto-path",
        dest="proto_path",
        action="append",
        default=None,
        metavar="dir",
        help="Import path for --proto compilation (repeatable).",
    )
    schema.add_argument(
        "--protoset",
        dest="protoset",
        action="append",
        default=None,
        metavar="file",
        help="Compiled FileDescriptorSet schema source (repeatable).",
    )

    export.add_argument(
        "--openapi",
        dest="openapi",
        default=None,
        metavar="path",
        help="Write one merged OpenAPI 3.1 JSON artifact for all targets, including descriptor diagnostics.",
    )


__all__ = ["configure_grpc_parser"]
