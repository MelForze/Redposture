"""CLI for credential verification across confirmed audit products."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def _positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def configure_spray_parser(
    parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
) -> None:
    common = parser.add_argument_group("Targets and products")
    inputs = parser.add_argument_group("Credential sources")
    pacing = parser.add_argument_group("Pacing and recovery")
    add_output_flags(common)
    common.add_argument(
        "-t", "--targets", required=True, metavar="targets", help="URL, host:port, bare host, or target file."
    )
    common.add_argument("--modules", required=True, metavar="list|all", help="Comma-separated audit modules or all.")
    common.add_argument(
        "--module-config", metavar="json-file", help="Strictly allowlisted per-module auth/transport settings."
    )
    common.add_argument("--proxy", metavar="url", help="Optional outbound proxy.")
    common.add_argument("--timeout", type=_positive_float, default=3.0, metavar="seconds")
    common.add_argument("--retries", type=int, default=0, metavar="count")
    common.add_argument("-w", "--workers", type=int, default=16, metavar="count")
    common.add_argument("-f", "--format", dest="output_format", choices=("txt", "json"), default="txt")
    add_save_flag(common, "Write results to a private 0600 file.")
    inputs.add_argument("--pairs", metavar="file", help="One user:password per line; split on the first colon.")
    inputs.add_argument("--users", metavar="file", help="Usernames, one per line; requires --passwords.")
    inputs.add_argument("--passwords", metavar="file", help="Passwords, one per line; requires --users.")
    inputs.add_argument("--tokens", metavar="file", help="API tokens/JWTs, one per line.")
    pacing.add_argument("--origin-rate", type=_positive_float, default=2.0, metavar="per-second")
    pacing.add_argument("--account-interval", type=_positive_float, default=60.0, metavar="seconds")
    pacing.add_argument("--checkpoint", metavar="file", help="Private SQLite attempt journal.")
    pacing.add_argument(
        "--resume", action="store_true", help="Resume from --checkpoint without retrying begun attempts."
    )


__all__ = ["configure_spray_parser"]
