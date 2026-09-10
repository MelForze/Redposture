"""Airflow CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def configure_airflow_parser(
    airflow_parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    port_type: Callable[[str], int],
) -> None:
    common = airflow_parser.add_argument_group("Common")
    auth = airflow_parser.add_argument_group("Auth")
    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=None,
        metavar="port",
        help="Airflow webserver port spec: single port, list/range, or file. If omitted, scans 8080,8081,18080,28080,8443.",
    )
    add_multi_ports_flag(common)
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Airflow audit output format for stdout/file.",
    )
    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="user",
        help="Airflow username for the REST API.",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="password",
        help="Airflow password for the REST API.",
    )
    auth.add_argument(
        "--defcreds",
        dest="defcreds",
        action="store_true",
        help="Try a curated catalog of Airflow default credentials (incl. airflow:airflow).",
    )
    # Transport is automatic (scheme probed per target; TLS certificates always
    # accepted) — no --https/--insecure/--ca-file flags.


__all__ = ["configure_airflow_parser"]
