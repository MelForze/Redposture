"""Grafana CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def configure_grafana_parser(
    grafana_parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    port_type: Callable[[str], int],
) -> None:
    grafana_common = grafana_parser.add_argument_group("Common")
    grafana_auth = grafana_parser.add_argument_group("Auth")
    grafana_actions = grafana_parser.add_argument_group("Actions")
    grafana_ssrf = grafana_parser.add_argument_group("SSRF / Probes")
    add_output_flags(grafana_common)
    add_log_flag(grafana_common)
    add_scan_host_flags(grafana_common, include_profiles=False)
    grafana_common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=3000,
        metavar="port",
        help="Grafana port spec: single port, list/range, or file (examples: 3000, 3000,3001, ./ports.txt).",
    )
    add_multi_ports_flag(grafana_common)
    grafana_auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Optional Grafana username or credential file for credential check.",
    )
    grafana_auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Optional Grafana password for credential check.",
    )
    grafana_auth.add_argument(
        "--defcreds",
        action="store_true",
        help="Try default Grafana credentials admin:admin.",
    )
    # E2E-batch fix: Grafana supports API keys / service account tokens
    # (`Authorization: Bearer glsa-*`) but the CLI previously exposed only
    # basic auth. Adding `--apitoken` gives operators feature parity with the
    # Grafana HTTP API. Both `--apitoken` and `--api-token` are accepted so
    # scripts written against different modules don't have to special-case.
    grafana_auth.add_argument(
        "--apitoken",
        "--api-token",
        dest="apitoken",
        default=None,
        metavar="value",
        help=(
            "Grafana API key or service-account token sent as "
            "'Authorization: Bearer <value>'. Legacy API keys start with "
            "glc_/eyJ..., service-account tokens with glsa_..."
        ),
    )
    grafana_actions.add_argument(
        "--show-datasources",
        "--show-datasource",
        dest="show_datasources",
        action="store_true",
        help="Show datasource details after successful access.",
    )
    grafana_ssrf.add_argument(
        "--ssrf-target",
        dest="ssrf_target",
        default=None,
        metavar="url",
        help="Optional URL/host/cidr for temporary Prometheus egress-check datasource (http/https).",
    )
    grafana_ssrf.add_argument(
        "--ssrf-port",
        dest="ssrf_port",
        type=str,
        default=None,
        metavar="port",
        help="Optional port override for --ssrf-target when URL has no explicit port.",
    )
    grafana_ssrf.add_argument(
        "--ssrf-path",
        dest="ssrf_path",
        type=str,
        default=None,
        metavar="path",
        help="Optional path/query override for generated --ssrf-target URLs (example: /debug/vars).",
    )
    add_save_flag(grafana_common, "Optional output file path. If omitted, results are printed to stdout.")
    grafana_common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Grafana audit output format for stdout/file.",
    )


__all__ = ["configure_grafana_parser"]
