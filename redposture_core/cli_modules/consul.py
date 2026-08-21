"""CLI parser builders."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..show_limits import optional_dump_count_kwargs


def configure_consul_parser(
    parser: argparse.ArgumentParser,
    *,
    add_output_flags: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    mirror_group_actions: Callable[..., None],
    port_type: Callable[[str], int],
) -> None:
    common = parser.add_argument_group("Common")
    auth = parser.add_argument_group("Auth")
    actions = parser.add_argument_group("Actions")
    ssrf_options = parser.add_argument_group("SSRF / Probes")
    revshell_options = parser.add_argument_group("Revshell")

    add_output_flags(common)
    add_log_flag(common)
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=None,
        metavar="port",
        help=("Consul port(s): single, list/range, or file. If omitted, scans HTTP 8500 and HTTPS 8501."),
    )
    add_multi_ports_flag(common)
    auth.add_argument(
        "--token",
        dest="token",
        default=None,
        metavar="value",
        help="Consul ACL token (X-Consul-Token) for API auth.",
    )
    auth.add_argument(
        "-u",
        "--username",
        dest="username",
        default=None,
        metavar="name",
        help="Basic auth username or credential file (for proxied/fronted Consul).",
    )
    auth.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        metavar="value",
        help="Basic auth password (for proxied/fronted Consul).",
    )
    transport = parser.add_argument_group("TLS")
    transport_mode = transport.add_mutually_exclusive_group()
    transport_mode.add_argument("--tls", action="store_true", help="Require HTTPS; do not downgrade to HTTP.")
    transport_mode.add_argument(
        "--plaintext",
        action="store_true",
        help="Require HTTP; do not retry HTTPS.",
    )
    transport.add_argument(
        "--insecure",
        action="store_true",
        help="Disable Consul TLS certificate and hostname verification.",
    )
    transport.add_argument("--tls-ca", default=None, metavar="path", help="CA bundle for Consul TLS verification.")
    transport.add_argument("--tls-cert", default=None, metavar="path", help="Client certificate for Consul mTLS.")
    transport.add_argument("--tls-key", default=None, metavar="path", help="Client private key for Consul mTLS.")
    ssrf_options.add_argument(
        "--ssrf-target",
        dest="ssrf_target",
        default=None,
        metavar="target",
        help=("SSRF target(s): ip/dns/cidr/url (comma-separated). Enables agent-check SSRF probing."),
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
        help="Path/query override for generated SSRF URLs (e.g. /debug/vars).",
    )
    actions.add_argument(
        "--keys",
        dest="show_keys",
        action="store_true",
        help="List KV keys (names only; use --dump for values).",
    )
    actions.add_argument(
        "--key",
        dest="kv_key",
        default=None,
        metavar="namekey",
        help="KV key to dump with --dump.",
    )
    revshell_options.add_argument(
        "--revshell",
        dest="revshell",
        action="store_true",
        help="Script-check RCE actions: create payload check or cleanup with --delete.",
    )
    revshell_options.add_argument(
        "--lhost",
        dest="revshell_host",
        default=None,
        metavar="addr",
        help="Listener host for default --revshell payload.",
    )
    revshell_options.add_argument(
        "--lport",
        dest="revshell_port",
        type=port_type,
        default=None,
        metavar="port",
        help="Listener port for default --revshell payload.",
    )
    revshell_options.add_argument(
        "--listen",
        dest="revshell_listen",
        action="store_true",
        help="Auto-start local listener on --lport (prefers rlwrap+nc, fallback nc).",
    )
    revshell_options.add_argument(
        "--payload",
        dest="revshell_payload",
        default=None,
        metavar="cmd",
        help=("Custom command for --revshell. Replaces the default payload and makes --lhost/--lport optional."),
    )
    actions.add_argument(
        "--services",
        dest="show_services",
        action="store_true",
        help="List catalog services (use --dump for instances/details).",
    )
    actions.add_argument(
        "--service",
        dest="service_dump_name",
        default=None,
        metavar="name",
        help="Catalog service name for --dump.",
    )
    actions.add_argument(
        "--agents",
        dest="show_agents",
        action="store_true",
        help="List agent members (use --dump for details).",
    )
    actions.add_argument(
        "--agent",
        dest="agent_name",
        default=None,
        metavar="name",
        help="Agent member name for --dump.",
    )
    checks_action = actions.add_argument(
        "--checks",
        dest="show_checks",
        action="store_true",
        help="List agent checks (use --dump for details/status/output/definition).",
    )
    actions.add_argument(
        "--nodes",
        dest="show_nodes",
        action="store_true",
        help="List catalog nodes (use --dump for details).",
    )
    actions.add_argument(
        "--node",
        dest="node_name",
        default=None,
        metavar="name",
        help="Catalog node name for --dump.",
    )
    actions.add_argument(
        "--dump",
        dest="dump",
        **optional_dump_count_kwargs(
            "Dump details for selected data. Optional count limits each dumped category. Without selectors, dumps KV/services/agents/checks/nodes."
        ),
    )
    revshell_options.add_argument(
        "--delete",
        dest="delete_revshell",
        action="store_true",
        help="Delete revshell check(s): all rev-rp-* or a specific --check-id.",
    )
    check_id_action = revshell_options.add_argument(
        "--check-id",
        dest="revshell_check_id",
        default=None,
        metavar="id",
        help=(
            "Consul check ID for --dump filter, targeted --delete, or custom --revshell create ID "
            "(supports id:<value>)."
        ),
    )
    # Help-only duplication for shared flags that are relevant to both dump and revshell workflows.
    mirror_group_actions(actions, check_id_action)
    dump_group_actions = getattr(actions, "_group_actions", None)
    if (
        isinstance(dump_group_actions, list)
        and check_id_action in dump_group_actions
        and checks_action in dump_group_actions
    ):
        dump_group_actions.remove(check_id_action)
        dump_group_actions.insert(dump_group_actions.index(checks_action) + 1, check_id_action)
    add_save_flag(common, "Optional output file path. If omitted, results are printed to stdout.")
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Consul audit output format for stdout/file.",
    )


__all__ = ["configure_consul_parser"]
