"""Oracle CLI parser builder."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ..show_limits import optional_dump_count_kwargs, optional_show_count_kwargs


def configure_oracle_parser(
    parser: argparse.ArgumentParser,
    *,
    add_scan_host_flags: Callable[..., None],
    add_multi_ports_flag: Callable[..., None],
    add_save_flag: Callable[..., None],
    add_log_flag: Callable[..., None],
    add_output_flags: Callable[..., None],
    append_selected_defaults: Callable[..., None],
    port_type: Callable[[str], int],
    positive_int: Callable[[str], int],
) -> None:
    common = parser.add_argument_group("Common")
    add_scan_host_flags(common, include_profiles=False)
    common.add_argument(
        "--port",
        dest="port",
        type=port_type,
        default=None,
        metavar="port",
        help="Oracle TNS listener port (default: 1521, 11521).",
    )
    add_multi_ports_flag(common)
    add_save_flag(
        common, "Optional output file path. If omitted, results are printed to stdout.", include_save_alias=False
    )
    common.add_argument(
        "-f",
        "--format",
        dest="output_format",
        choices=("json", "txt"),
        default="txt",
        help="Oracle audit output format for stdout/file.",
    )
    add_log_flag(common)
    add_output_flags(common, short=False)

    connect = parser.add_argument_group("Connect / TNS")
    connect.add_argument("--sid", default=None, metavar="name", help="Oracle SID to test/use.")
    connect.add_argument("--service", default=None, metavar="name", help="Oracle service name to test/use.")
    connect.add_argument(
        "--sid-list",
        dest="sid_list",
        default=None,
        metavar="list|file",
        help="Comma-separated SID candidates or file path.",
    )
    connect.add_argument(
        "--service-list",
        dest="service_list",
        default=None,
        metavar="list|file",
        help="Comma-separated service candidates or file path.",
    )
    connect.add_argument(
        "--protocol", choices=("auto", "tcp", "tcps"), default="auto", help="Oracle transport protocol probe order."
    )
    connect.add_argument("--wallet", default=None, metavar="dir", help="Oracle wallet/config directory for TCPS.")
    connect.add_argument(
        "--ssl-server-dn",
        dest="ssl_server_dn",
        default=None,
        metavar="dn",
        help="Expected server certificate DN for TCPS.",
    )
    connect.add_argument(
        "--insecure", action="store_true", help="Disable TCPS server DN/certificate matching where supported."
    )
    connect.add_argument(
        "--listener-dump",
        action="store_true",
        help="Dump Oracle TNS listener STATUS/SERVICES-style metadata where accessible.",
    )
    connect.add_argument(
        "--nne-check",
        action="store_true",
        help="Check Oracle Native Network Encryption/TCPS exposure and weak transport policy signals.",
    )

    auth = parser.add_argument_group("Auth")
    auth.add_argument(
        "-u",
        "--username",
        default=None,
        metavar="name",
        help="Oracle username or username:password credential file path.",
    )
    auth.add_argument("-p", "--password", default=None, metavar="value", help="Oracle password for credential check.")
    auth.add_argument(
        "--defcreds", action="store_true", help="Try default Oracle credentials such as system:oracle and scott:tiger."
    )
    auth.add_argument(
        "--combo-list",
        dest="combo_list",
        default=None,
        metavar="file",
        help="username:password combo file for Oracle auth checks.",
    )
    auth.add_argument(
        "--user-list",
        dest="user_list",
        default=None,
        metavar="file",
        help="Username list for password spraying/dictionary checks.",
    )
    auth.add_argument(
        "--pass-list", dest="pass_list", default=None, metavar="file", help="Password list for dictionary checks."
    )
    auth.add_argument(
        "--spray-passwords", action="store_true", help="Use password spraying order for --user-list/--pass-list."
    )
    auth.add_argument("--as-sysdba", action="store_true", help="Attempt authentication as SYSDBA where supported.")

    discovery = parser.add_argument_group("Discovery / Dump")
    discovery.add_argument(
        "--show-pdbs", **optional_show_count_kwargs("Show Oracle PDB/CDB containers. Optional count limits output.")
    )
    discovery.add_argument(
        "--show-users",
        **optional_show_count_kwargs("Show visible Oracle users/accounts. Optional count limits output."),
    )
    discovery.add_argument("--show-roles", action="store_true", help="Show granted roles for the active session.")
    discovery.add_argument(
        "--show-privs", action="store_true", help="Show visible system/object privileges for the active session."
    )
    discovery.add_argument(
        "--show-schemas",
        **optional_show_count_kwargs("Show schemas with visible tables. Optional count limits output."),
    )
    discovery.add_argument(
        "--show-tables", **optional_show_count_kwargs("Show visible tables. Optional count limits output.")
    )
    discovery.add_argument(
        "--schema", default=None, metavar="name", help="Schema owner for --show-tables/--table/--dump."
    )
    discovery.add_argument("--table", default=None, metavar="name", help="Table name for dump/query target.")
    discovery.add_argument(
        "--dump",
        **optional_dump_count_kwargs(
            "Dump Oracle table rows. Optional count limits rows; without count uses safety cap."
        ),
    )
    discovery.add_argument(
        "--query", default=None, metavar="sql", help="Run one read query after successful access/auth."
    )

    privesc = parser.add_argument_group("Privilege Escalation")
    privesc.add_argument(
        "--privesc-check", action="store_true", help="Check Oracle DBA/SYSDBA and known privilege escalation paths."
    )
    privesc.add_argument(
        "--privesc-chain",
        action="store_true",
        help="Attempt explicit privilege escalation chain checks/execution where privileges allow.",
    )

    actions = parser.add_argument_group("RCE / File / Exfil")
    actions.add_argument(
        "--exec-cmd",
        default=None,
        metavar="cmd",
        help="Explicit OS command execution attempt through selected Oracle method.",
    )
    actions.add_argument(
        "--exec-method",
        choices=("auto", "scheduler", "java", "external-table", "dbms-cloud"),
        default="auto",
        help="Oracle RCE method for --exec-cmd.",
    )
    actions.add_argument(
        "--reverse-shell",
        default=None,
        metavar="host:port",
        help="Explicit reverse shell target for generated command payload.",
    )
    actions.add_argument(
        "--reverse-shell-type",
        choices=("bash", "nc", "python", "powershell"),
        default="bash",
        help="Reverse shell payload style.",
    )
    actions.add_argument(
        "--fs-mode",
        choices=("auto", "directory", "scheduler"),
        default="auto",
        help="Oracle file operation mode: DIRECTORY first, scheduler fallback, or a fixed method.",
    )
    actions.add_argument("--os-read", default=None, metavar="path", help="Attempt server-side file read.")
    actions.add_argument(
        "--os-write",
        default=None,
        metavar="local:remote",
        help="Attempt server-side file write from local file to remote path.",
    )
    actions.add_argument("--download", default=None, metavar="remote:local", help="Attempt server-side file download.")
    actions.add_argument("--delete", default=None, metavar="remote", help="Attempt server-side file delete.")
    actions.add_argument(
        "--wallet-search",
        action="store_true",
        help="Search for Oracle wallet artifacts such as cwallet.sso and .p12 where visible.",
    )
    actions.add_argument(
        "--hashes", action="store_true", help="Attempt to extract visible Oracle password hash metadata."
    )
    actions.add_argument(
        "--sensitive-scan", action="store_true", help="Search visible metadata for sensitive column names."
    )
    actions.add_argument(
        "--dblink-check", action="store_true", help="List visible Oracle database links and linked usernames/hosts."
    )

    append_selected_defaults(parser, "timeout", "workers", "retries", "port", "protocol", "output_format")


__all__ = ["configure_oracle_parser"]
