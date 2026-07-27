from __future__ import annotations

import argparse
import re

import pytest

from redposture_core.cli_args import (
    COMMAND_DOCKER,
    COMMAND_ELASTIC,
    COMMAND_EXPORTERS,
    COMMAND_GRPC,
    COMMAND_KAFKA,
    COMMAND_MONGODB,
    COMMAND_ORACLE,
    COMMAND_QDRANT,
    COMMAND_SELFCERT,
    _non_negative_int,
    _normalize_multi_port_port_flag,
    _port,
    _positive_float,
    _positive_int,
    build_parser,
    parse_args,
)


def test_parse_args_without_args_shows_help_and_exits_cleanly() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args([])
    assert exc.value.code == 0


def test_cli_scalar_type_helpers_reject_invalid_values() -> None:
    assert _port("1") == 1
    assert _port("65535") == 65535
    with pytest.raises(argparse.ArgumentTypeError, match="integer"):
        _port("abc")
    with pytest.raises(argparse.ArgumentTypeError, match="range"):
        _port("0")

    assert _positive_float("1.25") == 1.25
    with pytest.raises(argparse.ArgumentTypeError, match="number"):
        _positive_float("nan?")
    with pytest.raises(argparse.ArgumentTypeError, match="> 0"):
        _positive_float("0")

    assert _positive_int("7") == 7
    with pytest.raises(argparse.ArgumentTypeError, match="integer"):
        _positive_int("bad")
    with pytest.raises(argparse.ArgumentTypeError, match="> 0"):
        _positive_int("-1")

    assert _non_negative_int("0") == 0
    with pytest.raises(argparse.ArgumentTypeError, match="integer"):
        _non_negative_int("bad")
    with pytest.raises(argparse.ArgumentTypeError, match=">= 0"):
        _non_negative_int("-1")


@pytest.mark.parametrize(
    "argv",
    [
        ["redis", "-t", "10.0.0.1", "--port", "0"],
        ["redis", "-t", "10.0.0.1", "--port", "65536"],
        ["redis", "-t", "10.0.0.1", "--timeout", "0"],
        ["redis", "-t", "10.0.0.1", "--workers", "0"],
        ["redis", "-t", "10.0.0.1", "--retries", "-1"],
        ["redis", "-t", "10.0.0.1", "--format", "xml"],
        ["exporters", "scan", "-t", "10.0.0.1", "--timeout", "0"],
        ["exporters", "collect", "-t", "10.0.0.1", "--max-inflight", "0"],
        ["exporters", "trigger", "-t", "10.0.0.1", "--postgres-port", "99999"],
        ["oracle", "-t", "10.0.0.1", "--protocol", "udp"],
        ["oracle", "-t", "10.0.0.1", "--exec-method", "bad"],
        ["oracle", "-t", "10.0.0.1", "--reverse-shell-type", "bad"],
        ["clickhouse", "-t", "10.0.0.1", "--format", "yaml"],
        ["zookeeper", "-t", "10.0.0.1", "--enum-workers", "0"],
        ["zookeeper", "-t", "10.0.0.1", "--max-znodes", "0"],
    ],
)
def test_parse_args_rejects_invalid_cli_values(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(argv)
    assert exc.value.code == 2


def test_normalize_multi_port_port_flag_variants() -> None:
    assert _normalize_multi_port_port_flag(["redis", "--port", "6379"]) == ["redis", "--port", "6379"]
    assert _normalize_multi_port_port_flag(["redis", "--port", "6379,6380"]) == [
        "redis",
        "--port",
        "6379",
        "--ports",
        "6379,6380",
    ]
    assert _normalize_multi_port_port_flag(["redis", "--port=6379-6381"]) == [
        "redis",
        "--port=6379",
        "--ports",
        "6379-6381",
    ]
    assert _normalize_multi_port_port_flag(["redis", "--port", "ports.txt"]) == ["redis", "--ports", "ports.txt"]
    assert _normalize_multi_port_port_flag(["redis", "--port=ports.txt"]) == ["redis", "--ports=ports.txt"]


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["grpc", "-t", "grpc.internal:8085"], False),
        (["grpc", "-t", "grpc.internal:8085", "--port", "50052"], True),
        (["grpc", "-t", "grpc.internal:8085", "--port=50052"], True),
        (["grpc", "-t", "grpc.internal:8085", "--port", "50052,50053"], True),
        (["grpc", "-t", "grpc.internal:8085", "--ports", "50052,50053"], True),
    ],
)
def test_parse_args_marks_whether_a_port_option_was_provided(argv: list[str], expected: bool) -> None:
    args = parse_args(argv)

    assert args._port_option_provided is expected


def test_parse_args_legacy_top_level_modes_and_selfcert_paths() -> None:
    args = parse_args(["--selfcert", "--cert-out", "cert.pem", "--key-out", "key.pem", "--force"])
    assert args.command == COMMAND_SELFCERT
    assert args.selfcert is True
    assert args.force is True

    with pytest.raises(SystemExit) as exc:
        parse_args(["redis", "--selfcert"])
    assert exc.value.code == 2

    for legacy_command in ("listen", "scan", "collect", "trigger"):
        with pytest.raises(SystemExit) as exc:
            parse_args([legacy_command])
        assert exc.value.code == 2

    with pytest.raises(SystemExit) as exc:
        parse_args(["exporters", "collect", "-t", "127.0.0.1", "-oA"])
    assert exc.value.code == 2

    with pytest.raises(SystemExit) as exc:
        parse_args(["--debug"])
    assert exc.value.code == 2


def test_db_command_is_not_available() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["db", "show"])
    assert exc.value.code == 2


def test_help_color_is_disabled_when_supported() -> None:
    parser = build_parser()
    parser_color = getattr(parser, "color", None)
    if parser_color is None:
        return

    assert parser_color is False
    root_action = parser._subparsers._group_actions[0]
    exporters_parser = root_action.choices["exporters"]
    assert getattr(exporters_parser, "color", None) is False
    exporters_action = exporters_parser._subparsers._group_actions[0]
    scan_parser = exporters_action.choices["scan"]
    assert getattr(scan_parser, "color", None) is False


def test_exporters_listen_parser_builder_wires_shared_flags() -> None:
    from redposture_core.cli_modules.exporters import configure_listen_parser

    calls: list[str] = []
    parser = argparse.ArgumentParser()

    configure_listen_parser(
        parser,
        add_output_flags=lambda _parser: calls.append("output"),
        add_log_flag=lambda _parser: calls.append("log"),
        add_listener_flags=lambda _parser: calls.append("listener"),
    )

    assert calls == ["output", "log", "listener"]


def _command_help(command: str) -> str:
    parser = build_parser()
    root_action = parser._subparsers._group_actions[0]
    command_parser = root_action.choices[command]
    return command_parser.format_help()


def _help_option_line_index(help_text: str, option_fragment: str) -> int:
    options_idx = help_text.find("\noptions:\n")
    search_text = help_text[options_idx:] if options_idx != -1 else help_text
    token = re.escape(option_fragment)
    match = re.search(rf"(?m)^\s{{2,}}.*(?<![A-Za-z0-9_-]){token}(?![A-Za-z0-9_-])", search_text)
    if not match:
        return -1
    return options_idx + match.start() if options_idx != -1 else match.start()


def test_postgres_help_groups_and_orders_flags() -> None:
    help_text = _command_help("postgres")

    auth_group_idx = help_text.find("\nDatabase / Auth:\n")
    discovery_group_idx = help_text.find("\nDiscovery / Dump:\n")
    exec_group_idx = help_text.find("\nExecute / Shell:\n")
    assert auth_group_idx != -1
    assert discovery_group_idx != -1
    assert exec_group_idx != -1
    assert auth_group_idx < discovery_group_idx < exec_group_idx

    targets_idx = _help_option_line_index(help_text, "--targets")
    port_idx = _help_option_line_index(help_text, "--port")
    output_idx = _help_option_line_index(help_text, "--output")
    format_idx = _help_option_line_index(help_text, "--format")
    log_idx = _help_option_line_index(help_text, "--log")
    debug_idx = _help_option_line_index(help_text, "--debug")
    assert -1 not in {targets_idx, port_idx, output_idx, format_idx, log_idx, debug_idx}
    assert targets_idx < port_idx < output_idx < format_idx < log_idx < debug_idx
    # --ports is now a deprecated hidden alias (merged into --port). It must
    # NOT surface in --help output any more.
    assert _help_option_line_index(help_text, "--ports") == -1

    username_idx = _help_option_line_index(help_text, "--username")
    password_idx = _help_option_line_index(help_text, "--password")
    defcreds_idx = _help_option_line_index(help_text, "--defcreds")
    assert -1 not in {username_idx, password_idx, defcreds_idx}
    assert username_idx < password_idx < defcreds_idx

    show_databases_idx = _help_option_line_index(help_text, "--show-databases")
    database_idx = _help_option_line_index(help_text, "--database name")
    show_tables_idx = _help_option_line_index(help_text, "--show-tables")
    table_idx = _help_option_line_index(help_text, "--table name")
    show_columns_idx = _help_option_line_index(help_text, "--show-columns")
    column_idx = _help_option_line_index(help_text, "--column name")
    dump_idx = _help_option_line_index(help_text, "--dump [count]")
    privesc_idx = _help_option_line_index(help_text, "--privesc-check")
    assert -1 not in {
        show_databases_idx,
        show_tables_idx,
        table_idx,
        show_columns_idx,
        column_idx,
        dump_idx,
        privesc_idx,
    }
    assert (
        show_databases_idx
        < database_idx
        < show_tables_idx
        < table_idx
        < show_columns_idx
        < column_idx
        < dump_idx
        < privesc_idx
    )

    execute_idx = _help_option_line_index(help_text, "--execute")
    os_read_idx = _help_option_line_index(help_text, "--os-read path")
    sql_cmd_idx = _help_option_line_index(help_text, "--sql-cmd query")
    os_shell_idx = _help_option_line_index(help_text, "--os-shell")
    sql_shell_idx = _help_option_line_index(help_text, "--sql-shell")
    assert -1 not in {execute_idx, os_read_idx, sql_cmd_idx, os_shell_idx, sql_shell_idx}
    assert execute_idx < os_read_idx < os_shell_idx < sql_shell_idx < sql_cmd_idx


def test_postgres_help_orders_show_columns_column_dump() -> None:
    help_text = _command_help("postgres")
    show_columns_idx = help_text.find("--show-columns")
    column_idx = help_text.find("--column")
    dump_idx = help_text.find("--dump")
    assert show_columns_idx != -1
    assert column_idx != -1
    assert dump_idx != -1
    assert show_columns_idx < column_idx < dump_idx


def test_elastic_help_sections_are_present() -> None:
    help_text = _command_help("elastic")
    assert "\nCommon:\n" in help_text
    assert "\nAuth:\n" in help_text
    assert "\nActions:\n" in help_text
    assert "--apitoken value" in help_text
    assert "--plugins" in help_text
    assert "--user" in help_text


def test_grpc_help_sections_are_present() -> None:
    help_text = _command_help(COMMAND_GRPC)
    assert "\nCommon:\n" in help_text
    assert "\nAuth:\n" in help_text
    assert "\nAnalysis:\n" in help_text
    assert "\nInvoke / Metadata:\n" in help_text
    assert "\nSchema:\n" in help_text
    assert "\nExport:\n" in help_text
    assert "--token value" in help_text
    assert "--defcreds" in help_text
    assert "--analyze" in help_text
    assert "--invoke /package.Service/Method" in help_text
    assert "--proto file" in help_text
    assert "--protoset file" in help_text
    assert "--openapi [path]" in help_text


def test_kafka_help_lists_every_runtime_default_port() -> None:
    help_text = _command_help(COMMAND_KAFKA)
    for port in (9092, 9093, 19092, 19093, 29092, 29093):
        assert str(port) in help_text


def test_help_documents_implicit_target_file_precedence() -> None:
    help_text = _command_help("registry")
    assert "treated as" in help_text
    assert "target files" in help_text


@pytest.mark.parametrize(
    ("command", "sections"),
    [
        (
            "registry",
            ["Common", "Auth", "Docker / OCI (Registry v2)", "Harbor", "GitLab Container Registry", "Nexus Repository"],
        ),
        ("grafana", ["Common", "Auth", "Actions", "SSRF / Probes"]),
        ("proxmox", ["Common", "Auth", "Actions"]),
        ("gitlab", ["Common", "Auth", "Actions"]),
        ("consul", ["Common", "Auth", "Actions", "SSRF / Probes", "Revshell"]),
        ("kubeapi", ["Common", "Auth", "Actions"]),
        ("postgres", ["Common", "Database / Auth", "Discovery / Dump", "Execute / Shell"]),
        ("mongodb", ["Common", "Database / Auth", "Discovery / Dump", "NoSQL / Shell"]),
        ("docker", ["Common", "TLS", "Inventory", "Exec"]),
        ("clickhouse", ["Common", "Auth", "Actions", "Execute / Shell"]),
        ("redis", ["Common", "Auth", "Actions"]),
        ("etcd", ["Common", "Actions"]),
        ("qdrant", ["Common", "Auth", "Actions", "SSRF / Probes"]),
        ("elastic", ["Common", "Auth", "Actions"]),
        ("grpc", ["Common", "Auth", "Invoke / Metadata", "Schema", "Export"]),
        ("kafka", ["Common", "Auth", "Actions"]),
        ("keeper", ["Common", "TLS (transport auto-detected)", "Auth", "Actions"]),
        ("zookeeper", ["Common", "Auth", "Actions"]),
    ],
)
def test_module_help_has_grouped_sections_in_stable_order(command: str, sections: list[str]) -> None:
    help_text = _command_help(command)
    positions: list[int] = []
    for section in sections:
        marker = f"\n{section}:\n"
        idx = help_text.find(marker)
        assert idx != -1, f"missing section {section!r} in {command} help"
        positions.append(idx)
    assert positions == sorted(positions), f"sections are out of order for {command}"


def test_exporters_subcommands_help_has_grouped_sections() -> None:
    parser = build_parser()
    root_action = parser._subparsers._group_actions[0]
    exporters_parser = root_action.choices["exporters"]
    exporters_action = exporters_parser._subparsers._group_actions[0]

    scan_help = exporters_action.choices["scan"].format_help()
    collect_help = exporters_action.choices["collect"].format_help()
    trigger_help = exporters_action.choices["trigger"].format_help()

    assert "\nCommon:\n" in scan_help and "\nActions:\n" in scan_help
    assert "\nCommon:\n" in collect_help and "\nActions:\n" in collect_help
    assert "\nCommon:\n" in trigger_help and "\nActions:\n" in trigger_help and "\nListener:\n" in trigger_help


def test_postgres_rows_and_dump_limit_flags_are_parsed() -> None:
    args = parse_args(
        [
            "postgres",
            "-t",
            "10.0.0.1",
            "--database",
            "appdb",
            "--table",
            "public.users",
            "--rows",
            "--dump",
            "25",
        ]
    )

    assert args.command == "postgres"
    assert args.database == "appdb"
    assert args.rows is True
    assert args.dump == 25


def test_postgres_dump_without_value_means_unlimited_dump() -> None:
    args = parse_args(["postgres", "-t", "10.0.0.1", "--dump"])
    assert args.dump is True


def test_postgres_help_shows_defaults_only_for_selected_flags() -> None:
    help_text = _command_help("postgres")

    assert "Network timeout in seconds. (default: 1.0)" in help_text
    assert "Worker threads used for parallel network checks." in help_text
    assert "(default: 50)" in help_text
    assert "Retry attempts for network requests (with exponential" in help_text
    assert "backoff). (default: 3)" in help_text
    assert "Postgres audit output format for stdout/file." in help_text
    assert "(default: txt)" in help_text

    assert "Optional Postgres username for credential check. (default:" not in help_text
    assert "Optional Postgres password for credential check. (default:" not in help_text
    assert "pgbouncer:pgbouncer" in help_text
    assert "Try default Postgres credentials postgres:postgres" in help_text
    assert "pgbouncer:pgbouncer when auth is required. (default:" not in help_text


def test_mongodb_help_sections_and_parse_flags() -> None:
    help_text = _command_help(COMMAND_MONGODB)
    assert "\nCommon:\n" in help_text
    assert "\nDatabase / Auth:\n" in help_text
    assert "\nDiscovery / Dump:\n" in help_text
    assert "\nNoSQL / Shell:\n" in help_text
    assert "--auth-db name" in help_text
    assert "--show-databases" in help_text
    assert "--show-collections" in help_text
    assert "--show-indexes" in help_text
    assert "--document id" in help_text
    assert "--index name" in help_text
    assert "--query json" in help_text
    assert "--nosql-cmd json" in help_text
    assert "--nosql-shell" in help_text
    args = parse_args(
        [
            "mongodb",
            "-t",
            "127.0.0.1",
            "--port",
            "27018",
            "-u",
            "root",
            "-p",
            "root",
            "--auth-db",
            "admin",
            "--database",
            "redposture",
            "--collection",
            "demo_accounts",
            "--document",
            "1",
            "--index",
            "username_1",
            "--projection",
            '{"username":1}',
            "--nosql-cmd",
            '{"dbStats":1}',
            "--dump",
            "5",
        ]
    )
    assert args.command == COMMAND_MONGODB
    assert args.port == 27018
    assert args.username == "root"
    assert args.password == "root"
    assert args.auth_db == "admin"
    assert args.database == "redposture"
    assert args.collections == ["demo_accounts"]
    assert args.document == "1"
    assert args.index == "username_1"
    assert args.nosql_cmd == '{"dbStats":1}'
    assert args.nosql_shell is False
    assert args.dump == 5


def test_docker_help_sections_and_parse_flags() -> None:
    help_text = _command_help(COMMAND_DOCKER)
    assert "\nCommon:\n" in help_text
    assert "\nTLS:\n" in help_text
    assert "\nInventory:\n" in help_text
    assert "\nExec:\n" in help_text
    assert "--tls-ca file" in help_text
    assert "--tls-cert file" in help_text
    assert "--containers" in help_text
    assert "--exec-cmd cmd" in help_text
    args = parse_args(
        [
            "docker",
            "-t",
            "127.0.0.1",
            "--port",
            "2376",
            "--insecure",
            "--tls-ca",
            "ca.pem",
            "--tls-cert",
            "cert.pem",
            "--tls-key",
            "key.pem",
            "--containers",
            "--images",
            "--networks",
            "--volumes",
            "--system",
            "--container",
            "web",
            "--exec-cmd",
            "id",
        ]
    )
    assert args.command == COMMAND_DOCKER
    assert args.port == 2376
    assert args.insecure is True
    assert args.tls_ca == "ca.pem"
    assert args.tls_cert == "cert.pem"
    assert args.tls_key == "key.pem"
    assert args.containers is True
    assert args.images is True
    assert args.networks is True
    assert args.volumes is True
    assert args.system is True
    assert args.container == "web"
    assert args.exec_cmd == "id"


def test_oracle_help_sections_and_parse_flags() -> None:
    help_text = _command_help(COMMAND_ORACLE)
    assert "\nCommon:\n" in help_text
    assert "\nConnect / TNS:\n" in help_text
    assert "\nAuth:\n" in help_text
    assert "\nDiscovery / Dump:\n" in help_text
    assert "\nPrivilege Escalation:\n" in help_text
    assert "\nRCE / File / Exfil:\n" in help_text
    assert "--service name" in help_text
    assert "--sid-list list|file" in help_text
    assert "--listener-dump" in help_text
    assert "--nne-check" in help_text
    assert "--combo-list file" in help_text
    assert "--privesc-check" in help_text
    assert "--exec-cmd cmd" in help_text
    assert "--fs-mode {auto,directory,scheduler}" in help_text
    args = parse_args(
        [
            "oracle",
            "-t",
            "127.0.0.1",
            "--port",
            "1522",
            "--service",
            "FREEPDB1",
            "--listener-dump",
            "--nne-check",
            "-u",
            "system",
            "-p",
            "oracle",
            "--show-pdbs",
            "--show-users",
            "--show-tables",
            "--schema",
            "REDPOSTURE",
            "--table",
            "ACCOUNTS",
            "--dump",
            "5",
            "--query",
            "select 1 from dual",
            "--privesc-check",
            "--exec-cmd",
            "id",
            "--fs-mode",
            "scheduler",
            "--os-read",
            "/etc/hostname",
            "--hashes",
            "--dblink-check",
        ]
    )
    assert args.command == COMMAND_ORACLE
    assert args.port == 1522
    assert args.service == "FREEPDB1"
    assert args.listener_dump is True
    assert args.nne_check is True
    assert args.username == "system"
    assert args.password == "oracle"
    assert args.show_pdbs is True
    assert args.show_users is True
    assert args.dump == 5
    assert args.privesc_check is True
    assert args.exec_cmd == "id"
    assert args.fs_mode == "scheduler"
    assert args.os_read == "/etc/hostname"


def test_grpc_auth_flags_are_parsed() -> None:
    args = parse_args(
        [
            "grpc",
            "-t",
            "127.0.0.1",
            "--port",
            "50061",
            "--token",
            "grpc-lab-token-2026",
            "--defcreds",
        ]
    )
    assert args.command == "grpc"
    assert args.port == 50061
    assert args.token == "grpc-lab-token-2026"
    assert args.defcreds is True
    assert args.analyze is False

    analyze_args = parse_args(["grpc", "-t", "127.0.0.1", "--analyze"])
    assert analyze_args.analyze is True


def test_grpc_invoke_schema_export_flags_are_parsed() -> None:
    args = parse_args(
        [
            "grpc",
            "-t",
            "127.0.0.1",
            "--invoke",
            "/grpc.health.v1.Health/Check",
            "--data",
            '{"service":""}',
            "--meta",
            "x-lab=1",
            "--meta",
            "x-trace=test",
            "--proto",
            "health.proto",
            "--proto-path",
            "proto",
            "--protoset",
            "health.protoset",
            "--openapi",
            "grpc.openapi.json",
        ]
    )
    assert args.invoke == "/grpc.health.v1.Health/Check"
    assert args.data == '{"service":""}'
    assert args.meta == ["x-lab=1", "x-trace=test"]
    assert args.proto == ["health.proto"]
    assert args.proto_path == ["proto"]
    assert args.protoset == ["health.protoset"]
    assert args.openapi == "grpc.openapi.json"

    automatic_path_args = parse_args(["grpc", "-t", "127.0.0.1", "--openapi"])
    assert automatic_path_args.openapi == ""


def test_grpc_username_password_pair_validation() -> None:
    args = parse_args(["grpc", "-t", "127.0.0.1", "-u", "admin"])
    assert args.username == "admin"
    assert args.password is None


def test_clickhouse_help_shows_defaults_only_for_selected_flags() -> None:
    help_text = _command_help("clickhouse")
    assert "Show readable table names in output after successful access/auth. (default:" not in help_text


def test_clickhouse_help_orders_show_columns_column_dump() -> None:
    help_text = _command_help("clickhouse")
    show_columns_idx = help_text.find("--show-columns")
    column_idx = help_text.find("--column")
    dump_idx = help_text.find("--dump")
    assert show_columns_idx != -1
    assert column_idx != -1
    assert dump_idx != -1
    assert show_columns_idx < column_idx < dump_idx


def test_trigger_with_listen_flag_parses_listener_options() -> None:
    args = parse_args(
        [
            "exporters",
            "trigger",
            "-t",
            "10.0.0.1",
            "--callback-ip",
            "10.0.0.2",
            "--redis-port",
            "16379",
            "--postgres-tls",
            "--with-listen",
        ]
    )
    assert args.command == COMMAND_EXPORTERS
    assert args.exporters_action == "trigger"
    assert args.redis_port == 16379
    assert args.postgres_tls is True


def test_trigger_listen_seconds_flag_is_parsed() -> None:
    args = parse_args(
        [
            "exporters",
            "trigger",
            "-t",
            "10.0.0.1",
            "--callback-ip",
            "10.0.0.2",
            "--listen-seconds",
            "8",
        ]
    )
    assert args.listen_seconds == 8.0


def test_exporters_scan_flags_are_parsed() -> None:
    args = parse_args(["exporters", "scan", "-t", "10.0.0.1", "-p", "9100,9115"])
    assert args.command == COMMAND_EXPORTERS
    assert args.exporters_action == "scan"
    assert args.targets == "10.0.0.1"
    assert args.ports == "9100,9115"


@pytest.mark.parametrize("action", ["scan", "collect", "trigger"])
def test_exporter_actions_accept_singular_port_alias(action: str) -> None:
    args = parse_args(["exporters", action, "-t", "10.0.0.1:8085", "--port", "9100"])

    assert args.ports == "9100"


def test_trigger_listener_defaults_have_tls_enabled() -> None:
    args = parse_args(["exporters", "trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2"])
    assert args.postgres_tls is True
    assert args.proxmox_tls is True


def test_scan_flags_are_parsed() -> None:
    args = parse_args(
        [
            "exporters",
            "scan",
            "-t",
            "10.0.0.1,10.0.0.2",
            "--timeout",
            "1.5",
            "-w",
            "12",
            "-r",
            "3",
            "--profiles-file",
            "profiles.json",
            "-f",
            "json",
            "-o",
            "scan.jsonl",
            "-p",
            "9100,9115,9200-9202",
        ]
    )
    assert args.command == COMMAND_EXPORTERS
    assert args.exporters_action == "scan"
    assert args.targets == "10.0.0.1,10.0.0.2"
    assert args.timeout == 1.5
    assert args.workers == 12
    assert args.retries == 3
    assert args.profiles_file == "profiles.json"
    assert args.output_format == "json"
    assert args.output == "scan.jsonl"
    assert args.ports == "9100,9115,9200-9202"


def test_scan_save_alias_is_parsed() -> None:
    args = parse_args(["exporters", "scan", "-t", "10.0.0.1", "--save", "scan.txt"])
    assert args.output == "scan.txt"


def test_log_flag_is_parsed_for_scan() -> None:
    args = parse_args(["exporters", "scan", "-t", "10.0.0.1", "-log", "scan.log"])
    assert args.log == "scan.log"


def test_log_flag_is_parsed_for_implicit_listen() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["-log", "listen.log"])
    assert exc.value.code == 2


def test_listen_rejects_old_selfcert_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["listen", "-selfcert"])
    assert exc.value.code == 2


def test_trigger_rejects_old_selfcert_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["exporters", "trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2", "-selfcert"])
    assert exc.value.code == 2


def test_scan_workers_and_retries_defaults() -> None:
    args = parse_args(["exporters", "scan", "-t", "10.0.0.1"])
    assert args.workers == 50
    assert args.retries == 3


def test_trigger_can_parse_without_callback_values() -> None:
    args = parse_args(["exporters", "trigger", "-t", "10.0.0.1"])
    assert args.command == COMMAND_EXPORTERS
    assert args.exporters_action == "trigger"
    assert args.callback_ip is None
    assert args.callback_dns is None


def test_trigger_with_listen_flag_and_listener_defaults() -> None:
    args = parse_args(["exporters", "trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2", "--with-listen"])
    assert args.with_listen is True
    assert args.callback_ip == "10.0.0.2"
    assert args.callback_dns is None
    assert args.services == "postgres,redis,proxmox,blackbox"
    assert args.bind == "0.0.0.0"
    assert args.postgres_port == 5432
    assert args.redis_port == 6379
    assert args.proxmox_port == 8006
    assert args.blackbox_port == 9115
    assert args.postgres_tls is True
    assert args.proxmox_tls is True


def test_trigger_workers_and_retries_flags_are_parsed() -> None:
    args = parse_args(["exporters", "trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2", "-w", "20", "-r", "2"])
    assert args.workers == 20
    assert args.retries == 2


def test_trigger_postgres_auth_module_flags_are_parsed() -> None:
    args = parse_args(
        [
            "exporters",
            "trigger",
            "-t",
            "10.0.0.1",
            "--callback-ip",
            "10.0.0.2",
            "--postgres-auth-module",
            "lab,readonly",
            "--postgres-auth-module",
            "prod",
        ]
    )
    assert args.postgres_auth_modules == ["lab,readonly", "prod"]


def test_trigger_output_flag_is_parsed() -> None:
    args = parse_args(["exporters", "trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2", "-o", "trigger.txt"])
    assert args.output == "trigger.txt"


def test_trigger_json_format_flag_is_parsed() -> None:
    args = parse_args(
        ["exporters", "trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2", "-f", "json", "-o", "trigger.json"]
    )
    assert args.output_format == "json"
    assert args.output == "trigger.json"


def test_trigger_save_alias_is_parsed() -> None:
    args = parse_args(["exporters", "trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2", "--save", "trigger.txt"])
    assert args.output == "trigger.txt"


def test_trigger_with_optional_callback_dns_flag() -> None:
    args = parse_args(
        [
            "exporters",
            "trigger",
            "-t",
            "10.0.0.1",
            "--callback-ip",
            "10.0.0.2",
            "--callback-dns",
            "redposture.example.com",
        ]
    )
    assert args.callback_ip == "10.0.0.2"
    assert args.callback_dns == "redposture.example.com"


def test_trigger_ports_flag_is_parsed() -> None:
    args = parse_args(
        [
            "exporters",
            "trigger",
            "-t",
            "10.0.0.1",
            "--callback-ip",
            "10.0.0.2",
            "--ports",
            "9121,19121",
        ]
    )
    assert args.ports == "9121,19121"


def test_ports_file_is_accepted_across_all_modules(tmp_path) -> None:
    ports_file = tmp_path / "ports.txt"
    ports_file.write_text("9100\n9115\n", encoding="utf-8")
    file_value = str(ports_file)

    argv_variants = [
        ["exporters", "scan", "-t", "10.0.0.1", "--ports", file_value],
        ["exporters", "collect", "-t", "10.0.0.1", "--ports", file_value],
        [
            "exporters",
            "trigger",
            "-t",
            "10.0.0.1",
            "--callback-ip",
            "10.0.0.2",
            "--ports",
            file_value,
        ],
        ["redis", "-t", "10.0.0.1", "--ports", file_value],
        ["etcd", "-t", "10.0.0.1", "--ports", file_value],
        ["kafka", "-t", "10.0.0.1", "--ports", file_value],
        ["zookeeper", "-t", "10.0.0.1", "--ports", file_value],
        ["elastic", "-t", "10.0.0.1", "--ports", file_value],
        ["grafana", "-t", "10.0.0.1", "--ports", file_value],
        ["postgres", "-t", "10.0.0.1", "--ports", file_value],
        ["clickhouse", "-t", "10.0.0.1", "--ports", file_value],
        ["consul", "-t", "10.0.0.1", "--ports", file_value],
        ["qdrant", "-t", "10.0.0.1", "--ports", file_value],
        ["kubeapi", "-t", "10.0.0.1", "--ports", file_value],
        ["gitlab", "-t", "10.0.0.1", "--ports", file_value],
        ["registry", "-t", "10.0.0.1", "--ports", file_value],
        ["proxmox", "-t", "10.0.0.1", "--pveapitoken", "monitor@pve!audit=token", "--ports", file_value],
    ]

    for argv in argv_variants:
        args = parse_args(argv)
        assert args.ports == file_value


def test_port_file_is_normalized_to_ports_across_port_modules(tmp_path) -> None:
    ports_file = tmp_path / "ports.txt"
    ports_file.write_text("19000\n", encoding="utf-8")
    file_value = str(ports_file)

    argv_variants = [
        ["gitlab", "-t", "10.0.0.1", "--port", file_value],
        ["kubeapi", "-t", "10.0.0.1", "--port", file_value],
        ["consul", "-t", "10.0.0.1", "--port", file_value],
        ["qdrant", "-t", "10.0.0.1", "--port", file_value],
        ["registry", "-t", "10.0.0.1", "--port", file_value],
        ["grafana", "-t", "10.0.0.1", "--port", file_value],
        ["proxmox", "-t", "10.0.0.1", "--pveapitoken", "monitor@pve!audit=token", "--port", file_value],
        ["postgres", "-t", "10.0.0.1", "--port", file_value],
        ["clickhouse", "-t", "10.0.0.1", "--port", file_value],
        ["redis", "-t", "10.0.0.1", "--port", file_value],
        ["etcd", "-t", "10.0.0.1", "--port", file_value],
        ["kafka", "-t", "10.0.0.1", "--port", file_value],
        ["zookeeper", "-t", "10.0.0.1", "--port", file_value],
        ["elastic", "-t", "10.0.0.1", "--port", file_value],
    ]

    for argv in argv_variants:
        args = parse_args(argv)
        assert args.ports == file_value


def test_redis_flags_are_parsed() -> None:
    args = parse_args(
        [
            "redis",
            "-t",
            "10.0.0.7,10.0.0.8",
            "--timeout",
            "0.8",
            "-w",
            "8",
            "-r",
            "1",
            "--port",
            "6380",
            "--ports",
            "6379,6380,16379",
            "--username",
            "redis",
            "--password",
            "redis",
            "--defcreds",
            "--show-keys",
            "--dump",
            "-key",
            "session:admin",
            "-f",
            "json",
            "-o",
            "redis_audit.jsonl",
        ]
    )
    assert args.command == "redis"
    assert args.targets == "10.0.0.7,10.0.0.8"
    assert args.timeout == 0.8
    assert args.workers == 8
    assert args.retries == 1
    assert args.port == 6380
    assert args.ports == "6379,6380,16379"
    assert args.username == "redis"
    assert args.password == "redis"
    assert args.defcreds is True
    assert args.show_keys is True
    assert args.dump is True
    assert args.key == "session:admin"
    assert args.output_format == "json"
    assert args.output == "redis_audit.jsonl"


@pytest.mark.parametrize(
    ("argv", "dest", "expected"),
    [
        (["redis", "-t", "10.0.0.7", "--show-keys", "25"], "show_keys", 25),
        (["etcd", "-t", "10.0.0.9", "--show-keys", "25"], "show_keys", 25),
        (["kafka", "-t", "10.0.0.21", "--show-topics", "25"], "show_topics", 25),
        (["zookeeper", "-t", "10.0.0.21", "--show-znodes", "25"], "show_znodes", 25),
        (["postgres", "-t", "10.0.0.1", "--show-databases", "25"], "show_databases", 25),
        (["postgres", "-t", "10.0.0.1", "--show-tables", "25"], "show_tables", 25),
        (["postgres", "-t", "10.0.0.1", "--show-columns", "25", "--table", "public.users"], "show_columns", 25),
        (["clickhouse", "-t", "10.0.0.1", "--show-databases", "25"], "show_databases", 25),
        (["clickhouse", "-t", "10.0.0.1", "--show-tables", "25"], "show_tables", 25),
        (["clickhouse", "-t", "10.0.0.1", "--show-columns", "25", "--table", "default.users"], "show_columns", 25),
        (["mongodb", "-t", "10.0.0.1", "--show-databases", "25"], "show_databases", 25),
        (["mongodb", "-t", "10.0.0.1", "--show-collections", "25"], "show_collections", 25),
        (["mongodb", "-t", "10.0.0.1", "--show-indexes", "25"], "show_indexes", 25),
    ],
)
def test_show_flags_accept_optional_count(argv: list[str], dest: str, expected: int) -> None:
    args = parse_args(argv)
    assert getattr(args, dest) == expected


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["redis", "-t", "10.0.0.7", "--dump", "10"], 10),
        (["etcd", "-t", "10.0.0.9", "--dump", "10"], 10),
        (["clickhouse", "-t", "10.0.0.1", "--dump", "10"], 10),
        (["kafka", "-t", "10.0.0.21", "--dump", "10"], 10),
        (["zookeeper", "-t", "10.0.0.21", "--dump", "10"], 10),
        (["consul", "-t", "10.0.0.40", "--dump", "10"], 10),
        (["qdrant", "-t", "10.0.0.60", "--dump", "10"], 10),
        (["postgres", "-t", "10.0.0.1", "--dump", "10"], 10),
        (["mongodb", "-t", "10.0.0.1", "--dump", "10"], 10),
        (["oracle", "-t", "10.0.0.1", "--dump", "10"], 10),
    ],
)
def test_dump_flags_accept_optional_count(argv: list[str], expected: int) -> None:
    args = parse_args(argv)
    assert args.dump == expected


@pytest.mark.parametrize(
    "argv",
    [
        ["redis", "-t", "10.0.0.7", "--dump", "0"],
        ["etcd", "-t", "10.0.0.9", "--dump", "0"],
        ["clickhouse", "-t", "10.0.0.1", "--dump", "0"],
        ["kafka", "-t", "10.0.0.21", "--dump", "0"],
        ["zookeeper", "-t", "10.0.0.21", "--dump", "0"],
        ["consul", "-t", "10.0.0.40", "--dump", "0"],
        ["qdrant", "-t", "10.0.0.60", "--dump", "0"],
        ["postgres", "-t", "10.0.0.1", "--dump", "0"],
        ["mongodb", "-t", "10.0.0.1", "--dump", "0"],
        ["oracle", "-t", "10.0.0.1", "--dump", "0"],
    ],
)
def test_dump_flags_reject_zero_count(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(argv)
    assert exc.value.code == 2


def test_redis_short_user_password_flags_are_parsed() -> None:
    args = parse_args(["redis", "-t", "10.0.0.7", "-u", "redis", "-p", "redis"])
    assert args.command == "redis"
    assert args.username == "redis"
    assert args.password == "redis"
    assert args.defcreds is False


def test_redis_key_flag_is_parsed() -> None:
    args = parse_args(["redis", "-t", "10.0.0.7", "-key", "app:token"])
    assert args.command == "redis"
    assert args.key == "app:token"


def test_redis_dump_keys_flag_is_parsed() -> None:
    args = parse_args(["redis", "-t", "10.0.0.7", "--dump"])
    assert args.command == "redis"
    assert args.dump is True


def test_redis_dump_keys_legacy_alias_is_parsed() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["redis", "-t", "10.0.0.7", "--dump-keys"])
    assert exc.value.code == 2


def test_redis_defcreds_flag_is_parsed() -> None:
    args = parse_args(["redis", "-t", "10.0.0.7", "--defcreds"])
    assert args.command == "redis"
    assert args.defcreds is True


def test_gitlab_flags_are_parsed() -> None:
    args = parse_args(
        [
            "gitlab",
            "-t",
            "10.0.0.20",
            "--timeout",
            "2.0",
            "-w",
            "12",
            "-r",
            "1",
            "--port",
            "80",
            "--ports",
            "80,443,8080",
            "--https",
            "--token",
            "glpat-xxx",
            "--project",
            "group/app,42",
            "--project",
            "team/api",
            "--clone",
            "--clone-dir",
            "./gitlab_clones",
            "-f",
            "json",
            "-o",
            "gitlab_audit.jsonl",
        ]
    )
    assert args.command == "gitlab"
    assert args.targets == "10.0.0.20"
    assert args.timeout == 2.0
    assert args.workers == 12
    assert args.retries == 1
    assert args.port == 80
    assert args.ports == "80,443,8080"
    assert args.https is True
    assert args.token == "glpat-xxx"
    assert args.project == ["group/app,42", "team/api"]
    assert args.clone is True
    assert args.clone_dir == "./gitlab_clones"
    assert args.output_format == "json"
    assert args.output == "gitlab_audit.jsonl"


def test_kubeapi_flags_are_parsed() -> None:
    args = parse_args(
        [
            "kubeapi",
            "-t",
            "10.0.0.30,10.0.0.31",
            "--timeout",
            "2.5",
            "-w",
            "20",
            "-r",
            "1",
            "--port",
            "6443",
            "--ports",
            "6443,8443",
            "--https",
            "--insecure",
            "--ca-file",
            "./ca.crt",
            "--token",
            "k8s-token",
            "-u",
            "ignored",
            "-p",
            "ignored-pass",
            "--namespaces",
            "--pods",
            "--namespace",
            "default,kube-system",
            "--namespace",
            "prod",
            "--pod",
            "redposture-lab/exec-demo",
            "-X",
            "id && uname -a",
            "--secrets",
            "-f",
            "json",
            "-o",
            "kubeapi_audit.jsonl",
        ]
    )
    assert args.command == "kubeapi"
    assert args.targets == "10.0.0.30,10.0.0.31"
    assert args.timeout == 2.5
    assert args.workers == 20
    assert args.retries == 1
    assert args.port == 6443
    assert args.ports == "6443,8443"
    assert args.https is True
    assert args.insecure is True
    assert args.ca_file == "./ca.crt"
    assert args.token == "k8s-token"
    assert args.username == "ignored"
    assert args.password == "ignored-pass"
    assert args.namespaces is True
    assert args.pods is True
    assert args.namespace == ["default,kube-system", "prod"]
    assert args.pod == "redposture-lab/exec-demo"
    assert args.exec_command == "id && uname -a"
    assert args.secrets is True
    assert args.output_format == "json"
    assert args.output == "kubeapi_audit.jsonl"


def test_consul_flags_are_parsed() -> None:
    args = parse_args(
        [
            "consul",
            "-t",
            "10.0.0.40,10.0.0.41",
            "--timeout",
            "2.0",
            "-w",
            "16",
            "-r",
            "1",
            "--port",
            "8500",
            "--ports",
            "8500,8501",
            "--token",
            "consul-token",
            "-u",
            "ignored",
            "-p",
            "ignored-pass",
            "--ssrf-target",
            "127.0.0.1,10.10.0.0/30",
            "--ssrf-port",
            "80,8080-8081",
            "--ssrf-path",
            "/debug/vars?full=1",
            "--keys",
            "--key",
            "redposture/env/prod/db_password",
            "--dump",
            "--services",
            "--service",
            "web",
            "--agents",
            "--checks",
            "--agent",
            "consul-agent-1",
            "--nodes",
            "--node",
            "consul-node-1",
            "--revshell",
            "--lhost",
            "host.docker.internal",
            "--lport",
            "4444",
            "--listen",
            "--payload",
            "sh -c 'id >/tmp/rp.out'",
            "--delete",
            "--check-id",
            "rev-rp-123",
            "-f",
            "json",
            "-o",
            "consul_audit.jsonl",
        ]
    )
    assert args.command == "consul"
    assert args.targets == "10.0.0.40,10.0.0.41"
    assert args.timeout == 2.0
    assert args.workers == 16
    assert args.retries == 1
    assert args.port == 8500
    assert args.ports == "8500,8501"
    assert args.token == "consul-token"
    assert args.username == "ignored"
    assert args.password == "ignored-pass"
    assert args.ssrf_target == "127.0.0.1,10.10.0.0/30"
    assert args.ssrf_port == "80,8080-8081"
    assert args.ssrf_path == "/debug/vars?full=1"
    assert args.show_keys is True
    assert args.kv_key == "redposture/env/prod/db_password"
    assert args.dump is True
    assert args.show_services is True
    assert args.service_dump_name == "web"
    assert args.show_agents is True
    assert args.show_checks is True
    assert args.agent_name == "consul-agent-1"
    assert args.show_nodes is True
    assert args.node_name == "consul-node-1"
    assert args.revshell is True
    assert args.revshell_host == "host.docker.internal"
    assert args.revshell_port == 4444
    assert args.revshell_listen is True
    assert args.revshell_payload == "sh -c 'id >/tmp/rp.out'"
    assert args.delete_revshell is True
    assert args.revshell_check_id == "rev-rp-123"
    assert args.output_format == "json"
    assert args.output == "consul_audit.jsonl"


def test_consul_revshell_delete_flags_are_parsed() -> None:
    args = parse_args(
        [
            "consul",
            "-t",
            "10.0.0.50",
            "--revshell",
            "--delete",
            "--check-id",
            "rev-rp-1700000000-abcd1234",
        ]
    )
    assert args.command == "consul"
    assert args.revshell is True
    assert args.delete_revshell is True
    assert args.revshell_payload is None
    assert args.revshell_check_id == "rev-rp-1700000000-abcd1234"


def test_consul_delete_with_check_id_without_revshell_flags_are_parsed() -> None:
    args = parse_args(
        [
            "consul",
            "-t",
            "10.0.0.50",
            "--delete",
            "--check-id",
            "rev-rp-1700000000-abcd1234",
        ]
    )
    assert args.command == "consul"
    assert args.revshell is False
    assert args.delete_revshell is True
    assert args.revshell_check_id == "rev-rp-1700000000-abcd1234"


def test_consul_revshell_custom_check_id_create_flags_are_parsed() -> None:
    args = parse_args(
        [
            "consul",
            "-t",
            "10.0.0.50",
            "--revshell",
            "--check-id",
            "rev-rp-custom-id",
            "--payload",
            "id",
        ]
    )
    assert args.command == "consul"
    assert args.revshell is True
    assert args.delete_revshell is False
    assert args.revshell_check_id == "rev-rp-custom-id"
    assert args.revshell_payload == "id"


def test_consul_revshell_listen_flag_is_parsed() -> None:
    args = parse_args(
        [
            "consul",
            "-t",
            "10.0.0.50",
            "--revshell",
            "--lhost",
            "127.0.0.1",
            "--lport",
            "4444",
            "--listen",
        ]
    )
    assert args.command == "consul"
    assert args.revshell is True
    assert args.revshell_port == 4444
    assert args.revshell_listen is True


def test_consul_dump_with_check_id_selector_flags_are_parsed() -> None:
    args = parse_args(
        [
            "consul",
            "-t",
            "127.0.0.1",
            "--port",
            "8500",
            "--check-id",
            "id:rev-rp-1772108877-b638b10f",
            "--dump",
        ]
    )
    assert args.command == "consul"
    assert args.revshell is False
    assert args.delete_revshell is False
    assert args.dump is True
    assert args.revshell_check_id == "id:rev-rp-1772108877-b638b10f"


def test_consul_dump_with_service_selector_flags_are_parsed() -> None:
    args = parse_args(
        [
            "consul",
            "-t",
            "127.0.0.1",
            "--service",
            "web",
            "--dump",
        ]
    )
    assert args.command == "consul"
    assert args.dump is True
    assert args.show_services is False
    assert args.service_dump_name == "web"


def test_qdrant_flags_are_parsed() -> None:
    args = parse_args(
        [
            "qdrant",
            "-t",
            "10.0.0.60,10.0.0.61",
            "--timeout",
            "1.2",
            "-w",
            "10",
            "-r",
            "1",
            "--port",
            "6333",
            "--ports",
            "6333,7333",
            "--api-key",
            "qdrant-lab-key",
            "--collections",
            "--collection",
            "demo_vectors",
            "--dump",
            "--ssrf-target",
            "127.0.0.1,10.10.0.0/30",
            "--ssrf-port",
            "80,8080-8081",
            "--ssrf-path",
            "/snapshot.bin",
            "--listen",
            "-f",
            "json",
            "-o",
            "qdrant_audit.jsonl",
        ]
    )
    assert args.command == COMMAND_QDRANT
    assert args.targets == "10.0.0.60,10.0.0.61"
    assert args.timeout == 1.2
    assert args.workers == 10
    assert args.retries == 1
    assert args.port == 6333
    assert args.ports == "6333,7333"
    assert args.api_key == "qdrant-lab-key"
    assert args.show_collections is True
    assert args.collection == "demo_vectors"
    assert args.dump is True
    assert args.ssrf_target == "127.0.0.1,10.10.0.0/30"
    assert args.ssrf_port == "80,8080-8081"
    assert args.ssrf_path == "/snapshot.bin"
    assert args.ssrf_listen is True
    assert args.output_format == "json"
    assert args.output == "qdrant_audit.jsonl"


def test_qdrant_dump_single_collection_flags_are_parsed() -> None:
    args = parse_args(["qdrant", "-t", "127.0.0.1", "--collection", "demo", "--dump"])
    assert args.command == COMMAND_QDRANT
    assert args.collection == "demo"
    assert args.dump is True
    assert args.show_collections is False


def test_etcd_flags_are_parsed() -> None:
    args = parse_args(
        [
            "etcd",
            "-t",
            "10.0.0.9,10.0.0.10",
            "--timeout",
            "0.8",
            "-w",
            "8",
            "-r",
            "1",
            "--port",
            "22379",
            "--ports",
            "2379,22379",
            "--show-keys",
            "--dump",
            "-key",
            "/redposture/env",
            "-f",
            "json",
            "-o",
            "etcd_audit.jsonl",
        ]
    )
    assert args.command == "etcd"
    assert args.targets == "10.0.0.9,10.0.0.10"
    assert args.timeout == 0.8
    assert args.workers == 8
    assert args.retries == 1
    assert args.port == 22379
    assert args.ports == "2379,22379"
    assert args.show_keys is True
    assert args.dump is True
    assert args.key == "/redposture/env"
    assert args.output_format == "json"
    assert args.output == "etcd_audit.jsonl"


def test_etcd_dump_keys_flag_is_parsed() -> None:
    args = parse_args(["etcd", "-t", "10.0.0.9", "--dump"])
    assert args.command == "etcd"
    assert args.dump is True


def test_etcd_dump_keys_legacy_alias_is_parsed() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["etcd", "-t", "10.0.0.9", "--dump-keys"])
    assert exc.value.code == 2


def test_etcd_show_keys_flag_is_parsed() -> None:
    args = parse_args(["etcd", "-t", "10.0.0.9", "--show-keys"])
    assert args.command == "etcd"
    assert args.show_keys is True
    assert args.dump is False


def test_proxmox_flags_are_parsed() -> None:
    args = parse_args(
        [
            "proxmox",
            "-t",
            "10.0.0.21,10.0.0.22",
            "--timeout",
            "1.2",
            "-w",
            "7",
            "-r",
            "2",
            "--port",
            "18006",
            "--ports",
            "8006,18006",
            "--https",
            "--insecure",
            "--pveapitoken",
            "monitor@pve!audit=super-secret-token",
            "--proxy",
            "socks5h://audit:token@127.0.0.1:1080",
            "--discover-creds",
            "--nodes",
            "--users",
            "-add-user",
            "scanner-bot",
            "-f",
            "json",
            "-o",
            "proxmox_audit.jsonl",
        ]
    )
    assert args.command == "proxmox"
    assert args.targets == "10.0.0.21,10.0.0.22"
    assert args.timeout == 1.2
    assert args.workers == 7
    assert args.retries == 2
    assert args.port == 18006
    assert args.ports == "8006,18006"
    assert args.https is True
    assert args.insecure is True
    assert args.pve_api_token == "monitor@pve!audit=super-secret-token"
    assert args.proxy == "socks5h://audit:token@127.0.0.1:1080"
    assert args.discover_creds is True
    assert args.nodes is True
    assert args.users is True
    assert args.add_user == "scanner-bot"
    assert args.output_format == "json"
    assert args.output == "proxmox_audit.jsonl"


def test_proxy_flag_accepts_socks4a_url() -> None:
    args = parse_args(["redis", "-t", "proxy-redis", "--proxy", "socks4a://127.0.0.1:1080"])
    assert args.proxy == "socks4a://127.0.0.1:1080"


def test_proxmox_auth_flags_are_optional_at_parse_time() -> None:
    args = parse_args(["proxmox", "-t", "10.0.0.21"])
    assert args.pve_api_token is None
    assert args.username is None
    assert args.password is None
    assert args.defcreds is False


def test_proxmox_username_password_and_defcreds_are_parsed() -> None:
    args = parse_args(["proxmox", "-t", "10.0.0.21", "-u", "root@pam", "-p", "toor", "--defcreds"])
    assert args.username == "root@pam"
    assert args.password == "toor"
    assert args.defcreds is True


def test_proxmox_discover_creds_default_is_disabled() -> None:
    args = parse_args(["proxmox", "-t", "10.0.0.21", "--pveapitoken", "monitor@pve!audit=token"])
    assert args.discover_creds is False


def test_proxmox_add_user_default_is_none() -> None:
    args = parse_args(["proxmox", "-t", "10.0.0.21", "--pveapitoken", "monitor@pve!audit=token"])
    assert args.add_user is None


def test_proxmox_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(
            [
                "proxmox",
                "-t",
                "10.0.0.21",
                "--pveapitoken",
                "monitor@pve!audit=super-secret-token",
                "--profiles-file",
                "profiles.json",
            ]
        )
    assert exc.value.code == 2


def test_registry_flags_are_parsed() -> None:
    args = parse_args(
        [
            "registry",
            "-t",
            "10.0.0.41,10.0.0.42",
            "--timeout",
            "0.9",
            "-w",
            "6",
            "-r",
            "2",
            "--port",
            "5001",
            "--ports",
            "5000,5001,15000-15001",
            "-u",
            "robot$ci",
            "-p",
            "secret",
            "--images",
            "--repository",
            "gitlab/project-api",
            "--show-tags",
            "--tag",
            "latest",
            "--metadata",
            "--harbor",
            "--gitlab",
            "--nexus",
            "--assets",
            "--inspect",
            "--image",
            "library/nginx:latest",
            "--download",
            "--download-dir",
            "./dl",
            "-f",
            "json",
            "-o",
            "registry_audit.jsonl",
        ]
    )
    assert args.command == "registry"
    assert args.targets == "10.0.0.41,10.0.0.42"
    assert args.timeout == 0.9
    assert args.workers == 6
    assert args.retries == 2
    assert args.port == 5001
    assert args.ports == "5000,5001,15000-15001"
    assert args.username == "robot$ci"
    assert args.password == "secret"
    assert args.images is True
    assert args.repository == "gitlab/project-api"
    assert args.show_tags is True
    assert args.tag == "latest"
    assert args.metadata is True
    assert args.harbor is True
    assert args.gitlab is True
    assert args.nexus is True
    assert args.assets is True
    assert args.inspect is True
    assert args.image == "library/nginx:latest"
    assert args.download is True
    assert args.download_dir == "./dl"
    assert args.token is None
    assert args.output_format == "json"
    assert args.output == "registry_audit.jsonl"


def test_registry_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["registry", "-t", "10.0.0.9", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_registry_token_flag_is_parsed() -> None:
    args = parse_args(["registry", "-t", "10.0.0.9", "--token", "token-value"])
    assert args.command == "registry"
    assert args.token == "token-value"
    assert args.gitlab is False
    assert args.nexus is False
    assert args.show_tags is False
    assert args.metadata is False
    assert args.assets is False


def test_registry_port_list_in_port_flag_is_normalized() -> None:
    args = parse_args(["registry", "-t", "10.0.0.9", "--port", "15000,15002"])
    assert args.command == "registry"
    assert args.port == 15000
    assert args.ports == "15000,15002"


def test_registry_port_file_in_port_flag_is_normalized(tmp_path) -> None:
    ports_file = tmp_path / "ports.txt"
    ports_file.write_text("15000\n15002\n", encoding="utf-8")
    args = parse_args(["registry", "-t", "10.0.0.9", "--port", str(ports_file)])
    assert args.command == "registry"
    assert args.port is None
    assert args.ports == str(ports_file)


def test_kafka_flags_are_parsed() -> None:
    args = parse_args(
        [
            "kafka",
            "-t",
            "10.0.0.21,10.0.0.22",
            "--timeout",
            "0.8",
            "-w",
            "8",
            "-r",
            "1",
            "--port",
            "19092",
            "--ports",
            "9092,19092,29092",
            "-u",
            "metrics",
            "-p",
            "secret",
            "--show-topics",
            "--topic",
            "orders",
            "--dump",
            "--max-messages",
            "5000",
            "-f",
            "json",
            "-o",
            "kafka_audit.jsonl",
        ]
    )
    assert args.command == "kafka"
    assert args.targets == "10.0.0.21,10.0.0.22"
    assert args.timeout == 0.8
    assert args.workers == 8
    assert args.retries == 1
    assert args.port == 19092
    assert args.ports == "9092,19092,29092"
    assert args.username == "metrics"
    assert args.password == "secret"
    assert args.show_topics is True
    assert args.topic == "orders"
    assert args.dump is True
    assert args.max_messages == 5000
    assert args.output_format == "json"
    assert args.output == "kafka_audit.jsonl"


def test_kafka_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["kafka", "-t", "10.0.0.9", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_kafka_dump_without_topic_is_parsed() -> None:
    args = parse_args(["kafka", "-t", "10.0.0.9", "--dump"])
    assert args.command == "kafka"
    assert args.dump is True
    assert args.topic is None


def test_zookeeper_flags_are_parsed() -> None:
    args = parse_args(
        [
            "zookeeper",
            "-t",
            "10.0.0.31,10.0.0.32",
            "--timeout",
            "0.9",
            "-w",
            "6",
            "-r",
            "2",
            "--port",
            "22181",
            "--ports",
            "2181,22181",
            "-u",
            "zk-user",
            "-p",
            "zk-pass",
            "--show-znodes",
            "--dump",
            "--znode",
            "/brokers/ids/1",
            "--max-znodes",
            "500",
            "--enum-workers",
            "7",
            "-f",
            "json",
            "-o",
            "zookeeper_audit.jsonl",
        ]
    )
    assert args.command == "zookeeper"
    assert args.targets == "10.0.0.31,10.0.0.32"
    assert args.timeout == 0.9
    assert args.workers == 6
    assert args.retries == 2
    assert args.port == 22181
    assert args.ports == "2181,22181"
    assert args.username == "zk-user"
    assert args.password == "zk-pass"
    assert args.show_znodes is True
    assert args.dump is True
    assert args.znode == "/brokers/ids/1"
    assert args.max_znodes == 500
    assert args.enum_workers == 7
    assert args.output_format == "json"
    assert args.output == "zookeeper_audit.jsonl"


@pytest.mark.parametrize("command", ["zookeeper", "keeper"])
def test_znode_flag_uses_long_option_only(command: str) -> None:
    args = parse_args([command, "-t", "10.0.0.9", "--znode", "/clickhouse/tables"])
    assert args.znode == "/clickhouse/tables"

    help_text = _command_help(command)
    assert "\n  --znode path" in help_text
    assert "\n  -znode" not in help_text
    assert "[-znode path]" not in help_text

    with pytest.raises(SystemExit) as exc:
        parse_args([command, "-t", "10.0.0.9", "-znode", "/clickhouse/tables"])
    assert exc.value.code == 2


def test_zookeeper_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["zookeeper", "-t", "10.0.0.9", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_keeper_flags_and_auto_tls_defaults_are_parsed() -> None:
    args = parse_args(
        [
            "keeper",
            "-t",
            "10.0.0.41",
            "--port",
            "19181,29181",
            "--insecure",
            "--tls-cert",
            "client.pem",
            "--tls-key",
            "client.key",
            "--show-znodes",
            "20",
            "--dump",
            "10",
            "--enum-workers",
            "4",
        ]
    )
    assert args.command == "keeper"
    assert args.port == 19181
    assert args.ports == "19181,29181"
    assert not hasattr(args, "tls")
    assert not hasattr(args, "no_tls")
    assert args.insecure is True
    assert args.tls_cert == "client.pem"
    assert args.tls_key == "client.key"
    assert args.show_znodes == 20
    assert args.dump == 10
    assert args.enum_workers == 4
    assert args.timeout == 5.0


@pytest.mark.parametrize("removed_flag", ["--tls", "--no-tls"])
def test_keeper_transport_is_auto_detected_without_manual_mode_flags(removed_flag: str) -> None:
    help_text = _command_help("keeper")
    assert "\nTLS (transport auto-detected):\n" in help_text
    assert re.search(r"(?m)^  --tls\s", help_text) is None
    assert re.search(r"(?m)^  --no-tls\s", help_text) is None
    assert "--ca-file file" in help_text
    assert "--insecure" in help_text
    assert "--tls-cert file" in help_text
    assert "--tls-key file" in help_text

    with pytest.raises(SystemExit) as exc:
        parse_args(["keeper", "-t", "10.0.0.41", removed_flag])
    assert exc.value.code == 2


def test_zookeeper_dump_legacy_alias_is_parsed() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["zookeeper", "-t", "10.0.0.9", "--dump-znodes"])
    assert exc.value.code == 2


def test_zookeeper_default_timeout_is_five_seconds() -> None:
    args = parse_args(["zookeeper", "-t", "10.0.0.9"])
    assert args.timeout == 5.0
    assert args.enum_workers == 3


def test_zookeeper_help_timeout_default_is_five_seconds() -> None:
    help_text = _command_help("zookeeper")
    assert "Network timeout in seconds. (default: 5.0)" in help_text


def test_elastic_flags_are_parsed() -> None:
    args = parse_args(
        [
            "elastic",
            "-t",
            "10.0.0.71,10.0.0.72",
            "--timeout",
            "1.3",
            "-w",
            "9",
            "-r",
            "1",
            "--port",
            "19200",
            "--ports",
            "9200,19200",
            "--ca-file",
            "./elastic-ca.pem",
            "-u",
            "elastic",
            "-p",
            "ElasticRead!2026",
            "--apitoken",
            "ZXM6bGFiLXRva2Vu",
            "--defcreds",
            "--endpoints",
            "--plugins",
            "--cluster",
            "--user",
            "--discover",
            "-f",
            "json",
            "-o",
            "elastic_audit.jsonl",
        ]
    )
    assert args.command == COMMAND_ELASTIC
    assert args.targets == "10.0.0.71,10.0.0.72"
    assert args.timeout == 1.3
    assert args.workers == 9
    assert args.retries == 1
    assert args.port == 19200
    assert args.ports == "9200,19200"
    assert args.ca_file == "./elastic-ca.pem"
    assert args.username == "elastic"
    assert args.password == "ElasticRead!2026"
    assert args.apitoken == "ZXM6bGFiLXRva2Vu"
    assert args.defcreds is True
    assert args.endpoints is True
    assert args.plugins is True
    assert args.cluster is True
    assert args.user is True
    assert args.discover is True
    assert args.output_format == "json"
    assert args.output == "elastic_audit.jsonl"


def test_elastic_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["elastic", "-t", "10.0.0.71", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_elastic_rejects_insecure_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["elastic", "-t", "10.0.0.71", "--insecure"])
    assert exc.value.code == 2


def test_kafka_defcreds_flag_is_parsed() -> None:
    args = parse_args(["kafka", "-t", "10.0.0.31", "--defcreds"])
    assert args.command == COMMAND_KAFKA
    assert args.defcreds is True


def test_grafana_flags_are_parsed() -> None:
    args = parse_args(
        [
            "grafana",
            "-t",
            "10.0.0.11,10.0.0.12",
            "--timeout",
            "0.9",
            "-w",
            "6",
            "-r",
            "2",
            "--port",
            "3001",
            "--ports",
            "3000,3001",
            "-u",
            "admin",
            "-p",
            "secret",
            "--defcreds",
            "--show-datasources",
            "--ssrf-target",
            "http://127.0.0.1/probe",
            "--ssrf-port",
            "8081",
            "--ssrf-path",
            "/debug/vars?x=1",
            "-f",
            "json",
            "-o",
            "grafana_audit.jsonl",
        ]
    )
    assert args.command == "grafana"
    assert args.targets == "10.0.0.11,10.0.0.12"
    assert args.timeout == 0.9
    assert args.workers == 6
    assert args.retries == 2
    assert args.port == 3001
    assert args.ports == "3000,3001"
    assert args.username == "admin"
    assert args.password == "secret"
    assert args.defcreds is True
    assert args.show_datasources is True
    assert args.ssrf_target == "http://127.0.0.1/probe"
    assert args.ssrf_port == "8081"
    assert args.ssrf_path == "/debug/vars?x=1"
    assert args.output_format == "json"
    assert args.output == "grafana_audit.jsonl"


def test_grafana_help_documents_current_default_creds() -> None:
    help_text = _command_help("grafana")
    assert "admin:admin" in help_text
    assert "admin:prom-operator" not in help_text


def test_grafana_show_datasource_alias_is_parsed() -> None:
    args = parse_args(["grafana", "-t", "10.0.0.11", "--show-datasource"])
    assert args.command == "grafana"
    assert args.show_datasources is True


def test_grafana_temp_check_flags_are_parsed() -> None:
    args = parse_args(
        ["grafana", "-t", "10.0.0.11", "--ssrf-target", "example.com/path", "--ssrf-port", "8080", "--ssrf-path", "/x"]
    )
    assert args.command == "grafana"
    assert args.ssrf_target == "example.com/path"
    assert args.ssrf_port == "8080"
    assert args.ssrf_path == "/x"


def test_grafana_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["grafana", "-t", "10.0.0.11", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_etcd_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["etcd", "-t", "10.0.0.9", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_collect_save_responses_flag_is_parsed() -> None:
    args = parse_args(["exporters", "collect", "-t", "10.0.0.1", "--save-responses-dir", "collect_raw"])
    assert args.save_responses_dir == "collect_raw"


def test_collect_resume_and_checkpoint_flags_are_parsed() -> None:
    args = parse_args(
        [
            "exporters",
            "collect",
            "-t",
            "10.0.0.1",
            "--resume",
            "--checkpoint-file",
            "collect.ckpt.jsonl",
            "--max-inflight",
            "128",
            "--no-adaptive-collect",
        ]
    )
    assert args.resume is True
    assert args.checkpoint_file == "collect.ckpt.jsonl"
    assert args.max_inflight == 128
    assert args.adaptive_collect is False


def test_redis_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["redis", "-t", "10.0.0.7", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_redis_rejects_removed_fetch_keys_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["redis", "-t", "10.0.0.7", "--fetch-keys"])
    assert exc.value.code == 2


def test_postgres_flags_are_parsed() -> None:
    args = parse_args(
        [
            "postgres",
            "-t",
            "10.0.0.7,10.0.0.8",
            "--timeout",
            "0.8",
            "-w",
            "8",
            "-r",
            "1",
            "--port",
            "5433",
            "--ports",
            "5432,5433,15432",
            "--database",
            "appdb",
            "--username",
            "postgres",
            "--password",
            "postgres",
            "--defcreds",
            "--show-databases",
            "--show-tables",
            "--show-columns",
            "--os-shell",
            "--sql-shell",
            "--table",
            "public.users",
            "--dump",
            "--table",
            "redposture.demo_accounts,public.audit_log",
            "--column",
            "id,username",
            "--column",
            "created_at",
            "--execute",
            "id",
            "--os-read",
            "/etc/hostname",
            "--privesc-check",
            "--sql-cmd",
            "select 1",
            "-f",
            "json",
            "-o",
            "postgres_audit.jsonl",
        ]
    )
    assert args.command == "postgres"
    assert args.targets == "10.0.0.7,10.0.0.8"
    assert args.timeout == 0.8
    assert args.workers == 8
    assert args.retries == 1
    assert args.port == 5433
    assert args.ports == "5432,5433,15432"
    assert args.database == "appdb"
    assert args.username == "postgres"
    assert args.password == "postgres"
    assert args.defcreds is True
    assert args.show_databases is True
    assert args.show_tables is True
    assert args.show_columns is True
    assert args.os_shell is True
    assert args.sql_shell is True
    assert args.tables == ["public.users", "redposture.demo_accounts,public.audit_log"]
    assert args.dump is True
    assert args.columns == ["id,username", "created_at"]
    assert args.execute == "id"
    assert args.os_read == "/etc/hostname"
    assert args.privesc_check is True
    assert args.sql_cmd == "select 1"
    assert args.output_format == "json"
    assert args.output == "postgres_audit.jsonl"


def test_postgres_short_user_password_flags_are_parsed() -> None:
    args = parse_args(
        [
            "postgres",
            "-t",
            "10.0.0.7",
            "-u",
            "postgres",
            "-p",
            "postgres",
            "--database",
            "appdb",
            "--table",
            "public.users",
            "-x",
            "whoami",
        ]
    )
    assert args.command == "postgres"
    assert args.username == "postgres"
    assert args.password == "postgres"
    assert args.database == "appdb"
    assert args.defcreds is False
    assert args.show_databases is False
    assert args.show_tables is False
    assert args.show_columns is False
    assert args.os_shell is False
    assert args.sql_shell is False
    assert args.tables == ["public.users"]
    assert args.dump is False
    assert args.columns is None
    assert args.execute == "whoami"
    assert args.sql_cmd is None


def test_postgres_rejects_columns_alias() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["postgres", "-t", "10.0.0.7", "--table", "public.users", "--columns", "id"])
    assert exc.value.code == 2


def test_postgres_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["postgres", "-t", "10.0.0.7", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_postgres_defcreds_flag_is_parsed() -> None:
    args = parse_args(["postgres", "-t", "10.0.0.7", "--defcreds"])
    assert args.command == "postgres"
    assert args.defcreds is True


def test_postgres_debug_flag_is_long_only() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["postgres", "-t", "10.0.0.7", "-d"])
    assert exc.value.code == 2

    args = parse_args(["postgres", "-t", "10.0.0.7", "--debug"])
    assert args.debug is True


def test_postgres_no_color_flag_is_parsed() -> None:
    args = parse_args(["postgres", "-t", "10.0.0.7", "--no-color"])
    assert args.no_color is True


def test_elastic_help_includes_no_color_option() -> None:
    help_text = _command_help("elastic")
    assert "--no-color" in help_text


def test_postgres_rejects_short_database_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["postgres", "-t", "10.0.0.7", "-d", "appdb"])
    assert exc.value.code == 2


def test_postgres_accepts_save_alias() -> None:
    """F9 fix: `--save` used to be rejected exclusively by postgres/mongo/
    docker/oracle; every other module accepted it. Now aligned."""
    args = parse_args(["postgres", "-t", "10.0.0.7", "--save", "postgres_audit.jsonl"])
    assert args.output == "postgres_audit.jsonl"


def test_clickhouse_flags_are_parsed() -> None:
    args = parse_args(
        [
            "clickhouse",
            "-t",
            "10.0.0.7,10.0.0.8",
            "--timeout",
            "0.8",
            "-w",
            "8",
            "-r",
            "1",
            "--port",
            "9000",
            "--ports",
            "9000,8123,19000",
            "--http",
            "--database",
            "analytics",
            "--username",
            "default",
            "--password",
            "default",
            "--defcreds",
            "--show-databases",
            "--show-tables",
            "--show-columns",
            "--table",
            "analytics.sessions",
            "--dump",
            "--table",
            "observability.events,analytics.tokens",
            "--column",
            "id,token",
            "--column",
            "created_at",
            "-x",
            "FLUSH LOGS",
            "--sql-cmd",
            "select 1",
            "--sql-shell",
            "-f",
            "json",
            "-o",
            "clickhouse_audit.jsonl",
        ]
    )
    assert args.command == "clickhouse"
    assert args.targets == "10.0.0.7,10.0.0.8"
    assert args.timeout == 0.8
    assert args.workers == 8
    assert args.retries == 1
    assert args.port == 9000
    assert args.ports == "9000,8123,19000"
    assert args.http is True
    assert args.database == "analytics"
    assert args.username == "default"
    assert args.password == "default"
    assert args.defcreds is True
    assert args.show_databases is True
    assert args.show_tables is True
    assert args.show_columns is True
    assert args.tables == ["analytics.sessions", "observability.events,analytics.tokens"]
    assert args.dump is True
    assert args.columns == ["id,token", "created_at"]
    assert args.execute == "FLUSH LOGS"
    assert args.sql_cmd == "select 1"
    assert args.os_shell is False
    assert args.sql_shell is True
    assert args.output_format == "json"
    assert args.output == "clickhouse_audit.jsonl"


def test_clickhouse_short_user_password_flags_are_parsed() -> None:
    args = parse_args(["clickhouse", "-t", "10.0.0.7", "-u", "default", "-p", "default", "-d", "analytics"])
    assert args.command == "clickhouse"
    assert args.username == "default"
    assert args.password == "default"
    assert args.database == "analytics"
    assert args.http is False
    assert args.defcreds is False
    assert args.execute is None
    assert args.os_shell is False
    assert args.sql_cmd is None
    assert args.sql_shell is False


def test_clickhouse_os_shell_flag_is_parsed() -> None:
    args = parse_args(["clickhouse", "-t", "10.0.0.7", "--os-shell"])
    assert args.command == "clickhouse"
    assert args.os_shell is True


def test_clickhouse_rejects_columns_alias() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["clickhouse", "-t", "10.0.0.7", "--table", "analytics.sessions", "--columns", "id"])
    assert exc.value.code == 2


def test_clickhouse_rejects_profiles_file_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["clickhouse", "-t", "10.0.0.7", "--profiles-file", "profiles.json"])
    assert exc.value.code == 2


def test_clickhouse_defcreds_flag_is_parsed() -> None:
    args = parse_args(["clickhouse", "-t", "10.0.0.7", "--defcreds"])
    assert args.command == "clickhouse"
    assert args.defcreds is True


def test_version_flag_exits_cleanly() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["--version"])
    assert exc.value.code == 0


def test_selfcert_command_defaults_are_parsed() -> None:
    args = parse_args(["--selfcert"])
    assert args.command == COMMAND_SELFCERT
    assert args.cert_out == "cert.pem"
    assert args.key_out == "key.pem"
    assert args.force is False
    assert args.log is None


def test_selfcert_log_flag_is_parsed() -> None:
    args = parse_args(["--selfcert", "-log", "selfcert.log"])
    assert args.command == COMMAND_SELFCERT
    assert args.log == "selfcert.log"


def test_global_selfcert_alias_is_parsed() -> None:
    args = parse_args(["--selfcert", "--cert-out", "tls/cert.pem", "--key-out", "tls/key.pem", "--force"])
    assert args.command == COMMAND_SELFCERT
    assert args.cert_out == "tls/cert.pem"
    assert args.key_out == "tls/key.pem"
    assert args.force is True


def test_legacy_short_selfcert_alias_is_parsed() -> None:
    args = parse_args(["-selfcert"])
    assert args.command == COMMAND_SELFCERT


def test_selfcert_subcommand_is_not_supported() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args([COMMAND_SELFCERT])
    assert exc.value.code == 2


def test_collect_deep_flags_are_parsed() -> None:
    args = parse_args(
        ["exporters", "collect", "-t", "10.0.0.1", "--deep", "--pprof-seconds", "9", "--trace-seconds", "3"]
    )
    assert args.deep is True
    assert args.pprof_seconds == 9
    assert args.trace_seconds == 3


def test_collect_validation_flags_removed_from_collect() -> None:
    args = parse_args(["exporters", "collect", "-t", "10.0.0.1"])
    assert args.deep is False
    assert args.pprof_seconds == 5
    assert args.trace_seconds == 2
    assert not hasattr(args, "validate")
    assert not hasattr(args, "validate_show")
    assert not hasattr(args, "validate_max_lines")
    assert not hasattr(args, "validate_fail_on_creds")


def test_collect_rejects_removed_validate_flags() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["exporters", "collect", "-t", "10.0.0.1", "--validate"])
    assert exc.value.code == 2


def test_collect_exporters_filter_is_parsed() -> None:
    args = parse_args(["exporters", "collect", "-t", "10.0.0.1", "--exporters", "redis,postgres_exporter"])
    assert args.collect_exporters_filter == "redis,postgres_exporter"


def test_collect_rejects_removed_output_all_alias() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["exporters", "collect", "-t", "10.0.0.1", "-oA"])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        parse_args(["exporters", "collect", "-t", "10.0.0.1", "--output-all", "collect.txt"])
    assert exc.value.code == 2


def test_collect_rejects_removed_write_vulnerable_targets_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["exporters", "collect", "-t", "10.0.0.1", "--write-vulnerable-targets"])
    assert exc.value.code == 2


def test_direct_scan_trigger_collect_are_rejected() -> None:
    for argv in (
        ["scan", "-t", "10.0.0.1"],
        ["trigger", "-t", "10.0.0.1", "--callback-ip", "10.0.0.2"],
        ["collect", "-t", "10.0.0.1"],
    ):
        with pytest.raises(SystemExit) as exc:
            parse_args(argv)
        assert exc.value.code == 2
